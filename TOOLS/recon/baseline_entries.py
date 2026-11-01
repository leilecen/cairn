"""Deterministic, bounded L0 entry confirmation for broad reconnaissance.

This module deliberately has no crawl queue.  It consumes only explicitly
authorized assets, probes a finite candidate list, and stores compact entry
observations for a later operator-selected deep session.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Mapping
from typing import Any
from urllib.parse import urljoin, urlparse

from entry_probe import classify_response, generate_candidates
from recon.recon_store import ensure_recon_schema, record_entry
from recon.scope import is_active_scope

FetchResult = Mapping[str, Any]
Fetcher = Callable[[str, str], FetchResult]
_ALLOWED_ENTRY_TYPES = frozenset({"login", "admin", "api"})
_WAF_MARKERS = ("waf", "cloudflare", "access denied", "security challenge", "captcha")
# Assets already known not to answer at the HTTP layer must not consume the
# bounded probe budget; they would otherwise starve every live asset.
_LIVENESS_SKIP = frozenset({"unreachable", "dead", "internal_only"})
# One control request per asset establishes the response for a path that cannot
# exist.  Applications that return a fixed body for every path (catch-all) would
# otherwise make every candidate look like a real, auth-protected entry.
_CATCHALL_CONTROL_PATH = "/__entry_probe_control_7f3a__"


def _signature(status_code: int, body_hint: str) -> tuple[int, str]:
    """Compact response signature used to detect a catch-all responder."""
    return (status_code, body_hint or "")


def _asset_value(asset: Mapping[str, Any]) -> str:
    value = str(asset.get("asset_value") or asset.get("url") or "").strip()
    if not value:
        return ""
    return value if "://" in value else f"https://{value}"


def _json_list(asset: Mapping[str, Any], key: str) -> list[str]:
    value = asset.get(key, ())
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return []
    return [str(item) for item in value] if isinstance(value, (list, tuple)) else []


def _json_lists(asset: Mapping[str, Any], keys: tuple[str, ...]) -> list[str]:
    values: list[str] = []
    for key in keys:
        values.extend(_json_list(asset, key))
    return values


def _looks_like_waf(result: FetchResult) -> bool:
    text = " ".join(str(result.get(key) or "")[:500].lower() for key in ("location", "body_hint"))
    return any(marker in text for marker in _WAF_MARKERS)


def _stop_reason(result: FetchResult) -> str | None:
    code = int(result.get("status_code", 0) or 0)
    if code == 429:
        return "rate_limited"
    if code == 451:
        return "legal_block"
    if _looks_like_waf(result):
        return "waf_detected"
    return None


def _rows_from_assets(conn, *, target_name: str, assets: Iterable[Mapping[str, Any]] | None) -> list[Mapping[str, Any]]:
    if assets is not None:
        rows = list(assets)
        for row in rows:
            row_target = row.get("target_name")
            if row_target is not None and str(row_target) != target_name:
                raise ValueError("asset target_name does not match explicit target_name")
        return rows
    columns = {row[1] for row in conn.execute("PRAGMA table_info(target_assets)")}
    optional = (
        "known_urls_json",
        "tech_stack_json",
        "login_urls",
        "register_urls",
        "last_tech_stack",
        "tech_stack",
        "live_status",
    )
    selected = [
        column for column in ("id", "target_name", "asset_value", "scope_status", "scope_class", "authorization_state") if column in columns
    ]
    selected.extend(column for column in optional if column in columns)
    return [
        dict(row)
        for row in conn.execute(
            f"SELECT {','.join(selected)} FROM target_assets WHERE target_name=? ORDER BY id",  # noqa: S608 - columns come from PRAGMA.
            (target_name,),
        ).fetchall()
    ]


def run_baseline_entry_probe(
    conn,
    *,
    target_name: str,
    fetcher: Fetcher,
    assets: Iterable[Mapping[str, Any]] | None = None,
    per_asset_cap: int = 12,
    total_cap: int = 60,
) -> dict[str, Any]:
    """Confirm a bounded set of login/admin/docs/API entries across assets.

    ``fetcher`` is injected so callers can supply their HTTP layer; it receives
    ``(url, "GET")`` and must return compact response fields.  No response body
    is persisted and no recursive work is scheduled.
    """
    if not target_name.strip():
        raise ValueError("target_name is required")
    if per_asset_cap < 0 or total_cap < 0:
        raise ValueError("caps must be non-negative")
    ensure_recon_schema(conn)
    rows = _rows_from_assets(conn, target_name=target_name, assets=assets)
    processed = 0
    requests = 0
    observations = 0
    no_response = 0
    catchall_skipped = 0
    skipped_unreachable = 0
    stop_reason: str | None = None

    for asset in rows:
        if not is_active_scope(asset.get("scope_class"), asset.get("scope_status")):
            continue
        if requests >= total_cap:
            stop_reason = "total_cap"
            break
        if str(asset.get("live_status") or "").strip().casefold() in _LIVENESS_SKIP:
            skipped_unreachable += 1
            continue
        base_url = _asset_value(asset)
        if not base_url or not urlparse(base_url).netloc:
            continue
        processed += 1
        candidates = [
            candidate
            for candidate in generate_candidates(
                base_url,
                known_urls=_json_lists(asset, ("known_urls_json", "login_urls", "register_urls")),
                tech_stack=_json_lists(asset, ("tech_stack_json", "last_tech_stack", "tech_stack")),
            )
            if candidate.entry_type in _ALLOWED_ENTRY_TYPES
        ][:per_asset_cap]
        # One bounded control request: what does this asset return for a path
        # that cannot exist?  Anything matching it later is not a real entry.
        control_sig: tuple[int, str] | None = None
        if requests < total_cap:
            control = fetcher(urljoin(base_url, _CATCHALL_CONTROL_PATH), "GET")
            requests += 1
            control_code = int(control.get("status_code", 0) or 0)
            if control_code <= 0:
                # The control request itself did not answer, so this host is not
                # serving HTTP at all; skip it without spending the rest of its
                # budget, but keep going with the other assets.
                no_response += 1
                continue
            control_sig = _signature(control_code, str(control.get("body_hint") or "")[:500])
            control_stop = _stop_reason(control)
            if control_stop:
                stop_reason = control_stop
                break

        for candidate in candidates:
            if requests >= total_cap:
                stop_reason = "total_cap"
                break
            result = fetcher(candidate.url, "GET")
            requests += 1
            code = int(result.get("status_code", 0) or 0)
            if code <= 0:
                # Transport failure: the path was never actually served, so it
                # is not an entry fact.  Recording it as observed previously
                # fabricated login entries for unreachable hosts.  Stop probing
                # this host instead of burning the per-asset budget on it.
                no_response += 1
                break
            if control_sig is not None and _signature(code, str(result.get("body_hint") or "")[:500]) == control_sig:
                # Indistinguishable from a path that cannot exist, so it carries
                # no information about this candidate.
                catchall_skipped += 1
                continue
            response_class, response_confidence = classify_response(
                code,
                location=str(result.get("location") or ""),
                body_hint=str(result.get("body_hint") or "")[:500],
                request_url=candidate.url,
            )
            record_entry(
                conn,
                target_name=target_name,
                asset_id=asset.get("id"),
                url=candidate.url,
                entry_type=candidate.entry_type,
                source="baseline_entry_probe",
                status="observed",
                status_code=code,
                confidence=candidate.confidence if candidate.confidence != "low" else response_confidence,
                response_class=response_class,
                evidence_refs=(f"entry_observations:baseline_entry_probe:{asset.get('id', 'unknown')}",),
                notes="bounded L0 entry confirmation",
            )
            observations += 1
            stop_reason = _stop_reason(result)
            if stop_reason:
                break
        if stop_reason:
            break

    if stop_reason is None and observations == 0 and no_response:
        # Nothing answered, so the probe learned nothing about entries.  Report
        # it as blocked rather than as a clean "no entries exist" result.
        stop_reason = "no_response"
    status = "blocked" if stop_reason in {"rate_limited", "legal_block", "waf_detected", "no_response"} else "done"
    return {
        "status": status,
        "target": target_name,
        "assets_processed": processed,
        "requests": requests,
        "observations": observations,
        "no_response": no_response,
        "catchall_skipped": catchall_skipped,
        "skipped_unreachable": skipped_unreachable,
        "stop_reason": stop_reason,
    }
