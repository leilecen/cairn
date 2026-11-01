"""Offline M8 identity, vendor-family, and public-path classification helpers."""

from __future__ import annotations

import ipaddress
import json
import re
import sqlite3
from datetime import UTC, datetime
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit

_CONFIDENCE = {"unknown": 0, "low": 1, "medium": 2, "high": 3}
_EVIDENCE_CLASSES = {
    "title": "page",
    "page_title": "page",
    "favicon": "page",
    "login_js": "login_js",
    "js_constant": "login_js",
    "public_index": "public_index",
    "fofa": "public_index",
    "archive": "archive",
    "tls": "tls",
    "certificate": "tls",
    "http_header": "http_header",
}
_UNSAFE_SIGNAL = re.compile(
    r"(?:GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+\S+\s+HTTP/|"
    r"(?:authorization|cookie|password|passwd|secret|api[_-]?key|access[_-]?token)\s*[:=]|bearer\s+\S+",
    re.I,
)
_EVIDENCE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/#@-]{0,159}$")
_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_VENDOR_PRODUCTS = (
    (
        re.compile(r"\bsangfor\b|深信服", re.I),
        "Sangfor",
        (
            (re.compile(r"\batrust\b", re.I), "aTrust"),
            (re.compile(r"\baf\b", re.I), "AF"),
            (re.compile(r"\bpam\b", re.I), "PAM"),
        ),
    ),
    (re.compile(r"\blongshine\b|朗新", re.I), "Longshine", ((re.compile(r"\bhcm\b|stalent", re.I), "HCM"),)),
    (re.compile(r"\bsynology\b|群晖", re.I), "Synology", ((re.compile(r"\bdsm\b", re.I), "DSM"),)),
)


def validate_compact_text(
    value: Any, *, field: str, max_chars: int, allow_empty: bool = True, pattern: re.Pattern[str] | None = None
) -> str:
    text = str(value or "").strip()
    if not text:
        if allow_empty:
            return ""
        raise ValueError(f"{field} is required")
    if len(text) > max_chars or any(ord(char) < 32 for char in text) or _UNSAFE_SIGNAL.search(text):
        raise ValueError(f"{field} is not safe compact text")
    if pattern is not None and pattern.fullmatch(text) is None:
        raise ValueError(f"{field} has invalid format")
    return text


def validate_evidence_ref(value: Any) -> str:
    text = validate_compact_text(value, field="evidence ref", max_chars=160, allow_empty=False)
    if _EVIDENCE_REF.fullmatch(text) is None:
        raise ValueError("evidence ref has invalid format")
    return text


def validate_evidence_refs(value: Any, *, allow_empty: bool = True, limit: int = 10) -> list[str]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ValueError("evidence refs must be a JSON list") from exc
    if not isinstance(value, list):
        raise ValueError("evidence refs must be a list")
    refs = list(dict.fromkeys(validate_evidence_ref(item) for item in value[:limit]))
    if not refs and not allow_empty:
        raise ValueError("at least one evidence ref is required")
    return refs


def normalize_host(value: Any, *, allow_empty: bool = False) -> str:
    raw = validate_compact_text(value, field="host", max_chars=253, allow_empty=allow_empty)
    if not raw:
        return ""
    if "://" in raw or any(char in raw for char in "/?#@") or any(char.isspace() for char in raw):
        raise ValueError("host has invalid format")
    try:
        return ipaddress.ip_address(raw.strip("[]")).compressed.lower()
    except ValueError:
        pass
    try:
        host = raw.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("host has invalid IDNA encoding") from exc
    labels = host.split(".")
    if len(host) > 253 or any(_HOST_LABEL.fullmatch(label) is None for label in labels):
        raise ValueError("host has invalid format")
    return host


def normalize_ip(value: Any) -> str:
    raw = validate_compact_text(value, field="ip", max_chars=64, allow_empty=False)
    try:
        return ipaddress.ip_address(raw).compressed.lower()
    except ValueError as exc:
        raise ValueError("ip has invalid format") from exc


def validate_port(value: Any, *, allow_none: bool = True) -> int | None:
    if value in (None, "") and allow_none:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("port must be an integer between 1 and 65535")
    port = value
    if not 1 <= port <= 65535:
        raise ValueError("port must be an integer between 1 and 65535")
    return port


def validate_timestamp(value: Any, *, allow_none: bool = True) -> str | None:
    if value in (None, ""):
        if allow_none:
            return None
        raise ValueError("observed_at is required")
    text = validate_compact_text(value, field="observed_at", max_chars=40, allow_empty=False)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("observed_at must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is not None:
        parsed.astimezone(UTC)
    return text


def classify_identity(evidence: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Return an open identity decision; two independent evidence kinds corroborate."""
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    roles: set[str] = set()
    for raw in evidence:
        dumped = json.dumps(dict(raw), ensure_ascii=False)
        if _UNSAFE_SIGNAL.search(dumped) or any(
            re.search(r"password|passwd|secret|token|authorization|cookie", str(key), re.I) for key in raw
        ):
            raise ValueError("raw HTTP or credential material is not accepted")
        raw_kind = validate_compact_text(
            raw.get("kind") or raw.get("source") or "unknown",
            field="evidence kind",
            max_chars=80,
            allow_empty=False,
        )
        kind = _EVIDENCE_CLASSES.get(raw_kind.casefold(), "other")
        raw_ref = raw.get("evidence_ref")
        ref = validate_evidence_ref(raw_ref) if raw_ref else ""
        vendor = validate_compact_text(raw.get("vendor"), field="vendor", max_chars=120)
        product = validate_compact_text(raw.get("product"), field="product", max_chars=120)
        role = validate_compact_text(raw.get("deployment_role"), field="deployment role", max_chars=80)
        if role:
            roles.add(role[:80])
        if not (vendor or product) or not ref:
            continue
        key = (vendor.casefold(), product.casefold())
        item = grouped.setdefault(
            key,
            {"vendor": vendor, "product": product, "kinds": set(), "refs": [], "confidence": "unknown"},
        )
        item["kinds"].add(kind)
        item["refs"] = list(dict.fromkeys([*item["refs"], ref]))[:10]
        confidence = str(raw.get("confidence") or "unknown").lower()
        if _CONFIDENCE.get(confidence, 0) > _CONFIDENCE.get(item["confidence"], 0):
            item["confidence"] = confidence

    ranked = sorted(grouped.values(), key=lambda item: (-len(item["kinds"]), item["product"], item["vendor"]))
    top = ranked[0] if ranked else None
    top_strength = len(top["kinds"]) if top else 0
    top_ref_strength = len(top["refs"]) if top else 0
    conflicting_identities = {
        (item["vendor"].casefold(), item["product"].casefold()) for item in ranked if item["vendor"] or item["product"]
    }
    if not ranked:
        status = "unknown"
    elif len(conflicting_identities) > 1:
        status = "conflicted"
    elif top_strength >= 2 and top_ref_strength >= 2:
        status = "corroborated"
    else:
        status = "candidate"

    def candidates(field: str) -> list[dict[str, Any]]:
        aggregate: dict[str, dict[str, Any]] = {}
        for item in ranked:
            name = str(item[field]).strip()
            if not name:
                continue
            current = aggregate.setdefault(name.casefold(), {"name": name, "kinds": set(), "refs": []})
            current["kinds"].update(item["kinds"])
            current["refs"] = list(dict.fromkeys([*current["refs"], *item["refs"]]))[:10]
        return [
            {
                "name": item["name"],
                "confidence": "high" if len(item["kinds"]) >= 2 and len(item["refs"]) >= 2 else "medium",
                "evidence_refs": item["refs"],
                "evidence_kinds": sorted(item["kinds"]),
            }
            for item in sorted(aggregate.values(), key=lambda value: (-len(value["kinds"]), value["name"]))
        ]

    contradictions = []
    if len(conflicting_identities) > 1:
        contradictions.append(
            {
                "kind": "product_conflict",
                "candidates": [item["product"] for item in ranked if item["product"]],
                "evidence_refs": list(dict.fromkeys(ref for item in ranked for ref in item["refs"]))[:10],
            }
        )
    return {
        "identity_status": status,
        "vendor_candidates": candidates("vendor"),
        "product_candidates": candidates("product"),
        "deployment_role_candidates": sorted(roles),
        "contradictions": contradictions,
        "next_discriminator": "compare an independent loaded-JS or archived/public-index product signal"
        if status != "corroborated"
        else "retain time-stamped evidence and re-open on contradiction",
    }


def _vendor_product(technology: str) -> tuple[str, str] | None:
    for vendor_pattern, vendor, products in _VENDOR_PRODUCTS:
        if not vendor_pattern.search(technology):
            continue
        product = next((name for pattern, name in products if pattern.search(technology)), technology.strip())
        return vendor, product
    return None


def vendor_family_view(conn: sqlite3.Connection, *, target_name: str) -> list[dict[str, Any]]:
    """Derive a compact passive family view without reading or changing scope."""
    families: dict[str, dict[str, Any]] = {}
    rows = conn.execute(
        """SELECT host,technology,evidence_refs_json FROM technology_observations
           WHERE target_name=? ORDER BY host,technology""",
        (target_name,),
    ).fetchall()
    for row in rows:
        parsed = _vendor_product(str(row["technology"]))
        if parsed is None:
            continue
        vendor, product = parsed
        family = families.setdefault(vendor, {"products": set(), "hosts": set(), "refs": []})
        family["products"].add(product[:120])
        family["hosts"].add(str(row["host"])[:120])
        family["refs"] = list(dict.fromkeys([*family["refs"], *validate_evidence_refs(row["evidence_refs_json"])]))[:5]
    return [
        {
            "vendor": vendor,
            "products": sorted(item["products"])[:5],
            "hosts": sorted(item["hosts"])[:5],
            "evidence_refs": item["refs"],
            "scope_effect": "none",
        }
        for vendor, item in sorted(families.items())[:10]
    ]


def _path(value: str) -> str:
    parsed = urlsplit(value)
    path = parsed.path if parsed.scheme or parsed.netloc else value.split("?", 1)[0]
    normalized = "/" + "/".join(segment for segment in path.split("/") if segment)
    return normalized.casefold() if normalized != "/" else normalized


def match_public_path_indicators(observed_endpoints: Iterable[Mapping[str, Any]], rules: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Match only observed paths and emit offline hypotheses, never request plans."""
    indicators = rules.get("indicators") if isinstance(rules, Mapping) else []
    if not isinstance(indicators, list):
        raise ValueError("invalid public path indicator rules")
    matches: list[dict[str, Any]] = []
    for endpoint in observed_endpoints:
        observed_path = _path(str(endpoint.get("path") or endpoint.get("url") or ""))
        method = str(endpoint.get("method") or "GET").upper()
        params = {str(item).casefold() for item in endpoint.get("parameters", []) if isinstance(item, str)}
        for indicator in indicators:
            if not isinstance(indicator, Mapping) or _path(str(indicator.get("path") or "")) != observed_path:
                continue
            expected_method = str(indicator.get("method") or "ANY").upper()
            if expected_method not in {"ANY", method}:
                continue
            expected_params = {str(item).casefold() for item in indicator.get("parameters", [])}
            matches.append(
                {
                    "status": "hypothesis",
                    "observed_path": observed_path,
                    "method": method,
                    "parameter_overlap": sorted(params & expected_params),
                    "vendor": str(indicator.get("vendor") or "unknown"),
                    "product": str(indicator.get("product") or "unknown"),
                    "reference": str(indicator.get("reference") or "")[:240],
                    "evidence_ref": str(indicator.get("evidence_ref") or "")[:160],
                    "network_action": "none",
                    "next_action": "compare applicability/version preconditions against existing evidence",
                }
            )
    return matches
