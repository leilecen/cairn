"""Offline CDN classification and passive origin-candidate intake.

This module only consumes observations already collected by an approved source.
It never resolves DNS, opens TLS connections, or validates an origin candidate.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any

try:
    from .recon_store import ensure_recon_schema, record_cdn_observation, record_origin
except ImportError:  # pragma: no cover - direct script execution
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from recon_store import (  # type: ignore[no-redef]  # 回退分支与包内导入同一批名字
        ensure_recon_schema,
        record_cdn_observation,
        record_origin,
    )


_CDN_PATTERNS: dict[str, tuple[str, ...]] = {
    "cloudflare": ("cloudflare",),
    "cloudfront": ("cloudfront.net", "amazon cloudfront"),
    "akamai": ("akamai", "edgesuite.net", "edgekey.net"),
    "fastly": ("fastly",),
    "aliyun": ("alikunlun", "aliyuncs", "alibabacloud", "aliyun"),
    "tencent_cloud": ("myqcloud", "qcloud", "tencent cloud"),
    "baidu_cloud": ("bdydns", "baidubce"),
}


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def classify_cdn_observation(observation: dict[str, Any]) -> dict[str, Any]:
    """Classify supplied DNS/TLS metadata using static provider patterns only."""
    dns: dict[str, Any] = observation["dns"] if isinstance(observation.get("dns"), dict) else {}
    tls: dict[str, Any] = observation["tls"] if isinstance(observation.get("tls"), dict) else {}
    values = _strings(dns.get("cname")) + _strings(dns.get("cnames"))
    values += _strings(tls.get("issuer")) + _strings(tls.get("organization"))
    haystack = "\n".join(values).lower()
    for provider, patterns in _CDN_PATTERNS.items():
        matched = [pattern for pattern in patterns if pattern in haystack]
        if matched:
            return {"classification": "cdn", "provider": provider, "reasons": matched}
    if values:
        return {"classification": "non_cdn", "provider": None, "reasons": ["no_static_cdn_pattern"]}
    return {"classification": "unknown", "provider": None, "reasons": ["no_dns_or_tls_signal"]}


def _eligible_asset(conn: sqlite3.Connection, *, target_name: str, asset_id: int, hostname: str) -> bool:
    row = conn.execute(
        """SELECT target_name, asset_value, scope_status, scope_class, authorization_state
           FROM target_assets WHERE id=?""",
        (asset_id,),
    ).fetchone()
    if row is None or row["target_name"] != target_name:
        return False
    if str(row["asset_value"]).rstrip(".").lower() != hostname.rstrip(".").lower():
        return False
    return (
        row["scope_status"] == "in_scope"
        and row["scope_class"] in {"owned", "authorized_vendor"}
        and row["authorization_state"] in {"authorized", "explicit_init"}
    )


def _valid_public_ip(value: Any) -> str | None:
    try:
        parsed = ipaddress.ip_address(str(value))
    except ValueError:
        return None
    return str(parsed) if parsed.is_global else None


def _compact_refs(values: Any) -> set[str]:
    return {value[:240] for value in _strings(values) if value.strip()}


def ingest_passive_origin_candidates(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    observations: list[dict[str, Any]],
) -> dict[str, int]:
    """Store only passive, review-only origin candidates for eligible assets.

    ``origin_ips`` must come from the supplied passive observation. CDN edge
    addresses in DNS answers are deliberately not treated as origin candidates.
    """
    ensure_recon_schema(conn)
    grouped: dict[tuple[int, str, str], dict[str, Any]] = {}
    result = {"observations": 0, "cdn_detected": 0, "candidates": 0, "blocked": 0}
    for observation in observations:
        result["observations"] += 1
        if not isinstance(observation, dict):
            result["blocked"] += 1
            continue
        asset_id = observation.get("asset_id")
        hostname = str(observation.get("hostname") or "").strip().lower()
        if not isinstance(asset_id, int) or asset_id <= 0 or not hostname:
            result["blocked"] += 1
            continue
        if not _eligible_asset(conn, target_name=target_name, asset_id=asset_id, hostname=hostname):
            result["blocked"] += 1
            continue
        classified = classify_cdn_observation(observation)
        refs = _compact_refs(observation.get("evidence_refs"))
        record_cdn_observation(
            conn,
            target_name=target_name,
            asset_id=asset_id,
            hostname=hostname,
            classification=str(classified["classification"]),
            provider=classified["provider"],
            reasons=classified["reasons"],
            evidence_refs=refs,
        )
        if classified["classification"] != "cdn":
            continue
        result["cdn_detected"] += 1
        for raw_ip in _strings(observation.get("origin_ips")):
            candidate_ip = _valid_public_ip(raw_ip)
            if not candidate_ip:
                continue
            key = (asset_id, hostname, candidate_ip)
            grouped.setdefault(key, {"refs": set(), "providers": set(), "strong_evidence": False})
            grouped[key]["refs"].update(refs)
            grouped[key]["providers"].add(str(classified["provider"]))
            grouped[key]["strong_evidence"] = bool(grouped[key]["strong_evidence"] or observation.get("strong_evidence"))

    for (asset_id, hostname, candidate_ip), details in grouped.items():
        prior = conn.execute(
            """SELECT evidence_refs_json FROM origin_candidates
               WHERE target_name=? AND asset_id=? AND hostname=? AND candidate_ip=?
                 AND source='passive_cdn_source'""",
            (target_name, asset_id, hostname, candidate_ip),
        ).fetchone()
        prior_refs = _compact_refs(json.loads(prior[0])) if prior else set()
        providers = ",".join(sorted(details["providers"]))
        evidence_refs = sorted(prior_refs | details["refs"])
        ready_for_review = len(evidence_refs) >= 2 or bool(details.get("strong_evidence"))
        record_origin(
            conn,
            target_name=target_name,
            asset_id=asset_id,
            hostname=hostname,
            candidate_ip=candidate_ip,
            source="passive_cdn_source",
            confidence="medium" if ready_for_review else "low",
            score=1 if ready_for_review else 0,
            verification_status="candidate_ready_for_review" if ready_for_review else "evidence_insufficient",
            evidence_refs=evidence_refs,
            notes=(
                f"passive_only;cdn:{providers};origin verification requires operator-approved L3 work item"
                if ready_for_review
                else f"passive_only;cdn:{providers};needs a second independent evidence reference"
            ),
        )
        result["candidates"] += 1
    return result


def _connect_target(db_path: str, target_name: str) -> sqlite3.Connection:
    path = Path(db_path)
    if not path.is_file():
        raise ValueError(f"database file not found: {path}")
    try:
        from db.db_utils import connect  # noqa: PLC0415
    except ImportError:  # pragma: no cover - direct script execution
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
        from db.db_utils import connect  # noqa: PLC0415
    conn = connect(path)
    conn.row_factory = sqlite3.Row
    if conn.execute("SELECT 1 FROM targets WHERE target_name=?", (target_name,)).fetchone() is None:
        conn.close()
        raise ValueError(f"target not found in database: {target_name}")
    return conn


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline passive CDN/source-candidate intake")
    parser.add_argument("--target", required=True)
    parser.add_argument("--db", required=True)
    parser.add_argument("--input", required=True, help="JSON array of supplied passive DNS/TLS observations")
    args = parser.parse_args()
    try:
        payload = json.loads(Path(args.input).read_text(encoding="utf-8"))
        if not isinstance(payload, list):
            raise ValueError("input JSON must be an array of observations")
        conn = _connect_target(args.db, args.target)
        try:
            result = ingest_passive_origin_candidates(conn, target_name=args.target, observations=payload)
            print(json.dumps(result, ensure_ascii=False))
        finally:
            conn.close()
        return 0
    except (OSError, ValueError, json.JSONDecodeError, sqlite3.Error) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
