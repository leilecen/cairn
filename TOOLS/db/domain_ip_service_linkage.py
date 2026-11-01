"""Build an offline, time-aware domain to IP/service/system candidate chain."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

_TOOLS_DIR = Path(__file__).resolve().parent.parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

from db.db_utils import connect, find_db  # noqa: E402
from db.identity_classification import (  # noqa: E402
    normalize_host,
    normalize_ip,
    validate_compact_text,
    validate_evidence_refs,
    validate_port,
    validate_timestamp,
)


def _validate_target(conn: sqlite3.Connection, target_name: str) -> None:
    if conn.execute("SELECT 1 FROM targets WHERE target_name=? LIMIT 1", (target_name,)).fetchone() is None:
        raise ValueError("target_name does not exactly match the database targets")


def _loads(value: str | None) -> list[str]:
    return validate_evidence_refs(value or "[]")


class _SkipStats:
    """Bounded record of rows skipped because their stored facts are dirty."""

    def __init__(self) -> None:
        self.total = 0
        self.samples: list[dict[str, Any]] = []

    def skip(self, *, table: str, row_id: Any, raw: str, reason: str) -> None:
        self.total += 1
        if len(self.samples) < 10:
            self.samples.append({"table": table, "row_id": str(row_id)[:48], "raw": (raw or "")[:80], "reason": str(reason)[:120]})

    def result(self) -> dict[str, Any]:
        return {"skipped": self.total, "dirty": self.samples}


def _temporal_status(value: str | None, *, now: datetime | None = None) -> str:
    if not value:
        return "missing"
    text = str(value).strip().replace("Z", "+00:00")
    try:
        observed = datetime.fromisoformat(text)
    except ValueError:
        return "invalid"
    if observed.tzinfo is None:
        observed = observed.replace(tzinfo=UTC)
    reference = now or datetime.now(UTC)
    return "stale" if observed < reference - timedelta(days=365) else "current"


def _items(conn: sqlite3.Connection, target_name: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Load domain/IP/service facts with per-row tolerance for dirty history.

    One malformed evidence_ref/host/port/observed_at row is skipped and counted
    instead of failing the whole target (production reconciliation requirement).
    """
    stats = _SkipStats()
    assets: dict[int, dict[str, Any]] = {}
    for row in conn.execute(
        """SELECT id,asset_value,port,scope_status,authorization_state FROM target_assets
           WHERE target_name=? AND asset_type IN ('domain','subdomain') ORDER BY id""",
        (target_name,),
    ).fetchall():
        try:
            assets[int(row["id"])] = {
                "id": int(row["id"]),
                "asset_value": normalize_host(row["asset_value"]),
                "port": validate_port(row["port"]),
                "scope_status": str(row["scope_status"]),
                "authorization_state": str(row["authorization_state"]),
            }
        except (ValueError, TypeError) as exc:
            stats.skip(
                table="target_assets",
                row_id=row["id"],
                raw=str(row["asset_value"]) if row["asset_value"] is not None else "",
                reason=str(exc),
            )
    raw_observations = conn.execute(
        """SELECT id,asset_id,host,ip,port,protocol,service,source,evidence_refs_json,observed_at
           FROM network_observations WHERE target_name=? AND ip IS NOT NULL AND ip<>''
           ORDER BY host,ip,observed_at,id""",
        (target_name,),
    ).fetchall()
    observations: list[dict[str, Any]] = []
    for row in raw_observations:
        try:
            observations.append(
                {
                    "id": int(row["id"]),
                    "asset_id": int(row["asset_id"]) if row["asset_id"] is not None else None,
                    "host": normalize_host(row["host"]),
                    "ip": normalize_ip(row["ip"]),
                    "port": validate_port(row["port"]),
                    "protocol": validate_compact_text(row["protocol"], field="protocol", max_chars=20),
                    "service": validate_compact_text(row["service"], field="service", max_chars=80),
                    "source": validate_compact_text(row["source"], field="network source", max_chars=80, allow_empty=False),
                    "evidence_refs": _loads(row["evidence_refs_json"]),
                    "observed_at": validate_timestamp(row["observed_at"]),
                }
            )
        except (ValueError, TypeError) as exc:
            stats.skip(
                table="network_observations",
                row_id=row["id"],
                raw=str(row["evidence_refs_json"] or row["host"] or row["ip"]),
                reason=str(exc),
            )
    raw_technologies = conn.execute(
        """SELECT id,asset_id,host,technology,confidence,source,evidence_refs_json,observed_at
           FROM technology_observations WHERE target_name=? ORDER BY id""",
        (target_name,),
    ).fetchall()
    technologies: list[dict[str, Any]] = []
    for row in raw_technologies:
        try:
            technologies.append(
                {
                    "id": int(row["id"]),
                    "asset_id": int(row["asset_id"]) if row["asset_id"] is not None else None,
                    "host": normalize_host(row["host"]),
                    "technology": validate_compact_text(row["technology"], field="technology", max_chars=120, allow_empty=False),
                    "confidence": validate_compact_text(row["confidence"], field="confidence", max_chars=16),
                    "source": validate_compact_text(row["source"], field="technology source", max_chars=80, allow_empty=False),
                    "evidence_refs": _loads(row["evidence_refs_json"]),
                    "observed_at": validate_timestamp(row["observed_at"]),
                }
            )
        except (ValueError, TypeError) as exc:
            stats.skip(
                table="technology_observations",
                row_id=row["id"],
                raw=str(row["evidence_refs_json"] or row["host"]),
                reason=str(exc),
            )
    raw_links = conn.execute(
        """SELECT l.id,l.asset_id,l.system_id,l.relationship,l.confidence,l.evidence_refs_json
           FROM system_asset_links l JOIN target_systems s ON s.id=l.system_id
           WHERE l.target_name=? AND s.target_name=? ORDER BY l.id""",
        (target_name, target_name),
    ).fetchall()
    links: list[dict[str, Any]] = []
    for row in raw_links:
        try:
            links.append(
                {
                    "asset_id": int(row["asset_id"]),
                    "system_id": int(row["system_id"]),
                    "relationship": validate_compact_text(
                        row["relationship"], field="system relationship", max_chars=80, allow_empty=False
                    ),
                    "confidence": validate_compact_text(row["confidence"], field="confidence", max_chars=16),
                    "evidence_refs": _loads(row["evidence_refs_json"]),
                }
            )
        except (ValueError, TypeError) as exc:
            stats.skip(
                table="system_asset_links",
                row_id=row["id"],
                raw=str(row["evidence_refs_json"]),
                reason=str(exc),
            )
    result: list[dict[str, Any]] = []
    for row in observations:
        asset_id = int(row["asset_id"]) if row["asset_id"] is not None else None
        asset = assets.get(asset_id) if asset_id is not None else None
        domain = str(asset["asset_value"] if asset is not None else row["host"])
        exact_tech = [
            tech
            for tech in technologies
            if (asset_id is not None and tech["asset_id"] == asset_id) or (asset_id is None and tech["host"] == domain)
        ]
        exact_links = [link for link in links if asset_id is not None and link["asset_id"] == asset_id]
        dns_observations = [
            {
                "source": str(observation["source"])[:80],
                "observed_at": observation["observed_at"],
                "temporal_status": _temporal_status(observation["observed_at"]),
            }
            for observation in observations
            if observation["host"] == domain and observation["ip"] == row["ip"] and observation["port"] is None
        ][:3]
        product_candidates = list(dict.fromkeys(tech["technology"] for tech in exact_tech))[:2]
        refs = list(
            dict.fromkeys(
                [
                    *row["evidence_refs"],
                    *(ref for tech in exact_tech for ref in tech["evidence_refs"]),
                    *(ref for link in exact_links for ref in link["evidence_refs"]),
                ]
            )
        )[:2]
        system_link = None
        if exact_links:
            link = exact_links[0]
            system_link = {
                "system_id": int(link["system_id"]),
                "relationship": str(link["relationship"]),
                "confidence": str(link["confidence"]),
                "status": "candidate",
            }
        temporal_status = _temporal_status(row["observed_at"])
        confidence = {"current": "medium", "stale": "low"}.get(temporal_status, "unknown")
        result.append(
            {
                "domain": domain,
                "asset_id": asset_id,
                "ip": row["ip"],
                "port": row["port"],
                "protocol": row["protocol"],
                "service": row["service"],
                "source": row["source"],
                "observed_at": row["observed_at"],
                "temporal_status": temporal_status,
                "confidence": confidence if refs else "unknown",
                "evidence_refs": refs,
                "dns_observations": dns_observations,
                "product_candidates": product_candidates,
                "system_link_candidate": system_link,
                "scope_status": str(asset["scope_status"] if asset is not None else "needs_review"),
                "authorization_inherited": False,
                "shared_ip_effect": "association_only",
            }
        )
    return result, stats.result()


def reconcile_domain_ip_service(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    apply: bool = False,
    include_items: bool = False,
    sample_size: int = 10,
) -> dict[str, Any]:
    if not 0 <= sample_size <= 100:
        raise ValueError("sample_size must be between 0 and 100")
    if not apply:
        _validate_target(conn, target_name)
        items, dirty = _items(conn, target_name)
        return _result(target_name, "preview", items, 0, include_items, sample_size, dirty)
    nested = conn.in_transaction
    conn.execute("SAVEPOINT b7_domain_linkage" if nested else "BEGIN IMMEDIATE")
    try:
        _validate_target(conn, target_name)
        items, dirty = _items(conn, target_name)
        inserted = 0
        for item in items:
            query = "|".join(str(item.get(key) or "") for key in ("domain", "ip", "port", "protocol", "source", "observed_at"))
            result_json = json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            cur = conn.execute(
                """INSERT OR IGNORE INTO recon_sources(target_name,source_kind,query,result_json,status)
                   VALUES(?,'domain_ip_service_linkage',?,?,?)""",
                (target_name, query, result_json, "observed" if item["scope_status"] == "in_scope" else "needs_review"),
            )
            inserted += max(cur.rowcount, 0)
        if nested:
            conn.execute("RELEASE SAVEPOINT b7_domain_linkage")
        else:
            conn.commit()
    except Exception:
        if nested:
            conn.execute("ROLLBACK TO SAVEPOINT b7_domain_linkage")
            conn.execute("RELEASE SAVEPOINT b7_domain_linkage")
        else:
            conn.rollback()
        raise
    return _result(target_name, "apply", items, inserted, include_items, sample_size, dirty)


def _result(
    target_name: str,
    mode: str,
    items: list[dict[str, Any]],
    inserted: int,
    include_items: bool,
    sample_size: int,
    dirty: dict[str, Any] | None = None,
) -> dict[str, Any]:
    dirty = dirty or {"skipped": 0, "dirty": []}
    result: dict[str, Any] = {
        "target_name": target_name,
        "mode": mode,
        "planned": len(items),
        "inserted": inserted,
        "skipped": dirty["skipped"],
        "dirty": dirty["dirty"],
        "sample": [
            {
                "domain": item["domain"],
                "ip": item["ip"],
                "port": item["port"],
                "source": item["source"],
                "confidence": item["confidence"],
            }
            for item in items[:sample_size]
        ],
        "omitted": max(0, len(items) - sample_size),
    }
    if include_items:
        result["items"] = items
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline domain/IP/service reconciliation")
    parser.add_argument("--target", required=True)
    parser.add_argument("--file")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    path = Path(args.file) if args.file else find_db(args.target)
    if not path.exists():
        print(json.dumps({"ok": False, "error": "database file does not exist"}, ensure_ascii=False))
        return 1
    conn = connect(path)
    try:
        result = reconcile_domain_ip_service(conn, target_name=args.target, apply=args.apply)
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return 1
    finally:
        conn.close()
    print(json.dumps({"ok": True, **result}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
