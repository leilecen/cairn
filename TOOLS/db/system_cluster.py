"""Deterministic, evidence-led target-system clustering."""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlsplit

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from db.db_utils import connect, find_db  # noqa: E402


def _origin_path(value: str) -> str | None:
    parsed = urlsplit(str(value or "").strip())
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return None
    port = f":{parsed.port}" if parsed.port else ""
    return f"{parsed.scheme.lower()}://{parsed.hostname.lower()}{port}{parsed.path or '/'}"


def _asset_url(row: sqlite3.Row) -> str:
    raw = str(row["asset_value"] or "").strip()
    parsed = urlsplit(raw if "://" in raw else f"//{raw}")
    scheme = str(row["protocol"] or parsed.scheme or "https").lower()
    host = (parsed.hostname or raw).strip().lower()
    port = row["port"] or parsed.port
    suffix = "" if not port or (scheme, int(port)) in {("http", 80), ("https", 443)} else f":{port}"
    return f"{scheme}://{host}{suffix}/"


def _sld(host: str) -> str | None:
    raw = str(host or "").strip()
    parsed = urlsplit(raw if "://" in raw else f"//{raw}")
    labels = (parsed.hostname or raw).strip(".").lower().split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else None


def _scope(rows: list[sqlite3.Row]) -> str:
    values = {str(row["scope_class"] or "unknown") for row in rows}
    if values == {"owned"}:
        return "owned"
    if values and values <= {"owned", "authorized_vendor"}:
        return "authorized_vendor"
    if "intel_only" in values:
        return "intel_only"
    return "unknown"


def build_cluster_plan(conn: sqlite3.Connection, target_name: str) -> dict:
    """Build a zero-write plan; shared IP/SLD are only candidate links."""
    target_name = str(target_name or "").strip()
    if not target_name:
        raise ValueError("target_name is required")
    if not conn.execute("SELECT 1 FROM targets WHERE target_name=?", (target_name,)).fetchone():
        raise ValueError(f"target not found: {target_name}")
    assets = conn.execute(
        """SELECT id,target_name,asset_value,port,protocol,resolved_ip,scope_class
           FROM target_assets WHERE target_name=? ORDER BY id""",
        (target_name,),
    ).fetchall()
    auth: dict[int, str] = {}
    for row in conn.execute(
        """SELECT asset_id,url FROM asset_auth_entries
           WHERE target_name=? AND entry_type IN ('login','sso','oauth')
             AND confidence IN ('medium','high') ORDER BY id""",
        (target_name,),
    ):
        normalized = _origin_path(row["url"])
        if normalized and row["asset_id"] not in auth:
            auth[int(row["asset_id"])] = normalized
    product: dict[int, str] = {}
    for row in conn.execute(
        """SELECT asset_id,technology,source,category FROM technology_observations
           WHERE target_name=? AND confidence IN ('medium','high')
             AND technology IS NOT NULL AND trim(technology)<>'' ORDER BY id""",
        (target_name,),
    ):
        # A generic technology observation (for example nginx) is not a
        # product boundary by itself. Only an explicitly product-labelled
        # source is eligible for automatic clustering.
        explicit = (
            str(row["category"] or "").lower() in {"product", "application", "appliance", "vendor_product"}
            or "product" in str(row["source"] or "").lower()
        )
        if explicit and row["asset_id"] not in product:
            product[int(row["asset_id"])] = str(row["technology"]).strip().lower()

    groups: dict[tuple[str, str], list[sqlite3.Row]] = defaultdict(list)
    for row in assets:
        aid = int(row["id"])
        if aid in auth:
            key = ("auth_boundary", auth[aid])
        elif aid in product:
            key = ("product_evidence", product[aid])
        else:
            key = ("deployment_boundary", _asset_url(row))
        groups[key].append(row)

    systems = []
    for (basis, value), rows in sorted(groups.items()):
        digest = hashlib.sha256(f"{basis}:{value}".encode()).hexdigest()[:20]
        systems.append(
            {
                "system_key": f"cluster:{digest}",
                "display_name": str(rows[0]["asset_value"]),
                "canonical_url": _asset_url(rows[0]),
                "scope_class": _scope(rows),
                "basis": basis,
                "basis_value": value,
                "asset_ids": [int(row["id"]) for row in rows],
            }
        )

    candidates = []
    for index, left in enumerate(assets):
        for right in assets[index + 1 :]:
            reasons = []
            if left["resolved_ip"] and left["resolved_ip"] == right["resolved_ip"]:
                reasons.append("shared_ip")
            if _sld(left["asset_value"]) and _sld(left["asset_value"]) == _sld(right["asset_value"]):
                reasons.append("shared_sld")
            for reason in reasons:
                candidates.append({"asset_ids": [int(left["id"]), int(right["id"])], "reason": reason})
    return {"target_name": target_name, "systems": systems, "candidate_links": candidates}


def apply_cluster_plan(conn: sqlite3.Connection, target_name: str) -> dict:
    """Lock before reading mutable facts and apply the deterministic plan."""
    try:
        conn.execute("BEGIN IMMEDIATE")
        before = _managed_snapshot(conn, target_name)
        plan = build_cluster_plan(conn, target_name)
        desired: set[tuple[str, int, str]] = set()
        for item in plan["systems"]:
            for index, asset_id in enumerate(item["asset_ids"]):
                desired.add((item["system_key"], asset_id, "primary" if index == 0 else "related"))
        existing = conn.execute(
            """SELECT l.id,s.system_key,l.asset_id,l.relationship,l.evidence_refs_json
               FROM system_asset_links l JOIN target_systems s ON s.id=l.system_id
               WHERE l.target_name=? AND s.target_name=? AND s.created_by='system_cluster'""",
            (target_name, target_name),
        ).fetchall()
        for row in existing:
            key = (row["system_key"], int(row["asset_id"]), row["relationship"])
            if _is_cluster_link(row["evidence_refs_json"]) and key not in desired:
                conn.execute("DELETE FROM system_asset_links WHERE id=?", (row["id"],))
        for system in plan["systems"]:
            conn.execute(
                """INSERT INTO target_systems(
                     target_name,system_key,display_name,canonical_url,description,scope_class,created_by
                   )
                   VALUES(?,?,?,?,?,?, 'system_cluster')
                   ON CONFLICT(target_name,system_key) DO UPDATE SET
                     display_name=excluded.display_name,canonical_url=excluded.canonical_url,
                     description=excluded.description,scope_class=excluded.scope_class,
                     updated_at=datetime('now','localtime')""",
                (
                    target_name,
                    system["system_key"],
                    system["display_name"],
                    system["canonical_url"],
                    f"cluster basis: {system['basis']}",
                    system["scope_class"],
                ),
            )
            system_id = conn.execute(
                "SELECT id FROM target_systems WHERE target_name=? AND system_key=?",
                (target_name, system["system_key"]),
            ).fetchone()[0]
            for position, asset_id in enumerate(system["asset_ids"]):
                audit = json.dumps(
                    [{"kind": "cluster_basis", "basis": system["basis"], "value": system["basis_value"]}],
                    ensure_ascii=True,
                    separators=(",", ":"),
                )
                conn.execute(
                    """INSERT INTO system_asset_links(
                         target_name,system_id,asset_id,relationship,confidence,evidence_refs_json
                       )
                       VALUES(?,?,?,?,?,?) ON CONFLICT(system_id,asset_id,relationship) DO UPDATE SET
                         confidence=excluded.confidence,evidence_refs_json=excluded.evidence_refs_json,
                         updated_at=datetime('now','localtime')""",
                    (target_name, system_id, asset_id, "primary" if position == 0 else "related", "high", audit),
                )
        conn.execute(
            """DELETE FROM target_systems WHERE target_name=? AND created_by='system_cluster'
               AND NOT EXISTS(SELECT 1 FROM system_asset_links l WHERE l.system_id=target_systems.id)""",
            (target_name,),
        )
        after = _managed_snapshot(conn, target_name)
        if before == after:
            previous = conn.execute(
                """SELECT query FROM recon_sources
                   WHERE target_name=? AND source_kind='system_cluster_apply'
                   ORDER BY id DESC LIMIT 1""",
                (target_name,),
            ).fetchone()
            conn.commit()
            return {**plan, "run_key": previous[0] if previous else None, "changed": False}
        run_key = hashlib.sha256(
            json.dumps({"target": target_name, "before": before, "after": after}, sort_keys=True).encode()
        ).hexdigest()[:24]
        audit = json.dumps(
            {"schema": "system_cluster_audit/v1", "run_key": run_key, "before": before, "after": after},
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        conn.execute(
            """INSERT OR IGNORE INTO recon_sources(target_name,source_kind,query,result_json,status)
               VALUES(?,'system_cluster_apply',?,?,'applied')""",
            (target_name, run_key, audit),
        )
        conn.commit()
        return {**plan, "run_key": run_key, "changed": True}
    except Exception:
        conn.rollback()
        raise


def _is_cluster_link(raw: str | None) -> bool:
    try:
        items = json.loads(raw or "[]")
    except json.JSONDecodeError:
        return False
    return isinstance(items, list) and any(isinstance(item, dict) and item.get("kind") == "cluster_basis" for item in items)


def _managed_snapshot(conn: sqlite3.Connection, target_name: str) -> dict:
    systems = [
        dict(row)
        for row in conn.execute(
            """SELECT system_key,display_name,canonical_url,description,scope_class,lifecycle_state,created_by
               FROM target_systems WHERE target_name=? AND created_by='system_cluster' ORDER BY system_key""",
            (target_name,),
        )
    ]
    links = [
        dict(row)
        for row in conn.execute(
            """SELECT s.system_key,l.asset_id,l.relationship,l.confidence,l.evidence_refs_json
               FROM system_asset_links l JOIN target_systems s ON s.id=l.system_id
               WHERE l.target_name=? AND s.target_name=? AND s.created_by='system_cluster'
               ORDER BY s.system_key,l.asset_id,l.relationship""",
            (target_name, target_name),
        )
        if _is_cluster_link(row["evidence_refs_json"])
    ]
    return {"systems": systems, "links": links}


def rollback_cluster_run(conn: sqlite3.Connection, target_name: str, run_key: str) -> dict:
    """Restore the before image only if managed state still matches the run's after image."""
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            """SELECT id,result_json,status FROM recon_sources
               WHERE target_name=? AND source_kind='system_cluster_apply' AND query=?""",
            (target_name, run_key),
        ).fetchone()
        if row is None:
            raise ValueError("cluster audit run not found")
        audit = json.loads(row["result_json"])
        if row["status"] == "rolled_back":
            conn.commit()
            return {"rolled_back": False, "already_rolled_back": True, "run_key": run_key}
        if _managed_snapshot(conn, target_name) != audit["after"]:
            raise RuntimeError("cluster state changed after this run; refusing rollback")
        managed_links = conn.execute(
            """SELECT l.id FROM system_asset_links l JOIN target_systems s ON s.id=l.system_id
               WHERE l.target_name=? AND s.target_name=? AND s.created_by='system_cluster'""",
            (target_name, target_name),
        ).fetchall()
        for link_row in managed_links:
            raw = conn.execute("SELECT evidence_refs_json FROM system_asset_links WHERE id=?", (link_row["id"],)).fetchone()[0]
            if _is_cluster_link(raw):
                conn.execute("DELETE FROM system_asset_links WHERE id=?", (link_row["id"],))
        conn.execute(
            """DELETE FROM target_systems WHERE target_name=? AND created_by='system_cluster'
               AND NOT EXISTS(SELECT 1 FROM system_asset_links l WHERE l.system_id=target_systems.id)""",
            (target_name,),
        )
        for system in audit["before"]["systems"]:
            conn.execute(
                """INSERT INTO target_systems(
                     target_name,system_key,display_name,canonical_url,description,scope_class,lifecycle_state,created_by
                   ) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(target_name,system_key) DO UPDATE SET
                     display_name=excluded.display_name,canonical_url=excluded.canonical_url,
                     description=excluded.description,scope_class=excluded.scope_class,
                     lifecycle_state=excluded.lifecycle_state""",
                (
                    target_name,
                    system["system_key"],
                    system["display_name"],
                    system["canonical_url"],
                    system["description"],
                    system["scope_class"],
                    system["lifecycle_state"],
                    system["created_by"],
                ),
            )
        for link in audit["before"]["links"]:
            system_id = conn.execute(
                "SELECT id FROM target_systems WHERE target_name=? AND system_key=?",
                (target_name, link["system_key"]),
            ).fetchone()[0]
            conn.execute(
                """INSERT INTO system_asset_links(
                     target_name,system_id,asset_id,relationship,confidence,evidence_refs_json
                   ) VALUES(?,?,?,?,?,?)""",
                (
                    target_name,
                    system_id,
                    link["asset_id"],
                    link["relationship"],
                    link["confidence"],
                    link["evidence_refs_json"],
                ),
            )
        conn.execute("UPDATE recon_sources SET status='rolled_back' WHERE id=?", (row["id"],))
        conn.commit()
        return {"rolled_back": True, "already_rolled_back": False, "run_key": run_key}
    except Exception:
        conn.rollback()
        raise


def _path(args: argparse.Namespace) -> Path:
    if bool(args.file) == bool(args.target):
        raise ValueError("exactly one of --target or --file is required")
    if args.file:
        path = Path(args.file)
        if not path.is_file():
            raise ValueError(f"database file not found: {path}")
        return path
    return find_db(args.target)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target")
    parser.add_argument("--file")
    parser.add_argument("--target-name")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    try:
        path = _path(args)
        target = args.target_name or args.target
        if not target:
            raise ValueError("--target-name is required with --file")
        conn = connect(path)
        try:
            plan = apply_cluster_plan(conn, target) if args.apply else build_cluster_plan(conn, target)
        finally:
            conn.close()
        print(
            json.dumps(
                {
                    "ok": True,
                    "applied": args.apply,
                    "counts": {"systems": len(plan["systems"]), "candidate_links": len(plan["candidate_links"])},
                    "sample": plan["systems"][:10],
                    "omitted": max(0, len(plan["systems"]) - 10),
                },
                ensure_ascii=True,
                separators=(",", ":"),
            )
        )
        return 0
    except (ValueError, RuntimeError, sqlite3.Error) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=True, separators=(",", ":")))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
