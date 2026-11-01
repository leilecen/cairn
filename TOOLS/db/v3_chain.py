"""Passive B7-B10 fact-building steps consumed by the main sprint tick.

This module wires the offline v3 capabilities into the run chain
(sprint_tick -> blackboard_tick -> dispatcher -> lane worker).  Every step is
offline (zero network requests), idempotent, table-guarded, and wrapped so one
failing step never blocks the rest of the tick:

1. system clustering   -> apply_cluster_plan (target_systems/system_asset_links)
2. system scoring      -> score_systems(apply=True)  (system_soft_targets)
3. domain/IP/service   -> reconcile_domain_ip_service(apply=True) (recon_sources)
4. M9 entry recursion  -> reconcile_entry_recursion for focused eligible systems
5. M9 param semantics  -> reconcile_param_semantics for public GET endpoints
6. pending intel       -> surfaces needs_review peer-document / passive-neighbor /
                          linkage / recursion sources for the operator
"""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

_TOOLS_DIR = Path(__file__).resolve().parent.parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

from db.db_utils import connect, session  # noqa: E402

PENDING_INTEL_KINDS = (
    "peer_document_asset",
    "peer_document_chain",
    "passive_neighbor_index",
    "domain_ip_service_linkage",
    "entry_recursion_seed",
)
PARAM_ENDPOINT_CAP = 20


def _table(conn: sqlite3.Connection, name: str) -> bool:
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None


def _focused_eligible_systems(conn: sqlite3.Connection, target_name: str) -> list[tuple[int, str]]:
    """Return (system_id, canonical_url) for operator-focused eligible systems."""
    if not _table(conn, "system_soft_targets") or not _table(conn, "hunt_sessions"):
        return []
    rows = conn.execute(
        """SELECT DISTINCT st.system_id, s.canonical_url
           FROM system_soft_targets st
           JOIN hunt_sessions h ON h.target_name=st.target_name AND h.system_id=st.system_id
             AND h.status='active' AND h.selected_by='operator'
           JOIN target_systems s ON s.id=st.system_id
           WHERE st.target_name=? AND st.eligibility_status='eligible' AND st.status='focused'
             AND (st.timebox_until IS NULL OR st.timebox_until>datetime('now','localtime'))
           ORDER BY st.system_id""",
        (target_name,),
    ).fetchall()
    return [(int(row[0]), str(row[1] or "")) for row in rows]


def _linked_hosts(conn: sqlite3.Connection, target_name: str, system_id: int) -> set[str]:
    if not _table(conn, "system_asset_links"):
        return set()
    return {
        str(row[0]).lower().rstrip(".")
        for row in conn.execute(
            """SELECT a.asset_value FROM system_asset_links l JOIN target_assets a ON a.id=l.asset_id
               WHERE l.target_name=? AND l.system_id=? AND a.target_name=?""",
            (target_name, system_id, target_name),
        ).fetchall()
        if row[0]
    }


def _host_matches(host: str | None, linked_hosts: set[str]) -> bool:
    """host 直接来自 urlsplit().hostname，它本身就可能返回 None，函数体内已做空值兜底。"""
    host = str(host or "").lower().rstrip(".")
    return any(host == item or host.endswith("." + item) for item in linked_hosts)


def _source_kind_for(db_source: str) -> str:
    """Map a database source kind onto the trusted M9 seed vocabulary."""
    normalized = str(db_source or "").lower()
    if normalized in {"har", "burp", "archive"}:
        return normalized
    if "script" in normalized or normalized == "js":
        return "js"
    if "html" in normalized or normalized in {"page", "pages", "browser"}:
        return "html"
    return "html"


def _entry_fixture_from_db(conn: sqlite3.Connection, *, target_name: str, system_id: int, linked_hosts: set[str]) -> dict[str, Any] | None:
    """Derive a bounded, evidence-backed M9 fixture from observed facts only."""
    seed: dict[str, Any] | None = None
    if _table(conn, "recon_sources"):
        row = conn.execute(
            """SELECT query,result_json FROM recon_sources
               WHERE target_name=? AND source_kind='entry_recursion_observed' AND status='needs_review'
               ORDER BY id LIMIT 20""",
            (target_name,),
        ).fetchall()
        for item in row:
            try:
                payload = json.loads(item["result_json"] or "{}")
            except (json.JSONDecodeError, TypeError):
                continue
            url = str(payload.get("url") or item["query"] or "")
            refs = [str(ref) for ref in payload.get("evidence_refs", []) if isinstance(ref, str)][:10]
            if url and _host_matches(urlsplit(url).hostname, linked_hosts) and refs:
                seed = {
                    "url": url,
                    "source_kind": "har",
                    "evidence_refs": refs,
                    "depth": 0,
                    "observed": True,
                    "guessed": False,
                }
                break
    if seed is None and _table(conn, "js_files"):
        row = conn.execute(
            """SELECT url,page_url FROM js_files
               WHERE source_kind='browser_script' AND url IS NOT NULL AND url<>''
               ORDER BY id LIMIT 20""",
        ).fetchall()
        for item in row:
            url = str(item["url"])
            if _host_matches(urlsplit(url).hostname, linked_hosts):
                seed = {
                    "url": url,
                    "source_kind": "js",
                    "evidence_refs": [f"js_files:{item['id']}"],
                    "depth": 0,
                    "observed": True,
                    "guessed": False,
                }
                break
    if seed is None:
        return None

    observations: list[dict[str, Any]] = []
    if _table(conn, "endpoint_observations"):
        endpoint_rows = conn.execute(
            """SELECT id,canonical_url,method,parameter_names_json,evidence_refs_json,source
               FROM endpoint_observations WHERE target_name=?
               ORDER BY id LIMIT 60""",
            (target_name,),
        ).fetchall()
        for row in endpoint_rows:
            url = str(row["canonical_url"] or "")
            if not _host_matches(urlsplit(url).hostname, linked_hosts):
                continue
            try:
                params = json.loads(row["parameter_names_json"] or "[]")
            except (json.JSONDecodeError, TypeError):
                params = []
            try:
                refs = json.loads(row["evidence_refs_json"] or "[]")
            except (json.JSONDecodeError, TypeError):
                refs = []
            refs = [str(ref) for ref in refs if isinstance(ref, str)][:10] or [f"endpoint_observations:{row['id']}"]
            observations.append(
                {
                    "url": url,
                    "parent_url": seed["url"],
                    "source_kind": _source_kind_for(row["source"]),
                    "kind": "endpoint",
                    "method": str(row["method"] or "GET").upper(),
                    "parameter_names": [str(p) for p in params if isinstance(p, str)][:50],
                    "evidence_refs": refs,
                    "depth": 1,
                    "response_class": "observed",
                    "observed": True,
                    "guessed": False,
                }
            )
    if _table(conn, "js_files"):
        js_rows = conn.execute("""SELECT id,url FROM js_files WHERE url IS NOT NULL AND url<>'' ORDER BY id LIMIT 60""").fetchall()
        for row in js_rows:
            url = str(row["url"])
            if url == seed["url"] or not _host_matches(urlsplit(url).hostname, linked_hosts):
                continue
            observations.append(
                {
                    "url": url,
                    "parent_url": seed["url"],
                    "source_kind": "js",
                    "kind": "js",
                    "evidence_refs": [f"js_files:{row['id']}"],
                    "depth": 1,
                    "response_class": "observed",
                    "observed": True,
                    "guessed": False,
                }
            )
    return {"seed": seed, "observations": observations[:50]}


def _param_semantics_endpoints(conn: sqlite3.Connection, *, target_name: str, system_id: int, linked_hosts: set[str]) -> list[int]:
    """Public GET/HEAD/OPTIONS endpoints of the system that still need classification."""
    if not _table(conn, "endpoint_observations"):
        return []
    rows = conn.execute(
        """SELECT e.id,e.canonical_url,e.parameter_names_json
           FROM endpoint_observations e
           WHERE e.target_name=? AND e.auth_state='public'
             AND upper(COALESCE(e.method,'GET')) IN ('GET','HEAD','OPTIONS')
             AND e.parameter_names_json IS NOT NULL AND e.parameter_names_json<>'[]'
           ORDER BY e.id LIMIT ?""",
        (target_name, PARAM_ENDPOINT_CAP),
    ).fetchall()
    return [int(row["id"]) for row in rows if _host_matches(urlsplit(str(row["canonical_url"] or "")).hostname, linked_hosts)]


def _pending_intel(conn: sqlite3.Connection, target_name: str) -> list[dict[str, Any]]:
    if not _table(conn, "recon_sources"):
        return []
    rows = conn.execute(
        """SELECT source_kind, COUNT(*) AS total FROM recon_sources
           WHERE target_name=? AND status='needs_review'
           GROUP BY source_kind ORDER BY total DESC""",
        (target_name,),
    ).fetchall()
    by_kind = {str(row["source_kind"]): int(row["total"]) for row in rows}
    return [{"source_kind": kind, "count": by_kind.get(kind, 0)} for kind in PENDING_INTEL_KINDS if by_kind.get(kind, 0) > 0]


def run_v3_chain_facts(conn: sqlite3.Connection, *, target_name: str, apply: bool = True) -> dict[str, Any]:
    """Run the offline B7-B10 fact-building steps; each step is independently guarded."""
    summary: dict[str, Any] = {
        "types": {"observed": 0},
        "cluster": None,
        "score": None,
        "linkage": None,
        "entry_recursion": [],
        "param_semantics": [],
        "pending_intel": [],
        "errors": [],
    }
    if not str(target_name or "").strip():
        raise ValueError("target_name is required")

    # Type observations are asset-local and must refresh for the broad map even
    # when no operator focus exists.  They are presentation facts only; cluster
    # and score remain the owners of system identity and eligibility.
    if apply and _table(conn, "target_assets"):
        try:
            from recon.system_type_store import observe_asset_system_types

            summary["types"] = observe_asset_system_types(conn, target_name=target_name)
        except (sqlite3.Error, ValueError, RuntimeError) as exc:
            summary["errors"].append(f"types: {exc}")

    # 1. system clustering (M0/M8)
    try:
        if _table(conn, "system_asset_links"):
            from db.system_cluster import apply_cluster_plan

            cluster = apply_cluster_plan(conn, target_name)
            summary["cluster"] = {
                "systems": len(cluster.get("systems") or []),
                "changed": bool(cluster.get("changed", False)),
            }
    except (sqlite3.Error, ValueError, RuntimeError) as exc:
        summary["errors"].append(f"cluster: {exc}")

    # 2. system scoring / eligibility (M0)
    try:
        if _table(conn, "system_soft_targets"):
            from db.system_scorer import score_systems

            scored = score_systems(conn, target_name, apply=apply)
            summary["score"] = {
                "systems": int(scored.get("count", 0)),
                "downgrade_stop": scored.get("downgrade_stop", {}),
            }
    except (sqlite3.Error, ValueError, RuntimeError) as exc:
        summary["errors"].append(f"score: {exc}")

    # 3. domain -> IP -> service linkage (M8)
    try:
        if _table(conn, "network_observations"):
            from db.domain_ip_service_linkage import reconcile_domain_ip_service

            linkage = reconcile_domain_ip_service(conn, target_name=target_name, apply=apply)
            summary["linkage"] = {
                "planned": int(linkage.get("planned", 0)),
                "inserted": int(linkage.get("inserted", 0)),
                "skipped": int(linkage.get("skipped", 0)),
            }
    except (sqlite3.Error, ValueError, RuntimeError) as exc:
        summary["errors"].append(f"linkage: {exc}")

    # 4/5. M9 entry recursion + param semantics for focused eligible systems
    if apply and _table(conn, "system_soft_targets") and _table(conn, "hunt_sessions"):
        for system_id, _canonical_url in _focused_eligible_systems(conn, target_name):
            linked_hosts = _linked_hosts(conn, target_name, system_id)
            if not linked_hosts:
                continue
            try:
                from db.entry_recursion import reconcile_entry_recursion

                fixture = _entry_fixture_from_db(conn, target_name=target_name, system_id=system_id, linked_hosts=linked_hosts)
                if fixture is not None:
                    result = reconcile_entry_recursion(conn, target_name=target_name, system_id=system_id, fixture=fixture, apply=True)
                    summary["entry_recursion"].append(
                        {
                            "system_id": system_id,
                            "queued": int(result.get("work_items_inserted", 0)),
                            "sources": int(result.get("sources_inserted", 0)),
                            "status": result.get("status", "unknown"),
                        }
                    )
            except (sqlite3.Error, ValueError, RuntimeError) as exc:
                summary["errors"].append(f"entry_recursion system {system_id}: {exc}")
            try:
                from db.param_semantics import reconcile_param_semantics

                endpoint_ids = _param_semantics_endpoints(conn, target_name=target_name, system_id=system_id, linked_hosts=linked_hosts)
                for endpoint_id in endpoint_ids:
                    result = reconcile_param_semantics(
                        conn,
                        target_name=target_name,
                        system_id=system_id,
                        endpoint_id=endpoint_id,
                        evidence_refs=[f"endpoint_observations:{endpoint_id}"],
                        public_confirmed=True,
                        state_change=False,
                        apply=True,
                    )
                    if result.get("work_items_inserted") or result.get("coverage_inserted") or result.get("coverage_updated"):
                        summary["param_semantics"].append(
                            {
                                "system_id": system_id,
                                "endpoint_id": endpoint_id,
                                "families": list(result.get("families", {}).keys()),
                            }
                        )
            except (sqlite3.Error, ValueError, RuntimeError) as exc:
                summary["errors"].append(f"param_semantics system {system_id}: {exc}")

    # 6. pending operator intel (B7/B8 importers are operator-fed)
    summary["pending_intel"] = _pending_intel(conn, target_name)
    return summary


def _path(args: Any) -> Path:
    path = Path(args.db)
    if not path.is_file():
        raise ValueError(f"database file not found: {path}")
    with session(path, read_only=True) as conn:
        row = conn.execute("SELECT 1 FROM targets WHERE target_name=? LIMIT 1", (args.target,)).fetchone()
    if row is None:
        raise ValueError("target is not present in the explicit database")
    return path


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Run offline v3 chain-fact building steps")
    parser.add_argument("--target", required=True)
    parser.add_argument("--db", "--file", dest="db", required=True, help="explicit database path for this target")
    parser.add_argument("--preview", action="store_true", help="dry run without persisting")
    args = parser.parse_args()
    try:
        conn = connect(_path(args))
        try:
            result = run_v3_chain_facts(conn, target_name=args.target, apply=not args.preview)
        finally:
            conn.close()
        print(json.dumps({"ok": True, "db": str(_path(args)), **result}, ensure_ascii=False, default=str))
        return 0
    except (ValueError, RuntimeError, sqlite3.Error) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
