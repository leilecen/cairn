"""Preview or apply deterministic M3/M4 lifecycle settlement for one target DB."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any

TOOLS_DIR = Path(__file__).resolve().parent.parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from db.db_utils import connect, find_db  # noqa: E402
from db.vuln_review_sync import sync_vuln_review_result  # noqa: E402
from db.work_queue import create_work_item, settle_blocked_work_item  # noqa: E402

BLOCKER_CLASSES = {
    "auth_barrier",
    "network",
    "scope",
    "evidence",
    "critical_found",
    "refuted",
    "parked",
    "other",
}
OPERATOR_KIND_CLASSES = {
    "login_required": "auth_barrier",
    "secondary_account_required": "auth_barrier",
    "role_account_required": "auth_barrier",
    "confirm_scope": "scope",
    "scope_cluster_confirm": "scope",
    "confirm_high_risk": "critical_found",
    "screenshot_needed": "evidence",
    "evidence_capture": "evidence",
}


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {str(row[1]) for row in conn.execute(f'PRAGMA table_info("{table}")')}


def _require_schema(conn: sqlite3.Connection) -> None:
    required = {
        "suspicious_points": {"id", "test_status"},
        "findings": {"sp_id"},
        "work_items": {"id", "target_name", "status", "blocker_class", "attack_thread_id"},
        "attack_threads": {"id", "target_name", "status", "evaluation_status"},
        "attack_thread_events": {"attack_thread_id", "event_type", "payload_json"},
        "operator_inbox": {"target_name", "related_work_item_id", "kind", "action_key"},
    }
    missing = [f"{table}.{column}" for table, cols in required.items() for column in cols - _columns(conn, table)]
    if missing:
        raise ValueError(f"schema 034 settlement prerequisites missing: {', '.join(sorted(missing))}")


def _validate_target(conn: sqlite3.Connection, target_name: str) -> None:
    row = conn.execute("SELECT 1 FROM targets WHERE target_name=? LIMIT 1", (target_name,)).fetchone()
    if row is None:
        raise ValueError(f"target not found in DB: {target_name}")


def _latest_review(conn: sqlite3.Connection, target_name: str, sp_id: str) -> sqlite3.Row | None:
    return conn.execute(
        """
        SELECT wi.* FROM work_items wi
        WHERE wi.target_name=? AND wi.lane='vuln_review' AND wi.subtype='single_sp_review'
          AND wi.subject_table='suspicious_points' AND wi.subject_id=?
        ORDER BY wi.id DESC LIMIT 1
        """,
        (target_name, sp_id),
    ).fetchone()


def _worker_result(conn: sqlite3.Connection, work_item_id: int) -> dict[str, Any] | None:
    rows = conn.execute(
        "SELECT payload_json FROM agent_events WHERE work_item_id=? AND event_type='done' ORDER BY id DESC",
        (work_item_id,),
    ).fetchall()
    for row in rows:
        try:
            value = json.loads(row[0] or "{}")
            result = value.get("worker_result") if isinstance(value, dict) else None
            if isinstance(result, dict):
                return result
        except (json.JSONDecodeError, TypeError):
            continue
    return None


def _confirmed_plan(conn: sqlite3.Connection, target_name: str) -> list[dict[str, Any]]:
    malformed = conn.execute(
        "SELECT COUNT(*) FROM suspicious_points WHERE test_status='confirmed' AND (id IS NULL OR trim(id)='')"
    ).fetchone()[0]
    if malformed:
        raise ValueError("confirmed suspicious_points contains NULL/empty id; run S1 backfill first")
    target_count = int(conn.execute("SELECT COUNT(DISTINCT target_name) FROM targets").fetchone()[0])
    rows = conn.execute(
        """
        SELECT sp.* FROM suspicious_points sp
        WHERE sp.test_status='confirmed'
          AND (
            ?=1
            OR EXISTS (
              SELECT 1 FROM work_items wi
              WHERE wi.target_name=? AND wi.subject_table='suspicious_points' AND wi.subject_id=sp.id
            )
            OR EXISTS (
              SELECT 1 FROM findings f JOIN targets t ON t.id=f.target_id
              WHERE f.sp_id=sp.id AND t.target_name=?
            )
          )
        ORDER BY sp.id
        """,
        (target_count, target_name, target_name),
    ).fetchall()
    if any(row["id"] is None or not str(row["id"]).strip() for row in rows):
        raise ValueError("confirmed suspicious_points contains NULL/empty id; run S1 backfill first")
    plan: list[dict[str, Any]] = []
    for sp in rows:
        sp_id = str(sp["id"])
        if conn.execute("SELECT 1 FROM findings WHERE sp_id=? LIMIT 1", (sp_id,)).fetchone():
            disposition = "existing_finding"
        else:
            review = _latest_review(conn, target_name, sp_id)
            result = _worker_result(conn, int(review["id"])) if review is not None else None
            risk = str(sp["risk"] if "risk" in sp.keys() else "").lower()
            if risk in {"high", "critical"}:
                disposition = "operator_gate"
            elif result and result.get("evidence_refs") and result.get("sufficient_evidence") is True:
                disposition = "candidate"
            else:
                disposition = "review_insufficient_evidence"
        plan.append({"sp_id": sp_id, "disposition": disposition})
    return plan


def _deterministic_blocker_class(conn: sqlite3.Connection, row: sqlite3.Row) -> str:
    existing = str(row["blocker_class"] or "").strip().lower()
    if existing in BLOCKER_CLASSES:
        return existing
    if row["attack_thread_id"] is not None:
        thread = conn.execute(
            "SELECT status,evaluation_status FROM attack_threads WHERE id=? AND target_name=?",
            (row["attack_thread_id"], row["target_name"]),
        ).fetchone()
        if thread is not None and thread["evaluation_status"] == "refuted":
            return "refuted"
        if thread is not None and thread["status"] == "parked" and thread["evaluation_status"] != "blocked":
            return "parked"
    kinds = conn.execute(
        "SELECT kind FROM operator_inbox WHERE target_name=? AND related_work_item_id=? ORDER BY id",
        (row["target_name"], row["id"]),
    ).fetchall()
    mapped = {OPERATOR_KIND_CLASSES.get(str(item[0])) for item in kinds} - {None}
    if len(mapped) == 1:
        return str(mapped.pop())
    if "risk_class" in row.keys() and row["risk_class"] == "high_risk":
        return "critical_found"
    if "auth_requirement" in row.keys() and row["auth_requirement"] in {
        "required",
        "multi_account_required",
        "role_required",
    }:
        return "auth_barrier"
    return "other"


def build_plan(conn: sqlite3.Connection, target_name: str) -> dict[str, Any]:
    _require_schema(conn)
    _validate_target(conn, target_name)
    blocked = conn.execute("SELECT * FROM work_items WHERE target_name=? AND status='blocked' ORDER BY id", (target_name,)).fetchall()
    return {
        "target": target_name,
        "confirmed": _confirmed_plan(conn, target_name),
        "blocked": [{"work_item_id": int(row["id"]), "blocker_class": _deterministic_blocker_class(conn, row)} for row in blocked],
    }


def apply_plan(conn: sqlite3.Connection, target_name: str) -> dict[str, Any]:
    conn.execute("BEGIN IMMEDIATE")
    try:
        plan = build_plan(conn, target_name)
        for item in plan["confirmed"]:
            if item["disposition"] == "existing_finding":
                continue
            sp_id = item["sp_id"]
            work_item = _latest_review(conn, target_name, sp_id)
            result = _worker_result(conn, int(work_item["id"])) if work_item is not None else None
            if work_item is None:
                work_id = create_work_item(
                    conn,
                    target_name=target_name,
                    lane="vuln_review",
                    subtype="single_sp_review",
                    subject_table="suspicious_points",
                    subject_id=sp_id,
                    title=f"Settle historical suspicious point {sp_id}",
                    objective="Offline lifecycle settlement only; do not issue requests.",
                    risk_class="safe_passive",
                    commit=False,
                )
                conn.execute("UPDATE work_items SET status='done' WHERE id=?", (work_id,))
                work_item = conn.execute("SELECT * FROM work_items WHERE id=?", (work_id,)).fetchone()
            if result is None:
                result = {
                    "status": "done",
                    "summary": "Historical confirmed item has no traceable sufficient review evidence.",
                    "confidence": "unknown",
                    "evidence_refs": [],
                    "sufficient_evidence": False,
                    "next_action": "Review compact evidence references before any promotion.",
                }
            sync_vuln_review_result(conn, work_item=work_item, worker_result=result)

        for item in plan["blocked"]:
            work_id = item["work_item_id"]
            blocker_class = item["blocker_class"]
            row = conn.execute("SELECT blocker_reason FROM work_items WHERE id=?", (work_id,)).fetchone()
            reason = str(row[0] or "Historical blocked item requires operator decision.")
            conn.execute("UPDATE work_items SET blocker_class=? WHERE id=?", (blocker_class, work_id))
            settle_blocked_work_item(
                conn,
                work_item_id=work_id,
                blocker_class=blocker_class,
                block_reason=reason,
                actor="settlement_backfill",
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    plan["applied"] = True
    return plan


def _path(args: argparse.Namespace) -> Path:
    if bool(args.target) == bool(args.file):
        raise ValueError("exactly one of --target or --file is required")
    if args.file:
        path = Path(args.file)
        if not path.is_file():
            raise FileNotFoundError(f"DB file does not exist: {path}")
        return path
    return find_db(args.target)


def _bounded_cli_result(result: dict[str, Any], *, include_items: bool) -> dict[str, Any]:
    if include_items:
        return result
    compact = dict(result)
    for key in ("confirmed", "blocked"):
        items = list(result.get(key, []))
        compact[key] = {
            "count": len(items),
            "sample": items[:10],
            "omitted": max(0, len(items) - 10),
        }
    return compact


def main() -> int:
    parser = argparse.ArgumentParser(description="Preview/apply offline M3/M4 settlement")
    parser.add_argument("--target", help="explicit target name and DB selector")
    parser.add_argument("--file", help="explicit DB path")
    parser.add_argument("--target-name", help="required with --file when the DB target cannot be inferred")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--include-items", action="store_true", help="include every settlement item")
    args = parser.parse_args()
    try:
        path = _path(args)
        conn = connect(path)
        try:
            target_name = args.target or args.target_name
            if not target_name:
                names = [row[0] for row in conn.execute("SELECT DISTINCT target_name FROM targets")]
                if len(names) != 1:
                    raise ValueError("--target-name is required for a multi-target DB")
                target_name = str(names[0])
            result = apply_plan(conn, target_name) if args.apply else build_plan(conn, target_name)
            result.update({"status": "ok", "mode": "apply" if args.apply else "preview"})
            result = _bounded_cli_result(result, include_items=args.include_items)
        finally:
            conn.close()
    except (FileNotFoundError, RuntimeError, sqlite3.Error, ValueError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False, sort_keys=True))
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
