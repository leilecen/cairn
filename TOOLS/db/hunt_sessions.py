"""Focused hunt session state machine."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

STATUSES = {"proposed", "active", "paused", "completed", "abandoned"}


def _row(cur, row):
    return dict(zip([d[0] for d in cur.description], row, strict=True))


def _get(conn, session_id):
    cur = conn.execute("SELECT * FROM hunt_sessions WHERE id=?", (session_id,))
    row = cur.fetchone()
    if row is None:
        raise ValueError(f"hunt_session not found: {session_id}")
    return _row(cur, row)


def create_session(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    focus_subject_table: str,
    focus_subject_id: str,
    goal: str,
    selected_by: str,
    soft_target_id: int | None = None,
    success_criteria: list[Any] | None = None,
    stop_conditions: list[Any] | None = None,
    system_id: int | None = None,
    operator_acknowledged_at: str | None = None,
    recon_readiness_snapshot: dict[str, Any] | None = None,
    commit: bool = True,
) -> int:
    if not all(str(x or "").strip() for x in (target_name, focus_subject_table, focus_subject_id, goal, selected_by)):
        raise ValueError("session focus and goal are required")
    columns = {row[1] for row in conn.execute("PRAGMA table_info(hunt_sessions)")}
    if system_id is not None and "system_id" in columns:
        cur = conn.execute(
            "INSERT INTO hunt_sessions(target_name,soft_target_id,focus_subject_table,focus_subject_id,goal,success_criteria_json,stop_conditions_json,selected_by,system_id,recon_readiness_snapshot_json,operator_acknowledged_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                target_name,
                soft_target_id,
                focus_subject_table,
                str(focus_subject_id),
                goal,
                json.dumps(success_criteria or [], ensure_ascii=False),
                json.dumps(stop_conditions or [], ensure_ascii=False),
                selected_by,
                system_id,
                json.dumps(recon_readiness_snapshot or {}, ensure_ascii=False),
                operator_acknowledged_at,
            ),
        )
    else:
        cur = conn.execute(
            "INSERT INTO hunt_sessions(target_name,soft_target_id,focus_subject_table,focus_subject_id,goal,success_criteria_json,stop_conditions_json,selected_by) VALUES(?,?,?,?,?,?,?,?)",
            (
                target_name,
                soft_target_id,
                focus_subject_table,
                str(focus_subject_id),
                goal,
                json.dumps(success_criteria or [], ensure_ascii=False),
                json.dumps(stop_conditions or [], ensure_ascii=False),
                selected_by,
            ),
        )
    if commit:
        conn.commit()
    return int(cur.lastrowid or 0)


def set_status(conn, session_id: int, status: str, *, actor: str = "main", commit: bool = True) -> dict[str, Any]:
    if status not in STATUSES:
        raise ValueError(f"invalid hunt session status: {status}")
    row = _get(conn, session_id)
    if status == "active" and actor not in {"main", "operator"}:
        raise PermissionError("only main session or operator can activate a hunt session")
    if status == "active":
        columns = {item[1] for item in conn.execute("PRAGMA table_info(hunt_sessions)")}
        human_focus_enabled = (
            conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_version'").fetchone() is not None
            and conn.execute("SELECT 1 FROM schema_version WHERE version>=33 LIMIT 1").fetchone() is not None
        )
        if human_focus_enabled and "system_id" in columns and not row.get("system_id"):
            raise ValueError("active hunt session must be bound to a system")
        if human_focus_enabled and "operator_acknowledged_at" in columns and not row.get("operator_acknowledged_at"):
            raise PermissionError("operator acknowledgement is required before activation")
        existing = conn.execute(
            "SELECT id FROM hunt_sessions WHERE target_name=? AND status='active' AND id<>?",
            (row["target_name"], session_id),
        ).fetchone()
        if existing:
            raise ValueError(f"target already has active hunt session: {existing[0]}")
    conn.execute(
        "UPDATE hunt_sessions SET status=?, started_at=CASE WHEN ?='active' THEN COALESCE(started_at,datetime('now','localtime')) ELSE started_at END, ended_at=CASE WHEN ? IN ('completed','abandoned') THEN datetime('now','localtime') ELSE ended_at END, updated_at=datetime('now','localtime') WHERE id=?",
        (status, status, status, session_id),
    )
    if commit:
        conn.commit()
    return _get(conn, session_id)


def get_active_session(conn, *, target_name: str):
    cur = conn.execute("SELECT * FROM hunt_sessions WHERE target_name=? AND status='active' ORDER BY id DESC LIMIT 1", (target_name,))
    row = cur.fetchone()
    return _row(cur, row) if row else None


def main(argv=None):
    import argparse
    import json

    from db.db_utils import connect, find_db

    p = argparse.ArgumentParser(description="focused cognitive hunt session operations")
    p.add_argument("--target", required=True)
    p.add_argument("--db")
    sub = p.add_subparsers(dest="command", required=True)
    create = sub.add_parser("propose")
    create.add_argument("--subject-table", required=True)
    create.add_argument("--subject-id", required=True)
    create.add_argument("--goal", required=True)
    create.add_argument("--selected-by", required=True)
    create.add_argument("--soft-target-id", type=int)
    state = sub.add_parser("state")
    state.add_argument("status", choices=sorted(STATUSES))
    state.add_argument("--session-id", type=int, required=True)
    state.add_argument("--actor", default="main")
    sub.add_parser("view")
    args = p.parse_args(argv)
    path = args.db or find_db(args.target)
    if not path:
        raise SystemExit(f"target DB not found: {args.target}")
    conn = connect(path)
    try:
        if args.command == "propose":
            result = {
                "id": create_session(
                    conn,
                    target_name=args.target,
                    focus_subject_table=args.subject_table,
                    focus_subject_id=args.subject_id,
                    goal=args.goal,
                    selected_by=args.selected_by,
                    soft_target_id=args.soft_target_id,
                )
            }
        elif args.command == "state":
            result = set_status(conn, args.session_id, args.status, actor=args.actor)
        else:
            result = get_active_session(conn, target_name=args.target)
        print(json.dumps(result, ensure_ascii=False, default=str))
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    main()
