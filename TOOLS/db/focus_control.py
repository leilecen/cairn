"""Transactional, operator-confirmed system focus control."""

from __future__ import annotations

import json
import sqlite3
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

_TOOLS_DIR = Path(__file__).resolve().parent.parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

from db.recon_readiness import evaluate_readiness  # noqa: E402
from db.system_contract import is_active_capable  # noqa: E402
from db.system_registry import get_system, system_compact  # noqa: E402


def _require_actor(actor: str) -> None:
    if actor != "operator":
        raise PermissionError("focus changes require an explicit operator actor")


def activate_focus(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    system_id: int,
    goal: str,
    actor: str = "operator",
    operator_acknowledged: bool = False,
    selected_by: str | None = None,
    commit: bool = True,
) -> dict[str, Any]:
    _require_actor(actor)
    if not operator_acknowledged:
        raise PermissionError("operator acknowledgement is required before focus activation")
    transaction_mode = _begin_scope(conn, "activate_focus") if commit else None
    try:
        system, linked, readiness = _validate_focus_candidate(conn, target_name=target_name, system_id=system_id)
        existing = conn.execute("SELECT id FROM hunt_sessions WHERE target_name=? AND status='active'", (target_name,)).fetchone()
        if existing:
            raise ValueError(f"target already has active hunt session: {existing[0]}")
        session = conn.execute(
            """INSERT INTO hunt_sessions(target_name,focus_subject_table,focus_subject_id,goal,success_criteria_json,stop_conditions_json,status,selected_by,started_at,system_id,recon_readiness_snapshot_json,operator_acknowledged_at) VALUES(?,?,?,?,?,?,?,?,datetime('now','localtime'),?,?,datetime('now','localtime'))""",  # noqa: E501
            (
                target_name,
                "target_systems",
                str(system_id),
                goal,
                "[]",
                "[]",
                "active",
                selected_by or actor,
                system_id,
                json.dumps(readiness, ensure_ascii=False, separators=(",", ":")),
            ),
        )
        session_id = int(session.lastrowid or 0)
        conn.execute(
            "UPDATE target_systems SET lifecycle_state=?,updated_at=datetime('now','localtime') WHERE id=?",
            ("testing" if readiness["state"] == "ready" else "mapping", system_id),
        )
        if _table(conn, "soft_targets"):
            primary_ids = [int(row["asset_id"]) for row in linked]
            st_cols = {row[1] for row in conn.execute("PRAGMA table_info(soft_targets)")}
            updated = ",updated_at=datetime('now','localtime')" if "updated_at" in st_cols else ""
            conn.execute(
                "UPDATE soft_targets SET status='parked'{} WHERE target_name=? AND status IN ('focused','active') AND (asset_id IS NULL OR asset_id NOT IN ({}))".format(  # noqa: E501,S608
                    updated, ",".join("?" for _ in primary_ids)
                ),
                (target_name, *primary_ids),
            )
            focused = ",focused_at=COALESCE(focused_at,datetime('now','localtime'))" if "focused_at" in st_cols else ""
            conn.execute(
                "UPDATE soft_targets SET status='focused'{}{} WHERE target_name=? AND asset_id IN ({})".format(  # noqa: S608
                    focused, updated, ",".join("?" for _ in primary_ids)
                ),
                (target_name, *primary_ids),
            )
        if _table(conn, "system_soft_targets"):
            conn.execute(
                "UPDATE system_soft_targets SET status='parked',updated_at=datetime('now','localtime') WHERE target_name=? AND status='focused' AND system_id<>?",  # noqa: E501
                (target_name, system_id),
            )
            conn.execute(
                """UPDATE system_soft_targets SET status='focused',
                   focused_at=COALESCE(focused_at,datetime('now','localtime')),
                   timebox_minutes=120,
                   timebox_until=datetime('now','localtime','+120 minutes'),
                   updated_at=datetime('now','localtime')
                   WHERE target_name=? AND system_id=? AND eligibility_status='eligible'""",
                (target_name, system_id),
            )
        parked_cursor = conn.execute(
            "UPDATE work_items SET dispatch_state='parked',park_reason='human focus activated; unrelated system or unmapped legacy task' WHERE target_name=? AND COALESCE(dispatch_state,'active')='active' AND status IN ('queued','partial') AND (system_id IS NULL OR system_id<>?)",  # noqa: E501
            (target_name, system_id),
        )
        parked_count = parked_cursor.rowcount
        if _table(conn, "decision_events"):
            conn.execute(
                "INSERT INTO decision_events(target_name,hunt_session_id,actor,decision_type,compact_snapshot_json,chosen_action,rationale,expected_change) VALUES(?,?,?,?,?,?,?,?)",  # noqa: E501
                (
                    target_name,
                    session_id,
                    actor,
                    "focus",
                    json.dumps(
                        {
                            "system": system_compact(conn, target_name=target_name, system_id=system_id),
                            "readiness": readiness,
                        },
                        ensure_ascii=False,
                    ),
                    f"activate system {system_id}",
                    "operator confirmed focused system",
                    "only same-system tasks remain dispatchable",
                ),
            )
        if commit:
            _finish_scope(conn, transaction_mode, "activate_focus")
    except Exception:
        if commit:
            _rollback_scope(conn, transaction_mode, "activate_focus")
        raise
    return {
        "session_id": session_id,
        "system": system_compact(conn, target_name=target_name, system_id=system_id),
        "readiness": readiness,
        "parked": parked_count,
    }


def _validate_focus_candidate(
    conn: sqlite3.Connection, *, target_name: str, system_id: int
) -> tuple[dict[str, Any], list[sqlite3.Row], dict[str, Any]]:
    system = get_system(conn, target_name=target_name, system_id=system_id)
    if not is_active_capable(system["scope_class"]):
        raise PermissionError("intel_only/unknown systems cannot become active focus")
    linked = conn.execute(
        "SELECT l.asset_id,a.scope_class,a.scope_status,a.authorization_state "
        "FROM system_asset_links l JOIN target_assets a ON a.id=l.asset_id "
        "WHERE l.target_name=? AND l.system_id=? AND a.target_name=?",
        (target_name, system_id, target_name),
    ).fetchall()
    if not linked:
        raise PermissionError("active focus requires a target-scoped asset link")
    if any(
        row["scope_class"] not in {"owned", "authorized_vendor"}
        or row["scope_status"] != "in_scope"
        or str(row["authorization_state"] or "").lower() not in {"active", "authorized", "confirmed"}
        for row in linked
    ):
        raise PermissionError("every linked asset must be explicitly authorized and in scope")
    if _table(conn, "system_soft_targets"):
        ranked = conn.execute(
            "SELECT eligibility_status FROM system_soft_targets WHERE target_name=? AND system_id=?",
            (target_name, system_id),
        ).fetchone()
        if ranked is None or ranked["eligibility_status"] != "eligible":
            raise PermissionError("system is not execution-eligible; run system scorer and resolve scope first")
    readiness = evaluate_readiness(conn, target_name=target_name, system_id=system_id)
    return system, linked, readiness


def pause_focus(
    conn: sqlite3.Connection, *, target_name: str, session_id: int, actor: str = "operator", status: str = "paused"
) -> dict[str, Any]:
    _require_actor(actor)
    if status not in {"paused", "completed", "abandoned"}:
        raise ValueError("invalid focus stop status")
    transaction_mode = _begin_scope(conn, "pause_focus")
    try:
        row = conn.execute(
            "SELECT system_id FROM hunt_sessions WHERE id=? AND target_name=? AND status='active'",
            (session_id, target_name),
        ).fetchone()
        if row is None:
            raise ValueError("active focus session not found")
        conn.execute(
            """UPDATE hunt_sessions SET status=?,
               ended_at=CASE WHEN ? IN ('completed','abandoned') THEN datetime('now','localtime') ELSE ended_at END,
               updated_at=datetime('now','localtime') WHERE id=?""",
            (status, status, session_id),
        )
        if row["system_id"]:
            conn.execute(
                "UPDATE target_systems SET lifecycle_state=?,updated_at=datetime('now','localtime') WHERE id=?",
                ("completed" if status == "completed" else "parked", row["system_id"]),
            )
            if _table(conn, "system_soft_targets"):
                conn.execute(
                    """UPDATE system_soft_targets SET status=?,timebox_until=NULL,
                       updated_at=datetime('now','localtime') WHERE target_name=? AND system_id=?""",
                    ("completed" if status == "completed" else "parked", target_name, row["system_id"]),
                )
        _decision(
            conn,
            target_name,
            session_id,
            actor,
            "stop" if status in {"completed", "abandoned"} else "park",
            f"{status} focus session {session_id}",
            "operator changed focus lifecycle",
        )
        _finish_scope(conn, transaction_mode, "pause_focus")
    except Exception:
        _rollback_scope(conn, transaction_mode, "pause_focus")
        raise
    return {"session_id": session_id, "status": status}


def propose_switch(conn: sqlite3.Connection, *, target_name: str, from_system_id: int, to_system_id: int, reason: str) -> dict[str, Any]:
    get_system(conn, target_name=target_name, system_id=from_system_id)
    get_system(conn, target_name=target_name, system_id=to_system_id)
    return {
        "kind": "focus_switch",
        "from_system": system_compact(conn, target_name=target_name, system_id=from_system_id),
        "to_system": system_compact(conn, target_name=target_name, system_id=to_system_id),
        "reason": str(reason)[:500],
        "requires_operator_confirmation": True,
    }


def reconcile_focus(conn: sqlite3.Connection, *, target_name: str) -> dict[str, Any]:
    active = conn.execute("SELECT * FROM hunt_sessions WHERE target_name=? AND status='active' ORDER BY id DESC", (target_name,)).fetchall()
    systems = conn.execute(
        "SELECT id,lifecycle_state FROM target_systems WHERE target_name=? AND lifecycle_state IN ('mapping','ready','testing','human_blocked')",  # noqa: E501
        (target_name,),
    ).fetchall()
    return {
        "target_name": target_name,
        "active_sessions": [dict(x) for x in active],
        "focused_systems": [dict(x) for x in systems],
        "consistent": len(active) <= 1 and (not active or active[0]["system_id"] in {x[0] for x in systems}),
    }


def accept_switch(conn: sqlite3.Connection, *, target_name: str, to_system_id: int, goal: str, actor: str = "operator") -> dict[str, Any]:
    _require_actor(actor)
    transaction_mode = _begin_scope(conn, "accept_switch")
    try:
        current = conn.execute(
            "SELECT id,system_id FROM hunt_sessions WHERE target_name=? AND status='active' ORDER BY id DESC LIMIT 1",
            (target_name,),
        ).fetchone()
        if current is None:
            raise ValueError("no active focus to switch from")
        if int(current["system_id"]) == int(to_system_id):
            raise ValueError("switch target is already focused")
        conn.execute(
            "UPDATE hunt_sessions SET status='paused',updated_at=datetime('now','localtime') WHERE id=?",
            (current["id"],),
        )
        conn.execute(
            "UPDATE target_systems SET lifecycle_state='parked',updated_at=datetime('now','localtime') WHERE id=?",
            (current["system_id"],),
        )
        result = activate_focus(
            conn,
            target_name=target_name,
            system_id=to_system_id,
            goal=goal,
            actor=actor,
            operator_acknowledged=True,
            selected_by=actor,
            commit=False,
        )
        if _table(conn, "decision_events"):
            conn.execute(
                "INSERT INTO decision_events(target_name,hunt_session_id,actor,decision_type,compact_snapshot_json,chosen_action,rationale,expected_change) VALUES(?,?,?,?,?,?,?,?)",  # noqa: E501
                (
                    target_name,
                    result["session_id"],
                    actor,
                    "pivot",
                    json.dumps({"from_system_id": current["system_id"], "to_system_id": to_system_id}, ensure_ascii=False),
                    f"switch to system {to_system_id}",
                    "operator accepted focus switch",
                    "new system becomes the only active focus",
                ),
            )
        _finish_scope(conn, transaction_mode, "accept_switch")
        return {"from_session_id": current["id"], **result}
    except Exception:
        _rollback_scope(conn, transaction_mode, "accept_switch")
        raise


def cancel_switch(*, proposal: dict[str, Any]) -> dict[str, Any]:
    return {"cancelled": True, "focus_changed": False, "proposal": proposal}


def renew_focus(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    session_id: int,
    actor: str = "operator",
    minutes: int = 120,
) -> dict[str, Any]:
    """Renew one active operator-selected focus and record the decision."""
    _require_actor(actor)
    if minutes <= 0 or minutes > 480:
        raise ValueError("minutes must be between 1 and 480")
    transaction_mode = _begin_scope(conn, "renew_focus")
    try:
        row = conn.execute(
            "SELECT system_id FROM hunt_sessions WHERE id=? AND target_name=? AND status='active'",
            (session_id, target_name),
        ).fetchone()
        if row is None or not row["system_id"]:
            raise ValueError("active focus session not found")
        if not _table(conn, "system_soft_targets"):
            raise RuntimeError("system_soft_targets is required for focus renewal")
        ranked = conn.execute(
            "SELECT eligibility_status FROM system_soft_targets WHERE target_name=? AND system_id=?",
            (target_name, row["system_id"]),
        ).fetchone()
        if ranked is None or ranked["eligibility_status"] != "eligible":
            raise PermissionError("system is no longer execution-eligible")
        conn.execute(
            """UPDATE system_soft_targets SET status='focused',timebox_minutes=?,
               timebox_until=datetime('now','localtime',?),updated_at=datetime('now','localtime')
               WHERE target_name=? AND system_id=?""",
            (minutes, f"+{minutes} minutes", target_name, row["system_id"]),
        )
        _decision(
            conn,
            target_name,
            session_id,
            actor,
            "continue",
            f"renew system {row['system_id']}",
            "operator renewed focus timebox",
        )
        _finish_scope(conn, transaction_mode, "renew_focus")
    except Exception:
        _rollback_scope(conn, transaction_mode, "renew_focus")
        raise
    return {"session_id": session_id, "system_id": int(row["system_id"]), "timebox_minutes": minutes}


def expire_focus(conn: sqlite3.Connection, *, target_name: str, now: datetime | None = None) -> dict[str, Any]:
    """Park elapsed focus sessions; repeated expiry is a no-op."""
    if not _table(conn, "system_soft_targets"):
        return {"expired": 0, "session_ids": []}
    timestamp = (now or datetime.now()).strftime("%Y-%m-%d %H:%M:%S")
    transaction_mode = _begin_scope(conn, "expire_focus")
    try:
        rows = conn.execute(
            """SELECT h.id,h.system_id FROM hunt_sessions h JOIN system_soft_targets st
               ON st.target_name=h.target_name AND st.system_id=h.system_id
               WHERE h.target_name=? AND h.status='active' AND st.timebox_until IS NOT NULL AND st.timebox_until<=?""",
            (target_name, timestamp),
        ).fetchall()
        for row in rows:
            conn.execute(
                "UPDATE hunt_sessions SET status='paused',updated_at=datetime('now','localtime') WHERE id=?",
                (row["id"],),
            )
            conn.execute(
                "UPDATE target_systems SET lifecycle_state='parked',updated_at=datetime('now','localtime') WHERE id=? AND target_name=?",  # noqa: E501
                (row["system_id"], target_name),
            )
            conn.execute(
                "UPDATE system_soft_targets SET status='parked',timebox_until=NULL,updated_at=datetime('now','localtime') WHERE target_name=? AND system_id=?",  # noqa: E501
                (target_name, row["system_id"]),
            )
            _decision(
                conn,
                target_name,
                int(row["id"]),
                "operator",
                "park",
                f"expire system {row['system_id']}",
                "focus timebox elapsed",
            )
        _finish_scope(conn, transaction_mode, "expire_focus")
    except Exception:
        _rollback_scope(conn, transaction_mode, "expire_focus")
        raise
    return {"expired": len(rows), "session_ids": [int(row["id"]) for row in rows]}


def _decision(
    conn: sqlite3.Connection,
    target_name: str,
    session_id: int,
    actor: str,
    decision_type: str,
    chosen: str,
    rationale: str,
) -> None:
    if _table(conn, "decision_events"):
        conn.execute(
            """INSERT INTO decision_events(target_name,hunt_session_id,actor,decision_type,compact_snapshot_json,
               chosen_action,rationale,expected_change) VALUES(?,?,?,?,?,?,?,?)""",
            (
                target_name,
                session_id,
                actor,
                decision_type,
                "{}",
                chosen,
                rationale,
                "focus lifecycle remains explicit",
            ),
        )


def _begin_scope(conn: sqlite3.Connection, name: str) -> str:
    if conn.in_transaction:
        conn.execute(f"SAVEPOINT {name}")
        return "savepoint"
    conn.execute("BEGIN IMMEDIATE")
    return "transaction"


def _finish_scope(conn: sqlite3.Connection, mode: str | None, name: str) -> None:
    if mode == "savepoint":
        conn.execute(f"RELEASE SAVEPOINT {name}")
    else:
        conn.commit()


def _rollback_scope(conn: sqlite3.Connection, mode: str | None, name: str) -> None:
    if mode == "savepoint":
        conn.execute(f"ROLLBACK TO SAVEPOINT {name}")
        conn.execute(f"RELEASE SAVEPOINT {name}")
    else:
        conn.rollback()


def main(argv: list[str] | None = None) -> int:
    import argparse

    from db.db_utils import connect, find_db

    p = argparse.ArgumentParser(description="Operator-confirmed system focus control")
    p.add_argument("--target", required=True)
    p.add_argument("--db")
    sub = p.add_subparsers(dest="command", required=True)
    a = sub.add_parser("activate-focus")
    a.add_argument("--system-id", type=int, required=True)
    a.add_argument("--goal", required=True)
    a.add_argument("--ack", action="store_true")
    a.add_argument("--actor", required=True, choices=["operator"])
    s = sub.add_parser("accept-switch")
    s.add_argument("--system-id", type=int, required=True)
    s.add_argument("--goal", required=True)
    s.add_argument("--actor", required=True, choices=["operator"])
    sub.add_parser("reconcile")
    args = p.parse_args(argv)
    try:
        if args.db:
            path = Path(args.db)
            if not path.is_file():
                raise ValueError(f"database file not found: {path}")
        else:
            path = find_db(args.target)
        conn = connect(path)
        if args.command == "activate-focus":
            result = activate_focus(
                conn,
                target_name=args.target,
                system_id=args.system_id,
                goal=args.goal,
                actor=args.actor,
                operator_acknowledged=args.ack,
            )
        elif args.command == "accept-switch":
            result = accept_switch(conn, target_name=args.target, to_system_id=args.system_id, goal=args.goal, actor=args.actor)
        else:
            result = reconcile_focus(conn, target_name=args.target)
        print(json.dumps({"ok": True, "data": result}, ensure_ascii=True, default=str, separators=(",", ":")))
        return 0
    except (ValueError, RuntimeError, PermissionError, sqlite3.Error) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=True, separators=(",", ":")))
        return 1
    finally:
        if "conn" in locals():
            conn.close()


def _table(conn: sqlite3.Connection, table: str) -> bool:
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone() is not None


if __name__ == "__main__":
    raise SystemExit(main())
