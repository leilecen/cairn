"""Compact, explicit main-session decisions."""

from __future__ import annotations

import json
import sqlite3

from db.cognitive_contract import DECISION_TYPES


def record_decision(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    actor: str,
    decision_type: str,
    chosen_action: str,
    rationale: str,
    expected_change: str = "",
    actual_change: str = "",
    hunt_session_id: int | None = None,
    attack_thread_id: int | None = None,
    experiment_id: int | None = None,
    snapshot: dict | None = None,
    candidate_actions: list | None = None,
    commit: bool = True,
) -> int:
    if decision_type not in DECISION_TYPES:
        raise ValueError("invalid decision type")
    if not chosen_action.strip() or not rationale.strip():
        raise ValueError("chosen_action and rationale are required")
    cur = conn.execute(
        "INSERT INTO decision_events(target_name,hunt_session_id,attack_thread_id,experiment_id,actor,decision_type,compact_snapshot_json,candidate_actions_json,chosen_action,rationale,expected_change,actual_change) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            target_name,
            hunt_session_id,
            attack_thread_id,
            experiment_id,
            actor,
            decision_type,
            json.dumps(snapshot or {}, ensure_ascii=False)[:4000],
            json.dumps((candidate_actions or [])[:20], ensure_ascii=False)[:4000],
            chosen_action[:300],
            rationale[:800],
            expected_change[:800],
            actual_change[:800],
        ),
    )
    if commit:
        conn.commit()
    return int(cur.lastrowid or 0)


def list_decisions(conn, *, target_name: str, limit: int = 20):
    cur = conn.execute("SELECT * FROM decision_events WHERE target_name=? ORDER BY id DESC LIMIT ?", (target_name, limit))
    return [dict(zip([d[0] for d in cur.description], r, strict=True)) for r in cur.fetchall()]


def main(argv=None):
    import argparse
    import json

    from db.db_utils import connect, find_db

    p = argparse.ArgumentParser(description="record compact cognitive decisions")
    p.add_argument("--target", required=True)
    p.add_argument("--db")
    sub = p.add_subparsers(dest="command", required=True)
    record = sub.add_parser("record")
    record.add_argument("--actor", required=True)
    record.add_argument("--decision-type", required=True)
    record.add_argument("--chosen-action", required=True)
    record.add_argument("--rationale", required=True)
    record.add_argument("--expected-change", default="")
    record.add_argument("--actual-change", default="")
    record.add_argument("--session-id", type=int)
    record.add_argument("--thread-id", type=int)
    record.add_argument("--experiment-id", type=int)
    view = sub.add_parser("view")
    view.add_argument("--limit", type=int, default=20)
    args = p.parse_args(argv)
    path = args.db or find_db(args.target)
    if not path:
        raise SystemExit(f"target DB not found: {args.target}")
    conn = connect(path)
    try:
        result = (
            record_decision(
                conn,
                target_name=args.target,
                actor=args.actor,
                decision_type=args.decision_type,
                chosen_action=args.chosen_action,
                rationale=args.rationale,
                expected_change=args.expected_change,
                actual_change=args.actual_change,
                hunt_session_id=args.session_id,
                attack_thread_id=args.thread_id,
                experiment_id=args.experiment_id,
            )
            if args.command == "record"
            else list_decisions(conn, target_name=args.target, limit=args.limit)
        )
        print(json.dumps(result, ensure_ascii=False, default=str))
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    main()
