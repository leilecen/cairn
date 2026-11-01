"""Experiment repository and lifecycle."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from db.cognitive_contract import normalize_outcome, require_falsifiable

STATUSES = {"proposed", "approved", "queued", "running", "observed", "blocked", "cancelled"}
METHODS = {"offline", "passive", "active_low", "operator_gated"}


def unknown_keys_for_target(conn: sqlite3.Connection, target_name: str) -> list[str]:
    keys: set[str] = set()
    try:
        rows = conn.execute(
            "SELECT canonical_url,method FROM endpoint_observations WHERE target_name=? AND auth_state IN ('unknown','ok_unknown','passive_hint')",
            (target_name,),
        ).fetchall()
        keys.update(f"endpoint:{row[0]}|{row[1] or 'GET'}" for row in rows)
    except sqlite3.Error:
        pass
    try:
        rows = conn.execute(
            "SELECT category,item_key FROM coverage_ledger WHERE target_name=? AND status IN ('unknown','blocked')",
            (target_name,),
        ).fetchall()
        keys.update(f"coverage:{row[0]}|{row[1]}" for row in rows)
    except sqlite3.Error:
        pass
    return sorted(keys)


def _get(conn, experiment_id):
    cur = conn.execute("SELECT * FROM experiments WHERE id=?", (experiment_id,))
    row = cur.fetchone()
    if row is None:
        raise ValueError(f"experiment not found: {experiment_id}")
    return dict(zip([d[0] for d in cur.description], row, strict=True))


def propose_experiment(
    conn: sqlite3.Connection,
    *,
    hunt_session_id: int,
    attack_thread_id: int,
    experiment_key: str,
    question: str,
    method_class: str = "offline",
    expected_observation: str,
    control_description: str,
    stop_conditions: list[Any],
    risk_class: str = "safe_passive",
    budget: dict[str, Any] | None = None,
    commit: bool = True,
) -> int:
    if method_class not in METHODS:
        raise ValueError("invalid experiment method_class")
    require_falsifiable(question=question, expected_observation=expected_observation)
    if not stop_conditions:
        raise ValueError("stop_conditions are required")
    target_name = conn.execute("SELECT target_name FROM hunt_sessions WHERE id=?", (hunt_session_id,)).fetchone()
    if target_name is None:
        raise ValueError(f"hunt_session not found: {hunt_session_id}")
    before = unknown_keys_for_target(conn, target_name[0])
    cur = conn.execute(
        "INSERT INTO experiments(hunt_session_id,attack_thread_id,experiment_key,question,method_class,expected_observation,control_description,budget_json,stop_conditions_json,risk_class,unknown_items_before_json) VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(hunt_session_id,experiment_key) DO UPDATE SET question=excluded.question,expected_observation=excluded.expected_observation,control_description=excluded.control_description,updated_at=datetime('now','localtime')",
        (
            hunt_session_id,
            attack_thread_id,
            experiment_key,
            question,
            method_class,
            expected_observation,
            control_description,
            json.dumps(budget or {}, ensure_ascii=False),
            json.dumps(stop_conditions, ensure_ascii=False),
            risk_class,
            json.dumps(before, ensure_ascii=False),
        ),
    )
    if commit:
        conn.commit()
    return int(
        cur.lastrowid
        or conn.execute(
            "SELECT id FROM experiments WHERE hunt_session_id=? AND experiment_key=?", (hunt_session_id, experiment_key)
        ).fetchone()[0]
    )


def set_status(conn, experiment_id: int, status: str, *, actor: str = "main", commit: bool = True):
    if status not in STATUSES:
        raise ValueError("invalid experiment status")
    if status in {"approved", "queued", "running"} and actor not in {"main", "operator"}:
        raise PermissionError("only main session or operator can approve or run experiments")
    conn.execute("UPDATE experiments SET status=?, updated_at=datetime('now','localtime') WHERE id=?", (status, experiment_id))
    if commit:
        conn.commit()
    return _get(conn, experiment_id)


def observe_experiment(
    conn: sqlite3.Connection,
    experiment_id: int,
    *,
    outcome: str,
    observation_summary: str,
    evidence_refs: list[Any] | None = None,
    alternative_explanation: str = "",
    confidence_after: str = "unknown",
    unknown_items_after: list[Any] | None = None,
    surprise_score: int = 0,
    commit: bool = True,
):
    refs = evidence_refs or []
    result = normalize_outcome(outcome, evidence_refs=refs)
    if not 0 <= int(surprise_score) <= 3:
        raise ValueError("surprise_score must be 0..3")
    row = _get(conn, experiment_id)
    target = conn.execute("SELECT target_name FROM hunt_sessions WHERE id=?", (row["hunt_session_id"],)).fetchone()
    after = unknown_items_after if unknown_items_after is not None else unknown_keys_for_target(conn, target[0])
    conn.execute(
        "UPDATE experiments SET status=?,outcome=?,observation_summary=?,alternative_explanation=?,evidence_refs_json=?,confidence_after=?,unknown_items_after_json=?,surprise_score=?,finished_at=datetime('now','localtime'),updated_at=datetime('now','localtime') WHERE id=?",
        (
            "blocked" if result == "blocked" else "observed",
            result,
            observation_summary[:800],
            alternative_explanation[:800],
            json.dumps(refs[:20], ensure_ascii=False),
            confidence_after,
            json.dumps(after, ensure_ascii=False),
            surprise_score,
            experiment_id,
        ),
    )
    if commit:
        conn.commit()
    return _get(conn, experiment_id)


def list_experiments(conn, *, hunt_session_id: int | None = None, attack_thread_id: int | None = None, limit: int = 50):
    where = []
    params = []
    if hunt_session_id is not None:
        where.append("hunt_session_id=?")
        params.append(hunt_session_id)
    if attack_thread_id is not None:
        where.append("attack_thread_id=?")
        params.append(attack_thread_id)
    sql = "SELECT * FROM experiments" + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY id DESC LIMIT ?"  # noqa: S608 -- 仅拼接 "?" 占位符与固定字面量
    params.append(limit)
    cur = conn.execute(sql, params)
    return [dict(zip([d[0] for d in cur.description], r, strict=True)) for r in cur.fetchall()]


def approve_experiment(conn: sqlite3.Connection, experiment_id: int, *, actor: str = "main", commit: bool = True):
    return set_status(conn, experiment_id, "approved", actor=actor, commit=commit)


def main(argv=None):
    import argparse
    import json

    from db.db_utils import connect, find_db

    p = argparse.ArgumentParser(description="cognitive experiment lifecycle")
    p.add_argument("--target", required=True)
    p.add_argument("--db")
    sub = p.add_subparsers(dest="command", required=True)
    propose = sub.add_parser("propose")
    propose.add_argument("--session-id", type=int, required=True)
    propose.add_argument("--thread-id", type=int, required=True)
    propose.add_argument("--key", required=True)
    propose.add_argument("--question", required=True)
    propose.add_argument("--expected", required=True)
    propose.add_argument("--control", required=True)
    propose.add_argument("--stop", action="append", required=True)
    propose.add_argument("--method", default="offline")
    approve = sub.add_parser("approve")
    approve.add_argument("--experiment-id", type=int, required=True)
    approve.add_argument("--actor", default="main")
    observe = sub.add_parser("observe")
    observe.add_argument("--experiment-id", type=int, required=True)
    observe.add_argument("--outcome", required=True)
    observe.add_argument("--summary", required=True)
    observe.add_argument("--evidence-ref", action="append", default=[])
    view = sub.add_parser("view")
    view.add_argument("--session-id", type=int)
    args = p.parse_args(argv)
    path = args.db or find_db(args.target)
    if not path:
        raise SystemExit(f"target DB not found: {args.target}")
    conn = connect(path)
    try:
        if args.command == "propose":
            result = {
                "id": propose_experiment(
                    conn,
                    hunt_session_id=args.session_id,
                    attack_thread_id=args.thread_id,
                    experiment_key=args.key,
                    question=args.question,
                    expected_observation=args.expected,
                    control_description=args.control,
                    stop_conditions=args.stop,
                    method_class=args.method,
                )
            }
        elif args.command == "approve":
            result = approve_experiment(conn, args.experiment_id, actor=args.actor)
        elif args.command == "observe":
            result = observe_experiment(
                conn,
                args.experiment_id,
                outcome=args.outcome,
                observation_summary=args.summary,
                evidence_refs=args.evidence_ref,
            )
        else:
            result = list_experiments(conn, hunt_session_id=args.session_id)
        print(json.dumps(result, ensure_ascii=False, default=str))
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    main()
