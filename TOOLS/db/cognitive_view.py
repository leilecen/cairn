"""Compact cognitive snapshot; safe when migration 032 is absent."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from db.hunt_sessions import get_active_session


def _count(conn, sql, params=()):
    try:
        return int(conn.execute(sql, params).fetchone()[0])
    except sqlite3.Error:
        return 0


def build_cognitive_view(conn: sqlite3.Connection, *, target_name: str) -> dict[str, Any]:
    try:
        active = get_active_session(conn, target_name=target_name)
    except sqlite3.Error:
        active = None
    base = {
        "active_session": _compact_session(active),
        "focus": _compact_session(active),
        "hypothesis_summary": {"active": 0, "supported": 0, "refuted": 0, "stale": 0},
        "experiment_summary": {"proposed": 0, "running": 0, "inconclusive_streak": 0},
        "critical_unknowns": [],
        "unknown_delta": {"before": 0, "after": 0, "delta": 0},
        "next_candidates": [],
        "pivot_recommended": False,
        "pivot_reason": "",
        "operator_gates": [],
        "broad_queue_dominance": False,
        "repeated_inconclusive_direction": False,
        "observation_without_evidence": False,
        "experiment_without_expected_observation": False,
        "new_lane_not_consumed": False,
    }
    if not active:
        return base | {"blocker": "no active hunt session; operator or main session must select focus"}
    sid = active["id"]
    base["hypothesis_summary"]["active"] = _count(
        conn, "SELECT COUNT(*) FROM attack_threads WHERE hunt_session_id=? AND status='active'", (sid,)
    )
    for status, key in (("supported", "supported"), ("refuted", "refuted"), ("inconclusive", "stale")):
        base["hypothesis_summary"][key] = _count(
            conn, "SELECT COUNT(*) FROM attack_threads WHERE hunt_session_id=? AND evaluation_status=?", (sid, status)
        )
    for status in ("proposed", "running"):
        base["experiment_summary"][status] = _count(
            conn, "SELECT COUNT(*) FROM experiments WHERE hunt_session_id=? AND status=?", (sid, status)
        )
    base["experiment_summary"]["inconclusive_streak"] = _max_inconclusive_streak(conn, sid)
    snapshots = []
    try:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(experiments)").fetchall()}
        order = "finished_at ASC, id ASC" if "finished_at" in columns else "id ASC"
        rows = conn.execute(
            f"SELECT unknown_items_before_json,unknown_items_after_json FROM experiments WHERE hunt_session_id=? AND status IN ('observed','blocked') ORDER BY {order}",  # noqa: S608 -- ORDER BY 取自 schema 列存在性判断，值走参数绑定
            (sid,),
        ).fetchall()
        for row in rows:
            before = json.loads(row[0] or "[]")
            after = json.loads(row[1] or "[]")
            if isinstance(before, list) and isinstance(after, list):
                snapshots.append((set(map(str, before)), set(map(str, after))))
    except (sqlite3.Error, json.JSONDecodeError):
        pass
    if snapshots:
        before = snapshots[0][0]
        after = snapshots[-1][1]
        base["unknown_delta"] = {"before": len(before), "after": len(after), "delta": len(after) - len(before)}
    else:
        unknown_after = _unknown_count(conn, target_name)
        base["unknown_delta"] = {"before": unknown_after, "after": unknown_after, "delta": 0}
    base["broad_queue_dominance"] = (
        _count(
            conn,
            "SELECT COUNT(*) FROM work_items WHERE target_name=? AND status IN ('queued','claimed','partial') AND lane='asset_triage'",
            (target_name,),
        )
        > 100
    )
    base["critical_unknowns"] = _critical_unknowns(conn, target_name=target_name, session_id=sid)
    base["operator_gates"] = _operator_gates(conn, target_name=target_name)
    try:
        rows = conn.execute(
            "SELECT id,method_class,question FROM experiments WHERE hunt_session_id=? AND method_class IN ('active_low','operator_gated') AND status IN ('proposed','approved','queued') LIMIT 10",
            (sid,),
        ).fetchall()
        base["operator_gates"].extend(
            {
                "id": row[0],
                "kind": "confirm_high_risk",
                "title": f"experiment requires operator gate: {str(row[2] or '')[:140]}",
                "method_class": row[1],
            }
            for row in rows
        )
    except sqlite3.Error:
        pass
    base["new_lane_not_consumed"] = (
        _count(
            conn,
            "SELECT COUNT(*) FROM experiments WHERE hunt_session_id=? AND method_class IN ('offline','passive') AND status='approved' AND work_item_id IS NULL",
            (sid,),
        )
        > 0
    )
    base["repeated_inconclusive_direction"] = _max_inconclusive_streak(conn, sid) >= 3 and base["unknown_delta"]["delta"] >= 0
    base["observation_without_evidence"] = (
        _count(
            conn,
            "SELECT COUNT(*) FROM experiments WHERE hunt_session_id=? AND outcome IN ('supports','refutes') AND (evidence_refs_json='[]' OR evidence_refs_json IS NULL)",
            (sid,),
        )
        > 0
    )
    base["experiment_without_expected_observation"] = (
        _count(
            conn,
            "SELECT COUNT(*) FROM experiments WHERE hunt_session_id=? AND status IN ('proposed','approved','queued','running','observed','blocked') AND COALESCE(TRIM(expected_observation),'')=''",
            (sid,),
        )
        > 0
    )
    try:
        rows = conn.execute(
            "SELECT id,experiment_key,question,method_class,status,attack_thread_id FROM experiments WHERE hunt_session_id=? AND status IN ('proposed','approved','queued') ORDER BY id DESC LIMIT 10",
            (sid,),
        ).fetchall()
        base["next_candidates"] = [
            {
                "experiment_id": r[0],
                "experiment_key": r[1],
                "question": str(r[2])[:300],
                "method_class": r[3],
                "status": r[4],
                "attack_thread_id": r[5],
            }
            for r in rows
            if r[3] in {"offline", "passive"}
        ]
    except sqlite3.Error:
        base["next_candidates"] = []
    if base["experiment_summary"]["inconclusive_streak"] >= 3 and base["unknown_delta"]["delta"] >= 0:
        base["pivot_recommended"] = True
        base["pivot_reason"] = "three consecutive inconclusive experiments without a measurable unknown reduction"
    return base


def _critical_unknowns(conn: sqlite3.Connection, *, target_name: str, session_id: int) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    try:
        rows = conn.execute(
            "SELECT category,item_key,status,summary FROM coverage_ledger WHERE target_name=? AND status IN ('unknown','blocked') ORDER BY CASE status WHEN 'blocked' THEN 0 ELSE 1 END,id LIMIT 20",
            (target_name,),
        ).fetchall()
        result.extend({"key": f"coverage:{row[0]}|{row[1]}", "status": row[2], "summary": str(row[3] or "")[:200]} for row in rows)
    except sqlite3.Error:
        pass
    try:
        rows = conn.execute(
            "SELECT roles_json,flows_json,trust_boundaries_json FROM attack_surface_profiles WHERE target_name=? AND status IN ('draft','active') LIMIT 5",
            (target_name,),
        ).fetchall()
        for row in rows:
            for raw in row:
                try:
                    items = json.loads(raw or "[]")
                except json.JSONDecodeError:
                    items = []
                for item in items if isinstance(items, list) else []:
                    if isinstance(item, dict):
                        for unknown in item.get("unknowns") or []:
                            result.append(
                                {
                                    "key": f"profile:{str(unknown)[:120]}",
                                    "status": "unknown",
                                    "summary": "profile unknown requires a falsifiable experiment",
                                }
                            )
    except sqlite3.Error:
        pass
    return result[:20]


def _operator_gates(conn: sqlite3.Connection, *, target_name: str) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    try:
        rows = conn.execute(
            "SELECT id,kind,title,related_work_item_id FROM operator_inbox WHERE target_name=? AND status='open' ORDER BY id LIMIT 20",
            (target_name,),
        ).fetchall()
        result.extend({"id": row[0], "kind": row[1], "title": str(row[2] or "")[:200], "work_item_id": row[3]} for row in rows)
    except sqlite3.Error:
        pass
    return result


def _unknown_count(conn, target_name):
    return _count(
        conn,
        "SELECT COUNT(*) FROM endpoint_observations WHERE target_name=? AND auth_state IN ('unknown','ok_unknown')",
        (target_name,),
    ) + _count(conn, "SELECT COUNT(*) FROM coverage_ledger WHERE target_name=? AND status='unknown'", (target_name,))


def _max_inconclusive_streak(conn, session_id: int) -> int:
    try:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(experiments)").fetchall()}
        order = "finished_at ASC, id ASC" if "finished_at" in columns else "id ASC"
        rows = conn.execute(
            f"SELECT attack_thread_id,outcome FROM experiments WHERE hunt_session_id=? ORDER BY {order}",  # noqa: S608 -- ORDER BY 取自 schema 列存在性判断，值走参数绑定
            (session_id,),
        ).fetchall()
    except sqlite3.Error:
        return 0
    streaks: dict[int, int] = {}
    maximum = 0
    for row in rows:
        thread = row[0]
        streaks[thread] = streaks.get(thread, 0) + 1 if row[1] == "inconclusive" else 0
        maximum = max(maximum, streaks[thread])
    return maximum


def _compact_session(row):
    if not row:
        return None
    return {
        k: row.get(k)
        for k in (
            "id",
            "target_name",
            "soft_target_id",
            "focus_subject_table",
            "focus_subject_id",
            "goal",
            "status",
            "selected_by",
        )
    }
