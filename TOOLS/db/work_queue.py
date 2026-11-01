"""Blackboard work queue helpers."""
# ruff: noqa: S608

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

_TOOLS_DIR = Path(__file__).resolve().parent.parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

from db.db_utils import connect, find_db  # noqa: E402
from db.worker_result import compact_public_payload, compact_public_text, normalize_worker_result  # noqa: E402

TERMINAL_STATUSES = {"blocked", "done", "failed", "cancelled"}
VALID_BLOCKER_CLASSES = {
    "auth_barrier",
    "network",
    "scope",
    "evidence",
    "critical_found",
    "refuted",
    "parked",
    "other",
}


def _now_local(now: datetime | None = None) -> datetime:
    if now is not None:
        return now
    return datetime.now().replace(microsecond=0)


def _fmt_dt(value: datetime | None = None) -> str:
    return _now_local(value).strftime("%Y-%m-%d %H:%M:%S")


def _row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row is not None else None


def _fetch_work_item(conn: sqlite3.Connection, work_item_id: int) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM work_items WHERE id = ?", (work_item_id,)).fetchone()
    if row is None:
        raise ValueError(f"work_item not found: {work_item_id}")
    return row


def _ensure_agent_owns_or_item_is_available(row: sqlite3.Row, agent_id: str) -> None:
    claimed_by = row["claimed_by"]
    if claimed_by != agent_id:
        if claimed_by:
            raise ValueError(f"work_item {row['id']} is owned by {claimed_by}")
        raise ValueError(f"work_item {row['id']} is not claimed by {agent_id}")


def _lease_expr(lease_minutes: int | None = None) -> str:
    if lease_minutes is None:
        return "datetime(?, '+' || heartbeat_minutes || ' minutes')"
    return "datetime(?, '+' || ? || ' minutes')"


def _lease_params(timestamp: str, lease_minutes: int | None = None) -> list[Any]:
    if lease_minutes is None:
        return [timestamp]
    return [timestamp, lease_minutes]


def _write_event(
    conn: sqlite3.Connection,
    *,
    work_item_id: int,
    agent_id: str,
    event_type: str,
    payload: dict[str, Any] | None,
    severity: str = "info",
    now: datetime | None = None,
) -> None:
    conn.execute(
        """
        INSERT INTO agent_events (work_item_id, agent_id, event_type, severity, payload_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            work_item_id,
            agent_id,
            event_type,
            severity,
            json.dumps(payload or {}, ensure_ascii=False, sort_keys=True),
            _fmt_dt(now),
        ),
    )


def _sync_logic_probe_result_if_applicable(
    conn: sqlite3.Connection,
    *,
    work_item: sqlite3.Row,
    worker_result: dict[str, Any],
) -> None:
    if work_item["lane"] != "logic_probe" or not str(work_item["subtype"] or "").startswith("generic_probe:"):
        return
    from db.generic_probe import sync_logic_probe_result  # noqa: PLC0415

    sync_logic_probe_result(conn, work_item=work_item, worker_result=worker_result)


def _sync_vuln_review_result_if_applicable(
    conn: sqlite3.Connection,
    *,
    work_item: sqlite3.Row,
    worker_result: dict[str, Any],
) -> None:
    if work_item["lane"] != "vuln_review" or work_item["subtype"] != "single_sp_review":
        return
    from db.vuln_review_sync import sync_vuln_review_result  # noqa: PLC0415

    sync_vuln_review_result(conn, work_item=work_item, worker_result=worker_result)


def _sync_hypothesis_result_if_applicable(
    conn: sqlite3.Connection,
    *,
    work_item: sqlite3.Row,
    worker_result: dict[str, Any],
) -> None:
    if work_item["lane"] != "hypothesis":
        return
    from db.hypothesis_sync import sync_hypothesis_result  # noqa: PLC0415

    sync_hypothesis_result(conn, work_item=work_item, worker_result=worker_result)


def _sync_experiment_result_if_applicable(conn: sqlite3.Connection, *, work_item: sqlite3.Row, worker_result: dict[str, Any]) -> None:
    """Idempotently attach cognitive worker observations to one experiment."""
    if not str(work_item["subtype"] or "").startswith("experiment:"):
        return
    try:
        from db.experiments import observe_experiment

        experiment_id = int(str(work_item["subtype"]).split(":", 1)[1])
        outcome = worker_result.get("outcome", "not_run")
        observe_experiment(
            conn,
            experiment_id,
            outcome=outcome,
            observation_summary=worker_result.get("observation_summary") or worker_result.get("summary", ""),
            evidence_refs=worker_result.get("evidence_refs", []),
            alternative_explanation=worker_result.get("alternative_explanation", ""),
            confidence_after=worker_result.get("confidence", "unknown"),
            commit=False,
        )
        conn.execute("UPDATE experiments SET work_item_id=COALESCE(work_item_id, ?) WHERE id=?", (work_item["id"], experiment_id))
        thread_id = work_item["attack_thread_id"]
        if thread_id:
            mapped = {
                "supports": "supported",
                "refutes": "refuted",
                "inconclusive": "inconclusive",
                "blocked": "blocked",
            }.get(outcome)
            if mapped:
                evidence = json.dumps(
                    {
                        "outcome": outcome,
                        "summary": worker_result.get("summary", "")[:800],
                        "evidence_refs": worker_result.get("evidence_refs", [])[:20],
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                )
                conn.execute(
                    """
                    UPDATE attack_threads
                    SET evaluation_status=?,
                        last_evaluated_at=datetime('now','localtime'),
                        current_evidence=?,
                        confidence=CASE
                            WHEN ?='high' THEN 'high'
                            WHEN ?='medium' THEN 'medium'
                            ELSE confidence
                        END,
                        updated_at=datetime('now','localtime')
                    WHERE id=?
                    """,
                    (mapped, evidence, worker_result.get("confidence"), worker_result.get("confidence"), thread_id),
                )
    except (sqlite3.Error, ValueError):
        # Legacy queues and pre-migration DBs remain usable.
        return


def _normalize_worker_result_for_item(
    *,
    work_item: sqlite3.Row,
    payload: dict[str, Any],
    expected_status: str,
) -> dict[str, Any]:
    if work_item["lane"] == "hypothesis":
        from db.hypothesis_sync import normalize_hypothesis_worker_result  # noqa: PLC0415

        return normalize_hypothesis_worker_result(payload, expected_status=expected_status)
    if work_item["lane"] == "logic_probe" and str(work_item["subtype"] or "").startswith("generic_probe:"):
        from db.generic_probe import normalize_probe_worker_result  # noqa: PLC0415

        return normalize_probe_worker_result(payload, expected_status=expected_status)
    if work_item["lane"] == "vuln_review" and work_item["subtype"] == "single_sp_review":
        from db.vuln_review_sync import normalize_vuln_review_worker_result  # noqa: PLC0415

        return normalize_vuln_review_worker_result(payload, expected_status=expected_status)
    return normalize_worker_result(payload, expected_status=expected_status)


def _clear_claim_fields() -> str:
    return """
        claimed_by = NULL,
        claimed_at = NULL,
        lease_until = NULL,
        heartbeat_at = NULL
    """


def create_work_item(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    lane: str,
    subject_table: str,
    subject_id: str,
    subtype: str | None = None,
    attack_thread_id: int | None = None,
    title: str = "",
    objective: str = "",
    priority: int = 50,
    model_tier: str = "sonnet",
    reasoning_tier: str = "low",
    auth_requirement: str = "unknown",
    risk_class: str = "safe_passive",
    timebox_minutes: int = 10,
    heartbeat_minutes: int = 5,
    system_id: int | None = None,
    commit: bool = True,
) -> int:
    has_system_id = any(row[1] == "system_id" for row in conn.execute("PRAGMA table_info(work_items)"))
    if has_system_id:
        cur = conn.execute(
            """
        INSERT INTO work_items (
            target_name, lane, subtype, subject_table, subject_id, attack_thread_id, title, objective, priority,
            model_tier, reasoning_tier, auth_requirement, risk_class, timebox_minutes, heartbeat_minutes, system_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                target_name,
                lane,
                subtype,
                subject_table,
                subject_id,
                attack_thread_id,
                title,
                objective,
                priority,
                model_tier,
                reasoning_tier,
                auth_requirement,
                risk_class,
                timebox_minutes,
                heartbeat_minutes,
                system_id,
            ),
        )
    else:
        cur = conn.execute(
            """
        INSERT INTO work_items (
            target_name, lane, subtype, subject_table, subject_id, attack_thread_id, title, objective, priority,
            model_tier, reasoning_tier, auth_requirement, risk_class, timebox_minutes, heartbeat_minutes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                target_name,
                lane,
                subtype,
                subject_table,
                subject_id,
                attack_thread_id,
                title,
                objective,
                priority,
                model_tier,
                reasoning_tier,
                auth_requirement,
                risk_class,
                timebox_minutes,
                heartbeat_minutes,
            ),
        )
    if commit:
        conn.commit()
    return int(cur.lastrowid or 0)


def claim_next(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    agent_id: str,
    lanes: list[str] | None = None,
    limit: int = 1,
    lease_minutes: int | None = None,
) -> list[dict[str, Any]]:
    now = _now_local()
    claimed_at = _fmt_dt(now)

    conditions = [
        "target_name = ?",
        "status IN ('queued', 'partial')",
        "COALESCE(dispatch_state, 'active') = 'active'",
        "claimed_by IS NULL",
        "attempt_count < max_attempts",
    ]
    params: list[Any] = [target_name]

    if lanes:
        placeholders = ", ".join("?" for _ in lanes)
        conditions.append(f"lane IN ({placeholders})")
        params.extend(lanes)

    where_clause = " AND ".join(conditions)
    lease_expr = _lease_expr(lease_minutes)

    conn.execute("BEGIN IMMEDIATE")
    try:
        candidate_rows = conn.execute(
            f"""
            SELECT *
            FROM work_items
            WHERE {where_clause}
            ORDER BY CASE status WHEN 'queued' THEN 0 ELSE 1 END,
                     priority DESC,
                     created_at ASC,
                     id ASC
            LIMIT ?
            """,
            (*params, limit),
        ).fetchall()

        claimed_ids: list[int] = []
        for row in candidate_rows:
            row_params: list[Any] = [agent_id, claimed_at]
            row_params.extend(_lease_params(claimed_at, lease_minutes))
            row_params.extend([claimed_at, row["id"]])
            updated = conn.execute(
                f"""
                UPDATE work_items
                SET status='claimed',
                    claimed_by=?,
                    claimed_at=?,
                    lease_until={lease_expr},
                    heartbeat_at=NULL,
                    attempt_count=attempt_count+1,
                    updated_at=?
                WHERE id=?
                  AND status IN ('queued', 'partial')
                  AND COALESCE(dispatch_state, 'active') = 'active'
                  AND claimed_by IS NULL
                  AND attempt_count < max_attempts
                """,
                row_params,
            )
            if updated.rowcount:
                claimed_ids.append(row["id"])

        conn.commit()
    except Exception:
        conn.rollback()
        raise

    if not claimed_ids:
        return []

    placeholders = ", ".join("?" for _ in claimed_ids)
    rows = conn.execute(
        f"""
        SELECT *
        FROM work_items
        WHERE id IN ({placeholders})
        """,
        claimed_ids,
    ).fetchall()
    row_map = {row["id"]: dict(row) for row in rows}
    return [row_map[row_id] for row_id in claimed_ids]


def claim_by_id(
    conn: sqlite3.Connection,
    *,
    work_item_id: int,
    agent_id: str,
    target_name: str | None = None,
    lease_minutes: int | None = None,
) -> dict[str, Any] | None:
    now = _now_local()
    claimed_at = _fmt_dt(now)
    lease_expr = _lease_expr(lease_minutes)
    conditions = [
        "id = ?",
        "status IN ('queued', 'partial')",
        "COALESCE(dispatch_state, 'active') = 'active'",
        "claimed_by IS NULL",
        "attempt_count < max_attempts",
    ]
    params: list[Any] = [work_item_id]
    if target_name is not None:
        conditions.append("target_name = ?")
        params.append(target_name)

    conn.execute("BEGIN IMMEDIATE")
    try:
        row_params: list[Any] = [agent_id, claimed_at]
        row_params.extend(_lease_params(claimed_at, lease_minutes))
        row_params.extend([claimed_at, *params])
        updated = conn.execute(
            f"""
            UPDATE work_items
            SET status='claimed',
                claimed_by=?,
                claimed_at=?,
                lease_until={lease_expr},
                heartbeat_at=NULL,
                attempt_count=attempt_count+1,
                updated_at=?
            WHERE {" AND ".join(conditions)}
            """,
            row_params,
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise

    if not updated.rowcount:
        return None
    return _row_to_dict(_fetch_work_item(conn, work_item_id))


def heartbeat(
    conn: sqlite3.Connection,
    *,
    work_item_id: int,
    agent_id: str,
    payload: dict[str, Any] | None = None,
) -> None:
    now = _now_local()
    row = _fetch_work_item(conn, work_item_id)
    _ensure_agent_owns_or_item_is_available(row, agent_id)
    timestamp = _fmt_dt(now)
    lease_expr = _lease_expr()
    conn.execute(
        f"""
        UPDATE work_items
        SET heartbeat_at = ?,
            lease_until = {lease_expr},
            updated_at = ?
        WHERE id = ?
        """,
        (timestamp, *_lease_params(timestamp), timestamp, work_item_id),
    )
    _write_event(conn, work_item_id=work_item_id, agent_id=agent_id, event_type="heartbeat", payload=payload, now=now)
    conn.commit()


def partial_result(
    conn: sqlite3.Connection,
    *,
    work_item_id: int,
    agent_id: str,
    payload: dict[str, Any],
) -> None:
    now = _now_local()
    row = _fetch_work_item(conn, work_item_id)
    _ensure_agent_owns_or_item_is_available(row, agent_id)
    worker_result = _normalize_worker_result_for_item(
        work_item=row,
        payload=payload,
        expected_status="partial",
    )
    summary = worker_result.get("summary", "")
    timestamp = _fmt_dt(now)
    lease_expr = _lease_expr()
    conn.execute(
        f"""
        UPDATE work_items
        SET status = 'partial',
            summary = COALESCE(?, summary),
            heartbeat_at = ?,
            lease_until = {lease_expr},
            updated_at = ?
        WHERE id = ?
        """,
        (summary or None, timestamp, *_lease_params(timestamp), timestamp, work_item_id),
    )
    _write_event(
        conn,
        work_item_id=work_item_id,
        agent_id=agent_id,
        event_type="partial_result",
        payload={"worker_result": worker_result},
        now=now,
    )
    _sync_logic_probe_result_if_applicable(conn, work_item=row, worker_result=worker_result)
    _sync_vuln_review_result_if_applicable(conn, work_item=row, worker_result=worker_result)
    _sync_hypothesis_result_if_applicable(conn, work_item=row, worker_result=worker_result)
    _sync_experiment_result_if_applicable(conn, work_item=row, worker_result=worker_result)
    conn.commit()


def complete_work_item(
    conn: sqlite3.Connection,
    *,
    work_item_id: int,
    agent_id: str,
    summary: str,
    next_action: str = "",
    result_payload: dict[str, Any] | None = None,
) -> None:
    now = _now_local()
    row = _fetch_work_item(conn, work_item_id)
    _ensure_agent_owns_or_item_is_available(row, agent_id)
    payload = {"status": "done", "summary": summary, "next_action": next_action}
    if result_payload:
        payload.update(result_payload)
    worker_result = _normalize_worker_result_for_item(
        work_item=row,
        payload=payload,
        expected_status="done",
    )
    summary = worker_result["summary"]
    next_action = worker_result["next_action"]
    timestamp = _fmt_dt(now)
    try:
        conn.execute(
            f"""
        UPDATE work_items
        SET status = 'done',
            summary = ?,
            next_action = ?,
            updated_at = ?,
            {_clear_claim_fields()}
        WHERE id = ?
        """,
            (summary, next_action, timestamp, work_item_id),
        )
        _write_event(
            conn,
            work_item_id=work_item_id,
            agent_id=agent_id,
            event_type="done",
            payload={"worker_result": worker_result},
            now=now,
        )
        _sync_logic_probe_result_if_applicable(conn, work_item=row, worker_result=worker_result)
        _sync_vuln_review_result_if_applicable(conn, work_item=row, worker_result=worker_result)
        _sync_hypothesis_result_if_applicable(conn, work_item=row, worker_result=worker_result)
        _sync_experiment_result_if_applicable(conn, work_item=row, worker_result=worker_result)
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def fail_work_item(
    conn: sqlite3.Connection,
    *,
    work_item_id: int,
    agent_id: str,
    error: str,
    severity: str = "warning",
) -> None:
    now = _now_local()
    row = _fetch_work_item(conn, work_item_id)
    _ensure_agent_owns_or_item_is_available(row, agent_id)
    timestamp = _fmt_dt(now)
    conn.execute(
        f"""
        UPDATE work_items
        SET status = 'failed',
            last_error = ?,
            updated_at = ?,
            {_clear_claim_fields()}
        WHERE id = ?
        """,
        (error, timestamp, work_item_id),
    )
    _write_event(
        conn,
        work_item_id=work_item_id,
        agent_id=agent_id,
        event_type="failed",
        payload={"error": error},
        severity=severity,
        now=now,
    )
    conn.commit()


def block_work_item(
    conn: sqlite3.Connection,
    *,
    work_item_id: int,
    agent_id: str,
    reason: str,
    blocker_class: str | None = None,
    operator_payload: dict[str, Any] | None = None,
    result_payload: dict[str, Any] | None = None,
) -> None:
    blocker_class = str(blocker_class or "").strip().lower()
    if not blocker_class:
        raise ValueError("blocker_class is required for a blocked settlement")
    if blocker_class not in VALID_BLOCKER_CLASSES:
        raise ValueError(f"invalid blocker_class: {blocker_class}")
    now = _now_local()
    row = _fetch_work_item(conn, work_item_id)
    _ensure_agent_owns_or_item_is_available(row, agent_id)
    payload = {"status": "blocked", "reason": reason}
    if result_payload:
        payload.update(result_payload)
    worker_result = _normalize_worker_result_for_item(
        work_item=row,
        payload=payload,
        expected_status="blocked",
    )
    reason = worker_result["block_reason"] or worker_result["blocker"] or worker_result["summary"]
    timestamp = _fmt_dt(now)
    try:
        conn.execute(
            f"""
        UPDATE work_items
        SET status = 'blocked',
            blocker_reason = ?,
            blocker_class = ?,
            updated_at = ?,
            {_clear_claim_fields()}
        WHERE id = ?
        """,
            (reason, blocker_class, timestamp, work_item_id),
        )
        _write_event(
            conn,
            work_item_id=work_item_id,
            agent_id=agent_id,
            event_type="blocker",
            payload={"worker_result": worker_result, "operator_payload": operator_payload or {}},
            severity="warning",
            now=now,
        )
        _sync_logic_probe_result_if_applicable(conn, work_item=row, worker_result=worker_result)
        _sync_vuln_review_result_if_applicable(conn, work_item=row, worker_result=worker_result)
        _sync_hypothesis_result_if_applicable(conn, work_item=row, worker_result=worker_result)
        _sync_experiment_result_if_applicable(conn, work_item=row, worker_result=worker_result)
        if operator_payload:
            payload = dict(operator_payload)
            kind = payload.pop("kind")
            title = payload.pop("title")
            if any(item[1] == "action_key" for item in conn.execute("PRAGMA table_info(operator_inbox)")):
                _insert_action_card_without_commit(
                    conn,
                    target_name=row["target_name"],
                    system_id=row["system_id"] if "system_id" in row.keys() else None,
                    kind=kind,
                    action_key=str(payload.pop("action_key", f"work-{work_item_id}-{kind}")),
                    action_label=title,
                    why_needed=payload.get("why_needed") or payload.get("detail") or reason,
                    steps=_as_step_list(payload.pop("steps", [payload.get("suggested_action") or "让主 session 指定可操作步骤"])),
                    expected_observation=payload.pop("expected_observation", "返回紧凑观察结果"),
                    report_back_format=payload.pop("report_back_format", "回复：行动卡完成；结果=..."),
                    url=payload.get("url"),
                    related_work_item_id=work_item_id,
                    burp_action_id=_as_optional_int(payload.get("burp_action_id")),
                    blocking=bool(payload.pop("blocking", True)),
                )
            else:
                conn.execute(
                    """
            INSERT INTO operator_inbox (
                target_name,
                related_work_item_id,
                kind,
                title,
                detail,
                suggested_action,
                url,
                burp_action_id,
                evidence_ref_id,
                status,
                created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?)
            """,
                    (
                        row["target_name"],
                        work_item_id,
                        kind,
                        title,
                        payload.get("detail"),
                        payload.get("suggested_action"),
                        payload.get("url"),
                        payload.get("burp_action_id"),
                        payload.get("evidence_ref_id"),
                        timestamp,
                    ),
                )
        settle_blocked_work_item(
            conn,
            work_item_id=work_item_id,
            blocker_class=blocker_class,
            block_reason=reason,
            actor=agent_id,
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def settle_blocked_work_item(
    conn: sqlite3.Connection,
    *,
    work_item_id: int,
    blocker_class: str,
    block_reason: str,
    actor: str,
) -> int:
    """Idempotently park one attack thread and create its decision card."""

    row = _fetch_work_item(conn, work_item_id)
    thread_id = row["attack_thread_id"]
    if thread_id is not None:
        thread = conn.execute("SELECT target_name FROM attack_threads WHERE id=?", (thread_id,)).fetchone()
        if thread is None or thread["target_name"] != row["target_name"]:
            raise ValueError("work_item attack_thread target mismatch")
    else:
        cur = conn.execute(
            """
            INSERT INTO attack_threads(
                target_name, asset_url, hypothesis, why_promising, owner, status,
                evaluation_status, last_evaluated_at
            ) VALUES (?, NULL, ?, '', 'main', 'parked', 'blocked', datetime('now','localtime'))
            """,
            (row["target_name"], compact_public_text(block_reason, max_chars=500) or "blocked work item"),
        )
        thread_id = int(cur.lastrowid or 0)
        conn.execute("UPDATE work_items SET attack_thread_id=? WHERE id=?", (thread_id, work_item_id))
        conn.execute(
            "INSERT INTO attack_thread_events(attack_thread_id,actor,event_type,payload_json) VALUES (?,?,'created',?)",
            (thread_id, actor, json.dumps({"source_work_item_id": work_item_id}, sort_keys=True)),
        )

    refuting = compact_public_text(block_reason, max_chars=500) if blocker_class == "refuted" else None
    conn.execute(
        """
        UPDATE attack_threads
        SET status='parked', evaluation_status='blocked',
            last_evaluated_at=datetime('now','localtime'),
            refuting_observation=CASE WHEN ? IS NULL THEN refuting_observation ELSE ? END,
            updated_at=datetime('now','localtime')
        WHERE id=?
        """,
        (refuting, refuting, thread_id),
    )
    event_exists = conn.execute(
        """
        SELECT 1 FROM attack_thread_events
        WHERE attack_thread_id=? AND event_type='parked'
          AND json_extract(payload_json, '$.work_item_id')=?
        LIMIT 1
        """,
        (thread_id, work_item_id),
    ).fetchone()
    if event_exists is None:
        event_payload = compact_public_payload(
            {"blocker_class": blocker_class, "block_reason": block_reason, "work_item_id": work_item_id},
            max_chars=500,
        )
        conn.execute(
            """
            INSERT INTO attack_thread_events(attack_thread_id,actor,event_type,severity,payload_json)
            VALUES (?,?,'parked','warning',?)
            """,
            (thread_id, actor, json.dumps(event_payload, ensure_ascii=False, sort_keys=True)),
        )

    _insert_action_card_without_commit(
        conn,
        target_name=row["target_name"],
        system_id=row["system_id"] if "system_id" in row.keys() else None,
        kind="blocked_decision",
        action_key=f"blocked-work-{work_item_id}",
        action_label=f"Decide blocked work item {work_item_id}",
        why_needed=block_reason or blocker_class,
        steps=[_blocker_step(blocker_class)],
        expected_observation="Return the operator decision and any new evidence reference.",
        report_back_format="decision=<resume|park|refute>; evidence_ref=<id|none>; note=<compact reason>",
        url=_work_item_url(conn, row),
        related_work_item_id=work_item_id,
        blocking=True,
    )
    return int(thread_id)


def _as_optional_int(value: Any) -> int | None:
    """action card 的 burp_action_id 允许调用方传字符串形式的 id。"""
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _as_step_list(value: Any) -> list[str]:
    """action card 的 steps 允许调用方传单个字符串，统一收敛成 list[str]。"""
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value]
    return [str(value)] if value is not None else []


def _insert_action_card_without_commit(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    system_id: int | None,
    kind: str,
    action_key: str,
    action_label: str,
    why_needed: str,
    steps: list[str],
    expected_observation: str,
    report_back_format: str,
    url: str | None = None,
    related_work_item_id: int | None = None,
    burp_action_id: int | None = None,
    blocking: bool = True,
    **_: Any,
) -> None:
    existing = conn.execute(
        "SELECT 1 FROM operator_inbox WHERE target_name=? AND action_key=? AND status='open' LIMIT 1",
        (target_name, action_key),
    ).fetchone()
    if existing is not None:
        return
    conn.execute(
        """
        INSERT INTO operator_inbox(
            target_name,related_work_item_id,kind,title,detail,suggested_action,url,
            burp_action_id,status,system_id,action_key,action_label,why_needed,steps_json,
            expected_observation,report_back_format,blocking
        ) VALUES (?,?,?,?,?,?,?,?, 'open',?,?,?,?,?,?,?,?)
        """,
        (
            target_name,
            related_work_item_id,
            kind,
            action_label,
            why_needed,
            report_back_format,
            url,
            burp_action_id,
            system_id,
            action_key,
            action_label,
            compact_public_text(why_needed, max_chars=500),
            json.dumps([compact_public_text(step, max_chars=300) for step in steps], ensure_ascii=False),
            compact_public_text(expected_observation, max_chars=500),
            compact_public_text(report_back_format, max_chars=500),
            int(blocking),
        ),
    )


def _blocker_step(blocker_class: str) -> str:
    return {
        "auth_barrier": "Prepare the explicitly authorized account or session, then decide whether to resume.",
        "network": "Confirm the approved network or proxy path before retrying.",
        "scope": "Confirm that the exact asset and action are in scope.",
        "evidence": "Collect the missing evidence reference before review resumes.",
        "critical_found": "Review the high-risk signal and explicitly authorize any next validation.",
        "refuted": "Review the refuting observation; keep the thread parked unless new evidence appears.",
        "parked": "Keep the direction parked and preserve its evidence.",
        "other": "Classify the blocker manually; do not infer or auto-resume.",
    }[blocker_class]


def _work_item_url(conn: sqlite3.Connection, row: sqlite3.Row) -> str | None:
    if "system_id" not in row.keys() or row["system_id"] is None:
        return None
    system = conn.execute("SELECT canonical_url FROM target_systems WHERE id=?", (row["system_id"],)).fetchone()
    return str(system[0]) if system is not None and system[0] else None


def reclaim_expired(conn: sqlite3.Connection, *, now: datetime | None = None) -> dict[str, int]:
    current = _now_local(now)
    rows = conn.execute(
        """
        SELECT *
        FROM work_items
        WHERE status IN ('claimed', 'partial')
          AND claimed_by IS NOT NULL
          AND attempt_count < max_attempts
        ORDER BY id
        """
    ).fetchall()

    requeued = 0
    partial_released = 0
    for row in rows:
        claimed_at = _parse_dt(row["claimed_at"])
        lease_until = _parse_dt(row["lease_until"])
        heartbeat_at = _parse_dt(row["heartbeat_at"])

        expired_by_lease = lease_until is not None and current >= lease_until
        heartbeat_deadline = None
        if heartbeat_at is not None:
            heartbeat_deadline = heartbeat_at + timedelta(minutes=row["heartbeat_minutes"] * 2)
        elif claimed_at is not None:
            heartbeat_deadline = claimed_at + timedelta(minutes=row["heartbeat_minutes"] * 2)
        expired_by_heartbeat = heartbeat_deadline is not None and current >= heartbeat_deadline
        timebox_deadline = claimed_at + timedelta(minutes=row["timebox_minutes"]) if claimed_at is not None else None
        expired_by_timebox = timebox_deadline is not None and current >= timebox_deadline

        if not (expired_by_lease or expired_by_heartbeat or expired_by_timebox):
            continue

        has_partial = (
            conn.execute(
                """
            SELECT 1
            FROM agent_events
            WHERE work_item_id = ?
              AND event_type = 'partial_result'
            LIMIT 1
            """,
                (row["id"],),
            ).fetchone()
            is not None
        )
        new_status = "partial" if has_partial else "queued"
        conn.execute(
            f"""
            UPDATE work_items
            SET status = ?,
                updated_at = ?,
                {_clear_claim_fields()}
            WHERE id = ?
            """,
            (new_status, _fmt_dt(current), row["id"]),
        )
        if new_status == "partial":
            partial_released += 1
        else:
            requeued += 1

    conn.commit()
    return {"requeued": requeued, "partial_released": partial_released, "total": requeued + partial_released}


def get_active_work_items(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    lanes: list[str] | None = None,
    limit: int = 20,
) -> list[dict[str, Any]]:
    sql = """
        SELECT *
        FROM work_items
        WHERE target_name = ?
          AND status IN ('claimed', 'partial')
          AND claimed_by IS NOT NULL
    """
    params: list[Any] = [target_name]
    if lanes:
        placeholders = ", ".join("?" for _ in lanes)
        sql += f" AND lane IN ({placeholders})"
        params.extend(lanes)
    sql += " ORDER BY CASE status WHEN 'claimed' THEN 0 ELSE 1 END, priority DESC, updated_at DESC, id DESC LIMIT ?"
    params.append(limit)
    rows = conn.execute(sql, params).fetchall()
    return [dict(row) for row in rows]


def get_open_operator_inbox(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    limit: int = 20,
) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT *
        FROM operator_inbox
        WHERE target_name = ?
          AND status = 'open'
        ORDER BY created_at ASC, id ASC
        LIMIT ?
        """,
        (target_name, limit),
    ).fetchall()
    return [dict(row) for row in rows]


def get_recent_agent_events(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    limit: int = 20,
) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT e.*, w.target_name, w.lane, w.subtype
        FROM agent_events e
        JOIN work_items w ON w.id = e.work_item_id
        WHERE w.target_name = ?
        ORDER BY e.created_at DESC, e.id DESC
        LIMIT ?
        """,
        (target_name, limit),
    ).fetchall()
    return [dict(row) for row in rows]


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value)


def _parse_payload(raw: str | None) -> dict[str, Any]:
    if not raw:
        return {}
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("payload must be a JSON object")
    return value


def _resolve_db_path(args: argparse.Namespace) -> Path:
    if getattr(args, "db", None):
        return Path(args.db)
    target = getattr(args, "target", None)
    if not target:
        raise ValueError("--db or --target is required")
    return find_db(target)


def _json_print(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))


def _run_cli(args: argparse.Namespace) -> dict[str, Any]:
    db_path = _resolve_db_path(args)
    conn = connect(db_path)
    try:
        if args.command == "create":
            work_item_id = create_work_item(
                conn,
                target_name=args.target,
                lane=args.lane,
                subtype=args.subtype,
                subject_table=args.subject_table,
                subject_id=args.subject_id,
                attack_thread_id=args.attack_thread_id,
                title=args.title or "",
                objective=args.objective or "",
                priority=args.priority,
                model_tier=args.model_tier,
                reasoning_tier=args.reasoning_tier,
                auth_requirement=args.auth_requirement,
                risk_class=args.risk_class,
                timebox_minutes=args.timebox_minutes,
                heartbeat_minutes=args.heartbeat_minutes,
            )
            return {"ok": True, "work_item_id": work_item_id}

        if args.command == "claim":
            lanes = [item for item in (args.lanes or "").split(",") if item]
            if args.work_item_id is not None:
                item = claim_by_id(
                    conn,
                    work_item_id=args.work_item_id,
                    agent_id=args.agent_id,
                    target_name=args.target,
                )
                if item is None:
                    raise ValueError(f"work_item {args.work_item_id} is not claimable")
                return {"ok": True, "items": [item]}
            return {
                "ok": True,
                "items": claim_next(
                    conn,
                    target_name=args.target,
                    agent_id=args.agent_id,
                    lanes=lanes or None,
                    limit=args.limit,
                ),
            }

        if args.command == "heartbeat":
            heartbeat(conn, work_item_id=args.work_item_id, agent_id=args.agent_id)
            return {"ok": True, "work_item_id": args.work_item_id}

        if args.command == "partial":
            payload = _parse_payload(args.payload)
            payload.setdefault("summary", args.summary)
            payload.setdefault("status", "partial")
            partial_result(conn, work_item_id=args.work_item_id, agent_id=args.agent_id, payload=payload)
            return {"ok": True, "work_item_id": args.work_item_id}

        if args.command == "complete":
            complete_work_item(
                conn,
                work_item_id=args.work_item_id,
                agent_id=args.agent_id,
                summary=args.summary,
                next_action=args.next_action or "",
                result_payload=_parse_payload(args.payload),
            )
            return {"ok": True, "work_item_id": args.work_item_id}

        if args.command == "block":
            operator_payload = None
            if args.operator_kind or args.operator_title:
                if not (args.operator_kind and args.operator_title):
                    raise ValueError("--operator-kind and --operator-title must be provided together")
                operator_payload = {
                    "kind": args.operator_kind,
                    "title": args.operator_title,
                    "detail": args.operator_detail,
                    "url": args.operator_url,
                }
            block_work_item(
                conn,
                work_item_id=args.work_item_id,
                agent_id=args.agent_id,
                reason=args.reason,
                blocker_class=args.blocker_class,
                operator_payload=operator_payload,
                result_payload=_parse_payload(args.payload),
            )
            return {"ok": True, "work_item_id": args.work_item_id}

        raise ValueError(f"unknown command: {args.command}")
    finally:
        conn.close()


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Claim and update blackboard work_items")
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create")
    create.add_argument("--target", required=True)
    create.add_argument("--lane", required=True)
    create.add_argument("--subject-table", required=True)
    create.add_argument("--subject-id", required=True)
    create.add_argument("--subtype")
    create.add_argument("--attack-thread-id", type=int)
    create.add_argument("--title")
    create.add_argument("--objective")
    create.add_argument("--priority", type=int, default=50)
    create.add_argument("--model-tier", default="sonnet")
    create.add_argument("--reasoning-tier", default="low")
    create.add_argument("--auth-requirement", default="unknown")
    create.add_argument("--risk-class", default="safe_passive")
    create.add_argument("--timebox-minutes", type=int, default=10)
    create.add_argument("--heartbeat-minutes", type=int, default=5)
    create.add_argument("--db")

    claim = subparsers.add_parser("claim")
    claim.add_argument("--target", required=True)
    claim.add_argument("--agent-id", required=True)
    claim.add_argument("--lanes")
    claim.add_argument("--work-item-id", type=int)
    claim.add_argument("--limit", type=int, default=1)
    claim.add_argument("--db")

    for name in ("heartbeat", "partial", "complete", "block"):
        sub = subparsers.add_parser(name)
        sub.add_argument("--work-item-id", required=True, type=int)
        sub.add_argument("--agent-id", required=True)
        sub.add_argument("--db")
        sub.add_argument("--target")
        if name == "partial":
            sub.add_argument("--summary", required=True)
            sub.add_argument("--payload")
        elif name == "complete":
            sub.add_argument("--summary", required=True)
            sub.add_argument("--next-action")
            sub.add_argument("--payload")
        elif name == "block":
            sub.add_argument("--reason", required=True)
            sub.add_argument("--blocker-class", required=True, choices=sorted(VALID_BLOCKER_CLASSES))
            sub.add_argument("--payload")
            sub.add_argument("--operator-kind")
            sub.add_argument("--operator-title")
            sub.add_argument("--operator-detail")
            sub.add_argument("--operator-url")

    return parser


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()
    try:
        _json_print(_run_cli(args))
    except Exception as exc:
        _json_print({"ok": False, "error": str(exc)})
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
