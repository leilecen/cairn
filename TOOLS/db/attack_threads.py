"""Sprint attack thread helpers."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from db.cognitive_contract import require_falsifiable


def _row_to_dict(cursor: sqlite3.Cursor, row: sqlite3.Row | tuple[Any, ...]) -> dict[str, Any]:
    if isinstance(row, sqlite3.Row):
        return dict(row)
    return {column[0]: row[index] for index, column in enumerate(cursor.description or [])}


def _commit_if_requested(conn: sqlite3.Connection, commit: bool) -> None:
    if commit:
        conn.commit()


def _fetch_thread(conn: sqlite3.Connection, attack_thread_id: int) -> dict[str, Any]:
    cur = conn.execute(
        "SELECT * FROM attack_threads WHERE id = ?",
        (attack_thread_id,),
    )
    row = cur.fetchone()
    if row is None:
        raise ValueError(f"attack_thread not found: {attack_thread_id}")
    return _row_to_dict(cur, row)


def create_attack_thread(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    asset_url: str | None,
    hypothesis: str,
    why_promising: str = "",
    priority: int = 50,
    owner: str = "",
    sprint_id: str | None = None,
    hunt_session_id: int | None = None,
    expected_observation: str = "",
    refuting_observation: str = "",
    alternative_explanations: list[Any] | None = None,
    information_gain: int = 0,
    stop_conditions: list[Any] | None = None,
    commit: bool = True,
) -> int:
    if hunt_session_id is not None:
        require_falsifiable(
            question=hypothesis,
            expected_observation=expected_observation,
            refuting_observation=refuting_observation,
            alternatives=alternative_explanations,
        )
        if not refuting_observation.strip():
            raise ValueError("cognitive attack thread requires refuting_observation")
        if not stop_conditions:
            raise ValueError("cognitive attack thread requires stop_conditions")
    cur = conn.execute(
        """
        INSERT INTO attack_threads (
            target_name, asset_url, hypothesis, why_promising, priority, owner, sprint_id,
            hunt_session_id, expected_observation, refuting_observation,
            alternative_explanations_json, information_gain, stop_conditions_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            target_name,
            asset_url,
            hypothesis,
            why_promising,
            priority,
            owner,
            sprint_id,
            hunt_session_id,
            expected_observation,
            refuting_observation,
            json.dumps(alternative_explanations or [], ensure_ascii=False),
            information_gain,
            json.dumps(stop_conditions or [], ensure_ascii=False),
        ),
    )
    thread_id = int(cur.lastrowid or 0)
    record_attack_thread_event(
        conn,
        attack_thread_id=thread_id,
        actor=owner or "main",
        event_type="created",
        payload={"hypothesis": hypothesis, "why_promising": why_promising},
        commit=False,
    )
    _commit_if_requested(conn, commit)
    return thread_id


def record_attack_thread_event(
    conn: sqlite3.Connection,
    *,
    attack_thread_id: int,
    actor: str,
    event_type: str,
    payload: dict[str, Any],
    severity: str = "info",
    commit: bool = True,
) -> int:
    _fetch_thread(conn, attack_thread_id)
    cur = conn.execute(
        """
        INSERT INTO attack_thread_events (
            attack_thread_id, actor, event_type, severity, payload_json
        ) VALUES (?, ?, ?, ?, ?)
        """,
        (
            attack_thread_id,
            actor,
            event_type,
            severity,
            json.dumps(payload, ensure_ascii=False, sort_keys=True),
        ),
    )
    conn.execute(
        """
        UPDATE attack_threads
        SET updated_at = datetime('now','localtime'),
            last_partial_at = CASE
                WHEN ? IN ('partial','candidate') THEN datetime('now','localtime')
                ELSE last_partial_at
            END
        WHERE id = ?
        """,
        (event_type, attack_thread_id),
    )
    _commit_if_requested(conn, commit)
    return int(cur.lastrowid or 0)


def update_attack_thread(
    conn: sqlite3.Connection,
    *,
    attack_thread_id: int,
    status: str | None = None,
    current_evidence: str | None = None,
    next_probe: str | None = None,
    confidence: str | None = None,
    priority: int | None = None,
    kill_condition: str | None = None,
    commit: bool = True,
) -> dict[str, Any]:
    _fetch_thread(conn, attack_thread_id)
    fields: list[str] = []
    params: list[Any] = []
    updates = {
        "status": status,
        "current_evidence": current_evidence,
        "next_probe": next_probe,
        "confidence": confidence,
        "priority": priority,
        "kill_condition": kill_condition,
    }
    for name, value in updates.items():
        if value is not None:
            fields.append(f"{name} = ?")
            params.append(value)
    if fields:
        fields.append("updated_at = datetime('now','localtime')")
        conn.execute(
            f"UPDATE attack_threads SET {', '.join(fields)} WHERE id = ?",  # noqa: S608
            (*params, attack_thread_id),
        )
        _commit_if_requested(conn, commit)
    return _fetch_thread(conn, attack_thread_id)


def list_attack_threads(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    statuses: list[str] | None = None,
    limit: int = 10,
) -> list[dict[str, Any]]:
    sql = "SELECT * FROM attack_threads WHERE target_name = ?"
    params: list[Any] = [target_name]
    if statuses:
        placeholders = ", ".join("?" for _ in statuses)
        sql += f" AND status IN ({placeholders})"
        params.extend(statuses)
    sql += " ORDER BY priority DESC, updated_at DESC, id DESC LIMIT ?"
    params.append(limit)
    cur = conn.execute(sql, params)
    return [_row_to_dict(cur, row) for row in cur.fetchall()]
