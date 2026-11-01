"""DB helpers for Burp action queue and repeater evidence refs."""

from __future__ import annotations

import json
import re
import sqlite3
from datetime import datetime
from typing import Any

AUTO_ALLOWED_RISK_CLASSES = {"safe_replay", "sensitive_read"}


def _table(conn: sqlite3.Connection, name: str) -> bool:
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None


def _now_local(now: datetime | None = None) -> datetime:
    if now is not None:
        return now
    return datetime.now().replace(microsecond=0)


def _fmt_dt(value: datetime | None = None) -> str:
    return _now_local(value).strftime("%Y-%m-%d %H:%M:%S")


def build_repeater_tab_name(
    *,
    target_name: str,
    work_item_id: int,
    variant: str,
    system_display: str | None = None,
    action_name: str | None = None,
) -> str:
    suffix = _normalize_variant(variant)
    if not system_display:
        return f"{target_name}-{work_item_id}-{suffix}"
    system = _safe_tab_part(system_display)
    action = _safe_tab_part(action_name or suffix)
    return f"{system}-{action}-{work_item_id}"


def create_burp_action(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    work_item_id: int,
    action_type: str = "send_to_repeater",
    method: str | None = None,
    url: str | None = None,
    headers_json: str | dict[str, Any] | list[Any] | None = None,
    body: str | None = None,
    note: str | None = None,
    risk_class: str = "safe_replay",
    repeater_tab_name: str | None = None,
    burp_request_ref: str | None = None,
    commit: bool = True,
) -> int:
    serialized_headers = _serialize_json(headers_json)
    cur = conn.execute(
        """
        INSERT INTO burp_actions (
            target_name, work_item_id, action_type, method, url, headers_json, body,
            note, risk_class, repeater_tab_name, burp_request_ref
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            target_name,
            work_item_id,
            action_type,
            method,
            url,
            serialized_headers,
            body,
            note,
            risk_class,
            repeater_tab_name,
            burp_request_ref,
        ),
    )
    if commit:
        conn.commit()
    return int(cur.lastrowid or 0)


def get_queued_burp_actions(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    allow_state_changing: bool = False,
    action_types: list[str] | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    allowed_risks = list(AUTO_ALLOWED_RISK_CLASSES)
    if allow_state_changing:
        allowed_risks.append("state_changing")

    sql = """
        SELECT *
        FROM burp_actions
        WHERE target_name = ?
          AND status = 'queued'
          AND risk_class != 'high_risk'
    """
    params: list[Any] = [target_name]

    placeholders = ", ".join("?" for _ in allowed_risks)
    sql += f" AND risk_class IN ({placeholders})"
    params.extend(allowed_risks)

    if action_types:
        action_placeholders = ", ".join("?" for _ in action_types)
        sql += f" AND action_type IN ({action_placeholders})"
        params.extend(action_types)

    sql += " ORDER BY created_at ASC, id ASC LIMIT ?"
    params.append(limit)

    rows = conn.execute(sql, params).fetchall()
    return [dict(row) for row in rows]


def mark_burp_action_sent(
    conn: sqlite3.Connection,
    *,
    action_id: int,
    evidence_title: str | None = None,
    evidence_summary: str | None = None,
    sent_at: datetime | None = None,
) -> int:
    row = _get_action(conn, action_id)
    timestamp = _fmt_dt(sent_at)
    conn.execute(
        """
        UPDATE burp_actions
        SET status = 'sent',
            error = NULL,
            sent_at = ?
        WHERE id = ?
        """,
        (timestamp, action_id),
    )
    existing = conn.execute(
        "SELECT id FROM evidence_refs WHERE source_table='burp_actions' AND source_id=? AND evidence_type='repeater_tab' ORDER BY id LIMIT 1",
        (str(action_id),),
    ).fetchone()
    if existing:
        return int(existing[0])
    cur = conn.execute(
        """
        INSERT INTO evidence_refs (
            target_name, source_table, source_id, evidence_type, title, summary, ref_json, created_at
        ) VALUES (?, 'burp_actions', ?, 'repeater_tab', ?, ?, ?, ?)
        """,
        (
            row["target_name"],
            str(action_id),
            evidence_title or _default_repeater_title(row),
            evidence_summary or row["note"],
            json.dumps(_evidence_ref_payload(row), ensure_ascii=False, sort_keys=True),
            timestamp,
        ),
    )
    conn.commit()
    return int(cur.lastrowid or 0)


def prepare_burp_action(
    conn: sqlite3.Connection,
    *,
    card_id: int,
    target_name: str,
    work_item_id: int,
    action_type: str = "send_to_repeater",
    method: str | None = None,
    url: str | None = None,
    note: str | None = None,
    risk_class: str = "safe_replay",
    repeater_tab_name: str | None = None,
    burp_request_ref: str | None = None,
) -> int:
    """Create the DB trace before a Burp MCP call; no card means no action."""
    card = conn.execute("SELECT * FROM operator_inbox WHERE id=?", (card_id,)).fetchone()
    work_table = _table(conn, "work_items")
    work = (
        conn.execute("SELECT * FROM work_items WHERE id=?", (work_item_id,)).fetchone()
        if work_table
        else {"target_name": target_name, "system_id": None}
    )
    if card is None or work is None or card["target_name"] != target_name or work["target_name"] != target_name:
        raise PermissionError("card and work item must belong to target")
    if risk_class in {"state_changing", "high_risk"} and card["status"] != "accepted":
        raise PermissionError("high-risk Burp action requires an accepted operator card")
    if card["status"] not in {"open", "accepted"}:
        raise PermissionError("an open/accepted operator action card is required before Burp dispatch")
    card_work_id = card["related_work_item_id"] if "related_work_item_id" in card.keys() else None
    card_system_id = card["system_id"] if "system_id" in card.keys() else None
    work_system_id = work["system_id"] if "system_id" in work.keys() else None
    if card_work_id is not None and int(card_work_id) != int(work_item_id):
        raise PermissionError("operator card is not linked to this work item")
    if card_system_id is not None and work_system_id != card_system_id:
        raise PermissionError("operator card and work item belong to different systems")
    transaction_mode = "savepoint" if conn.in_transaction else "transaction"
    conn.execute("SAVEPOINT burp_prepare" if transaction_mode == "savepoint" else "BEGIN")
    try:
        if repeater_tab_name is None:
            system_display = (
                conn.execute("SELECT display_name FROM target_systems WHERE id=?", (work_system_id,)).fetchone()
                if work_system_id and _table(conn, "target_systems")
                else None
            )
            repeater_tab_name = build_repeater_tab_name(
                target_name=target_name,
                work_item_id=work_item_id,
                variant="orig",
                system_display=system_display[0] if system_display else None,
                action_name=action_type,
            )
        action_id = create_burp_action(
            conn,
            target_name=target_name,
            work_item_id=work_item_id,
            action_type=action_type,
            method=method,
            url=url,
            note=note,
            risk_class=risk_class,
            repeater_tab_name=repeater_tab_name,
            burp_request_ref=burp_request_ref,
            commit=False,
        )
        conn.execute("UPDATE operator_inbox SET burp_action_id=? WHERE id=?", (action_id, card_id))
        if transaction_mode == "savepoint":
            conn.execute("RELEASE SAVEPOINT burp_prepare")
        else:
            conn.commit()
        return action_id
    except Exception:
        if transaction_mode == "savepoint":
            conn.execute("ROLLBACK TO SAVEPOINT burp_prepare")
            conn.execute("RELEASE SAVEPOINT burp_prepare")
        else:
            conn.rollback()
        raise


def mark_burp_action_failed(conn: sqlite3.Connection, *, action_id: int, error: str) -> None:
    _update_action_status(conn, action_id=action_id, status="failed", error=error)


def mark_burp_action_skipped(conn: sqlite3.Connection, *, action_id: int, error: str | None = None) -> None:
    _update_action_status(conn, action_id=action_id, status="skipped", error=error)


def _update_action_status(
    conn: sqlite3.Connection,
    *,
    action_id: int,
    status: str,
    error: str | None,
) -> None:
    _get_action(conn, action_id)
    conn.execute(
        """
        UPDATE burp_actions
        SET status = ?,
            error = ?,
            sent_at = CASE WHEN ? = 'sent' THEN COALESCE(sent_at, ?) ELSE sent_at END
        WHERE id = ?
        """,
        (status, error, status, _fmt_dt(), action_id),
    )
    conn.commit()


def _get_action(conn: sqlite3.Connection, action_id: int) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM burp_actions WHERE id = ?", (action_id,)).fetchone()
    if row is None:
        raise ValueError(f"burp_action not found: {action_id}")
    return row


def _normalize_variant(variant: str) -> str:
    value = variant.strip().lower().replace("-", "_")
    aliases = {
        "orig": "orig",
        "original": "orig",
        "ab": "ab",
        "ab_swap": "ab",
        "unauth": "unauth",
        "unauthorized": "unauth",
        "state": "state",
        "state_change": "state",
    }
    if value not in aliases:
        raise ValueError(f"unsupported repeater variant: {variant}")
    return aliases[value]


def _safe_tab_part(value: str) -> str:
    return re.sub(r"[^\w._-]+", "_", str(value).strip(), flags=re.UNICODE)[:48] or "action"


def _serialize_json(value: str | dict[str, Any] | list[Any] | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _default_repeater_title(row: sqlite3.Row) -> str:
    tab_name = row["repeater_tab_name"] or f"action-{row['id']}"
    return f"Repeater tab {tab_name}"


def _evidence_ref_payload(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "burp_action_id": row["id"],
        "action_type": row["action_type"],
        "method": row["method"],
        "url": row["url"],
        "risk_class": row["risk_class"],
        "repeater_tab_name": row["repeater_tab_name"],
        "burp_request_ref": row["burp_request_ref"],
    }
