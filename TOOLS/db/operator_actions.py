"""Structured, idempotent operator action cards."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from db.system_contract import ACTION_KINDS, validate_action_card


def create_action_card(
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
    incomplete: bool = False,
) -> dict[str, Any]:
    if kind not in ACTION_KINDS:
        raise ValueError(f"invalid action card kind: {kind}")
    card = (
        {
            "action_label": str(action_label)[:200],
            "why_needed": str(why_needed)[:500],
            "steps": [],
            "expected_observation": "",
            "report_back_format": "",
            "url": None,
        }
        if incomplete
        else validate_action_card(
            action_label=action_label,
            why_needed=why_needed,
            steps=steps,
            expected_observation=expected_observation,
            report_back_format=report_back_format,
            url=url,
        )
    )
    existing = conn.execute(
        "SELECT * FROM operator_inbox WHERE target_name=? AND system_id IS ? AND action_key=? AND status='open' ORDER BY id LIMIT 1",
        (target_name, system_id, action_key),
    ).fetchone()
    if existing:
        return dict(existing)
    # Validation normalizes URLs for canonical system records, but legacy
    # operator payloads are an audit record and must remain byte-for-byte
    # equivalent after a queue block.
    stored_url = url if url else card.get("url")
    cur = conn.execute(
        """INSERT INTO operator_inbox(target_name,related_work_item_id,kind,title,detail,suggested_action,url,burp_action_id,status,system_id,action_key,action_label,why_needed,steps_json,expected_observation,report_back_format,blocking) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            target_name,
            related_work_item_id,
            kind,
            action_label,
            why_needed,
            report_back_format,
            stored_url,
            burp_action_id,
            "open",
            system_id,
            action_key,
            card["action_label"],
            card["why_needed"],
            json.dumps(card["steps"], ensure_ascii=False),
            card["expected_observation"],
            card["report_back_format"],
            int(blocking),
        ),
    )
    conn.commit()
    return dict(conn.execute("SELECT * FROM operator_inbox WHERE id=?", (cur.lastrowid,)).fetchone())


def complete_action_card(conn: sqlite3.Connection, *, card_id: int, report: str, evidence_ref_id: int | None = None) -> dict[str, Any]:
    if not str(report or "").strip() or len(report) > 1000:
        raise ValueError("compact report is required")
    row = conn.execute("SELECT * FROM operator_inbox WHERE id=?", (card_id,)).fetchone()
    if row is None:
        raise ValueError("action card not found")
    columns = {item[1] for item in conn.execute("PRAGMA table_info(operator_inbox)")}
    if "resolved_at" in columns:
        conn.execute(
            "UPDATE operator_inbox SET status='done',resolved_at=datetime('now','localtime'),evidence_ref_id=COALESCE(?,evidence_ref_id),detail=? WHERE id=?",
            (evidence_ref_id, f"{row['detail'] or ''}\nreport: {report}"[:1500], card_id),
        )
    else:
        conn.execute(
            "UPDATE operator_inbox SET status='done',evidence_ref_id=COALESCE(?,evidence_ref_id),detail=? WHERE id=?",
            (evidence_ref_id, f"{row['detail'] or ''}\nreport: {report}"[:1500], card_id),
        )
    conn.commit()
    return dict(conn.execute("SELECT * FROM operator_inbox WHERE id=?", (card_id,)).fetchone())


def open_action_cards(conn: sqlite3.Connection, *, target_name: str, system_id: int | None = None) -> list[dict[str, Any]]:
    columns = {item[1] for item in conn.execute("PRAGMA table_info(operator_inbox)")}
    order = "created_at,id" if "created_at" in columns else "id"
    if system_id is None:
        rows = conn.execute(
            f"SELECT * FROM operator_inbox WHERE target_name=? AND status='open' ORDER BY {order}",  # noqa: S608 -- ORDER BY 取自 schema 列存在性判断
            (target_name,),
        ).fetchall()
    else:
        if "blocking" in columns:
            rows = conn.execute(
                f"SELECT * FROM operator_inbox WHERE target_name=? AND status='open' AND (system_id=? OR (system_id IS NULL AND COALESCE(blocking,1)=0)) ORDER BY {order}",  # noqa: S608 -- ORDER BY 取自 schema 列存在性判断，值走参数绑定
                (target_name, system_id),
            ).fetchall()
        else:
            rows = conn.execute(
                f"SELECT * FROM operator_inbox WHERE target_name=? AND status='open' AND (system_id=? OR system_id IS NULL) ORDER BY {order}",  # noqa: S608 -- ORDER BY 取自 schema 列存在性判断，值走参数绑定
                (target_name, system_id),
            ).fetchall()
    result = []  # noqa: S608 -- ORDER BY 取自 schema 列存在性判断，值走参数绑定
    for row in rows:
        item = dict(row)
        try:
            item["steps"] = json.loads(item.get("steps_json") or "[]")
        except json.JSONDecodeError:
            item["steps"] = []
        result.append(item)
    return result
