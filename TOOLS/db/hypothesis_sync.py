"""Promote compact hypothesis worker output into attack threads."""

from __future__ import annotations

import sqlite3
from typing import Any

from db.attack_threads import create_attack_thread, update_attack_thread
from db.worker_result import compact_public_text, normalize_worker_result


def normalize_hypothesis_worker_result(payload: dict[str, Any], *, expected_status: str | None = None) -> dict[str, Any]:
    result = normalize_worker_result(payload, expected_status=expected_status)
    for key in ("hypothesis", "why_promising", "next_probe", "asset_url"):
        if payload.get(key):
            result[key] = compact_public_text(payload[key], max_chars=500)
    return result


def sync_hypothesis_result(conn: sqlite3.Connection, *, work_item: sqlite3.Row, worker_result: dict[str, Any]) -> None:
    if work_item["lane"] != "hypothesis" or not _table_exists(conn, "attack_threads"):
        return
    hypothesis = worker_result.get("hypothesis") or worker_result.get("summary") or worker_result.get("conclusion")
    if not hypothesis:
        return
    thread_id = work_item["attack_thread_id"]
    if thread_id:
        update_attack_thread(
            conn,
            attack_thread_id=int(thread_id),
            current_evidence=worker_result.get("summary") or worker_result.get("conclusion"),
            next_probe=worker_result.get("next_probe"),
            confidence=worker_result.get("confidence") if worker_result.get("confidence") in {"low", "medium", "high"} else None,
            commit=False,
        )
        return
    existing = conn.execute(
        "SELECT id FROM attack_threads WHERE target_name=? AND hypothesis=? ORDER BY id ASC LIMIT 1",
        (work_item["target_name"], hypothesis),
    ).fetchone()
    if existing:
        thread_id = int(existing[0])
    else:
        thread_id = create_attack_thread(
            conn,
            target_name=work_item["target_name"],
            asset_url=worker_result.get("asset_url"),
            hypothesis=hypothesis,
            why_promising=worker_result.get("why_promising") or "derived from structured attack-surface evidence",
            priority=70,
            owner="hypothesis-worker",
            commit=False,
        )
    conn.execute("UPDATE work_items SET attack_thread_id=? WHERE id=?", (thread_id, work_item["id"]))


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    return bool(conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1", (table,)).fetchone())
