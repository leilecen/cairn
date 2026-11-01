"""Read blackboard status for main session summaries."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any

_TOOLS_DIR = Path(__file__).resolve().parent.parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

from db.cognitive_view import build_cognitive_view  # noqa: E402
from db.db_utils import connect, find_db  # noqa: E402
from db.human_brief import build_human_brief  # noqa: E402
from db.soft_target_scorer import list_soft_targets  # noqa: E402
from db.work_queue import get_active_work_items, get_open_operator_inbox, get_recent_agent_events  # noqa: E402
from db.worker_result import compact_public_payload, compact_public_text, normalize_worker_result  # noqa: E402
from recon.recon_store import compact_recon_summary  # noqa: E402

WORK_STATUSES = ["queued", "claimed", "partial", "blocked", "done", "failed", "cancelled"]


def build_blackboard_view(conn: sqlite3.Connection, *, target_name: str) -> dict[str, Any]:
    work_summary = _work_summary(conn, target_name=target_name)
    active_agents = _active_agents(conn, target_name=target_name)
    attack_threads = _attack_threads(conn, target_name=target_name)
    recent_rows = get_recent_agent_events(conn, target_name=target_name, limit=3)
    recent_events = _compact_event_headers(recent_rows)
    recent_worker_results = _recent_worker_results(recent_rows)
    recent_event_summary = _recent_event_summary(recent_events)
    operator_inbox = _operator_inbox(conn, target_name=target_name)
    soft_targets = _soft_targets(conn, target_name=target_name)
    attack_surface = _attack_surface_summary(conn, target_name=target_name)
    recon = compact_recon_summary(conn, target_name=target_name)
    cognitive_loop = build_cognitive_view(conn, target_name=target_name)
    human_brief = build_human_brief(conn, target_name=target_name)
    next_recommended_actions = _next_recommended_actions(
        conn,
        target_name=target_name,
        operator_inbox=operator_inbox,
        work_summary=work_summary,
    )
    return {
        "target": target_name,
        "work_summary": work_summary,
        "active_agents": active_agents,
        "attack_threads": attack_threads,
        "recent_events": recent_events,
        "recent_event_summary": recent_event_summary,
        "recent_worker_results": recent_worker_results,
        "operator_inbox": operator_inbox,
        "soft_targets": soft_targets,
        "attack_surface": attack_surface,
        "recon": recon,
        "cognitive_loop": cognitive_loop,
        "human_brief": human_brief,
        "next_recommended_actions": next_recommended_actions,
    }


def format_blackboard_text(payload: dict[str, Any]) -> str:
    lines = []
    summary = payload["work_summary"]
    summary_parts = [f"{status}={summary.get(status, 0)}" for status in WORK_STATUSES if summary.get(status, 0) > 0]
    lines.append("[BLACKBOARD]")
    lines.append(" ".join(summary_parts) if summary_parts else "empty=1")

    lines.append("")
    lines.append("[ACTIVE]")
    if payload["active_agents"]:
        for item in payload["active_agents"]:
            subtype = f" {item['subtype']}" if item.get("subtype") else ""
            claim_text = f"claimed_by={item['agent_id']}" if item.get("agent_id") else "claimed_by=unassigned"
            heartbeat_text = f" heartbeat={item['heartbeat_at']}" if item.get("heartbeat_at") else ""
            lease_text = f" lease_until={item['lease_until']}" if item.get("lease_until") else ""
            lines.append(f"#{item['work_item_id']} {item['lane']}{subtype} {claim_text}{heartbeat_text}{lease_text}")
    else:
        lines.append("none")

    lines.append("")
    lines.append("[THREADS]")
    if payload.get("attack_threads"):
        for item in payload["attack_threads"]:
            lines.append(f"#{item['id']} {item['status']} priority={item['priority']} {item['hypothesis']}")
    else:
        lines.append("none")

    lines.append("")
    lines.append("[WORKER_RESULTS]")
    if payload.get("recent_worker_results"):
        for item in payload["recent_worker_results"][:5]:
            lines.append(
                f"#{item['work_item_id']} {item['status']} confidence={item['confidence']} {item['summary'] or item['conclusion']}"
            )
    else:
        lines.append("none")

    lines.append("")
    lines.append("[SOFT_TARGETS]")
    if payload.get("soft_targets", {}).get("results"):
        for item in payload["soft_targets"]["results"][:5]:
            lines.append(f"#{item['rank']} id={item['id']} score={item['score']} cost={item['estimated_test_cost']} {item['asset']}")
    else:
        lines.append("none")

    lines.append("")
    lines.append("[RECON]")
    recon = payload.get("recon", {})
    lines.append(
        "sources={sources} origin={origin_candidates} network={network_observations} "
        "tech={technology_observations} entries={entry_observations}".format(
            **{
                "sources": recon.get("sources", 0),
                "origin_candidates": recon.get("origin_candidates", 0),
                "network_observations": recon.get("network_observations", 0),
                "technology_observations": recon.get("technology_observations", 0),
                "entry_observations": recon.get("entry_observations", 0),
            }
        )
    )

    lines.append("")
    lines.append("[ATTACK_SURFACE]")
    profiles = payload.get("attack_surface", {}).get("profiles", [])
    if profiles:
        for item in profiles[:3]:
            counts = item.get("coverage_counts", {})
            lines.append(
                f"#{item['id']} {item['status']} confidence={item['confidence']} "
                f"covered={counts.get('covered', 0)} unknown={counts.get('unknown', 0)} "
                f"uncovered={counts.get('uncovered', 0)} blocked={counts.get('blocked', 0)} "
                f"{item['summary']}"
            )
    else:
        lines.append("none")

    lines.append("")
    lines.append("[OPERATOR_INBOX]")
    if payload["operator_inbox"]:
        for item in payload["operator_inbox"]:
            lines.append(f"#{item['id']} {item['kind']} {item['title']}")
    else:
        lines.append("none")

    lines.append("")
    lines.append("[NEXT]")
    if payload["next_recommended_actions"]:
        for idx, action in enumerate(payload["next_recommended_actions"], start=1):
            lines.append(f"{idx}. {action}")
    else:
        lines.append("none")

    return "\n".join(lines)


def _work_summary(conn: sqlite3.Connection, *, target_name: str) -> dict[str, int]:
    rows = conn.execute(
        """
        SELECT status, COUNT(*) AS cnt
        FROM work_items
        WHERE target_name = ?
        GROUP BY status
        """,
        (target_name,),
    ).fetchall()
    summary = {status: 0 for status in WORK_STATUSES}
    for row in rows:
        summary[row["status"]] = row["cnt"]
    return summary


def _active_agents(conn: sqlite3.Connection, *, target_name: str) -> list[dict[str, Any]]:
    rows = get_active_work_items(conn, target_name=target_name, limit=20)
    items: list[dict[str, Any]] = []
    for row in rows:
        items.append(
            {
                "agent_id": row.get("claimed_by"),
                "work_item_id": row["id"],
                "lane": row["lane"],
                "subtype": row.get("subtype"),
                "heartbeat_at": row.get("heartbeat_at"),
                "lease_until": row.get("lease_until"),
                "status": row["status"],
            }
        )
    return items


def _attack_threads(conn: sqlite3.Connection, *, target_name: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT id, asset_url, hypothesis, why_promising, priority, status,
               confidence, next_probe, updated_at
        FROM attack_threads
        WHERE target_name = ?
          AND status IN ('proposed','active','candidate')
        ORDER BY CASE status WHEN 'candidate' THEN 0 WHEN 'active' THEN 1 ELSE 2 END,
                 priority DESC,
                 updated_at DESC,
                 id DESC
        LIMIT 5
        """,
        (target_name,),
    ).fetchall()
    return [
        {
            "id": row["id"],
            "asset_url": compact_public_text(row["asset_url"], max_chars=300),
            "hypothesis": compact_public_text(row["hypothesis"]),
            "why_promising": compact_public_text(row["why_promising"]),
            "priority": row["priority"],
            "status": row["status"],
            "confidence": row["confidence"],
            "next_probe": compact_public_text(row["next_probe"]),
            "updated_at": row["updated_at"],
        }
        for row in rows
    ]


def _recent_events(conn: sqlite3.Connection, *, target_name: str) -> list[dict[str, Any]]:
    rows = get_recent_agent_events(conn, target_name=target_name, limit=3)
    items: list[dict[str, Any]] = []
    for row in rows:
        items.append(
            {
                "work_item_id": row["work_item_id"],
                "agent_id": row["agent_id"],
                "event_type": row["event_type"],
                "severity": row["severity"],
                "lane": row["lane"],
                "subtype": row.get("subtype"),
                "created_at": row["created_at"],
                "payload": _compact_event_payload(row["payload_json"]),
            }
        )
    return items


def _compact_event_headers(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "work_item_id": row["work_item_id"],
            "agent_id": row["agent_id"],
            "event_type": row["event_type"],
            "severity": row["severity"],
            "lane": row["lane"],
            "subtype": row.get("subtype"),
            "created_at": row["created_at"],
        }
        for row in rows
    ]


def _recent_event_summary(events: list[dict[str, Any]]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for event in events:
        event_type = str(event.get("event_type") or "unknown")
        counts[event_type] = counts.get(event_type, 0) + 1
    return {"count": len(events), "by_type": counts, "latest_types": [event.get("event_type") for event in events]}


def _recent_worker_results(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for row in events:
        if row["event_type"] not in {"partial_result", "done", "blocker"}:
            continue
        payload = _compact_event_payload(row.get("payload_json"))
        if not isinstance(payload, dict):
            continue
        result = payload.get("worker_result")
        if not isinstance(result, dict):
            continue
        try:
            result = normalize_worker_result(result)
        except ValueError:
            result = compact_public_payload(result)
        items.append(
            {
                "work_item_id": row["work_item_id"],
                "agent_id": row["agent_id"],
                "event_type": row["event_type"],
                "lane": row["lane"],
                "status": result.get("status", ""),
                "conclusion": result.get("conclusion", ""),
                "summary": result.get("summary", ""),
                "evidence_refs": result.get("evidence_refs", []),
                "confidence": result.get("confidence", "unknown"),
                "blocker": result.get("blocker", ""),
                "block_reason": result.get("block_reason", ""),
                "next_action": result.get("next_action", ""),
                "risk_level": result.get("risk_level"),
                "upgrade_request": result.get("upgrade_request"),
                "created_at": row["created_at"],
            }
        )
    return items


def _operator_inbox(conn: sqlite3.Connection, *, target_name: str) -> list[dict[str, Any]]:
    rows = get_open_operator_inbox(conn, target_name=target_name, limit=20)
    items: list[dict[str, Any]] = []
    for row in rows:
        items.append(
            {
                "id": row["id"],
                "kind": row["kind"],
                "title": compact_public_text(row["title"]),
                "detail": compact_public_text(row["detail"]),
                "related_work_item_id": row["related_work_item_id"],
                "created_at": row["created_at"],
            }
        )
    return items


def _soft_targets(conn: sqlite3.Connection, *, target_name: str) -> dict[str, Any]:
    try:
        payload = list_soft_targets(conn, target_name=target_name, top=5)
        for row in payload.get("results", []):
            login = row.pop("login_urls", []) or []
            register = row.pop("register_urls", []) or []
            row["login_url_count"] = len(login) if isinstance(login, list) else 0
            row["register_url_count"] = len(register) if isinstance(register, list) else 0
        return payload
    except sqlite3.Error:
        return {
            "target": target_name,
            "count": 0,
            "results": [],
            "empty": True,
            "selection_required": False,
            "message": "soft target view unavailable",
        }


def _attack_surface_summary(conn: sqlite3.Connection, *, target_name: str) -> dict[str, Any]:
    try:
        profile_rows = conn.execute(
            """
            SELECT *
            FROM attack_surface_profiles
            WHERE target_name = ?
            ORDER BY CASE status WHEN 'active' THEN 0 WHEN 'draft' THEN 1 ELSE 2 END,
                     updated_at DESC,
                     id DESC
            LIMIT 5
            """,
            (target_name,),
        ).fetchall()
    except sqlite3.Error:
        return {"profiles": [], "coverage_items": [], "available": False}

    profiles: list[dict[str, Any]] = []
    profile_ids: list[int] = []
    for row in profile_rows:
        profile_id = int(row["id"])
        profile_ids.append(profile_id)
        profiles.append(
            {
                "id": profile_id,
                "soft_target_id": row["soft_target_id"],
                "subject": f"{row['subject_table']}#{row['subject_id']}",
                "status": row["status"],
                "confidence": row["confidence"],
                "summary": compact_public_text(row["summary"], max_chars=240),
                "system_tags": _json_list(row["system_tags_json"], limit=8),
                "business_tags": _json_list(row["business_tags_json"], limit=8),
                "roles": _json_list(row["roles_json"], limit=6),
                "flows": _json_list(row["flows_json"], limit=6),
                "trust_boundaries": _json_list(row["trust_boundaries_json"], limit=6),
                "tech_stack": _json_list(row["tech_stack_json"], limit=6),
                "evidence_refs": _json_list(row["evidence_refs_json"], limit=10),
                "coverage_counts": _coverage_counts(conn, profile_id=profile_id),
                "updated_at": row["updated_at"],
            }
        )

    coverage_items = _coverage_items(conn, target_name=target_name, profile_ids=profile_ids)
    return {
        "available": True,
        "profiles": profiles,
        "coverage_items": coverage_items,
        "policy": "compact profile/ledger only; preserve unknown, uncovered and blocked items",
    }


def _coverage_counts(conn: sqlite3.Connection, *, profile_id: int) -> dict[str, int]:
    rows = conn.execute(
        """
        SELECT status, COUNT(*) AS cnt
        FROM coverage_ledger
        WHERE profile_id = ?
        GROUP BY status
        """,
        (profile_id,),
    ).fetchall()
    counts = {"covered": 0, "unknown": 0, "uncovered": 0, "blocked": 0}
    for row in rows:
        counts[row["status"]] = int(row["cnt"])
    return counts


def _coverage_items(conn: sqlite3.Connection, *, target_name: str, profile_ids: list[int]) -> list[dict[str, Any]]:
    if not profile_ids:
        return []
    placeholders = ", ".join("?" for _ in profile_ids)
    rows = conn.execute(
        f"""
        SELECT id, profile_id, work_item_id, item_key, category, status, confidence,
               evidence_refs_json, summary, blocker_reason, next_action, updated_at
        FROM coverage_ledger
        WHERE target_name = ?
          AND profile_id IN ({placeholders})
        ORDER BY CASE status WHEN 'blocked' THEN 0 WHEN 'unknown' THEN 1
                             WHEN 'uncovered' THEN 2 ELSE 3 END,
                 updated_at DESC,
                 id DESC
        LIMIT 20
        """,  # noqa: S608 - placeholders are generated from trusted in-memory profile_ids.
        (target_name, *profile_ids),
    ).fetchall()
    return [
        {
            "id": int(row["id"]),
            "profile_id": row["profile_id"],
            "work_item_id": row["work_item_id"],
            "item_key": compact_public_text(row["item_key"], max_chars=120),
            "category": compact_public_text(row["category"], max_chars=80),
            "status": row["status"],
            "confidence": row["confidence"],
            "summary": compact_public_text(row["summary"], max_chars=240),
            "blocker_reason": compact_public_text(row["blocker_reason"], max_chars=160),
            "next_action": compact_public_text(row["next_action"], max_chars=160),
            "evidence_refs": _json_list(row["evidence_refs_json"], limit=10),
            "updated_at": row["updated_at"],
        }
        for row in rows
    ]


def _json_list(raw: str | None, *, limit: int) -> list[Any]:
    try:
        value = json.loads(raw or "[]")
    except json.JSONDecodeError:
        return []
    if not isinstance(value, list):
        return []
    return compact_public_payload(value[:limit])


def _compact_event_payload(raw: str | None) -> dict[str, Any]:
    try:
        payload = json.loads(raw or "{}")
    except json.JSONDecodeError:
        return {"summary": compact_public_text(raw)}
    if not isinstance(payload, dict):
        return {"summary": compact_public_text(payload)}
    if isinstance(payload.get("worker_result"), dict):
        try:
            payload["worker_result"] = normalize_worker_result(payload["worker_result"])
        except ValueError:
            payload["worker_result"] = compact_public_payload(payload["worker_result"])
        result = payload["worker_result"]
        return {
            "worker_result": {
                key: result.get(key)
                for key in (
                    "status",
                    "outcome",
                    "summary",
                    "conclusion",
                    "observation_summary",
                    "alternative_explanation",
                    "evidence_refs",
                    "confidence",
                    "blocker",
                    "block_reason",
                    "next_action",
                )
                if key in result
            }
        }
    allowed = {
        key: payload[key]
        for key in (
            "summary",
            "conclusion",
            "reason",
            "blocker",
            "block_reason",
            "next_action",
            "evidence_refs",
            "hypothesis",
            "anomaly",
            "coverage_updates",
        )
        if key in payload
    }
    return compact_public_payload(allowed or {"summary": compact_public_text(payload)})


def _next_recommended_actions(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    operator_inbox: list[dict[str, Any]],
    work_summary: dict[str, int],
) -> list[str]:
    actions: list[str] = []
    if operator_inbox:
        item = operator_inbox[0]
        actions.append(f"handle operator_inbox #{item['id']} {item['kind']} for work_item #{item['related_work_item_id']}")

    next_work = conn.execute(
        """
        SELECT id, lane, subtype, priority, status
        FROM work_items
        WHERE target_name = ?
          AND status IN ('queued', 'partial')
          AND claimed_by IS NULL
        ORDER BY CASE status WHEN 'queued' THEN 0 ELSE 1 END,
                 priority DESC,
                 created_at ASC,
                 id ASC
        LIMIT 1
        """,
        (target_name,),
    ).fetchone()
    if next_work is not None:
        subtype = f" {next_work['subtype']}" if next_work["subtype"] else ""
        actions.append(f"claim next work_item #{next_work['id']} {next_work['lane']}{subtype} priority={next_work['priority']}")

    burp_row = conn.execute(
        """
        SELECT COUNT(*) AS cnt
        FROM burp_actions
        WHERE target_name = ?
          AND status = 'queued'
        """,
        (target_name,),
    ).fetchone()
    burp_count = burp_row["cnt"] if burp_row is not None else 0
    if burp_count:
        actions.append(f"review burp_actions {burp_count} queued")

    if not actions and any(work_summary.values()):
        actions.append("monitor blackboard for next transition")
    return actions


def _resolve_db_path(args: argparse.Namespace) -> Path:
    if args.db:
        return Path(args.db)
    return find_db(args.target)


def main() -> None:
    parser = argparse.ArgumentParser(description="Show blackboard status for one target")
    parser.add_argument("--target", required=True, help="target_name in the DB")
    parser.add_argument("--db", help="explicit DB path")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    conn = connect(_resolve_db_path(args))
    try:
        payload = build_blackboard_view(conn, target_name=args.target)
    finally:
        conn.close()

    if args.json:
        print(json.dumps(payload, ensure_ascii=False))
    else:
        print(format_blackboard_text(payload))


if __name__ == "__main__":
    main()
