"""Compact, DB-derived handoff for operators and main sessions."""

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

from db.db_utils import session  # noqa: E402 -- 必须排在 sys.path bootstrap 之后
from db.operator_actions import open_action_cards  # noqa: E402 -- 必须排在 sys.path bootstrap 之后
from db.recon_readiness import evaluate_readiness  # noqa: E402 -- 必须排在 sys.path bootstrap 之后
from db.system_registry import system_compact  # noqa: E402 -- 必须排在 sys.path bootstrap 之后
from db.worker_result import compact_public_text  # noqa: E402 -- 必须排在 sys.path bootstrap 之后


def build_human_brief(conn: sqlite3.Connection, *, target_name: str, now: datetime | None = None) -> dict[str, Any]:
    now = now or datetime.now()
    if not _table(conn, "target_systems"):
        return _empty(conn, target_name, "system registry is not migrated")
    session = (
        conn.execute(
            "SELECT * FROM hunt_sessions WHERE target_name=? AND status='active' ORDER BY id DESC LIMIT 1",
            (target_name,),
        ).fetchone()
        if _table(conn, "hunt_sessions")
        else None
    )
    if session is None or not session["system_id"]:
        return _unfocused_brief(conn, target_name=target_name)
    system = system_compact(conn, target_name=target_name, system_id=int(session["system_id"]))
    readiness = evaluate_readiness(conn, target_name=target_name, system_id=int(session["system_id"]))
    actions = [_compact_action_card(item) for item in open_action_cards(conn, target_name=target_name, system_id=int(session["system_id"]))]
    workers = conn.execute(
        "SELECT id,lane,subtype,status,claimed_by,timebox_minutes,heartbeat_minutes,heartbeat_at,lease_until FROM work_items WHERE target_name=? AND status IN ('claimed','partial') AND claimed_by IS NOT NULL AND (system_id=? OR system_id IS NULL) ORDER BY updated_at DESC,id DESC LIMIT 5",
        (target_name, session["system_id"]),
    ).fetchall()
    completed = conn.execute(
        "SELECT id,lane,subtype,status,updated_at FROM work_items WHERE target_name=? AND status IN ('done','blocked') AND (system_id=? OR system_id IS NULL) ORDER BY updated_at DESC,id DESC LIMIT 5",
        (target_name, session["system_id"]),
    ).fetchall()
    stale = []
    overdue_cutoff = now - timedelta(minutes=5)
    for row in workers:
        item = dict(row)
        item["overdue"] = bool(row["heartbeat_at"] and _parse_dt(row["heartbeat_at"]) < overdue_cutoff)
        item["split_recommended"] = int(row["timebox_minutes"] or 0) > 10
        stale.append(item)
    phase = (
        "human_blocked"
        if actions and any(item.get("blocking", 1) for item in actions)
        else ("testing" if readiness["state"] == "ready" else readiness["state"])
    )
    return {
        "current_system": system,
        "focus_session": {
            "id": session["id"],
            "goal": session["goal"],
            "started_at": session["started_at"],
            "operator_acknowledged_at": session["operator_acknowledged_at"],
        },
        "phase": phase,
        "readiness": readiness,
        "what_we_know": [{"item": key, "status": value} for key, value in readiness["coverage"]["keys"].items() if value == "covered"],
        "critical_unknowns": readiness["blockers"][:5],
        "ai_activity": stale,
        "operator_actions": actions[:8],
        "completed_since_last_tick": [dict(item) for item in completed],
        "switch_proposal": None,
        "wait": False,
        "next_update_due_at": _next_update(stale),
        "recon_overview": _recon_overview(conn, target_name=target_name),
        "compact_contract": {"max_actions": 8, "raw_data": False},
    }


def render_markdown(brief: dict[str, Any]) -> str:
    system = brief.get("current_system")
    if not system:
        return f"当前系统\n未选择。{brief.get('wait_reason', '')}\n请操作员从候选系统中确认焦点，或明确放弃历史焦点。"
    lines = [
        f"当前系统：{system['display_name']}（{system['canonical_url']}）[system #{system['id']}]",
        f"当前阶段：{brief['phase']}；readiness={brief['readiness']['state']}",
        "刚刚完成：" + ("；".join(f"#{x['id']} {x['status']}" for x in brief.get("completed_since_last_tick", [])[:3]) or "无"),
        "AI 正在执行：" + ("；".join(f"#{x['id']} {x['lane']}" for x in brief.get("ai_activity", [])[:3]) or "无"),
        "你现在可以做：",
    ]
    actions = brief.get("operator_actions", [])
    lines.extend(
        [
            f"- {x.get('action_label') or x.get('title')}：{x.get('url') or system['canonical_url']}；步骤="
            + " → ".join(x.get("steps") or [])
            for x in actions[:5]
        ]
        or ["- 当前无需人工操作"]
    )
    lines.append("当前阻塞：" + ("；".join(brief.get("critical_unknowns", [])[:5]) or "无"))
    lines.append("是否建议切换：否（系统只生成建议，需操作员确认）")
    return "\n".join(lines)


def _empty(conn: sqlite3.Connection, target_name: str, reason: str) -> dict[str, Any]:
    return {
        "current_system": None,
        "focus_session": None,
        "phase": "unmapped",
        "readiness": {
            "state": "unmapped",
            "blockers": [reason],
            "next_safe_actions": ["登记系统、填写完整 URL，并由操作员确认焦点"],
        },
        "what_we_know": [],
        "critical_unknowns": [reason],
        "ai_activity": [],
        "operator_actions": [],
        "completed_since_last_tick": [],
        "switch_proposal": None,
        "wait": False,
        "next_update_due_at": None,
        "wait_reason": reason,
        "recon_overview": _recon_overview(conn, target_name=target_name),
        "compact_contract": {"raw_data": False},
    }


def _unfocused_brief(conn: sqlite3.Connection, *, target_name: str) -> dict[str, Any]:
    candidates = []
    if _table(conn, "target_systems") and _table(conn, "system_asset_links"):
        rows = conn.execute(
            "SELECT s.id,s.display_name,s.canonical_url,s.scope_class,s.lifecycle_state,COUNT(l.id) asset_count FROM target_systems s LEFT JOIN system_asset_links l ON l.system_id=s.id WHERE s.target_name=? AND s.lifecycle_state NOT IN ('excluded','completed') GROUP BY s.id ORDER BY CASE s.scope_class WHEN 'owned' THEN 0 WHEN 'authorized_vendor' THEN 1 WHEN 'intel_only' THEN 2 ELSE 3 END,s.id LIMIT 12",
            (target_name,),
        ).fetchall()
        candidates = [dict(row) for row in rows]
    elif _table(conn, "target_systems"):
        rows = conn.execute(
            "SELECT id,display_name,canonical_url,scope_class,lifecycle_state,0 AS asset_count FROM target_systems WHERE target_name=? AND lifecycle_state NOT IN ('excluded','completed') ORDER BY id LIMIT 12",
            (target_name,),
        ).fetchall()
        candidates = [dict(row) for row in rows]
    for candidate in candidates:
        _add_candidate_facts(conn, target_name=target_name, candidate=candidate)
    historical = []
    if _table(conn, "hunt_sessions"):
        session_cols = {row[1] for row in conn.execute("PRAGMA table_info(hunt_sessions)")}
        selected = [name for name in ("id", "system_id", "goal", "status", "selected_by") if name in session_cols]
        order = "h.updated_at DESC,h.id DESC" if "updated_at" in session_cols else "h.id DESC"
        historical = [
            dict(row)
            for row in conn.execute(
                f"""SELECT {",".join("h." + name for name in selected)},
            s.display_name,s.canonical_url,s.scope_class,s.lifecycle_state
            FROM hunt_sessions h LEFT JOIN target_systems s ON s.id=h.system_id AND s.target_name=h.target_name
            WHERE h.target_name=? AND h.status IN ('proposed','paused') ORDER BY {order} LIMIT 5""",  # noqa: S608 -- 列名取自 PRAGMA 白名单，值走参数绑定
                (target_name,),
            ).fetchall()
        ]
        for item in historical:
            session_id = item.get("id")
            if item.get("system_id") is not None:
                item["hunt_session_id"] = session_id
                item["id"] = item["system_id"]
            item["restore_blocker"] = "需操作员确认历史焦点" if item.get("system_id") else "历史焦点缺少 system_id"
            if item.get("lifecycle_state") in {"excluded", "completed", "stale"}:
                item["restore_blocker"] = f"系统状态为 {item['lifecycle_state']}，不可直接恢复"
    actions = (
        [_compact_action_card(item) for item in open_action_cards(conn, target_name=target_name)] if _table(conn, "operator_inbox") else []
    )
    reason = "历史焦点只能恢复为候选，尚未得到本轮操作员确认" if historical else "当前没有 active focused system"
    ordered = []
    seen = set()
    for item in historical + candidates:
        key = item.get("system_id", item.get("id"))
        if key in seen:
            continue
        seen.add(key)
        ordered.append(item)
    return {
        "current_system": None,
        "focus_session": None,
        "phase": "human_blocked" if any(x.get("blocking", 1) for x in actions) else "unmapped",
        "readiness": {
            "state": "unmapped",
            "blockers": [reason],
            "next_safe_actions": ["确认候选系统及授权", "选择一个 system_id 激活焦点", "放弃历史焦点并从候选重新开始"],
        },
        "historical_focus": historical,
        "candidate_systems": candidates,
        "what_we_know": [],
        "critical_unknowns": [reason],
        "ai_activity": [],
        "operator_actions": actions[:8],
        "completed_since_last_tick": [],
        "switch_proposal": None,
        "wait": True,
        "wait_reason": reason,
        "operator_choices": [
            {"action": "confirm_focus", "label": "确认候选系统（历史焦点置顶）", "candidates": ordered},
            {"action": "abandon_history", "label": "放弃历史焦点"},
        ],
        "next_update_due_at": None,
        "recon_overview": _recon_overview(conn, target_name=target_name),
        "compact_contract": {"max_actions": 8, "raw_data": False},
    }


def _recon_overview(conn: sqlite3.Connection, *, target_name: str) -> dict[str, Any]:
    """Return only aggregate L0/L1 state; never expose provider payloads."""
    source_health: dict[str, Any] = {"by_status": {}, "latest": []}
    if _has_columns(conn, "recon_runs", {"target_name", "source", "status", "attempt", "next_retry_at", "updated_at"}):
        rows = conn.execute(
            """SELECT source,status,attempt,next_retry_at,updated_at FROM recon_runs
               WHERE target_name=? ORDER BY updated_at DESC,id DESC""",
            (target_name,),
        ).fetchall()
        status_counts: dict[str, int] = {}
        latest_sources: set[str] = set()
        for row in rows:
            status = str(row["status"] or "unknown")
            status_counts[status] = status_counts.get(status, 0) + 1
            source = str(row["source"] or "unknown")
            if source not in latest_sources and len(source_health["latest"]) < 8:
                source_health["latest"].append(
                    {
                        "source": source,
                        "status": status,
                        "attempt": int(row["attempt"] or 0),
                        "next_retry_at": row["next_retry_at"],
                        "updated_at": row["updated_at"],
                    }
                )
                latest_sources.add(source)
        source_health["by_status"] = dict(sorted(status_counts.items()))

    review_assets = 0
    if _has_columns(conn, "target_assets", {"target_name", "scope_status"}):
        review_assets = int(
            conn.execute(
                "SELECT COUNT(*) FROM target_assets WHERE target_name=? AND scope_status='needs_review'",
                (target_name,),
            ).fetchone()[0]
        )

    origin_candidates = {"total": 0, "ready_for_review": 0, "evidence_insufficient": 0}
    if _has_columns(conn, "origin_candidates", {"target_name", "verification_status"}):
        rows = conn.execute(
            """SELECT verification_status,COUNT(*) AS total FROM origin_candidates
               WHERE target_name=? GROUP BY verification_status""",
            (target_name,),
        ).fetchall()
        for row in rows:
            status = str(row["verification_status"] or "unknown")
            count = int(row["total"] or 0)
            origin_candidates["total"] += count
            if status == "candidate_ready_for_review":
                origin_candidates["ready_for_review"] += count
            elif status == "evidence_insufficient":
                origin_candidates["evidence_insufficient"] += count

    cdn_observations = {"total": 0, "cdn": 0, "non_cdn": 0, "unknown": 0}
    if _has_columns(conn, "cdn_observations", {"target_name", "classification"}):
        rows = conn.execute(
            """SELECT classification,COUNT(*) AS total FROM cdn_observations
               WHERE target_name=? GROUP BY classification""",
            (target_name,),
        ).fetchall()
        for row in rows:
            classification = str(row["classification"] or "unknown")
            count = int(row["total"] or 0)
            cdn_observations["total"] += count
            if classification in cdn_observations:
                cdn_observations[classification] += count

    public_exposure: dict[str, Any] = {"items": 0, "by_status": {}}
    if _has_columns(conn, "coverage_ledger", {"target_name", "category", "status"}):
        rows = conn.execute(
            """SELECT status,COUNT(*) AS total FROM coverage_ledger
               WHERE target_name=? AND category='public_exposure' GROUP BY status""",
            (target_name,),
        ).fetchall()
        public_exposure["by_status"] = {str(row["status"]): int(row["total"]) for row in rows}
        by_status = public_exposure["by_status"]
        public_exposure["items"] = sum(by_status.values()) if isinstance(by_status, dict) else 0

    return {
        "source_health": source_health,
        "review_assets": review_assets,
        "origin_candidates": origin_candidates,
        "cdn_observations": cdn_observations,
        "public_exposure": public_exposure,
    }


def _compact_action_card(item: dict[str, Any]) -> dict[str, Any]:
    result = dict(item)
    for key in ("title", "detail", "suggested_action", "why_needed", "expected_observation", "report_back_format"):
        if result.get(key) is not None:
            result[key] = compact_public_text(result[key], max_chars=300)
    result["steps"] = [compact_public_text(step, max_chars=160) for step in (result.get("steps") or [])[:8]]
    return result


def _add_candidate_facts(conn: sqlite3.Connection, *, target_name: str, candidate: dict[str, Any]) -> None:
    """Attach presentation-only type/entry facts to an unfocused card."""
    system_id = candidate.get("id")
    candidate["type_labels"] = []
    candidate["entry_summary"] = {}
    candidate["evidence_refs"] = []
    if not isinstance(system_id, int) or not _table(conn, "system_asset_links"):
        return
    asset_ids = [
        int(row[0])
        for row in conn.execute(
            "SELECT asset_id FROM system_asset_links WHERE target_name=? AND system_id=? ORDER BY asset_id",
            (target_name, system_id),
        ).fetchall()
    ]
    if not asset_ids:
        return
    labels: set[str] = set()
    refs: list[str] = []
    if _table(conn, "system_type_observations"):
        for asset_id in asset_ids:
            for row in conn.execute(
                "SELECT label,evidence_refs_json FROM system_type_observations WHERE target_name=? AND asset_id=? ORDER BY rowid",
                (target_name, asset_id),
            ).fetchall():
                if row[0]:
                    labels.add(str(row[0]))
                refs.extend(_compact_refs(row[1]))
    counts: dict[str, int] = {}
    if _table(conn, "entry_observations"):
        for asset_id in asset_ids:
            for row in conn.execute(
                "SELECT entry_type,evidence_refs_json FROM entry_observations WHERE target_name=? AND asset_id=? ORDER BY rowid",
                (target_name, asset_id),
            ).fetchall():
                entry_type = str(row[0] or "unknown")
                counts[entry_type] = counts.get(entry_type, 0) + 1
                refs.extend(_compact_refs(row[1]))
    candidate["type_labels"] = sorted(labels)
    candidate["entry_summary"] = dict(sorted(counts.items()))
    candidate["evidence_refs"] = list(dict.fromkeys(refs))[:8]
    if _table(conn, "system_soft_targets"):
        row = conn.execute(
            "SELECT eligibility_status,total_score,rank FROM system_soft_targets WHERE target_name=? AND system_id=? LIMIT 1",
            (target_name, system_id),
        ).fetchone()
        if row:
            candidate["eligibility_status"] = row[0]
            candidate["total_score"] = int(row[1] or 0)
            candidate["rank"] = row[2]


def _compact_refs(raw: Any) -> list[str]:
    try:
        values = json.loads(raw or "[]") if isinstance(raw, str) else raw
    except (TypeError, ValueError):
        values = []
    return [str(item)[:240] for item in values if isinstance(item, str)][:5] if isinstance(values, list) else []


def _table(conn: sqlite3.Connection, name: str) -> bool:
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None


def _has_columns(conn: sqlite3.Connection, table: str, required: set[str]) -> bool:
    if not _table(conn, table):
        return False
    available = {str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})")}
    return required <= available


def _resolve_db(target_name: str, db_value: str | None) -> Path:
    if not db_value:
        raise ValueError("explicit --db is required")
    path = Path(db_value)
    if not path.is_file():
        raise ValueError(f"database file not found: {path}")
    with session(path, read_only=True) as conn:
        row = conn.execute("SELECT 1 FROM targets WHERE target_name=? LIMIT 1", (target_name,)).fetchone()
    if row is None:
        raise ValueError("target is not present in the explicit database")
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only compact candidate and focus brief")
    parser.add_argument("--target", required=True)
    parser.add_argument("--db", required=True, help="explicit database path for this target")
    parser.add_argument("--json", action="store_true", help="emit the compact JSON contract")
    args = parser.parse_args(argv)
    try:
        path = _resolve_db(args.target, args.db)
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        try:
            brief = build_human_brief(conn, target_name=args.target)
        finally:
            conn.close()
        payload = {"ok": True, "db": str(path), "brief": brief}
        print(json.dumps(payload, ensure_ascii=False) if args.json else render_markdown(brief))
        return 0
    except (OSError, sqlite3.Error, ValueError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return 1


def _parse_dt(value: str) -> datetime:
    return datetime.fromisoformat(value.replace(" ", "T"))


def _next_update(items: list[dict[str, Any]]) -> str | None:
    if not items:
        return None
    return (datetime.now() + timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")


if __name__ == "__main__":
    raise SystemExit(main())
