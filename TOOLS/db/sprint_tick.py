"""Two-hour vulnerability sprint main-session tick."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

_TOOLS_DIR = Path(__file__).resolve().parent.parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

from db.attack_threads import list_attack_threads  # noqa: E402
from db.blackboard_tick import run_blackboard_tick  # noqa: E402
from db.cognitive_view import build_cognitive_view  # noqa: E402
from db.db_utils import connect, find_db  # noqa: E402
from db.dispatcher import DEFAULT_LIMIT as DISPATCH_LIMIT  # noqa: E402
from db.dispatcher import build_dispatch_plan  # noqa: E402
from db.experiment_planner import materialize_approved_experiments  # noqa: E402
from db.profile_contract import seed_profile_hypotheses  # noqa: E402
from db.soft_target_scorer import list_soft_targets  # noqa: E402
from db.sprint_candidate_gate import evaluate_attack_thread_candidate  # noqa: E402
from db.v3_chain import run_v3_chain_facts  # noqa: E402
from db.worker_result import compact_public_text  # noqa: E402

ACTIVE_STATUSES = ["proposed", "active", "candidate"]
PIVOT_PRESSURE_MINUTES = 60


def run_sprint_tick(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    sprint_id: str | None = None,
    seed: bool = True,
    reclaim: bool = True,
    max_candidates: int = 3,
    chain_facts: bool = True,
) -> dict[str, Any]:
    blackboard = run_blackboard_tick(
        conn,
        target_name=target_name,
        seed=seed,
        reclaim=reclaim,
    )
    v3_chain = _safe_v3_chain(conn, target_name=target_name) if chain_facts else None
    cognitive_loop = build_cognitive_view(conn, target_name=target_name)
    cognitive_schema_present = (
        conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='hunt_sessions'").fetchone() is not None
    )
    materialized = []
    seeded_hypotheses = []
    if cognitive_schema_present and cognitive_loop.get("active_session"):
        active_session_id = int(cognitive_loop["active_session"]["id"])
        seeded_hypotheses = seed_profile_hypotheses(conn, target_name=target_name, hunt_session_id=active_session_id)
        materialized = materialize_approved_experiments(
            conn, target_name=target_name, hunt_session_id=active_session_id, limit=DISPATCH_LIMIT
        )
        if materialized:
            cognitive_loop = build_cognitive_view(conn, target_name=target_name)
    dispatch_plan = _safe_dispatch_plan(conn, target_name=target_name)
    if cognitive_schema_present and cognitive_loop.get("blocker"):
        dispatch_plan = {
            **dispatch_plan,
            "cognitive_gate": cognitive_loop["blocker"],
            "tasks": [t for t in dispatch_plan.get("tasks", []) if not str(t.get("subtype") or "").startswith("experiment:")],
        }
    elif cognitive_schema_present and cognitive_loop.get("active_session"):
        # The dispatcher has already applied the authoritative system/readiness
        # gate.  A focused session owns the lane, but it must not starve the
        # same-system mapping work needed to make that session actionable.
        dispatch_plan = {
            **dispatch_plan,
            "cognitive_gate": "focused session owns dispatch; same-system recon and approved experiments are allowed",
            "tasks": dispatch_plan.get("tasks", [])[:DISPATCH_LIMIT],
        }
    threads = list_attack_threads(
        conn,
        target_name=target_name,
        statuses=ACTIVE_STATUSES,
        limit=50,
    )
    if sprint_id:
        threads = [row for row in threads if row.get("sprint_id") == sprint_id]

    assessed = []
    for row in threads:
        gate = evaluate_attack_thread_candidate(conn, attack_thread_id=row["id"])
        assessed.append({"thread": row, "gate": gate})

    high_value = [item for item in assessed if item["gate"]["classification"] == "high_value_escalation"]
    b_candidates = [item for item in assessed if item["gate"]["classification"] == "B"]
    b_candidates.sort(key=lambda item: item["thread"]["priority"], reverse=True)
    candidates = [_candidate_payload(item) for item in b_candidates[:max_candidates]]
    pivot_recommended = not candidates and _has_stale_thread_without_candidate(assessed)
    pivot_reason = ""
    if pivot_recommended:
        pivot_reason = (
            "no B-class candidate in active sprint threads; mark the current focused soft target "
            "failed/parked with evidence, then ask the operator to choose the next candidate"
        )

    if high_value:
        status = "high_value_escalation"
    elif candidates:
        status = "candidate_ready"
    elif blackboard["view"].get("soft_targets", {}).get("selection_required"):
        status = "soft_target_selection_required"
    else:
        status = "insufficient_evidence"

    decision = _derive_pipeline_decision(
        blackboard=blackboard,
        dispatch_plan=dispatch_plan,
        status=status,
    )

    return {
        "target": target_name,
        "sprint_id": sprint_id,
        "status": status,
        "pipeline_stage": decision["stage"],
        "decision": decision,
        "candidates": candidates,
        "b_class_count": len(candidates),
        "active_threads": [_thread_summary(item) for item in assessed],
        "pivot_recommended": pivot_recommended,
        "pivot_reason": pivot_reason,
        "pivot_count": _parked_count(conn, target_name=target_name, sprint_id=sprint_id),
        "soft_targets": _safe_soft_targets(conn, target_name=target_name),
        "operator_decision_required": bool(
            candidates
            or high_value
            or blackboard["view"]["operator_inbox"]
            or blackboard["view"].get("soft_targets", {}).get("selection_required")
        ),
        "blackboard": blackboard,
        "dispatch_plan": dispatch_plan,
        "cognitive_loop": cognitive_loop,
        "v3_chain": v3_chain,
        "human_brief": blackboard["view"].get("human_brief", {}),
        "materialized_experiments": materialized,
        "seeded_hypotheses": seeded_hypotheses,
    }


def _derive_pipeline_decision(*, blackboard: dict[str, Any], dispatch_plan: dict[str, Any], status: str) -> dict[str, Any]:
    """Return the main-session decision without waiting on any worker."""
    view = blackboard.get("view", {})
    if view.get("operator_inbox"):
        return {"stage": "operator_gate", "next_actions": ["处理 operator_inbox，再继续派发"], "wait": False}
    if status == "high_value_escalation":
        return {"stage": "escalation", "next_actions": ["暂停自动验证，交操作员确认"], "wait": False}
    tasks = dispatch_plan.get("tasks", [])
    lanes = {item.get("lane") for item in tasks}
    if "source_intel" in lanes or "network_profile" in lanes:
        return {"stage": "recon", "next_actions": ["派发情报/网络画像任务，继续处理其他已完成事件"], "wait": False}
    if "entry_probe" in lanes or "entry_explore" in lanes:
        return {"stage": "entry_surface", "next_actions": ["派发入口任务，收割入口事实后再进入业务分析"], "wait": False}
    if "js_reverse" in lanes or "hypothesis" in lanes:
        return {
            "stage": "attack_surface",
            "next_actions": ["派发 JS/语义画像任务，生成可验证 hypothesis"],
            "wait": False,
        }
    if "logic_probe" in lanes or "vuln_review" in lanes:
        return {"stage": "verification", "next_actions": ["派发低风险 probe/review，按证据升级或阻塞"], "wait": False}
    if status == "soft_target_selection_required":
        return {"stage": "selection", "next_actions": ["等待操作员选择 soft_targets.id"], "wait": False}
    return {
        "stage": "pivot_or_collect",
        "next_actions": ["无可派发任务；检查 coverage，补情报或切换方向"],
        "wait": False,
    }


def _safe_v3_chain(conn: sqlite3.Connection, *, target_name: str) -> dict[str, Any]:
    try:
        return run_v3_chain_facts(conn, target_name=target_name, apply=True)
    except (sqlite3.Error, KeyError, TypeError, ValueError, RuntimeError) as exc:
        return {
            "error": {
                "type": exc.__class__.__name__,
                "message": str(exc),
            }
        }


def _safe_dispatch_plan(conn: sqlite3.Connection, *, target_name: str) -> dict[str, Any]:
    try:
        return build_dispatch_plan(conn, target_name=target_name, limit=DISPATCH_LIMIT)
    except (sqlite3.Error, KeyError, TypeError, ValueError) as exc:
        return {
            "target_name": target_name,
            "max_dispatch": DISPATCH_LIMIT,
            "tasks": [],
            "skipped_decision_lanes": [],
            "error": {
                "type": exc.__class__.__name__,
                "message": str(exc),
            },
            "contract": {
                "read_only": True,
                "source": "work_items",
                "statuses": ["queued", "partial"],
                "runtime_policy": (
                    "Python only generates a dispatch plan and does not invoke Claude Agent(...) or Codex spawn_agent(...)."
                ),
            },
        }


def _safe_soft_targets(conn: sqlite3.Connection, *, target_name: str) -> dict[str, Any]:
    try:
        payload = list_soft_targets(conn, target_name=target_name, top=5)
        for row in payload.get("results", []):
            login = row.pop("login_urls", []) or []
            register = row.pop("register_urls", []) or []
            row["login_url_count"] = len(login) if isinstance(login, list) else 0
            row["register_url_count"] = len(register) if isinstance(register, list) else 0
        return payload
    except sqlite3.Error as exc:
        return {
            "target": target_name,
            "count": 0,
            "results": [],
            "empty": True,
            "selection_required": False,
            "message": f"soft target view unavailable: {exc.__class__.__name__}",
        }


def _candidate_payload(item: dict[str, Any]) -> dict[str, Any]:
    thread = item["thread"]
    gate = item["gate"]
    return {
        "attack_thread_id": thread["id"],
        "priority": thread["priority"],
        "asset": compact_public_text(thread["asset_url"], max_chars=300),
        "hypothesis": compact_public_text(thread["hypothesis"]),
        "why_promising": compact_public_text(thread["why_promising"]),
        "current_evidence": compact_public_text(thread["current_evidence"]),
        "next_probe": compact_public_text(thread["next_probe"]),
        "missing_proof": compact_public_text(gate.get("missing_proof", "")),
        "gate_reason": compact_public_text(gate["reason"]),
    }


def _thread_summary(item: dict[str, Any]) -> dict[str, Any]:
    thread = item["thread"]
    gate = item["gate"]
    return {
        "attack_thread_id": thread["id"],
        "status": thread["status"],
        "priority": thread["priority"],
        "classification": gate["classification"],
        "reason": compact_public_text(gate["reason"]),
        "hypothesis": compact_public_text(thread["hypothesis"]),
    }


def _has_stale_thread_without_candidate(items: list[dict[str, Any]]) -> bool:
    now = datetime.now().replace(microsecond=0)
    for item in items:
        raw_created = item["thread"].get("created_at") or item["thread"].get("updated_at")
        if not raw_created:
            continue
        try:
            created_at = datetime.fromisoformat(str(raw_created))
        except ValueError:
            continue
        if (now - created_at).total_seconds() >= PIVOT_PRESSURE_MINUTES * 60:
            return True
    return False


def _parked_count(conn: sqlite3.Connection, *, target_name: str, sprint_id: str | None) -> int:
    sql = "SELECT COUNT(*) FROM attack_threads WHERE target_name = ? AND status = 'parked'"
    params: list[Any] = [target_name]
    if sprint_id:
        sql += " AND sprint_id = ?"
        params.append(sprint_id)
    return int(conn.execute(sql, params).fetchone()[0])


def _resolve_db_path(args: argparse.Namespace) -> Path:
    if args.db:
        return Path(args.db)
    return find_db(args.target)


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        # This is a machine-readable CLI as well as a console command.  Do
        # not inherit Windows' active ANSI code page when stdout is piped.
        # ``backslashreplace`` still makes the text mode safe for unusual
        # surrogate-containing data without corrupting valid Unicode output.
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    parser = argparse.ArgumentParser(description="Run one two-hour sprint scheduling tick")
    parser.add_argument("--target", required=True, help="target_name in the DB")
    parser.add_argument("--db", help="explicit DB path")
    parser.add_argument("--sprint-id", help="filter to one sprint id")
    parser.add_argument("--no-seed", action="store_true", help="skip blackboard seed")
    parser.add_argument("--no-reclaim", action="store_true", help="skip work item reclaim")
    parser.add_argument("--no-chain-facts", action="store_true", help="skip passive v3 chain-fact building")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    conn = connect(_resolve_db_path(args))
    try:
        payload = run_sprint_tick(
            conn,
            target_name=args.target,
            sprint_id=args.sprint_id,
            seed=not args.no_seed,
            reclaim=not args.no_reclaim,
            chain_facts=not args.no_chain_facts,
        )
    finally:
        conn.close()

    if args.json:
        print(json.dumps(payload, ensure_ascii=False))
    else:
        print(f"[SPRINT] target={payload['target']} status={payload['status']} candidates={payload['b_class_count']}")
        if payload["pivot_recommended"]:
            print(f"[PIVOT] {payload['pivot_reason']}")
        for item in payload["candidates"]:
            print(f"- #{item['attack_thread_id']} priority={item['priority']} {item['hypothesis']}")


if __name__ == "__main__":
    main()
