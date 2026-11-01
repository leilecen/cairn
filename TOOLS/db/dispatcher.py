"""Build compact, read-only dispatch plans for blackboard lane workers."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

_TOOLS_DIR = Path(__file__).resolve().parent.parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

from db.db_utils import connect, find_db  # noqa: E402
from db.generic_probe import RULES_PATH as GENERIC_PROBE_RULES_PATH  # noqa: E402
from db.lane_templates import MAPPING_LANES, render_lane_prompt, validate_template_input  # noqa: E402
from db.recon_readiness import evaluate_readiness, lane_allowed  # noqa: E402
from db.system_contract import COLLECTION_LANES  # noqa: E402
from db.worker_result import compact_public_text  # noqa: E402

# Total dispatch cap per tick. L3 recon and test workers share this small bound;
# broad L0 remains external and does not enter the AI worker queue.
DEFAULT_LIMIT = 2
# Test-lane concurrency sub-limit: preauth_probe/logic_probe/vuln_review/replay
# etc. stay at 2 concurrent tasks regardless of the raised total cap.
TEST_LANE_SUB_LIMIT = 2
MAX_CONTEXT_CHARS = 360

# These lanes only collect or classify already observed facts. They may run
# without a focused system, but still pass the scope and risk gates.
NO_FOCUS_COLLECTION_LANES = frozenset(
    {
        "asset_ingest",
        "source_intel",
        "network_profile",
        "entry_explore",
        "js_reverse",
        "semantic_profile",
    }
)


LANE_DISPATCH: dict[str, dict[str, Any]] = {
    "asset_ingest": {
        "dispatchable": True,
        "worker": "asset-recon",
        "agent_type": "worker",
        "model_tier": "cheap",
        "reasoning_effort": "low",
        "claude_model": "haiku",
        "codex_model": "gpt-5.4-mini",
    },
    "quick_scout": {
        "dispatchable": True,
        "worker": "surface-scout",
        "agent_type": "worker",
        "model_tier": "cheap",
        "reasoning_effort": "low",
        "claude_model": "haiku",
        "codex_model": "gpt-5.4-mini",
    },
    "cognitive_experiment": {
        "dispatchable": True,
        "worker": "surface-scout",
        "agent_type": "worker",
        "model_tier": "cheap",
        "reasoning_effort": "low",
        "claude_model": "haiku",
        "codex_model": "gpt-5.4-mini",
    },
    "entry_explore": {
        "dispatchable": True,
        "worker": "surface-scout",
        "agent_type": "worker",
        "model_tier": "cheap",
        "reasoning_effort": "low",
        "claude_model": "haiku",
        "codex_model": "gpt-5.4-mini",
    },
    "source_intel": {
        "dispatchable": True,
        "worker": "asset-recon",
        "agent_type": "worker",
        "model_tier": "cheap",
        "reasoning_effort": "low",
        "claude_model": "haiku",
        "codex_model": "gpt-5.4-mini",
    },
    "network_profile": {
        "dispatchable": True,
        "worker": "stealth-scanner",
        "agent_type": "worker",
        "model_tier": "cheap",
        "reasoning_effort": "low",
        "claude_model": "haiku",
        "codex_model": "gpt-5.4-mini",
    },
    "origin_verify": {
        "dispatchable": True,
        "worker": "stealth-scanner",
        "agent_type": "worker",
        "model_tier": "standard",
        "reasoning_effort": "low",
        "claude_model": "sonnet",
        "codex_model": "gpt-5.4",
    },
    "entry_probe": {
        "dispatchable": True,
        "worker": "entry-probe",
        "agent_type": "worker",
        "model_tier": "cheap",
        "reasoning_effort": "low",
        "claude_model": "haiku",
        "codex_model": "gpt-5.4-mini",
    },
    "preauth_probe": {
        "dispatchable": True,
        "worker": "preauth-probe",
        "agent_type": "worker",
        "model_tier": "cheap",
        "reasoning_effort": "low",
        "claude_model": "haiku",
        "codex_model": "gpt-5.4-mini",
    },
    "replay": {
        "dispatchable": True,
        "worker": "surface-scout",
        "agent_type": "worker",
        "model_tier": "cheap",
        "reasoning_effort": "low",
        "claude_model": "haiku",
        "codex_model": "gpt-5.4-mini",
    },
    "evidence_pack": {
        "dispatchable": True,
        "worker": "src-reporter",
        "agent_type": "worker",
        "model_tier": "cheap",
        "reasoning_effort": "low",
        "claude_model": "haiku",
        "codex_model": "gpt-5.4-mini",
    },
    "js_reverse": {
        "dispatchable": True,
        "worker": "js-reversing-helper",
        "agent_type": "explorer",
        "model_tier": "standard",
        "reasoning_effort": "medium",
        "claude_model": "sonnet",
        "codex_model": "gpt-5.4",
    },
    "logic_probe": {
        "dispatchable": True,
        "worker": "param-fuzzer",
        "agent_type": "worker",
        "model_tier": "standard",
        "reasoning_effort": "low",
        "claude_model": "sonnet",
        "codex_model": "gpt-5.4",
    },
    "vuln_review": {
        "dispatchable": True,
        "worker": "vuln-reviewer",
        "agent_type": "worker",
        "model_tier": "standard",
        "reasoning_effort": "low",
        "claude_model": "sonnet",
        "codex_model": "gpt-5.4",
    },
    "report_audit": {
        "dispatchable": True,
        "worker": "vuln-auditor",
        "agent_type": "worker",
        "model_tier": "standard",
        "reasoning_effort": "low",
        "claude_model": "sonnet",
        "codex_model": "gpt-5.4",
    },
    "hypothesis": {
        "dispatchable": True,
        "worker": "hypothesis-drafter",
        "agent_type": "worker",
        "model_tier": "standard",
        "reasoning_effort": "low",
        "claude_model": "sonnet",
        "codex_model": "gpt-5.4",
        "requires_main_approval": True,
    },
    "semantic_profile": {
        "dispatchable": True,
        "worker": "attack-surface-profiler",
        "agent_type": "worker",
        "model_tier": "standard",
        "reasoning_effort": "low",
        "claude_model": "sonnet",
        "codex_model": "gpt-5.4",
    },
    # NOTE(2026-10-16): `postexp` 仍**不在**本表里 —— 它只在 lane_templates.SUPPORTED_LANES
    # 与 LANE_TO_AGENT 中，因此没有 model_tier/claude_model/codex_model 可推导。
    # 结果：.agents/agents/postexp-worker.md 必须自带 model_overrides，否则生成器直接 fail loud
    # （历史上这里缺失导致产物里留下 `model: standard` 这种 tier 名泄漏）。
    # 是否给它补 tier（以及是否 dispatchable）属模型分层取舍，需操作员拍板，本表保持现状。
    "asset_triage": {
        "dispatchable": False,
        "decision_owner": "main_model",
        "reason": "asset triage selects direction and must remain with the main session",
    },
    "operator_task": {
        "dispatchable": False,
        "decision_owner": "operator",
        "reason": "operator tasks require human decision or action",
    },
}


def build_dispatch_plan(conn: sqlite3.Connection, *, target_name: str, limit: int = DEFAULT_LIMIT) -> dict[str, Any]:
    """Return a compact JSON-serializable plan without claiming or mutating work_items."""
    rows = _candidate_rows(conn, target_name=target_name)
    tasks: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []

    for row in rows:
        mapping = LANE_DISPATCH.get(row["lane"])
        if not mapping or not mapping.get("dispatchable"):
            skipped.append(_skipped_item(row, mapping))
            continue
        scope_reason = _active_scope_gate(conn, row)
        if scope_reason:
            skipped.append(
                {
                    "work_item_id": int(row["id"]),
                    "lane": row["lane"],
                    "status": row["status"],
                    "priority": int(row["priority"]),
                    "decision_owner": "operator",
                    "reason": scope_reason,
                }
            )
            continue
        focus_reason = _human_focus_gate(conn, row)
        if focus_reason:
            skipped.append(
                {
                    "work_item_id": int(row["id"]),
                    "lane": row["lane"],
                    "status": row["status"],
                    "priority": int(row["priority"]),
                    "decision_owner": "operator",
                    "reason": focus_reason,
                }
            )
            continue
        template_contract = _template_contract(conn, row)
        template_errors = validate_template_input(template_contract) if _human_focus_enabled(conn) else []
        if template_errors:
            skipped.append(
                {
                    "work_item_id": int(row["id"]),
                    "lane": row["lane"],
                    "status": row["status"],
                    "priority": int(row["priority"]),
                    "decision_owner": "main_model",
                    "reason": f"template_contract: missing or invalid {', '.join(template_errors)}",
                }
            )
            continue
        cognitive_reason = _cognitive_experiment_gate(conn, row)
        if cognitive_reason:
            skipped.append(
                {
                    "work_item_id": int(row["id"]),
                    "lane": row["lane"],
                    "status": row["status"],
                    "priority": int(row["priority"]),
                    "decision_owner": "operator",
                    "reason": cognitive_reason,
                }
            )
            continue
        if len(tasks) >= limit:
            continue
        if row["lane"] not in COLLECTION_LANES:
            test_count = sum(1 for task in tasks if task["lane"] not in COLLECTION_LANES)
            if test_count >= TEST_LANE_SUB_LIMIT:
                continue
        tasks.append(_dispatch_item(conn, row, mapping))

    return {
        "target_name": target_name,
        "max_dispatch": limit,
        "tasks": tasks,
        "skipped_decision_lanes": skipped[:10],
        "skipped_summary": _compact_skipped_summary(skipped),
        "contract": {
            "read_only": True,
            "source": "work_items",
            "statuses": ["queued", "partial"],
            "large_data_policy": (f"summary/prompt_context capped at {MAX_CONTEXT_CHARS} chars; raw HTML/JS/Burp bodies are not read"),
            "runtime_policy": (
                "Use adapter fields to call Claude Agent(...) or Codex spawn_agent(...); Python does not invoke runtime agents."
            ),
        },
    }


def _active_scope_gate(conn: sqlite3.Connection, row: sqlite3.Row) -> str | None:
    """Prevent active recon lanes from dispatching unresolved or unapproved subjects."""
    if row["lane"] == "quick_scout" and row["subject_table"] == "pages" and row["subtype"] != "explicit_single_page":
        return "scope_gate: broad quick_scout is parked; use explicit_single_page only"
    if row["lane"] in {"logic_probe", "replay"} and row["subject_table"] == "hunt_queue":
        subject = conn.execute("SELECT url FROM hunt_queue WHERE id=?", (row["subject_id"],)).fetchone()
        if subject and subject["url"]:
            host = (urlparse(subject["url"]).hostname or "").lower().rstrip(".")
            active = conn.execute(
                """SELECT 1 FROM target_assets
                   WHERE target_name=? AND scope_class IN ('owned','authorized_vendor')
                     AND scope_status='in_scope' AND authorization_state<>'revoked'
                     AND (?=asset_value OR ? LIKE '%.' || asset_value)
                   LIMIT 1""",
                (row["target_name"], host, host),
            ).fetchone()
            if active is None:
                return "scope_gate: work item URL is outside active asset scope"
    if row["lane"] not in {"preauth_probe", "network_profile", "origin_verify", "entry_probe"}:
        return None
    if row["subject_table"] == "target_assets":
        asset = conn.execute(
            "SELECT scope_class, scope_status, authorization_state FROM target_assets WHERE id=? AND target_name=?",
            (row["subject_id"], row["target_name"]),
        ).fetchone()
        if asset is None:
            return "scope_gate: asset not found"
        if asset["scope_class"] not in {"owned", "authorized_vendor"}:
            return "scope_gate: asset is not owned or explicitly authorized vendor"
        if asset["scope_status"] != "in_scope" or asset["authorization_state"] == "revoked":
            return "scope_gate: asset is not currently active in scope"
    if row["subject_table"] == "endpoint_observations":
        endpoint = conn.execute(
            "SELECT resolution_status, scope_class FROM endpoint_observations WHERE id=? AND target_name=?",
            (row["subject_id"], row["target_name"]),
        ).fetchone()
        if endpoint is None or endpoint["resolution_status"] != "resolved":
            return "scope_gate: endpoint URL is unresolved"
        if endpoint["scope_class"] not in {"owned", "authorized_vendor"}:
            return "scope_gate: endpoint is outside active scope"
    return None


def _cognitive_experiment_gate(conn: sqlite3.Connection, row: sqlite3.Row) -> str | None:
    """Final safety gate; planner filtering is not sufficient at dispatch time."""
    if row["lane"] != "cognitive_experiment":
        return None
    match = re.fullmatch(r"experiment:(\d+)", str(row["subtype"] or ""))
    if not match:
        return "cognitive_gate: malformed experiment reference; operator review required"
    experiment = conn.execute(
        """SELECT status, method_class, risk_class, question,
        expected_observation, control_description, stop_conditions_json, budget_json
        FROM experiments WHERE id=?""",
        (int(match.group(1)),),
    ).fetchone()
    if experiment is None:
        return "cognitive_gate: experiment not found; operator review required"
    if experiment["method_class"] not in {"offline", "passive"}:
        return "cognitive_gate: active/operator-gated experiment blocked; operator review required"
    if experiment["risk_class"] != "safe_passive":
        return "cognitive_gate: experiment risk is not safe_passive; operator review required"
    if experiment["status"] not in {"approved", "queued"}:
        return "cognitive_gate: experiment is not approved for dispatch"
    if not all(str(experiment[key] or "").strip() for key in ("question", "expected_observation", "control_description")):
        return "cognitive_gate: incomplete experiment contract; operator review required"
    try:
        stops = json.loads(experiment["stop_conditions_json"] or "[]")
        budget = json.loads(experiment["budget_json"] or "{}")
    except (TypeError, json.JSONDecodeError):
        return "cognitive_gate: invalid experiment contract JSON; operator review required"
    if not isinstance(stops, list) or not stops or not isinstance(budget, dict):
        return "cognitive_gate: incomplete experiment contract; operator review required"
    return None


def _human_focus_gate(conn: sqlite3.Connection, row: sqlite3.Row) -> str | None:
    """Final system/readiness gate, enabled only after migration 033 exists.

    Every AI worker lane, including legacy collection/recon items, requires an
    active manually selected deep system. L0 broad collection stays external;
    stale queued collection records are parked by this read-only dispatch gate.
    """
    if not _human_focus_enabled(conn):
        return None
    session = conn.execute(
        "SELECT system_id FROM hunt_sessions WHERE target_name=? AND status='active' ORDER BY id DESC LIMIT 1",
        (row["target_name"],),
    ).fetchone()
    if session is None:
        return "focus_gate: no active focused system; operator must select a system"
    if not session["system_id"]:
        return "focus_gate: active session has no system binding"
    if _focus_timebox_enabled(conn):
        expired = conn.execute(
            """SELECT 1 FROM system_soft_targets
               WHERE target_name=? AND system_id=? AND status='focused'
                 AND timebox_until IS NOT NULL
                 AND timebox_until<=datetime('now','localtime')
               LIMIT 1""",
            (row["target_name"], session["system_id"]),
        ).fetchone()
        if expired:
            return "focus_gate: focused system timebox expired; operator must renew or select a focus"
    system_id = row["system_id"] if "system_id" in row.keys() else None
    if system_id is None:
        return "focus_gate: legacy task has no system_id; park and map it before dispatch"
    if int(system_id) != int(session["system_id"]):
        return "focus_gate: task belongs to a different system than the active focus"
    if _table_exists(conn, "system_soft_targets"):
        ranked = conn.execute(
            "SELECT eligibility_status FROM system_soft_targets WHERE target_name=? AND system_id=?",
            (row["target_name"], session["system_id"]),
        ).fetchone()
        if ranked is None or ranked["eligibility_status"] != "eligible":
            return "eligibility_gate: focused system is no longer execution-eligible; operator must restore scope or authorization"
    readiness = evaluate_readiness(conn, target_name=row["target_name"], system_id=int(session["system_id"]))
    if row["lane"] in {
        "preauth_probe",
        "logic_probe",
        "vuln_review",
        "replay",
        "cognitive_experiment",
    } and not lane_allowed(readiness, row["lane"]):
        return f"readiness_gate: {readiness['state']} allows mapping lanes only"
    blocking = conn.execute(
        """SELECT 1 FROM operator_inbox
        WHERE target_name=? AND status='open' AND COALESCE(blocking,1)=1 AND system_id=? LIMIT 1""",
        (row["target_name"], session["system_id"]),
    ).fetchone()
    if blocking and row["lane"] not in {
        "source_intel",
        "network_profile",
        "entry_probe",
        "js_reverse",
        "semantic_profile",
        "entry_explore",
        "origin_verify",
    }:
        return "operator_gate: blocking human action card must be handled first"
    return None


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone() is not None


def _human_focus_enabled(conn: sqlite3.Connection) -> bool:
    if not _table_exists(conn, "target_systems") or not _table_exists(conn, "hunt_sessions"):
        return False
    return (
        _table_exists(conn, "schema_version")
        and conn.execute("SELECT 1 FROM schema_version WHERE version>=33 LIMIT 1").fetchone() is not None
    )


def _focus_timebox_enabled(conn: sqlite3.Connection) -> bool:
    """Timeboxes are a schema-34 contract; schema-33 remains compatible."""
    return (
        _table_exists(conn, "system_soft_targets")
        and _table_exists(conn, "schema_version")
        and conn.execute("SELECT 1 FROM schema_version WHERE version>=34 LIMIT 1").fetchone() is not None
    )


def to_codex_spawn_args(item: dict[str, Any]) -> dict[str, Any]:
    """Convert one dispatch task to the minimum Codex spawn_agent arguments."""
    return {
        "agent_type": item["agent_type"],
        "fork_context": False,
        "model": item["adapters"]["codex"]["model"],
        "reasoning_effort": item["reasoning_effort"],
        "message": item["adapters"]["codex"]["message"],
    }


def to_claude_agent_args(item: dict[str, Any]) -> dict[str, Any]:
    """Convert one dispatch task to the minimum Claude Code Agent(...) arguments."""
    return {
        "subagent_type": item["worker"],
        "description": item["adapters"]["claude"]["description"],
        "prompt": item["adapters"]["claude"]["prompt"],
        "model": item["adapters"]["claude"]["model"],
        "run_in_background": True,
    }


def _candidate_rows(conn: sqlite3.Connection, *, target_name: str) -> list[sqlite3.Row]:
    columns = {row[1] for row in conn.execute("PRAGMA table_info(work_items)")}
    system_column = "system_id" if "system_id" in columns else "NULL"
    risk_column = "risk_class" if "risk_class" in columns else "'safe_passive'"
    return conn.execute(
        f"""
        SELECT id, target_name, lane, subtype, subject_table, subject_id, title, objective,
               priority, status, timebox_minutes, heartbeat_minutes, summary,
               {risk_column} AS risk_class,
               {system_column} AS system_id
        FROM work_items
        WHERE target_name = ?
          AND status IN ('queued', 'partial')
          AND COALESCE(dispatch_state, 'active') = 'active'
          AND claimed_by IS NULL
          AND attempt_count < max_attempts
        ORDER BY priority DESC,
                 CASE lane
                   WHEN 'operator_task' THEN 0
                   WHEN 'origin_verify' THEN 1
                   WHEN 'network_profile' THEN 2
                   WHEN 'preauth_probe' THEN 3
                   WHEN 'entry_probe' THEN 4
                   WHEN 'source_intel' THEN 5
                   WHEN 'logic_probe' THEN 6
                   ELSE 6
                 END,
                 CASE status WHEN 'queued' THEN 0 ELSE 1 END,
                 created_at ASC,
                 id ASC
        """,  # noqa: S608 - interpolated value is a fixed schema column name.
        (target_name,),
    ).fetchall()


def _dispatch_item(conn: sqlite3.Connection, row: sqlite3.Row, mapping: dict[str, Any]) -> dict[str, Any]:
    target_name = row["target_name"]
    work_item_id = int(row["id"])
    worker = mapping["worker"]
    agent_id = _agent_id(target_name, worker, work_item_id)
    system_context = _system_context(conn, row)
    prompt_context = _prompt_context(row, mapping, system_context)
    item = {
        "target_name": target_name,
        "work_item_id": work_item_id,
        "lane": row["lane"],
        "subtype": row["subtype"],
        "worker": worker,
        "agent_type": mapping["agent_type"],
        "model_tier": mapping["model_tier"],
        "reasoning_effort": mapping["reasoning_effort"],
        "agent_id": agent_id,
        "timebox_minutes": int(row["timebox_minutes"]),
        "heartbeat_minutes": int(row["heartbeat_minutes"]),
        "subject_table": row["subject_table"],
        "subject_id": row["subject_id"],
        "summary": _clean_text(row["summary"] or row["title"] or row["objective"] or ""),
        "system_id": system_context["system_id"],
        "system_display_name": system_context["display_name"],
        "canonical_url": system_context["canonical_url"],
        "readiness": system_context["readiness"],
        "action_card_ids": system_context["action_card_ids"],
        "action_card_id": system_context["action_card_ids"][0] if system_context["action_card_ids"] else None,
        "prompt_context": prompt_context,
        "template_prompt": render_lane_prompt(_template_contract(conn, row)) if _human_focus_enabled(conn) else "",
        "requires_main_approval": bool(mapping.get("requires_main_approval", False)),
    }
    if row["lane"] == "cognitive_experiment":
        try:
            experiment_id = int(str(row["subtype"] or "").split(":", 1)[1])
            experiment = conn.execute(
                """SELECT question,expected_observation,control_description,
                          stop_conditions_json,budget_json,method_class
                FROM experiments WHERE id=?""",
                (experiment_id,),
            ).fetchone()
            if experiment:
                item["experiment_contract"] = {
                    "experiment_id": experiment_id,
                    "question": str(experiment[0] or "")[:500],
                    "expected_observation": str(experiment[1] or "")[:500],
                    "control_description": str(experiment[2] or "")[:500],
                    "stop_conditions": _compact_json_list(experiment[3]),
                    "budget": _compact_json_object(experiment[4]),
                    "method_class": experiment[5],
                }
        except (ValueError, sqlite3.Error):
            item["experiment_contract"] = {"error": "experiment contract unavailable"}
    item["adapters"] = {
        "claude": {
            "subagent_type": worker,
            "model": mapping["claude_model"],
            "description": f"{worker} #{work_item_id} {row['lane']}",
            "prompt": _agent_prompt(item, runtime="claude"),
        },
        "codex": {
            "agent_type": mapping["agent_type"],
            "model": mapping["codex_model"],
            "fork_context": False,
            "reasoning_effort": mapping["reasoning_effort"],
            "message": _agent_prompt(item, runtime="codex"),
        },
    }
    return item


def _skipped_item(row: sqlite3.Row, mapping: dict[str, Any] | None) -> dict[str, Any]:
    return {
        "work_item_id": int(row["id"]),
        "lane": row["lane"],
        "status": row["status"],
        "priority": int(row["priority"]),
        "decision_owner": (mapping or {}).get("decision_owner", "main_model"),
        "reason": (mapping or {}).get("reason", "lane has no automatic worker mapping"),
    }


def _agent_prompt(item: dict[str, Any], *, runtime: str) -> str:
    prefix = "遵循 .claude/agents" if runtime == "claude" else "遵循 .codex/agents"
    approval = " hypothesis 只输出 worker 草稿，最终结论必须由主模型批准。" if item["requires_main_approval"] else ""
    semantic_contract = (
        " semantic_profile lane 只做开放式攻击面语义画像和 coverage ledger 更新；"
        "画像不是固定漏洞清单，必须保留 unknown/uncovered/blocked 项，"
        "只写 compact tags/roles/flows/trust_boundaries/tech_stack evidence_refs。"
        if item["lane"] == "semantic_profile"
        else ""
    )
    logic_probe_contract = (
        " logic_probe lane 使用开放式、渐进式、低风险优先通用探针契约；"
        f"规则元数据路径: {GENERIC_PROBE_RULES_PATH}。"
        "只处理单个 work_item；只接收目标、work_item_id、必要摘要和规则路径。"
        "默认只能执行 L0/L1 低风险探针；涉及状态改变、敏感数据、弱口令/认证边界、"
        "并发/高负载或破坏性动作时必须 block 并生成 operator gate，不得自动发出。"
        "结果可选记录 compact anomaly/hypothesis，并更新 coverage_ledger 的 "
        "covered/unknown/uncovered/blocked；未测不得当作安全。"
        if item["lane"] == "logic_probe"
        else ""
    )
    cognitive_contract = (
        " cognitive_experiment 只执行一个已批准的 offline/passive experiment；"
        "必须返回 outcome(supports|refutes|inconclusive|blocked)、observation_summary、"
        "alternative_explanation 和 evidence_refs，不自行批准假设或 pivot。"
        if item["lane"] == "cognitive_experiment"
        else ""
    )
    preauth_contract = (
        " preauth_probe 只处理一个明确授权且 live 的资产；仅允许 GET/HEAD/OPTIONS，"
        "每轮最多 30 请求、默认间隔 2 秒；命中 WAF/429/451/IP 封禁立即停止并写 operator gate，"
        "禁止登录、注册、状态改变、敏感批量读取、代理轮换和 WAF 绕过。"
        if item["lane"] == "preauth_probe"
        else ""
    )
    system_line = (
        f"system_id: {item.get('system_id')}; system_display_name: {item.get('system_display_name') or ''}; "
        f"canonical_url: {item.get('canonical_url') or ''}; "
        f"readiness: {(item.get('readiness') or {}).get('state', 'unknown')}; "
        f"action_card_ids: {item.get('action_card_ids', [])}\n"
    )
    experiment_json = json.dumps(item.get("experiment_contract", {}), ensure_ascii=False, separators=(",", ":"))[:1600]
    return (
        f"{prefix}/{item['worker']}.md。\n"
        f"目标: {item['target_name']}\n"
        f"agent_id: {item['agent_id']}\n"
        f"work_item_id: {item['work_item_id']}\n"
        f"lane: {item['lane']}\n"
        f"subject: {item['subject_table']}#{item['subject_id']}\n"
        f"{system_line}"
        f"timebox_minutes: {item['timebox_minutes']}; heartbeat_minutes: {item['heartbeat_minutes']}\n"
        "要求: 先通过 TOOLS/db/work_queue.py claim 指定 work_item，"
        "再 heartbeat/partial/complete/block；只处理该 lane item。\n"
        "worker_result 契约: status(done|partial|blocked), conclusion/summary, "
        "evidence_refs, confidence(low|medium|high|unknown), blocker/block_reason, next_action; "
        "可选 risk_level/upgrade_request。\n"
        "你不独占代码库，不要回滚其他人改动。Do not request or output raw HTML/JS/Burp data. "
        f"{approval}{semantic_contract}{logic_probe_contract}{preauth_contract}{cognitive_contract}\n"
        f"experiment_contract: {experiment_json}\n"
        f"compact_context: {item['prompt_context']}"
        f"\nstrict_lane_contract: {item.get('template_prompt') or 'legacy pre-v33 compatibility'}"
    )


def _compact_json_list(raw: Any) -> list[Any]:
    try:
        value = json.loads(raw or "[]")
    except (TypeError, json.JSONDecodeError):
        return []
    return value[:10] if isinstance(value, list) else []


def _compact_json_object(raw: Any) -> dict[str, Any]:
    try:
        value = json.loads(raw or "{}")
    except (TypeError, json.JSONDecodeError):
        return {}
    return {str(k): value[k] for k in list(value)[:10]} if isinstance(value, dict) else {}


def _compact_skipped_summary(skipped: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[Any, Any], dict[str, Any]] = {}
    for item in skipped:
        key = (item.get("lane", "unknown"), item.get("reason", ""))
        group = groups.setdefault(key, {"lane": key[0], "reason": str(key[1])[:180], "count": 0, "sample_work_item_ids": []})
        group["count"] += 1
        if len(group["sample_work_item_ids"]) < 3:
            group["sample_work_item_ids"].append(item.get("work_item_id"))
    return list(groups.values())[:20]


def _system_context(conn: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
    system_id = row["system_id"]
    result: dict[str, Any] = {
        "system_id": int(system_id) if system_id is not None else None,
        "display_name": None,
        "canonical_url": None,
        "readiness": None,
        "action_card_ids": [],
    }
    if system_id is None or not _table_exists(conn, "target_systems"):
        return result
    system = conn.execute(
        "SELECT display_name,canonical_url FROM target_systems WHERE id=? AND target_name=?",
        (system_id, row["target_name"]),
    ).fetchone()
    if system:
        result["display_name"], result["canonical_url"] = system["display_name"], system["canonical_url"]
    try:
        result["readiness"] = evaluate_readiness(conn, target_name=row["target_name"], system_id=int(system_id))
    except (sqlite3.Error, KeyError, TypeError):
        result["readiness"] = {"state": "unknown"}
    if _table_exists(conn, "operator_inbox"):
        result["action_card_ids"] = [
            int(x[0])
            for x in conn.execute(
                """SELECT id FROM operator_inbox
                WHERE target_name=? AND status='open' AND system_id=? ORDER BY id LIMIT 10""",
                (row["target_name"], system_id),
            ).fetchall()
        ]
    return result


def _prompt_context(row: sqlite3.Row, mapping: dict[str, Any], system_context: dict[str, Any] | None = None) -> str:
    parts = [
        row["title"] or "",
        row["objective"] or "",
        row["summary"] or "",
    ]
    if mapping.get("requires_main_approval"):
        parts.append("worker output is a draft; main model must approve final hypothesis")
    if system_context:
        parts.append(
            "system_id={}; system={}; url={}; readiness={}; action_card_ids={}".format(
                system_context.get("system_id"),
                system_context.get("display_name") or "",
                system_context.get("canonical_url") or "",
                (system_context.get("readiness") or {}).get("state", "unknown"),
                system_context.get("action_card_ids", []),
            )
        )
    text = " | ".join(part for part in parts if part)
    return _clean_text(text)


def _template_contract(conn: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
    system = _system_context(conn, row)
    url = system.get("canonical_url") or ""
    if not url and row["lane"] == "js_reverse":
        # js_reverse subjects are js_files rows (new pipeline) or legacy
        # js_signal_clusters/pages. Resolve a concrete URL from the subject so the
        # template contract stays valid and the lane subagent gets a real target.
        subject_table = str(row["subject_table"] or "").strip()
        subject_id = str(row["subject_id"] or "").strip()
        if subject_table == "js_files" and _table_exists(conn, "js_files"):
            js = conn.execute("SELECT url, page_url FROM js_files WHERE id=?", (subject_id,)).fetchone()
            if js:
                url = str(js["url"] or js["page_url"] or "")
        elif subject_table == "js_signal_clusters" and _table_exists(conn, "js_signal_clusters"):
            cluster = conn.execute("SELECT canonical_url FROM js_signal_clusters WHERE id=?", (subject_id,)).fetchone()
            if cluster:
                url = str(cluster["canonical_url"] or "")
        elif subject_table == "pages" and _table_exists(conn, "pages"):
            page = conn.execute("SELECT url FROM pages WHERE id=?", (subject_id,)).fetchone()
            if page:
                url = str(page["url"] or "")
    if not url and row["lane"] in MAPPING_LANES:
        target = conn.execute("SELECT domain FROM targets WHERE target_name=? ORDER BY id LIMIT 1", (row["target_name"],)).fetchone()
        if target and target[0]:
            url = str(target[0])
    evidence_refs = []
    subject_table = str(row["subject_table"] or "").strip()
    subject_id = str(row["subject_id"] or "").strip()
    if (
        subject_table != "pattern_guesses"
        and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", subject_table)
        and re.fullmatch(r"[A-Za-z0-9_.:-]{1,120}", subject_id)
    ):
        evidence_refs = [f"{subject_table}:{subject_id}"]
    if row["subject_table"] == "pattern_guesses":
        try:
            guess = conn.execute(
                "SELECT seed_evidence_json FROM pattern_guesses WHERE id=? AND target_name=?",
                (row["subject_id"], row["target_name"]),
            ).fetchone()
            for item in json.loads(guess[0] if guess else "[]")[:20]:
                source_table, source_id = item.get("source_table"), item.get("source_id")
                if source_table and source_id:
                    evidence_refs.append(f"{source_table}:{source_id}")
        except (json.JSONDecodeError, sqlite3.Error, TypeError):
            evidence_refs = []
    return {
        "target_name": row["target_name"],
        "work_item_id": int(row["id"]),
        "lane": row["lane"],
        "subtype": row["subtype"],
        "subject_table": row["subject_table"],
        "subject_id": row["subject_id"],
        "url": url,
        "objective": _clean_text(row["objective"] or ""),
        "expected_output": ["status", "summary", "evidence_refs", "confidence", "next_action"],
        "timebox_minutes": int(row["timebox_minutes"]),
        "heartbeat_minutes": int(row["heartbeat_minutes"]),
        "risk_class": row["risk_class"],
        "scope_boundary": "single authorized subject; do not expand scope; bounded requests only",
        "evidence_refs": evidence_refs,
    }


def _clean_text(value: str) -> str:
    text = compact_public_text(value, max_chars=MAX_CONTEXT_CHARS)
    if "<html" in text.lower() or "<script" in text.lower():
        text = re.sub(r"<(?:html|script)\b.*", "[redacted-markup]", text, flags=re.IGNORECASE)
    redacted = re.sub(r"<[^>]{20,}>", "[redacted-markup]", text)
    redacted = re.sub(r"(https?://[^\s?#]+)\?[^\s#]*", r"\1?[redacted-query]", redacted)
    redacted = re.sub(r"https?://[^\s]{160,}", "[redacted-long-url]", redacted)
    if len(redacted) > MAX_CONTEXT_CHARS:
        return redacted[: MAX_CONTEXT_CHARS - 1].rstrip() + "…"
    return redacted


def _agent_id(target_name: str, worker: str, work_item_id: int) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", target_name).strip("-") or "target"
    digest = hashlib.sha256(f"{target_name}:{worker}:{work_item_id}".encode("utf-8")).hexdigest()[:8]
    return f"{slug}:{worker}:{work_item_id}:{digest}"


def _resolve_db_path(args: argparse.Namespace) -> Path:
    if args.db:
        return Path(args.db)
    return find_db(args.target)


def main() -> None:
    # Windows GBK console: force UTF-8 stdout so machine-readable JSON survives
    # subprocess capture (tests and dsh both decode as UTF-8).
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]  # 非常规流可能没有 reconfigure，外层已 catch AttributeError
    parser = argparse.ArgumentParser(description="Build compact read-only worker dispatch plan")
    parser.add_argument("--target", required=True, help="target_name in the DB")
    parser.add_argument("--db", help="explicit DB path")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT, help="max auto-dispatched worker tasks")
    args = parser.parse_args()

    conn = connect(_resolve_db_path(args))
    try:
        payload = build_dispatch_plan(conn, target_name=args.target, limit=max(0, args.limit))
    finally:
        conn.close()
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
