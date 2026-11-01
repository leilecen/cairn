"""Sanitized Claude Code session telemetry and Codex handoff generation.

The monitor deliberately stores metadata, not transcript content. Hook payloads
may contain prompts, commands, file contents, HTTP material, and tool output;
only a fixed allowlist of derived fields is persisted.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import shutil
import sqlite3
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

PROJECT_ROOT = Path(__file__).resolve().parents[2]
TOOLS_DIR = PROJECT_ROOT / "TOOLS"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))
DEFAULT_STORE = PROJECT_ROOT / "metrics" / "claude-sessions.jsonl"
DEFAULT_HANDOFF_DIR = PROJECT_ROOT / "metrics" / "claude-handoffs"

SCHEMA = "claude_monitor.v1"
HANDOFF_SCHEMA = "claude_handoff.v1"
MAX_FILES = 100
MAX_NOTE_ITEMS = 12
MAX_NOTE_LENGTH = 600

_SENSITIVE_KEYS = {
    "authorization",
    "cookie",
    "cookies",
    "set-cookie",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "client_secret",
    "password",
    "passwd",
    "secret",
}


def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).astimezone().isoformat(timespec="seconds")


def _safe_scalar(value: Any, *, maximum: int = 200) -> str | None:
    if value in (None, "") or isinstance(value, bool):
        return None
    if not isinstance(value, (str, int, float)):
        return None
    text = str(value).strip()
    if not text or "\x00" in text:
        return None
    text = text.encode("utf-8", errors="replace").decode("utf-8")
    return text[:maximum]


def _safe_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return None


def _safe_signed_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return max(-1000000, min(1000000, int(value)))
    except (TypeError, ValueError):
        return None


def _json_size(value: Any) -> int:
    try:
        return len(json.dumps(value, ensure_ascii=False, default=str).encode("utf-8"))
    except (TypeError, ValueError):
        return 0


def _iter_text(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from _iter_text(child)
    elif isinstance(value, list):
        for child in value:
            yield from _iter_text(child)


def _count_sensitive_fields(value: Any) -> int:
    if isinstance(value, dict):
        return sum((1 if str(key).lower() in _SENSITIVE_KEYS else 0) + _count_sensitive_fields(child) for key, child in value.items())
    if isinstance(value, list):
        return sum(_count_sensitive_fields(child) for child in value)
    return 0


def _workspace_relative(value: Any, cwd: Any = None) -> str | None:
    raw = _safe_scalar(value, maximum=1000)
    if not raw:
        return None
    path = Path(raw)
    candidates = [path]
    if not path.is_absolute():
        candidates = []
        if cwd:
            candidates.append(Path(str(cwd)) / path)
        candidates.append(PROJECT_ROOT / path)
    for candidate in candidates:
        try:
            relative = candidate.resolve(strict=False).relative_to(PROJECT_ROOT.resolve())
        except (OSError, ValueError):
            continue
        return relative.as_posix()
    return "<outside-workspace>"


def _tool_category(tool_name: str | None) -> str | None:
    if not tool_name:
        return None
    lowered = tool_name.lower()
    if lowered in {"write", "edit", "multiedit", "notebookedit"}:
        return "write"
    if lowered in {"read", "glob", "grep", "ls"}:
        return "read"
    if lowered in {"bash", "powershell", "shell"}:
        return "shell"
    if lowered in {"agent", "task"}:
        return "agent"
    if lowered in {"websearch", "webfetch"}:
        return "web"
    if lowered.startswith("mcp__"):
        if "browser" in lowered or "chrome" in lowered:
            return "browser"
        return "mcp"
    return "other"


def _command_kind(command: Any) -> str | None:
    text = _safe_scalar(command, maximum=10000)
    if not text:
        return None
    lowered = " ".join(text.lower().split())
    if "pytest" in lowered or re.search(r"\b(npm|pnpm|yarn)\s+(run\s+)?test\b", lowered):
        return "test"
    if "sprint_tick.py" in lowered:
        return "sprint_tick"
    if "work_queue.py" in lowered:
        return "work_queue"
    if re.search(r"\bgit\s+(status|diff|log|show|branch|rev-parse)\b", lowered):
        return "git_read"
    if re.search(r"\bgit\s+(add|commit|push|merge|rebase|switch|checkout)\b", lowered):
        return "git_write"
    if re.search(r"\b(uv\s+add|npm\s+install|pnpm\s+add|yarn\s+add)\b", lowered):
        return "dependency"
    if re.search(r"\b(nmap|naabu|nuclei|ffuf|httpx|curl|wget)\b", lowered):
        return "network_probe"
    if re.search(r"(^|[\s;&|])(rg|grep|findstr|get-content|select-string)([\s;&|]|$)", lowered):
        return "search"
    return "shell"


_COUNT_PATTERNS = {
    "passed": re.compile(r"(?<!\w)(\d+)\s+passed\b", re.IGNORECASE),
    "failed": re.compile(r"(?<!\w)(\d+)\s+failed\b", re.IGNORECASE),
    "errors": re.compile(r"(?<!\w)(\d+)\s+errors?\b", re.IGNORECASE),
    "skipped": re.compile(r"(?<!\w)(\d+)\s+skipped\b", re.IGNORECASE),
}


def _test_result(*values: Any) -> dict[str, int] | None:
    text = "\n".join(chunk for value in values for chunk in _iter_text(value))
    if not text:
        return None
    result: dict[str, int] = {}
    found = False
    for name, pattern in _COUNT_PATTERNS.items():
        matches = [int(match) for match in pattern.findall(text)]
        result[name] = max(matches, default=0)
        found = found or bool(matches)
    return result if found else None


def _error_type(payload: dict[str, Any], command_kind: str | None) -> str | None:
    if str(payload.get("hook_event_name") or "") != "PostToolUseFailure":
        return None
    error = str(payload.get("error") or "").lower()
    if payload.get("is_interrupt") or "interrupt" in error or "cancel" in error:
        return "interrupted"
    if command_kind == "test" or " failed" in error and "passed" in error:
        return "test_failure"
    if "timed out" in error or "timeout" in error:
        return "timeout"
    if "permission" in error or "denied" in error or "not allowed" in error:
        return "permission"
    if "not found" in error or "not recognized" in error or "no such file" in error:
        return "not_found"
    if "network" in error or "connection" in error or "dns" in error:
        return "network"
    if "non-zero" in error or "exit" in error or "failed" in error:
        return "command_failure"
    return "unknown"


def _event_status(event_name: str) -> str:
    return {
        "SessionStart": "started",
        "SessionEnd": "ended",
        "SubagentStart": "started",
        "Stop": "done",
        "SubagentStop": "done",
        "PostToolUse": "success",
        "PostToolUseFailure": "failure",
        "PermissionDenied": "denied",
        "UserPromptSubmit": "observed",
        "PreCompact": "started",
        "PostCompact": "done",
    }.get(event_name, "observed")


def normalize_hook_event(payload: dict[str, Any]) -> dict[str, Any]:
    """Convert an arbitrary Claude hook payload to the telemetry allowlist."""
    event_name = _safe_scalar(payload.get("hook_event_name") or payload.get("event_name")) or "unknown"
    tool_name = _safe_scalar(payload.get("tool_name"))
    tool_input = payload.get("tool_input")
    tool_response = payload.get("tool_response")
    command_kind = _command_kind(tool_input.get("command") if isinstance(tool_input, dict) else None)
    effort = payload.get("effort")
    if isinstance(effort, dict):
        effort = effort.get("level")

    event: dict[str, Any] = {
        "schema": SCHEMA,
        "recorded_at": _now_iso(),
        "event_name": event_name,
        "session_id": _safe_scalar(payload.get("session_id"), maximum=128) or "unknown",
        "status": _event_status(event_name),
    }
    optional = {
        "source": _safe_scalar(payload.get("source")),
        "reason": _safe_scalar(payload.get("reason")),
        "agent_id": _safe_scalar(payload.get("agent_id"), maximum=128),
        "agent_type": _safe_scalar(payload.get("agent_type")),
        "model": _safe_scalar(payload.get("model")),
        "permission_mode": _safe_scalar(payload.get("permission_mode")),
        "effort": _safe_scalar(effort),
        "tool_name": tool_name,
        "tool_category": _tool_category(tool_name),
        "command_kind": command_kind,
        "duration_ms": _safe_int(payload.get("duration_ms")),
    }
    event.update({key: value for key, value in optional.items() if value is not None})
    hook_target = _sanitize_note_text(payload.get("target_name") or payload.get("target"))
    if hook_target:
        event["target"] = hook_target
    hook_db = payload.get("db_path") or payload.get("db")
    if hook_db:
        event["db_path"] = _safe_scalar(hook_db, maximum=1000)

    if tool_input is not None:
        event["input_bytes"] = _json_size(tool_input)
        sensitive_count = _count_sensitive_fields(tool_input)
        if sensitive_count:
            event["sensitive_field_count"] = sensitive_count
    if tool_response is not None:
        event["output_bytes"] = _json_size(tool_response)
    elif payload.get("error") is not None:
        event["output_bytes"] = len(str(payload.get("error")).encode("utf-8", errors="ignore"))

    if event_name == "UserPromptSubmit" and payload.get("prompt") is not None:
        event["prompt_bytes"] = len(str(payload.get("prompt")).encode("utf-8", errors="ignore"))
    if event_name == "SubagentStop" and payload.get("last_assistant_message") is not None:
        event["message_bytes"] = len(str(payload.get("last_assistant_message")).encode("utf-8", errors="ignore"))

    files: list[str] = []
    if isinstance(tool_input, dict):
        for key in ("file_path", "path", "notebook_path"):
            relative = _workspace_relative(tool_input.get(key), payload.get("cwd"))
            if relative and relative not in files:
                files.append(relative)
    if files:
        event["files"] = files[:MAX_FILES]

    test_result = _test_result(tool_response, payload.get("error")) if command_kind == "test" else None
    if test_result:
        event["test_result"] = test_result
    error_type = _error_type(payload, command_kind)
    if error_type:
        event["error_type"] = error_type
    return event


def _sanitize_note_text(value: Any) -> str | None:
    text = _safe_scalar(value, maximum=5000)
    if not text:
        return None
    text = re.sub(r"(?is)```.*?```", "[code omitted]", text)
    text = re.sub(
        r"(?i)\b(authorization|cookie|set-cookie|x-api-key)\s*[:=]\s*[^\s,;]+(?:\s+[^\s,;]+)?",
        r"\1: [redacted]",
        text,
    )
    text = re.sub(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [redacted]", text)
    text = re.sub(r"(https?://[^\s?#]+)\?[^\s#]+", r"\1?[redacted]", text)
    text = re.sub(r"(?<![\w.-])[A-Za-z0-9_+/=-]{32,}(?![\w.-])", "[redacted]", text)
    text = " ".join(text.split())
    return text[:MAX_NOTE_LENGTH]


def _sanitize_note_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        value = [value] if value not in (None, "") else []
    output = []
    for item in value[:MAX_NOTE_ITEMS]:
        cleaned = _sanitize_note_text(item)
        if cleaned:
            output.append(cleaned)
    return output


def _sanitize_decision_notes(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    output = []
    for raw in value[:MAX_NOTE_ITEMS]:
        if not isinstance(raw, dict):
            continue
        # 值类型混合：id 类字段是 int，其余是 str / list[str]
        item: dict[str, Any] = {}
        for key in ("hunt_session_id", "attack_thread_id", "experiment_id", "decision_type", "chosen_action"):
            if raw.get(key) not in (None, ""):
                item[key] = _safe_int(raw[key]) if key.endswith("_id") else _sanitize_note_text(raw[key])
        for key in ("candidate_actions", "rationale", "expected_change", "actual_change"):
            if key == "candidate_actions":
                item[key] = _sanitize_note_list(raw.get(key))
            elif raw.get(key):
                item[key] = _sanitize_note_text(raw[key])
        if item:
            output.append(item)
    return output


def _sanitize_cognitive_summary(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    # 同一 dict 里混放 bool / int / str / list / 嵌套 dict，必须显式 Any，否则分支赋值全部报错
    output: dict[str, Any] = {}
    for key in (
        "active_hunt_session",
        "hypotheses_changed",
        "experiments_completed",
        "pivot_decisions",
        "repeated_directions",
        "missed_gates",
    ):
        if key in value:
            item = value[key]
            if isinstance(item, (int, float, bool)):
                output[key] = item
            elif isinstance(item, (list, dict)):
                output[key] = item if isinstance(item, dict) else [_sanitize_note_text(x) for x in item[:MAX_NOTE_ITEMS]]
            else:
                output[key] = _sanitize_note_text(item)
    for key in (
        "pivot_recommended",
        "broad_queue_dominance",
        "repeated_inconclusive_direction",
        "observation_without_evidence",
        "experiment_without_expected_observation",
        "new_lane_not_consumed",
    ):
        if isinstance(value.get(key), bool):
            output[key] = value[key]
    if isinstance(value.get("unknown_delta"), dict):
        delta = value["unknown_delta"]
        output["unknown_delta"] = {
            key: _safe_signed_int(delta.get(key)) for key in ("before", "after", "delta") if delta.get(key) is not None
        }
    if value.get("pivot_reason"):
        output["pivot_reason"] = _sanitize_note_text(value["pivot_reason"])
    return output


def normalize_session_note(payload: dict[str, Any]) -> dict[str, Any]:
    event: dict[str, Any] = {
        "schema": SCHEMA,
        "recorded_at": _now_iso(),
        "event_name": "SessionNote",
        "session_id": _safe_scalar(payload.get("session_id"), maximum=128) or "unknown",
        "status": "noted",
        "decisions": _sanitize_note_list(payload.get("decisions")),
        "blockers": _sanitize_note_list(payload.get("blockers")),
        "next_actions": _sanitize_note_list(payload.get("next_actions")),
        "work_items": [
            item
            for raw in ((payload["work_items"] if isinstance(payload.get("work_items"), list) else [])[:MAX_NOTE_ITEMS])
            if (item := _safe_scalar(raw, maximum=64))
        ],
        "decision_notes": _sanitize_decision_notes(payload.get("decision_notes")),
    }
    target = _sanitize_note_text(payload.get("target"))
    summary = _sanitize_note_text(payload.get("summary"))
    if target:
        event["target"] = target
    if summary:
        event["summary"] = summary
    cognitive = _sanitize_cognitive_summary(payload.get("cognitive_summary"))
    if cognitive:
        event["cognitive_summary"] = cognitive
    current_system = payload.get("current_system")
    if isinstance(current_system, dict):
        event["current_system"] = {
            "id": _safe_int(current_system.get("id")),
            "display_name": _sanitize_note_text(current_system.get("display_name")),
            "canonical_url": _sanitize_note_text(current_system.get("canonical_url")),
        }
    if isinstance(payload.get("human_brief"), dict):
        brief = payload["human_brief"]
        event["human_brief"] = {
            key: brief[key] for key in ("phase", "readiness", "operator_actions") if key in brief and _json_size(brief[key]) <= 3000
        }
    return event


def workspace_snapshot(cwd: Any) -> dict[str, Any] | None:
    raw = _safe_scalar(cwd, maximum=1000)
    if not raw:
        return None
    path = Path(raw)
    try:
        path.resolve(strict=False).relative_to(PROJECT_ROOT.resolve())
    except (OSError, ValueError):
        return None
    git_executable = shutil.which("git")
    if not git_executable:
        return None
    try:
        head = subprocess.run(  # noqa: S603 - fixed git argv in validated workspace cwd
            [git_executable, "rev-parse", "--short", "HEAD"],
            cwd=path,
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
        status = subprocess.run(  # noqa: S603 - fixed git argv in validated workspace cwd
            [git_executable, "status", "--porcelain=v1", "-z"],
            cwd=path,
            capture_output=True,
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if status.returncode != 0:
        return None
    raw_entries = [entry for entry in status.stdout.split(b"\0") if entry]
    files: list[str] = []
    untracked = 0
    statuses: Counter[str] = Counter()
    for raw_entry in raw_entries:
        entry = raw_entry.decode("utf-8", errors="replace")
        code = entry[:2]
        name = entry[3:] if len(entry) > 3 else ""
        if code == "??":
            untracked += 1
        statuses[code] += 1
        if name and len(files) < MAX_FILES:
            files.append(Path(name).as_posix())
    digest = hashlib.sha256(status.stdout).hexdigest()[:16]
    return {
        "head": head.stdout.strip()[:16] if head.returncode == 0 else "unknown",
        "dirty_count": len(raw_entries),
        "untracked_count": untracked,
        "status_counts": dict(sorted(statuses.items())),
        "status_digest": digest,
        "files": files,
        "files_truncated": len(raw_entries) > len(files),
    }


def append_event(event: dict[str, Any], store: Path = DEFAULT_STORE) -> None:
    store.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n"
    with store.open("a", encoding="utf-8") as handle:
        handle.write(line)


def load_events(store: Path = DEFAULT_STORE) -> list[dict[str, Any]]:
    if not store.exists():
        return []
    events = []
    with store.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(event, dict) and event.get("schema") == SCHEMA:
                events.append(event)
    return events


def _latest_session_id(events: list[dict[str, Any]]) -> str | None:
    for event in reversed(events):
        session_id = event.get("session_id")
        if session_id and session_id != "unknown":
            return str(session_id)
    return None


def _feedback(
    *,
    session_events: list[dict[str, Any]],
    note: dict[str, Any] | None,
    files: list[str],
    test_events: list[dict[str, Any]],
) -> list[dict[str, str]]:
    feedback: list[dict[str, str]] = []

    def add(rule_id: str, severity: str, message: str, action: str) -> None:
        feedback.append({"rule_id": rule_id, "severity": severity, "message": message, "action": action})

    if note is None:
        add(
            "missing_session_note",
            "medium",
            "会话没有 compact 语义总结，工具轨迹无法解释实现意图。",
            "结束前记录 summary、decisions、blockers 和 next_actions。",
        )
    decision_notes = (note or {}).get("decision_notes") or []
    if (note is not None) and (note.get("work_items") and not decision_notes):
        add(
            "work_without_hypothesis",
            "medium",
            "会话有工作项但没有认知决策记录。",
            "为派发记录假设、预期观察和选择理由。",
        )
    cognitive = (note or {}).get("cognitive_summary") or {}
    if cognitive.get("pivot_recommended") is True and not any(
        str(x.get("decision_type")) in {"pivot", "park"} for x in decision_notes if isinstance(x, dict)
    ):
        add(
            "missed_pivot",
            "high",
            "认知摘要建议 pivot，但未记录 park/pivot 决策。",
            "停止重复方向并记录保留证据的转向决策。",
        )
    unknown_delta = cognitive.get("unknown_delta")
    if isinstance(unknown_delta, dict):
        unknown_delta = unknown_delta.get("delta")
    if unknown_delta is not None and isinstance(unknown_delta, (int, float)) and unknown_delta >= 0:
        add("unknown_not_reduced", "low", "本次会话没有记录 unknown 下降。", "下一实验应明确要减少的 unknown。")
    if cognitive.get("broad_queue_dominance") is True:
        add(
            "broad_queue_dominance",
            "high",
            "广泛队列仍压过 focused session。",
            "停车 broad asset_triage，仅派发已批准的 focused experiment。",
        )
    if cognitive.get("repeated_inconclusive_direction") is True:
        add(
            "repeated_inconclusive_direction",
            "high",
            "同一方向连续产生 inconclusive 结果。",
            "停止参数变体，记录 park/pivot 并保留现有证据。",
        )
    if cognitive.get("observation_without_evidence") is True:
        add(
            "observation_without_evidence",
            "high",
            "实验宣称有观察结论但没有 evidence refs。",
            "将结论降级为 inconclusive 并补充可追溯证据。",
        )
    if cognitive.get("experiment_without_expected_observation") is True:
        add(
            "experiment_without_expected_observation",
            "high",
            "实验没有定义可验证的 expected observation。",
            "暂停派发并补齐可证伪的预期观察。",
        )
    if cognitive.get("new_lane_not_consumed") is True:
        add(
            "new_lane_not_consumed",
            "medium",
            "认知 lane 已建立但当前会话没有实际消费。",
            "检查 approval、work item 关联和 dispatcher gate。",
        )
    brief = (note or {}).get("human_brief") or {}
    if brief.get("phase") == "testing" and isinstance(brief.get("readiness"), dict) and brief["readiness"].get("state") != "ready":
        add(
            "testing_before_recon_ready",
            "high",
            "会话在 recon 未 ready 前进入 testing。",
            "先完成同系统侦察画像或生成明确人工 blocker。",
        )
    if (note or {}).get("focus_db_divergence"):
        add(
            "focus_db_conversation_divergence",
            "high",
            "session note 的系统焦点与 DB 当前焦点不一致。",
            "以 DB 当前 human brief 为准，废弃过期口头焦点。",
        )
    if brief.get("operator_task_without_action_card"):
        add(
            "operator_task_without_action_card",
            "high",
            "存在未关联行动卡的 operator task。",
            "为该任务补齐完整 URL、步骤、预期和回填格式。",
        )
    if (note or {}).get("pivot_without_focus_event"):
        add(
            "pivot_without_focus_event",
            "high",
            "出现跨系统或转向动作，但没有原子 focus decision。",
            "先记录 operator-confirmed focus/switch，再继续派发。",
        )
    if (note or {}).get("burp_call_without_burp_action"):
        add(
            "burp_call_without_burp_action",
            "high",
            "监控记录了 Burp 动作，但 DB 没有对应 burp_action。",
            "先登记 DB action 并关联 work item，再执行工具动作。",
        )
    if (note or {}).get("handoff_stale_work_item") or (note or {}).get("stale_work_items"):
        add(
            "handoff_stale_work_item",
            "medium",
            "handoff 的下一步仍指向已完成或取消的 work item。",
            "刷新 DB 状态后改写 next_actions，禁止重派旧任务。",
        )
    if brief.get("broad_queue_after_focus") or cognitive.get("broad_queue_after_focus"):
        add(
            "broad_queue_after_focus",
            "high",
            "焦点激活后仍有无关 broad queue 保持 active。",
            "按当前 system_id reconciliation 并停车无关队列。",
        )
    if (note or {}).get("long_human_silence"):
        add(
            "long_human_silence",
            "medium",
            "长时间有人机阻塞但没有可见状态更新。",
            "生成 compact operator card，明确等待、补证据或暂停。",
        )
    if (note or {}).get("operator_gate_dispatch_conflict"):
        add(
            "operator_gate_dispatch_conflict",
            "high",
            "operator gate 未解除时仍有依赖任务进入派发。",
            "dispatcher 最终边界应跳过任务并保留 gate。",
        )
    if (
        len(session_events) >= 20
        and len(decision_notes) == 0
        and sum(1 for event in session_events if event.get("event_name") == "PostToolUse") >= 15
    ):
        add(
            "main_session_mechanical_overrun",
            "medium",
            "主 session 机械调用明显多于决策记录。",
            "把批量动作下沉到 bounded worker，并按 tick 记录选择理由。",
        )
    failures = [event for event in session_events if event.get("status") == "failure"]
    failure_groups = Counter((event.get("tool_name"), event.get("error_type")) for event in failures)
    if any(count >= 2 for count in failure_groups.values()):
        add(
            "repeated_tool_failure",
            "high",
            "同类工具错误在一次会话中重复出现。",
            "第二次同类失败后停止重试，先诊断环境、参数或权限。",
        )
    if files and not test_events:
        add(
            "changes_without_tests",
            "high",
            "会话修改了文件，但没有观察到测试命令。",
            "至少运行与改动直接相关的定向测试并记录结果。",
        )
    failed_tests = sum(
        (event.get("test_result") or {}).get("failed", 0) + (event.get("test_result") or {}).get("errors", 0) for event in test_events
    )
    if failed_tests:
        add(
            "tests_not_green",
            "high",
            "会话结束时仍记录到测试失败。",
            "在交接中说明失败归属，修复本次回归或明确标记既有失败。",
        )
    max_output = max((int(event.get("output_bytes") or 0) for event in session_events), default=0)
    if max_output >= 100_000:
        add(
            "oversized_tool_output",
            "medium",
            "单次工具输出超过 100 KB，可能挤占模型上下文。",
            "改用 compact 查询、分页、计数或落盘后只读取摘要。",
        )
    denied = sum(1 for event in session_events if event.get("status") == "denied")
    if denied:
        add(
            "permission_denied",
            "medium",
            "会话中出现工具权限拒绝。",
            "核对权限边界；不要通过环境变量或替代命令静默绕过。",
        )
    target = (note or {}).get("target")
    work_items = (note or {}).get("work_items") or []
    if not target and not work_items:
        add(
            "unscoped_session",
            "low",
            "交接中没有目标名或 work_item 标识。",
            "涉及 SRC 管线时显式记录 target_name 和 work_item_id。",
        )
    if not any(event.get("event_name") == "SessionEnd" for event in session_events):
        add(
            "session_not_closed",
            "low",
            "当前交接来自 Stop 快照，Claude Code 会话尚未触发 SessionEnd。",
            "会话退出后重新读取 latest handoff 获取最终快照。",
        )
    return feedback


def build_handoff(events: list[dict[str, Any]], session_id: str, *, db_path: str | Path | None = None) -> dict[str, Any]:
    session_events = [event for event in events if str(event.get("session_id")) == str(session_id)]
    if db_path is None:
        event_db = next((event.get("db_path") for event in reversed(session_events) if event.get("db_path")), None)
        db_path = event_db
    notes = [event for event in session_events if event.get("event_name") == "SessionNote"]
    note = notes[-1] if notes else None
    tool_events = [
        event for event in session_events if event.get("event_name") in {"PostToolUse", "PostToolUseFailure", "PermissionDenied"}
    ]
    test_events = [event for event in tool_events if event.get("command_kind") == "test"]
    files = sorted({str(path) for event in tool_events for path in (event.get("files") or []) if path and path != "<outside-workspace>"})[
        :MAX_FILES
    ]
    starts = [event for event in session_events if event.get("event_name") == "SessionStart"]
    ends = [event for event in session_events if event.get("event_name") == "SessionEnd"]
    models = [event.get("model") for event in session_events if event.get("model")]
    efforts = [event.get("effort") for event in session_events if event.get("effort")]
    agents = sorted(
        {
            str(event.get("agent_type") or event.get("agent_id"))
            for event in session_events
            if event.get("agent_type") or event.get("agent_id")
        }
    )
    by_tool = Counter(str(event.get("tool_name") or "unknown") for event in tool_events)
    by_category = Counter(str(event.get("tool_category") or "unknown") for event in tool_events)
    command_kinds = Counter(str(event.get("command_kind")) for event in tool_events if event.get("command_kind"))
    verification = {
        "tests_run": len(test_events),
        "passed": sum((event.get("test_result") or {}).get("passed", 0) for event in test_events),
        "failed": sum((event.get("test_result") or {}).get("failed", 0) for event in test_events),
        "errors": sum((event.get("test_result") or {}).get("errors", 0) for event in test_events),
        "skipped": sum((event.get("test_result") or {}).get("skipped", 0) for event in test_events),
    }
    # 混合结构（str/int/list/dict），显式 Any；否则 842 行的 `+ [..]` 与 844 行的下标写入都会报错
    handoff: dict[str, Any] = {
        "schema": HANDOFF_SCHEMA,
        "generated_at": _now_iso(),
        "session_id": session_id,
        "started_at": starts[0].get("recorded_at") if starts else None,
        "ended_at": ends[-1].get("recorded_at") if ends else None,
        "end_reason": ends[-1].get("reason") if ends else None,
        "model": models[-1] if models else "unknown",
        "effort": efforts[-1] if efforts else "unknown",
        "target": (note or {}).get("target")
        or next((event.get("target") for event in reversed(session_events) if event.get("target")), None),
        "summary": (note or {}).get("summary"),
        "decisions": (note or {}).get("decisions") or [],
        "blockers": (note or {}).get("blockers") or [],
        "next_actions": (note or {}).get("next_actions") or [],
        "work_items": (note or {}).get("work_items") or [],
        "decision_notes": (note or {}).get("decision_notes") or [],
        "cognitive_summary": (note or {}).get("cognitive_summary") or {},
        "files_changed": files,
        "agents": agents,
        "tool_summary": {
            "total": len(tool_events),
            "successes": sum(1 for event in tool_events if event.get("status") == "success"),
            "failures": sum(1 for event in tool_events if event.get("status") == "failure"),
            "denied": sum(1 for event in tool_events if event.get("status") == "denied"),
            "duration_ms": sum(int(event.get("duration_ms") or 0) for event in tool_events),
            "output_bytes": sum(int(event.get("output_bytes") or 0) for event in tool_events),
            "max_output_bytes": max((int(event.get("output_bytes") or 0) for event in tool_events), default=0),
            "by_tool": dict(sorted(by_tool.items())),
            "by_category": dict(sorted(by_category.items())),
            "command_kinds": dict(sorted(command_kinds.items())),
        },
        "verification": verification,
        "workspace_start": starts[0].get("workspace") if starts else None,
        "workspace_end": ends[-1].get("workspace") if ends else None,
    }
    if db_path:
        try:
            from db.human_brief import build_human_brief

            target = handoff.get("target")
            if not target:
                handoff["db_state_unavailable"] = True
            else:
                conn = sqlite3.connect(str(db_path))
                conn.row_factory = sqlite3.Row
                brief = build_human_brief(conn, target_name=target)
                handoff["human_brief"] = brief
                if note is not None:
                    note["human_brief"] = brief
                handoff["current_system"] = brief.get("current_system")
                handoff["focus_session"] = brief.get("focus_session")
                handoff["readiness"] = brief.get("readiness")
                note_system = (note or {}).get("current_system") or {}
                db_system = brief.get("current_system") or {}
                if note_system.get("id") != db_system.get("id") and (note_system.get("id") or db_system.get("id") is None):
                    handoff["focus_consistency"] = "db_wins"
                    handoff["stale_notes"] = ["session note system focus differs from DB current system or no longer exists"]
                    if note is not None:
                        note["focus_db_divergence"] = True
                note_text = " ".join(str(x) for x in ((note or {}).get("next_actions") or []) + ((note or {}).get("work_items") or []))
                stale_ids = []
                for raw_id in re.findall(r"(?:#|work[_ -]?item\s*)(\d+)", note_text, flags=re.I):
                    row = conn.execute("SELECT id,status FROM work_items WHERE target_name=? AND id=?", (target, int(raw_id))).fetchone()
                    if row and row["status"] in {"done", "cancelled", "failed"}:
                        stale_ids.append(int(raw_id))
                if stale_ids:
                    handoff["stale_work_items"] = stale_ids
                    handoff["stale_notes"] = (handoff.get("stale_notes") or []) + [f"stale work items: {','.join(map(str, stale_ids))}"]
                    if note is not None:
                        note["handoff_stale_work_item"] = True
                    handoff["next_actions"] = [
                        item for item in handoff.get("next_actions", []) if not any(f"#{sid}" in str(item) for sid in stale_ids)
                    ]
                    handoff["next_actions"] += brief.get("readiness", {}).get("next_safe_actions", [])[:3]
                if not db_system:
                    handoff["next_actions"] = (
                        brief.get("readiness", {}).get("next_safe_actions")
                        or brief.get("operator_choices")
                        or ["先确认 candidate_systems 中的系统，再激活 focus"]
                    )
                conn.close()
        except (OSError, sqlite3.Error, ValueError):
            handoff["db_state_unavailable"] = True
    handoff["feedback"] = _feedback(
        session_events=session_events,
        note=note,
        files=files,
        test_events=test_events,
    )
    return handoff


def _safe_session_filename(session_id: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]", "_", session_id)[:100]
    return cleaned or hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:16]


def write_handoff(handoff: dict[str, Any], handoff_dir: Path = DEFAULT_HANDOFF_DIR) -> Path:
    handoff_dir.mkdir(parents=True, exist_ok=True)
    content = json.dumps(handoff, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    session_path = handoff_dir / f"{_safe_session_filename(str(handoff['session_id']))}.json"
    for path in (session_path, handoff_dir / "latest.json"):
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(content, encoding="utf-8")
        temporary.replace(path)
    return session_path


def load_latest_handoff(handoff_dir: Path = DEFAULT_HANDOFF_DIR) -> dict[str, Any] | None:
    path = handoff_dir / "latest.json"
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) and payload.get("schema") == HANDOFF_SCHEMA else None


def record_hook_from_stdin(
    *,
    store: Path = DEFAULT_STORE,
    handoff_dir: Path = DEFAULT_HANDOFF_DIR,
    db_path: Path | None = None,
    resolve_db_from_payload: bool = False,
) -> dict[str, Any] | None:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    if db_path is None and (resolve_db_from_payload or payload.get("db_path") or payload.get("db")):
        db_path = _db_path_from_hook_payload(payload)
    session_id = str(payload.get("session_id") or "unknown")
    if db_path is None and session_id != "unknown":
        db_path = _load_session_db(handoff_dir, session_id)
    if db_path is not None and session_id != "unknown":
        _remember_session_db(handoff_dir, session_id, db_path)
    event = normalize_hook_event(payload)
    if event.get("event_name") in {"SessionStart", "SessionEnd"}:
        snapshot = workspace_snapshot(payload.get("cwd"))
        if snapshot:
            event["workspace"] = snapshot
    append_event(event, store)
    if event.get("event_name") in {"Stop", "SessionEnd"} and event.get("session_id") != "unknown":
        write_handoff(build_handoff(load_events(store), str(event["session_id"]), db_path=db_path), handoff_dir)
    return event


def _db_path_from_hook_payload(payload: dict[str, Any]) -> Path | None:
    """Use only an explicit hook DB path or target name; never infer from env."""
    explicit = payload.get("db_path") or payload.get("db")
    if explicit:
        path = Path(str(explicit)).expanduser()
        return path if path.exists() else None
    target = payload.get("target_name") or payload.get("target")
    if not target:
        return None
    try:
        from db.db_utils import find_db

        path = find_db(str(target))
        return Path(path) if path else None
    except (OSError, RuntimeError, SystemExit):
        return None


def _session_db_map_path(handoff_dir: Path) -> Path:
    return handoff_dir / "session-db-map.json"


def _remember_session_db(handoff_dir: Path, session_id: str, db_path: Path) -> None:
    try:
        handoff_dir.mkdir(parents=True, exist_ok=True)
        path = _session_db_map_path(handoff_dir)
        data = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
        data[str(session_id)] = str(db_path)
        path.write_text(json.dumps(data, ensure_ascii=False, sort_keys=True), encoding="utf-8")
    except (OSError, json.JSONDecodeError):
        return


def _load_session_db(handoff_dir: Path, session_id: str) -> Path | None:
    try:
        path = _session_db_map_path(handoff_dir)
        data = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
        value = data.get(str(session_id))
        candidate = Path(value) if value else None
        return candidate if candidate and candidate.exists() else None
    except (OSError, json.JSONDecodeError, TypeError):
        return None


def record_note_from_stdin(
    *, store: Path = DEFAULT_STORE, handoff_dir: Path = DEFAULT_HANDOFF_DIR, db_path: Path | None = None
) -> dict[str, Any] | None:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    return record_note(payload, store=store, handoff_dir=handoff_dir, db_path=db_path)


def record_note(
    payload: dict[str, Any],
    *,
    store: Path = DEFAULT_STORE,
    handoff_dir: Path = DEFAULT_HANDOFF_DIR,
    db_path: Path | None = None,
) -> dict[str, Any]:
    if not payload.get("session_id"):
        payload = dict(payload)
        payload["session_id"] = _latest_session_id(load_events(store)) or "unknown"
    session_id = str(payload.get("session_id") or "unknown")
    if db_path is None:
        target = payload.get("target_name") or payload.get("target")
        if target:
            try:
                from db.db_utils import find_db

                db_path = Path(find_db(str(target)))
            except (OSError, RuntimeError, SystemExit, TypeError, ValueError):
                db_path = None
    if db_path is not None and session_id != "unknown":
        _remember_session_db(handoff_dir, session_id, Path(db_path))
    event = normalize_session_note(payload)
    append_event(event, store)
    if event.get("session_id") != "unknown":
        resolved_db = db_path or _load_session_db(handoff_dir, str(event["session_id"]))
        write_handoff(build_handoff(load_events(store), str(event["session_id"]), db_path=resolved_db), handoff_dir)
    return event


def _render_markdown(handoff: dict[str, Any]) -> str:
    lines = [
        f"# Claude Code 交接：{handoff.get('session_id', 'unknown')}",
        "",
        f"- 目标：{handoff.get('target') or '未记录'}",
        f"- 模型：{handoff.get('model') or 'unknown'} / {handoff.get('effort') or 'unknown'}",
        f"- 状态：{'已结束' if handoff.get('ended_at') else 'Stop 快照'}",
        f"- 工具：{handoff.get('tool_summary', {}).get('total', 0)} 次，失败 {handoff.get('tool_summary', {}).get('failures', 0)} 次",
        f"- 测试：{handoff.get('verification', {}).get('tests_run', 0)} 次，"
        f"{handoff.get('verification', {}).get('passed', 0)} passed / "
        f"{handoff.get('verification', {}).get('failed', 0)} failed",
        "",
        "## 会话结论",
        "",
        handoff.get("summary") or "未记录 session note。",
    ]
    for title, key in (
        ("决策", "decisions"),
        ("阻塞", "blockers"),
        ("下一步", "next_actions"),
        ("修改文件", "files_changed"),
    ):
        values = handoff.get(key) or []
        if values:
            lines.extend(["", f"## {title}", "", *[f"- {value}" for value in values]])
    feedback = handoff.get("feedback") or []
    if feedback:
        lines.extend(["", "## 系统优化反馈", ""])
        lines.extend(f"- [{item.get('severity')}] {item.get('rule_id')}: {item.get('message')} {item.get('action')}" for item in feedback)
    return "\n".join(lines) + "\n"


def _resolve_handoff(args: argparse.Namespace) -> dict[str, Any] | None:
    events = load_events(args.store)
    session_id = args.session or _latest_session_id(events)
    if not session_id:
        return load_latest_handoff(args.handoff_dir)
    return build_handoff(events, session_id, db_path=args.db_path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Record sanitized Claude Code telemetry and produce compact Codex handoffs.")
    sub = parser.add_subparsers(dest="command", required=True)

    record = sub.add_parser("record-hook", help="Read a Claude hook payload from stdin.")
    record.add_argument("--store", type=Path, default=DEFAULT_STORE)
    record.add_argument("--handoff-dir", type=Path, default=DEFAULT_HANDOFF_DIR)
    record.add_argument("--db", dest="db_path", type=Path)
    record.add_argument("--db-from-payload", action="store_true")

    note = sub.add_parser("note", help="Read a compact semantic session note from stdin.")
    note.add_argument("--store", type=Path, default=DEFAULT_STORE)
    note.add_argument("--handoff-dir", type=Path, default=DEFAULT_HANDOFF_DIR)
    note.add_argument("--db", dest="db_path", type=Path)
    note.add_argument("--session")
    note.add_argument("--target")
    note.add_argument("--summary")
    note.add_argument("--decision", action="append", default=[])
    note.add_argument("--blocker", action="append", default=[])
    note.add_argument("--next-action", action="append", default=[])
    note.add_argument("--work-item", action="append", default=[])

    decision = sub.add_parser("decision", help="Record one compact cognitive decision note.")
    decision.add_argument("--store", type=Path, default=DEFAULT_STORE)
    decision.add_argument("--handoff-dir", type=Path, default=DEFAULT_HANDOFF_DIR)
    decision.add_argument("--db", dest="db_path", type=Path)
    decision.add_argument("--session", required=True)
    decision.add_argument("--target")
    decision.add_argument("--decision-type", required=True)
    decision.add_argument("--chosen-action", required=True)
    decision.add_argument("--rationale", required=True)
    decision.add_argument("--expected-change", default="")
    decision.add_argument("--actual-change", default="")
    decision.add_argument("--hunt-session-id", type=int)
    decision.add_argument("--attack-thread-id", type=int)
    decision.add_argument("--experiment-id", type=int)

    handoff = sub.add_parser("handoff", help="Render a session handoff; defaults to the latest session.")
    handoff.add_argument("--store", type=Path, default=DEFAULT_STORE)
    handoff.add_argument("--handoff-dir", type=Path, default=DEFAULT_HANDOFF_DIR)
    handoff.add_argument("--db", dest="db_path", type=Path)
    handoff.add_argument("--session")
    handoff.add_argument("--json", action="store_true")

    feedback = sub.add_parser("feedback", help="Print only optimization feedback for a session.")
    feedback.add_argument("--store", type=Path, default=DEFAULT_STORE)
    feedback.add_argument("--handoff-dir", type=Path, default=DEFAULT_HANDOFF_DIR)
    feedback.add_argument("--db", dest="db_path", type=Path)
    feedback.add_argument("--session")
    feedback.add_argument("--json", action="store_true")

    args = parser.parse_args(argv)
    if args.command == "record-hook":
        record_hook_from_stdin(
            store=args.store,
            handoff_dir=args.handoff_dir,
            db_path=args.db_path,
            resolve_db_from_payload=args.db_from_payload,
        )
        return 0
    if args.command == "note":
        direct_payload = {
            "session_id": args.session,
            "target": args.target,
            "summary": args.summary,
            "decisions": args.decision,
            "blockers": args.blocker,
            "next_actions": args.next_action,
            "work_items": args.work_item,
        }
        if any(value for key, value in direct_payload.items() if key not in {"decisions", "blockers", "next_actions", "work_items"}) or any(
            direct_payload[key] for key in ("decisions", "blockers", "next_actions", "work_items")
        ):
            record_note(direct_payload, store=args.store, handoff_dir=args.handoff_dir, db_path=args.db_path)
        else:
            record_note_from_stdin(store=args.store, handoff_dir=args.handoff_dir, db_path=args.db_path)
        return 0
    if args.command == "decision":
        payload = {
            "session_id": args.session,
            "target": args.target,
            "decision_notes": [
                {
                    "hunt_session_id": args.hunt_session_id,
                    "attack_thread_id": args.attack_thread_id,
                    "experiment_id": args.experiment_id,
                    "decision_type": args.decision_type,
                    "chosen_action": args.chosen_action,
                    "rationale": args.rationale,
                    "expected_change": args.expected_change,
                    "actual_change": args.actual_change,
                }
            ],
        }
        record_note(payload, store=args.store, handoff_dir=args.handoff_dir, db_path=args.db_path)
        return 0

    resolved = _resolve_handoff(args)
    if resolved is None:
        print("No Claude Code session telemetry found.", file=sys.stderr)
        return 1
    if args.command == "feedback":
        output: Any = resolved.get("feedback") or []
        if args.json:
            print(json.dumps(output, ensure_ascii=False, indent=2))
        else:
            for item in output:
                print(f"[{item.get('severity')}] {item.get('rule_id')}: {item.get('message')} {item.get('action')}")
        return 0
    if args.json:
        print(json.dumps(resolved, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(_render_markdown(resolved), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
