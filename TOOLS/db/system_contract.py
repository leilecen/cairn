"""Central contracts for human-in-the-loop system focus and action cards."""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

SYSTEM_SCOPES = {"owned", "authorized_vendor", "intel_only", "unknown"}
SYSTEM_LIFECYCLES = {"discovered", "mapping", "ready", "testing", "human_blocked", "parked", "completed", "excluded"}
READINESS_STATES = {"unmapped", "mapping", "ready", "blocked", "stale"}
ASSET_RELATIONSHIPS = {"primary", "api", "auth", "admin", "static", "callback", "dependency", "related"}
# 信息收集/侦察类 lane：不依赖操作员聚焦（focus）锁，可跨多系统批量收集。
# 测试/验证类 lane 仍需 active focused eligible system（见 dispatcher._human_focus_gate）。
# 与 dispatcher 现有 blocking 例外列表（source_intel/network_profile/entry_probe/js_reverse/
# semantic_profile/entry_explore/origin_verify）保持一致，补上 asset_ingest/quick_scout。
# asset_triage 是信息收集阶段的资产分诊决策 lane（主 session 决策，非测试动作），同样不受聚焦锁。
COLLECTION_LANES = {
    "asset_ingest",
    "source_intel",
    "quick_scout",
    "entry_explore",
    "entry_probe",
    "network_profile",
    "origin_verify",
    "js_reverse",
    "semantic_profile",
    "asset_triage",
}
# Keep the original operator inbox kinds valid while adding structured cards.
# Migration 033 preserves these values for existing work_queue callers.
ACTION_KINDS = {
    "focus_switch",
    "registration_required",
    "burp_action_required",
    "evidence_capture",
    "choose_asset",
    "login_required",
    "secondary_account_required",
    "role_account_required",
    "screenshot_needed",
    "confirm_scope",
    "confirm_high_risk",
    "manual_review",
    "report_decision",
    "scope_cluster_confirm",
    "blocked_decision",
}
MAX_LABEL = 160
MAX_REASON = 1000
SENSITIVE = re.compile(r"(?:cookie|authorization|bearer\s|set-cookie|http/1\.[01]|\bhost:\s|content-length:|user-agent:)", re.I)


def normalize_url(value: str) -> str:
    """Validate and normalize a public, credential-free absolute HTTP(S) URL."""
    raw = str(value or "").strip()
    parsed = urlsplit(raw)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        raise ValueError("canonical_url must be an absolute http(s) URL")
    if parsed.username or parsed.password:
        raise ValueError("canonical_url must not contain credentials")
    if any(SENSITIVE.search(part or "") for part in (parsed.path, parsed.query, parsed.fragment)):
        raise ValueError("canonical_url contains sensitive material")
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    if any(re.search(r"(?:token|secret|password|passwd|auth|cookie|session|key)", k, re.I) for k, _ in query_pairs):
        raise ValueError("canonical_url contains a sensitive query parameter")
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", urlencode(query_pairs), ""))


def _text(value: Any, *, field: str, limit: int = MAX_REASON, required: bool = False) -> str:
    text = str(value or "").strip()
    if required and not text:
        raise ValueError(f"{field} is required")
    if len(text) > limit:
        raise ValueError(f"{field} exceeds {limit} characters")
    if SENSITIVE.search(text):
        raise ValueError(f"{field} contains sensitive or raw protocol data")
    return text


def validate_system(
    *, system_key: str, display_name: str, canonical_url: str, scope_class: str, lifecycle_state: str = "discovered"
) -> dict[str, str]:
    if scope_class not in SYSTEM_SCOPES:
        raise ValueError(f"invalid system scope: {scope_class}")
    if lifecycle_state not in SYSTEM_LIFECYCLES:
        raise ValueError(f"invalid system lifecycle: {lifecycle_state}")
    return {
        "system_key": _text(system_key, field="system_key", limit=96, required=True),
        "display_name": _text(display_name, field="display_name", limit=160, required=True),
        "canonical_url": normalize_url(canonical_url),
        "scope_class": scope_class,
        "lifecycle_state": lifecycle_state,
    }


def validate_steps(steps: Any) -> list[str]:
    if isinstance(steps, str):
        steps = [steps]
    if not isinstance(steps, list) or not 1 <= len(steps) <= 8:
        raise ValueError("steps must contain 1 to 8 compact strings")
    return [_text(step, field="step", limit=240, required=True) for step in steps]


def validate_action_card(
    *,
    action_label: str,
    why_needed: str,
    steps: Any,
    expected_observation: str,
    report_back_format: str,
    url: str | None = None,
    status: str = "open",
) -> dict[str, Any]:
    if status not in {"open", "accepted", "skipped", "done", "cancelled"}:
        raise ValueError(f"invalid action status: {status}")
    result = {
        "action_label": _text(action_label, field="action_label", limit=MAX_LABEL, required=True),
        "why_needed": _text(why_needed, field="why_needed", required=True),
        "steps": validate_steps(steps),
        "expected_observation": _text(expected_observation, field="expected_observation", required=True),
        "report_back_format": _text(report_back_format, field="report_back_format", required=True),
        "status": status,
    }
    if url:
        result["url"] = normalize_url(url)
    elif status in {"done", "accepted"}:
        raise ValueError("completed action cards require a URL")
    return result


def is_active_capable(scope_class: str) -> bool:
    return scope_class in {"owned", "authorized_vendor"}


def compact_json(value: Any, *, limit: int = 1200) -> str:
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if len(raw) > limit or SENSITIVE.search(raw):
        raise ValueError("compact payload is too large or contains sensitive data")
    return raw


def human_system_label(system_id: int | None, display_name: str, canonical_url: str) -> str:
    suffix = f"[system #{system_id}]" if system_id is not None else "[system unassigned]"
    return f"{display_name}（{canonical_url}）{suffix}"
