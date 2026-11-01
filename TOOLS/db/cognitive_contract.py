"""Shared vocabulary and compact validation for the cognitive loop."""

from __future__ import annotations

from typing import Any

AUTH_STATES = {
    "public",
    "auth_redirect",
    "auth_required",
    "restricted",
    "waf_blocked",
    "not_found",
    "spa_shell",
    "unknown",
    "passive_hint",
}
OUTCOMES = {"supports", "refutes", "inconclusive", "blocked", "not_run"}
DECISION_TYPES = {"focus", "dispatch", "continue", "park", "pivot", "escalate", "stop"}
OPERATOR_KINDS = {
    "choose_asset",
    "login_required",
    "secondary_account_required",
    "role_account_required",
    "screenshot_needed",
    "confirm_scope",
    "confirm_high_risk",
    "manual_review",
    "report_decision",
}
AUTH_ALIASES = {
    "login_redirect": "auth_redirect",
    "blocked_by_waf": "waf_blocked",
    "login_like": "auth_required",
    "ok_unknown": "unknown",
    "other": "unknown",
}


def normalize_auth_state(value: Any, *, has_response_evidence: bool = True) -> str:
    state = str(value or "unknown").strip().lower()
    state = AUTH_ALIASES.get(state, state)
    if state not in AUTH_STATES:
        state = "unknown"
    if not has_response_evidence and state in {
        "public",
        "auth_redirect",
        "auth_required",
        "restricted",
        "waf_blocked",
        "spa_shell",
    }:
        return "passive_hint"
    return state


def operator_kind_for_auth_state(state: Any) -> str:
    state = normalize_auth_state(state)
    return {
        "waf_blocked": "manual_review",
        "auth_redirect": "login_required",
        "auth_required": "login_required",
        "restricted": "manual_review",
    }.get(state, "manual_review")


def normalize_outcome(value: Any, *, evidence_refs: list[Any] | None = None) -> str:
    outcome = str(value or "not_run").strip().lower()
    if outcome not in OUTCOMES:
        raise ValueError(f"invalid experiment outcome: {outcome}")
    if outcome in {"supports", "refutes"} and not evidence_refs:
        return "inconclusive"
    return outcome


def require_falsifiable(
    *, question: str, expected_observation: str, refuting_observation: str = "", alternatives: list[Any] | None = None
) -> None:
    if not str(question or "").strip() or not str(expected_observation or "").strip():
        raise ValueError("question and expected_observation are required")
    if alternatives is not None and not alternatives:
        raise ValueError("at least one alternative explanation is required")


def compact_json_list(value: Any, limit: int = 20) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        value = [value]
    return value[:limit]
