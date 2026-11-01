"""Provider-neutral compact worker result contract.

This module intentionally has no DB dependency.  Claude Code and Codex workers
can both produce the same small JSON shape, and queue/event helpers can call
``normalize_worker_result`` before writing summaries into the blackboard.
"""

from __future__ import annotations

import re
from typing import Any

VALID_STATUSES = {"done", "partial", "blocked"}
VALID_CONFIDENCE = {"low", "medium", "high", "unknown"}
VALID_RISK_LEVELS = {"low", "medium", "high", "critical", "unknown"}
VALID_OUTCOMES = {"supports", "refutes", "inconclusive", "blocked", "not_run"}
MAX_TEXT_CHARS = 800
MAX_LIST_ITEMS = 20
MAX_INSIGHT_PROPOSALS = 3
MAX_PUBLIC_TEXT_CHARS = 800

RAW_DATA_PATTERNS = [
    re.compile(r"<!doctype\s+html\b", re.IGNORECASE),
    re.compile(r"<html\b", re.IGNORECASE),
    re.compile(r"<script\b", re.IGNORECASE),
    re.compile(r"\bHTTP/[12](?:\.\d)?\s+\d{3}\b", re.IGNORECASE),
    re.compile(r"\b(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+\S+\s+HTTP/[12](?:\.\d)?\b", re.IGNORECASE),
    re.compile(r"\b(?:Host|Cookie|Authorization|Set-Cookie):\s*", re.IGNORECASE),
    re.compile(r"\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{20,}", re.IGNORECASE),
    re.compile(r"\bwebpackJsonp\b|\b__webpack_require__\b|\bfunction\s*\([^)]*\)\s*\{", re.IGNORECASE),
]


def normalize_worker_result(
    payload: dict[str, Any] | None,
    *,
    expected_status: str | None = None,
) -> dict[str, Any]:
    """Return a compact, validated worker result summary.

    Required output fields are stable:
    ``status``, ``conclusion``, ``summary``, ``evidence_refs``,
    ``confidence``, ``blocker``, ``block_reason``, and ``next_action``.
    Optional ``risk_level`` and ``upgrade_request`` are preserved when present.
    Long or raw-looking text is redacted/truncated so the main model never
    receives full HTML/JS/Burp bodies through this summary channel.
    """

    source = dict(payload or {})
    status = str(source.get("status") or expected_status or "").strip().lower()
    if not status:
        raise ValueError("worker_result.status is required")
    if status not in VALID_STATUSES:
        raise ValueError(f"worker_result.status must be one of {sorted(VALID_STATUSES)}")
    if expected_status is not None and status != expected_status:
        raise ValueError(f"worker_result.status must be {expected_status!r} for this queue transition")

    conclusion = _compact_text(source.get("conclusion") or source.get("summary") or "")
    summary = _compact_text(source.get("summary") or conclusion)
    evidence_refs = _normalize_refs(source.get("evidence_refs", source.get("evidence_ids", [])))
    confidence = _normalize_enum(source.get("confidence"), VALID_CONFIDENCE, default="unknown", field="confidence")
    blocker = _compact_text(source.get("blocker") or "")
    block_reason = _compact_text(source.get("block_reason") or source.get("blocker_reason") or source.get("reason") or "")
    next_action = _compact_text(source.get("next_action") or "")
    outcome = str(source.get("outcome") or "not_run").strip().lower()
    if outcome not in VALID_OUTCOMES:
        raise ValueError(f"worker_result.outcome must be one of {sorted(VALID_OUTCOMES)}")
    if outcome in {"supports", "refutes"} and not evidence_refs:
        outcome = "inconclusive"

    result: dict[str, Any] = {
        "status": status,
        "conclusion": conclusion,
        "summary": summary,
        "evidence_refs": evidence_refs,
        "confidence": confidence,
        "blocker": blocker,
        "block_reason": block_reason,
        "next_action": next_action,
        "outcome": outcome,
        "observation_summary": _compact_text(source.get("observation_summary") or summary),
        "alternative_explanation": _compact_text(source.get("alternative_explanation") or ""),
        "coverage_updates": _normalize_refs(source.get("coverage_updates", [])),
    }

    if "risk_level" in source or "risk" in source:
        result["risk_level"] = _normalize_enum(
            source.get("risk_level", source.get("risk")),
            VALID_RISK_LEVELS,
            default="unknown",
            field="risk_level",
        )
    if source.get("upgrade_request"):
        result["upgrade_request"] = _compact_upgrade_request(source["upgrade_request"])
    if "sufficient_evidence" in source:
        if not isinstance(source["sufficient_evidence"], bool):
            raise ValueError("worker_result.sufficient_evidence must be a boolean")
        result["sufficient_evidence"] = source["sufficient_evidence"]
    proposals = source.get("insight_proposals", [])
    if proposals:
        if not isinstance(proposals, list):
            raise ValueError("worker_result.insight_proposals must be a list")
        result["insight_proposals"] = [_normalize_insight_proposal(item) for item in proposals[:MAX_INSIGHT_PROPOSALS]]
    if _raw_data_was_redacted(source):
        result["redactions"] = ["raw_or_long_data_removed"]

    return result


def _normalize_insight_proposal(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("worker_result.insight_proposals items must be objects")
    asset_id = value.get("asset_id")
    if not isinstance(asset_id, int) or asset_id <= 0:
        raise ValueError("worker_result.insight_proposals.asset_id must be a positive integer")
    summary = _compact_text(value.get("summary") or value.get("content") or "", max_chars=320)
    if not summary:
        raise ValueError("worker_result.insight_proposals.summary is required")
    return {
        "summary": summary,
        "trigger": _compact_text(value.get("trigger") or "", max_chars=160),
        "asset_id": asset_id,
        "evidence_refs": _normalize_refs(value.get("evidence_refs", []))[:8],
        "next_action": _compact_text(value.get("next_action") or "", max_chars=240),
    }


def _normalize_refs(value: Any) -> list[str]:
    if value is None or value == "":
        return []
    values = value if isinstance(value, list | tuple | set) else [value]
    refs: list[str] = []
    for item in values:
        if isinstance(item, dict):
            raw = item.get("id") or item.get("ref") or item.get("evidence_ref_id")
        else:
            raw = item
        if raw is None:
            continue
        text = _compact_text(str(raw), max_chars=120)
        if text and text not in refs:
            refs.append(text)
        if len(refs) >= MAX_LIST_ITEMS:
            break
    return refs


def _normalize_enum(value: Any, allowed: set[str], *, default: str, field: str) -> str:
    if value is None or value == "":
        return default
    text = str(value).strip().lower()
    aliases = {"med": "medium", "mid": "medium", "crit": "critical"}
    text = aliases.get(text, text)
    if text not in allowed:
        raise ValueError(f"worker_result.{field} must be one of {sorted(allowed)}")
    return text


def _compact_upgrade_request(value: Any) -> dict[str, str]:
    if isinstance(value, dict):
        return {
            "reason": _compact_text(value.get("reason") or ""),
            "requested_tier": _compact_text(value.get("requested_tier") or value.get("tier") or "", max_chars=80),
        }
    return {"reason": _compact_text(str(value))}


def _compact_text(value: Any, *, max_chars: int = MAX_TEXT_CHARS) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if _looks_like_raw_data(text):
        text = "[redacted-raw-data]"
    if len(text) > max_chars:
        return text[: max_chars - 1].rstrip() + "…"
    return text


def compact_public_text(value: Any, *, max_chars: int = MAX_PUBLIC_TEXT_CHARS) -> str:
    """Compact free text before it is exposed to the main-model JSON/text view."""

    return _compact_text(value, max_chars=max_chars)


def compact_public_payload(value: Any, *, max_chars: int = MAX_PUBLIC_TEXT_CHARS) -> Any:
    """Recursively compact public payloads while preserving IDs and status fields.

    This is a small safety wrapper for main-session views.  Raw evidence should
    stay in fact tables/evidence_refs; public views only carry compact summaries,
    references, statuses, scores, and conclusions.
    """

    if isinstance(value, dict):
        return {str(key): compact_public_payload(item, max_chars=max_chars) for key, item in value.items()}
    if isinstance(value, list | tuple | set):
        return [compact_public_payload(item, max_chars=max_chars) for item in list(value)[:MAX_LIST_ITEMS]]
    if isinstance(value, str):
        return compact_public_text(value, max_chars=max_chars)
    return value


def _looks_like_raw_data(text: str) -> bool:
    if not text:
        return False
    if any(pattern.search(text) for pattern in RAW_DATA_PATTERNS):
        return True
    return len(text) > MAX_TEXT_CHARS * 2


def _raw_data_was_redacted(source: dict[str, Any]) -> bool:
    for key in ("summary", "conclusion", "blocker", "block_reason", "reason", "next_action"):
        value = source.get(key)
        if isinstance(value, str) and _looks_like_raw_data(value):
            return True
    return False
