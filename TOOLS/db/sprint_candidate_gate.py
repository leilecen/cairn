"""Two-hour sprint candidate gates."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

PII_MIN_CLASSES = 3
PII_MAX_OBJECTS = 3
PII_MIN_UNAUTHORIZED_SUCCESSES = 2
HIGH_VALUE_TYPES = {"high_value", "rce", "getshell", "admin_takeover"}


def _row_value(row: sqlite3.Row | tuple[Any, ...], key: str, index: int) -> Any:
    if isinstance(row, sqlite3.Row):
        return row[key]
    return row[index]


def _load_thread(
    conn: sqlite3.Connection,
    attack_thread_id: int,
) -> sqlite3.Row | tuple[Any, ...]:
    row = conn.execute(
        "SELECT id, current_evidence FROM attack_threads WHERE id = ?",
        (attack_thread_id,),
    ).fetchone()
    if row is None:
        raise ValueError(f"attack_thread not found: {attack_thread_id}")
    return row


def _evidence_json(row: sqlite3.Row | tuple[Any, ...]) -> dict[str, Any]:
    raw = _row_value(row, "current_evidence", 1)
    if not raw:
        return {}
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        thread_id = _row_value(row, "id", 0)
        raise ValueError(f"invalid current_evidence JSON for attack_thread {thread_id}") from exc
    if not isinstance(payload, dict):
        raise ValueError("current_evidence must be a JSON object")
    return payload


def evaluate_attack_thread_candidate(
    conn: sqlite3.Connection,
    *,
    attack_thread_id: int,
) -> dict[str, object]:
    row = _load_thread(conn, attack_thread_id)
    evidence = _evidence_json(row)
    finding_type = str(evidence.get("type") or "")
    if finding_type in HIGH_VALUE_TYPES:
        return _decision(
            "high_value_escalation",
            "high value signal requires operator escalation",
            missing_proof=evidence.get("missing_proof", ""),
            should_stop=True,
        )
    if finding_type == "personal_info_idor" or _looks_like_personal_info_evidence(evidence):
        return _evaluate_personal_info(evidence)
    if evidence.get("request_refs") and evidence.get("response_refs") and evidence.get("hypothesis"):
        return _decision(
            "B",
            "has request, response, and explicit hypothesis",
            missing_proof=evidence.get("missing_proof", ""),
        )
    return _decision(
        "A",
        "insufficient evidence for B-class candidate",
        missing_proof=evidence.get("missing_proof", ""),
    )


def _looks_like_personal_info_evidence(evidence: dict[str, Any]) -> bool:
    objects = evidence.get("objects_tested")
    if not isinstance(objects, list):
        return False
    return any(
        isinstance(item, dict) and ("pii_classes" in item or "same_business_object" in item or "unauthorized_success" in item)
        for item in objects
    )


def _decision(
    classification: str,
    reason: str,
    *,
    success_count: int = 0,
    tested_count: int = 0,
    should_stop: bool = False,
    missing_proof: object = "",
) -> dict[str, object]:
    return {
        "classification": classification,
        "reason": reason,
        "success_count": success_count,
        "tested_count": tested_count,
        "should_stop": should_stop,
        "missing_proof": missing_proof or "",
    }


def _evaluate_personal_info(evidence: dict[str, Any]) -> dict[str, object]:
    objects = evidence.get("objects_tested") or []
    if not isinstance(objects, list):
        objects = []
    tested = [item for item in objects[:PII_MAX_OBJECTS] if isinstance(item, dict)]
    missing_proof = evidence.get("missing_proof", "")
    if tested and any(item.get("same_business_object") is not True for item in tested):
        return _decision(
            "kill",
            "personal info is not proven to belong to the same business object",
            tested_count=len(tested),
            should_stop=True,
            missing_proof=missing_proof,
        )

    successes = [
        item for item in tested if item.get("unauthorized_success") is True and len(set(item.get("pii_classes") or [])) >= PII_MIN_CLASSES
    ]
    weak_successes = [
        item for item in tested if item.get("unauthorized_success") is True and len(set(item.get("pii_classes") or [])) < PII_MIN_CLASSES
    ]
    if len(successes) >= PII_MIN_UNAUTHORIZED_SUCCESSES:
        return _decision(
            "B",
            "two unauthorized objects expose at least three personal-info classes",
            success_count=len(successes),
            tested_count=len(tested),
            should_stop=True,
            missing_proof=missing_proof,
        )
    if weak_successes:
        return _decision(
            "A",
            "personal-info gate needs at least three personal-info classes per successful object",
            success_count=len(successes),
            tested_count=len(tested),
            should_stop=len(tested) >= PII_MAX_OBJECTS,
            missing_proof=missing_proof,
        )
    if len(tested) >= PII_MAX_OBJECTS:
        return _decision(
            "kill",
            "three tested objects did not meet B-class threshold",
            success_count=len(successes),
            tested_count=len(tested),
            should_stop=True,
            missing_proof=missing_proof,
        )
    return _decision(
        "A",
        "personal-info gate needs more low-risk evidence before B-class promotion",
        success_count=len(successes),
        tested_count=len(tested),
        missing_proof=missing_proof,
    )
