"""Versioned compact attack-surface profile JSON contract."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from db.attack_threads import create_attack_thread

SECTIONS = ("roles", "objects", "flows", "states", "transitions", "unknowns")


def normalize_profile(payload: dict[str, Any] | None) -> dict[str, Any]:
    source = payload or {}
    result: dict[str, Any] = {}
    for section in SECTIONS:
        values = source.get(section, [])
        if not isinstance(values, list):
            values = [values]
        result[section] = [_normalize_item(item) for item in values[:50] if isinstance(item, dict)]
    result["schema"] = "attack_surface_profile.v2"
    return result


def _normalize_item(item):
    refs = item.get("evidence_refs") or []
    confidence = str(item.get("confidence") or ("medium" if refs else "unknown")).lower()
    if not refs:
        confidence = "unknown" if confidence not in {"low", "unknown"} else confidence
    return {
        "key": str(item.get("key") or item.get("name") or "unknown")[:120],
        "label": str(item.get("label") or item.get("name") or "")[:200],
        "confidence": confidence if confidence in {"low", "medium", "high", "unknown"} else "unknown",
        "evidence_refs": [str(x)[:120] for x in refs[:20]],
        "unknowns": [str(x)[:200] for x in (item.get("unknowns") or [])[:20]],
    }


def validate_profile(payload: dict[str, Any] | None) -> None:
    normalized = normalize_profile(payload)
    if any(not item["key"] for section in SECTIONS for item in normalized[section]):
        raise ValueError("profile item key is required")


def seed_profile_hypotheses(conn: sqlite3.Connection, *, target_name: str, hunt_session_id: int) -> list[int]:
    """Convert explicit profile unknowns into proposed, non-dispatchable hypotheses."""
    if not conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='attack_surface_profiles'").fetchone():
        return []
    rows = conn.execute(
        "SELECT subject_id,roles_json,flows_json,trust_boundaries_json FROM attack_surface_profiles WHERE target_name=? AND status IN ('draft','active')",
        (target_name,),
    ).fetchall()
    created = []
    for row in rows:
        unknowns: list[str] = []
        for raw in row[1:]:
            try:
                data = json.loads(raw or "[]")
            except json.JSONDecodeError:
                data = []
            for item in data if isinstance(data, list) else []:
                if isinstance(item, dict):
                    unknowns.extend(str(value) for value in (item.get("unknowns") or []))
        for unknown in sorted(set(x.strip() for x in unknowns if x.strip()))[:20]:
            hypothesis = f"The focused system boundary for {unknown} is not established"
            exists = conn.execute(
                "SELECT id FROM attack_threads WHERE target_name=? AND hunt_session_id=? AND hypothesis=?",
                (target_name, hunt_session_id, hypothesis),
            ).fetchone()
            if exists:
                continue
            thread_id = create_attack_thread(
                conn,
                target_name=target_name,
                asset_url=None,
                hypothesis=hypothesis,
                why_promising="derived from an explicit profile unknown",
                hunt_session_id=hunt_session_id,
                expected_observation="stored evidence distinguishes the boundary state",
                refuting_observation="evidence confirms a different boundary state",
                alternative_explanations=["profile evidence is incomplete"],
                stop_conditions=["stop when evidence cannot distinguish states"],
                information_gain=2,
                commit=False,
            )
            conn.execute("UPDATE attack_threads SET status='proposed' WHERE id=?", (thread_id,))
            created.append(thread_id)
    conn.commit()
    return created
