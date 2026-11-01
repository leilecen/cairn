"""Compact, explainable system type classification with no persistence side effects."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RULES = ROOT / "rules" / "system_signatures.json"
LABELS = ("oa", "druid", "admin_portal", "vpn", "cms", "api_gateway", "login", "unknown")
FIELDS = {"title", "technologies", "urls", "entry_types"}


def _validate_rule(rule: Any, *, label: str, polarity: str) -> None:
    if not isinstance(rule, dict):
        raise ValueError(f"{label}.{polarity} rule must be an object")
    required = {"rule_id", "field", "contains", "reason"}
    missing = required - set(rule)
    if missing:
        raise ValueError(f"{label}.{polarity} rule missing {sorted(missing)[0]}")
    if not isinstance(rule["rule_id"], str) or not rule["rule_id"].strip():
        raise ValueError(f"{label}.{polarity} rule_id must be a string")
    if rule["field"] not in FIELDS:
        raise ValueError(f"{label}.{polarity} rule has unsupported field")
    if not isinstance(rule["contains"], list) or not rule["contains"] or not all(isinstance(x, str) and x for x in rule["contains"]):
        raise ValueError(f"{label}.{polarity} contains must be a non-empty string list")
    if not isinstance(rule["reason"], str) or not rule["reason"].strip():
        raise ValueError(f"{label}.{polarity} reason must be a string")


def load_rules(path: str | Path = DEFAULT_RULES) -> dict[str, Any]:
    """Load and validate only the small declarative signature document."""
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot load system type rules: {exc}") from exc
    return _validate_document(document)


def _validate_document(document: Any) -> dict[str, Any]:
    if not isinstance(document, dict) or document.get("schema_version") != 1:
        raise ValueError("system type rules require schema_version 1")
    if document.get("labels") != list(LABELS):
        raise ValueError("system type rules labels do not match the supported labels")
    rules = document.get("rules")
    if not isinstance(rules, dict):
        raise ValueError("system type rules.rules must be an object")
    for label in LABELS[:-1]:
        item = rules.get(label)
        if not isinstance(item, dict):
            raise ValueError(f"missing rule set for {label}")
        if not isinstance(item.get("priority"), int) or item["priority"] < 0:
            raise ValueError(f"{label}.priority must be a non-negative integer")
        for polarity in ("positive", "negative"):
            entries = item.get(polarity)
            if not isinstance(entries, list):
                raise ValueError(f"{label}.{polarity} must be a list")
            for rule in entries:
                _validate_rule(rule, label=label, polarity=polarity)
    return document


def _compact_values(observation: dict[str, Any]) -> dict[str, list[str]]:
    values: dict[str, list[str]] = {field: [] for field in FIELDS}
    values["title"] = [observation.get("title", "")] if isinstance(observation.get("title", ""), str) else []
    values["technologies"] = [
        item if isinstance(item, str) else str(item.get("name", item.get("technology", "")))
        for item in observation.get("technologies", [])
        if isinstance(item, str) or isinstance(item, dict)
    ]
    values["entry_types"] = [
        item if isinstance(item, str) else str(item.get("entry_type", ""))
        for item in observation.get("urls", [])
        if isinstance(item, str) or isinstance(item, dict)
    ]
    values["entry_types"] += [item for item in observation.get("entry_types", []) if isinstance(item, str)]
    values["urls"] = [
        (item if isinstance(item, str) else str(item.get("url", "")))
        for item in observation.get("urls", [])
        if isinstance(item, str) or isinstance(item, dict)
    ]
    return {key: [item.casefold() for item in items if item] for key, items in values.items()}


def _evidence_refs(observation: dict[str, Any], field: str) -> list[str]:
    refs = observation.get("evidence_refs", {})
    if isinstance(refs, dict) and isinstance(refs.get(field), list):
        return [item for item in refs[field] if isinstance(item, str)][:3]
    if field == "urls":
        return [
            str(item["evidence_ref"])
            for item in observation.get("urls", [])
            if isinstance(item, dict) and isinstance(item.get("evidence_ref"), str)
        ][:3]
    if field in {"title", "technologies", "entry_types"}:
        if isinstance(refs, dict):
            direct = [item for item in refs.get(field, []) if isinstance(item, str)]
            if direct:
                return direct[:3]
        return [
            str(item["evidence_ref"])
            for item in observation.get("urls", [])
            if isinstance(item, dict) and isinstance(item.get("evidence_ref"), str)
        ][:3]
    return []


def classify_system(observation: dict[str, Any], rules: str | Path | dict[str, Any] = DEFAULT_RULES) -> dict[str, Any]:
    """Classify one compact observation; never clusters, stores, or returns raw content."""
    if not isinstance(observation, dict):
        raise ValueError("observation must be an object")
    document = load_rules(rules) if not isinstance(rules, dict) else _validate_document(rules)
    values = _compact_values(observation)
    candidates: list[tuple[int, int, str, list[dict[str, Any]]]] = []
    for label in LABELS[:-1]:
        spec = document["rules"][label]
        matches: list[dict[str, Any]] = []
        blocked = False
        for polarity in ("positive", "negative"):
            for rule in spec[polarity]:
                hit = any(needle.casefold() in value for needle in rule["contains"] for value in values[rule["field"]])
                if not hit:
                    continue
                if polarity == "negative":
                    blocked = True
                    continue
                matches.append(
                    {
                        "rule_id": rule["rule_id"],
                        "label": label,
                        "field": rule["field"],
                        "reason": rule["reason"],
                        "evidence_refs": _evidence_refs(observation, rule["field"]),
                    }
                )
        if matches and not blocked:
            candidates.append((spec["priority"], len(matches), label, matches))
    if not candidates:
        return {
            "label": "unknown",
            "matches": [],
            "evidence_refs": [],
            "reasons": ["no declarative system signature matched"],
        }
    _priority, _count, label, matches = max(candidates)
    refs = sorted({ref for match in matches for ref in match["evidence_refs"]})
    return {
        "label": label,
        "matches": matches,
        "evidence_refs": refs,
        "reasons": [match["reason"] for match in matches],
    }
