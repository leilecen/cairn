from __future__ import annotations

import json
from pathlib import Path

from db.identity_classification import match_public_path_indicators

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "rules" / "public_path_indicators.json"


def test_public_path_rules_are_metadata_only_and_match_observed_paths_only():
    rules = json.loads(RULES.read_text(encoding="utf-8"))
    assert rules["schema"] == "public_path_indicators/v1"
    dumped = json.dumps(rules, ensure_ascii=False).lower()
    assert all(term not in dumped for term in ("payload", "xp_cmdshell", "sleep(", "union select", "${jndi"))
    required = {"vendor", "product", "path", "method", "parameters", "response_markers", "reference", "evidence_ref"}
    assert all(required <= set(item) for item in rules["indicators"])

    matches = match_public_path_indicators(
        [
            {"path": "/directdata/direct/router/", "method": "POST", "parameters": ["action"]},
            {"path": "/unrelated", "method": "GET", "parameters": []},
        ],
        rules,
    )
    assert len(matches) == 1
    assert matches[0]["status"] == "hypothesis"
    assert matches[0]["network_action"] == "none"
    assert matches[0]["observed_path"] == "/directdata/direct/router"


def test_unobserved_rule_never_becomes_a_request_candidate():
    rules = json.loads(RULES.read_text(encoding="utf-8"))
    matches = match_public_path_indicators([], rules)
    assert matches == []
