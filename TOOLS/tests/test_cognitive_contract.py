import pytest
from db.cognitive_contract import (
    normalize_auth_state,
    normalize_outcome,
    operator_kind_for_auth_state,
    require_falsifiable,
)


def test_auth_aliases_and_passive_hint():
    assert normalize_auth_state("login_redirect") == "auth_redirect"
    assert normalize_auth_state("blocked_by_waf") == "waf_blocked"
    assert normalize_auth_state("login_like") == "auth_required"
    assert normalize_auth_state("ok_unknown") == "unknown"
    assert normalize_auth_state("public", has_response_evidence=False) == "passive_hint"


def test_waf_uses_valid_operator_kind():
    assert operator_kind_for_auth_state("waf_blocked") == "manual_review"


def test_evidence_required_for_support_or_refute():
    assert normalize_outcome("supports", evidence_refs=[]) == "inconclusive"
    assert normalize_outcome("refutes", evidence_refs=["ev-1"]) == "refutes"
    with pytest.raises(ValueError):
        require_falsifiable(question="", expected_observation="x")
