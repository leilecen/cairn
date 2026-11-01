from db.profile_contract import normalize_profile


def test_profile_without_evidence_is_unknown_and_compact():
    profile = normalize_profile({"roles": [{"name": "admin", "confidence": "high"}], "flows": [{"name": "x", "evidence_refs": ["ev-1"]}]})
    assert profile["roles"][0]["confidence"] == "unknown"
    assert profile["flows"][0]["confidence"] == "medium"
    assert profile["schema"] == "attack_surface_profile.v2"
