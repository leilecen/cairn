from __future__ import annotations

from pathlib import Path

import pytest
from recon.system_types import classify_system, load_rules

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "rules" / "system_signatures.json"


def test_oa_and_druid_have_explainable_positive_matches():
    oa = classify_system(
        {
            "title": "泛微 e-cology 登录",
            "technologies": ["e-cology"],
            "urls": [{"url": "https://oa.example.test/login", "entry_type": "login", "evidence_ref": "ev:oa"}],
        },
        RULES,
    )
    druid = classify_system(
        {
            "title": "Druid Stat",
            "technologies": ["Apache Druid"],
            "urls": [{"url": "https://app.example.test/druid/index.html", "entry_type": "admin", "evidence_ref": "ev:druid"}],
        },
        RULES,
    )
    assert oa["label"] == "oa"
    assert druid["label"] == "druid"
    assert oa["evidence_refs"] == ["ev:oa"]
    assert any("e-cology" in reason.lower() for reason in oa["reasons"])
    assert any(match["rule_id"] for match in druid["matches"])


@pytest.mark.parametrize(
    "observation, expected",
    [
        ({"title": "Admin Console", "technologies": [], "urls": []}, "admin_portal"),
        ({"title": "VPN Gateway", "technologies": ["SSL VPN"], "urls": []}, "vpn"),
        (
            {
                "title": "WordPress Login",
                "technologies": ["WordPress"],
                "urls": [{"url": "/wp-login.php", "entry_type": "login"}],
            },
            "cms",
        ),
        (
            {"title": "API Gateway", "technologies": ["Kong"], "urls": [{"url": "/api", "entry_type": "api"}]},
            "api_gateway",
        ),
        ({"title": "Sign in", "technologies": [], "urls": [{"url": "/login", "entry_type": "login"}]}, "login"),
    ],
)
def test_generic_type_rules_are_descriptive(observation, expected):
    result = classify_system(observation, RULES)
    assert result["label"] == expected


def test_admin_title_does_not_create_oa_or_druid_false_positive():
    result = classify_system({"title": "Admin Management", "technologies": [], "urls": []}, RULES)
    assert result["label"] == "admin_portal"
    assert result["label"] not in {"oa", "druid"}


@pytest.mark.parametrize(
    "observation, expected",
    [
        ({"title": "Druid Admin Console", "technologies": ["Apache Druid"]}, "druid"),
        ({"title": "泛微 OA Admin", "technologies": ["e-cology"]}, "oa"),
    ],
)
def test_explicit_product_signal_survives_admin_title(observation, expected):
    assert classify_system(observation, RULES)["label"] == expected


def test_ordinary_site_is_unknown_and_no_raw_content_is_returned():
    result = classify_system(
        {"title": "Example Home", "technologies": [], "urls": [{"url": "/", "entry_type": "page"}]},
        RULES,
    )
    assert result["label"] == "unknown"
    rendered = repr(result)
    assert "<html" not in rendered.lower()
    assert "authorization" not in rendered.lower()


def test_same_label_inputs_are_independent_and_have_no_merge_state():
    first = classify_system({"title": "Druid Console", "technologies": ["Druid"]}, RULES)
    second = classify_system({"title": "Druid Console", "technologies": ["Druid"]}, RULES)
    assert first == second
    first["evidence_refs"].append("ev:local-only")
    assert "ev:local-only" not in second["evidence_refs"]


def test_rule_file_is_validated_and_rejects_unsafe_shape(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(
        '{"schema_version": 1, "labels": ["oa", "druid", "admin_portal", "vpn", '
        '"cms", "api_gateway", "login", "unknown"], "rules": '
        '{"oa": {"priority": 1, "positive": "raw"}}}',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="positive"):
        load_rules(bad)
