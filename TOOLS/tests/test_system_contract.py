from __future__ import annotations

import pytest
from db.system_contract import (
    human_system_label,
    is_active_capable,
    normalize_url,
    validate_action_card,
    validate_system,
)


def test_system_contract_normalizes_safe_url_and_human_label():
    system = validate_system(
        system_key="blog",
        display_name="官方博客",
        canonical_url="HTTPS://Blog.Example.COM/path?x=1",
        scope_class="owned",
    )
    assert system["canonical_url"] == "https://blog.example.com/path?x=1"
    assert (
        human_system_label(3, system["display_name"], system["canonical_url"]) == "官方博客（https://blog.example.com/path?x=1）[system #3]"
    )


@pytest.mark.parametrize("value", ["example.com", "ftp://example.com", "https://u:p@example.com", "https://example.com/?token=secret"])
def test_canonical_url_rejects_unsafe_values(value):
    with pytest.raises(ValueError):
        normalize_url(value)


def test_action_card_requires_compact_human_contract():
    card = validate_action_card(
        action_label="补充截图",
        why_needed="审核缺少证据",
        steps=["打开页面", "截图并回填"],
        expected_observation="一张截图",
        report_back_format="回复：完成；附件=1",
        url="https://example.com/path",
    )
    assert card["steps"] == ["打开页面", "截图并回填"]
    with pytest.raises(ValueError):
        validate_action_card(action_label="x", why_needed="y", steps=[], expected_observation="z", report_back_format="r")


def test_intel_only_is_not_active_capable():
    assert is_active_capable("owned")
    assert is_active_capable("authorized_vendor")
    assert not is_active_capable("intel_only")
    assert not is_active_capable("unknown")
