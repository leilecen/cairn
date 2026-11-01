import pytest
from recon.public_exposure_intel import build_adapter_contract, parse_adapter_fixture


def test_searxng_requires_one_explicit_trusted_base_and_never_rotates():
    with pytest.raises(ValueError):
        build_adapter_contract(provider="searxng", query="example.com", family="public_docs_search")
    contract = build_adapter_contract(
        provider="searxng",
        query="example.com",
        family="public_docs_search",
        trusted_base="https://search.internal.example",
    )
    assert contract["endpoint"] == "https://search.internal.example/search"
    assert contract["network_allowed"] is False and "fallbacks" not in contract


@pytest.mark.parametrize("provider", ["gitlab", "huggingface"])
def test_external_provider_contracts_are_offline_only(provider):
    contract = build_adapter_contract(provider=provider, query="acme", family="code_search_external")
    assert contract["provider"] == provider and contract["network_allowed"] is False


def test_parse_local_fixture_emits_unified_compact_schema():
    payload = {"results": [{"url": "https://docs.example/x", "title": "x", "content": "anchor"}]}
    result = parse_adapter_fixture(
        provider="searxng",
        family="public_docs_search",
        query="example",
        payload=payload,
        evidence_ref="fixture:1",
    )
    assert result["status"] == "hits" and result["result_count"] == 1
    assert set(result["hits"][0]) == {"url", "title", "snippet", "matched_anchor", "evidence_refs"}
