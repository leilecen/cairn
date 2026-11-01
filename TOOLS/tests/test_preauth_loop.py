import sqlite3

import pytest
from recon.endpoint_normalizer import normalize_endpoint
from recon.preauth import ProbeBudget, classify_response, compact_auth_blocker
from recon.preauth_probe import run_preauth_probe
from recon.scope import classify_asset_scope, is_active_scope


def test_scope_classifies_vendor_as_intel_only_without_explicit_authorization():
    assert classify_asset_scope("act.weikayun.com", "example.com") == "unknown"
    assert classify_asset_scope("www.example.com", "example.com") == "owned"
    assert is_active_scope("owned", "in_scope") is True
    assert is_active_scope("unknown", "in_scope") is False


def test_endpoint_normalizer_resolves_relative_js_route_from_js_origin():
    result = normalize_endpoint(
        "/customer/search",
        page_url="https://portal.example.com/app",
        js_url="https://portal.example.com/assets/main.js",
        target_hosts={"portal.example.com"},
    )
    assert result["resolved_url"] == "https://portal.example.com/customer/search"
    assert result["origin_host"] == "portal.example.com"
    assert result["resolution_status"] == "resolved"
    assert result["scope_class"] == "owned"


def test_endpoint_normalizer_does_not_promote_service_word_to_host():
    result = normalize_endpoint(
        "/customer/search",
        page_url="",
        js_url="",
        target_hosts={"portal.example.com"},
    )
    assert result["resolution_status"] == "unresolved"
    assert result["origin_host"] is None


@pytest.mark.parametrize(
    ("status", "location", "body", "expected"),
    [
        (200, "", "<form>密码 登录</form>", "auth_required"),
        (302, "/login", "", "auth_redirect"),
        (401, "", "", "auth_required"),
        (403, "", "forbidden", "restricted"),
        (404, "", "", "not_found"),
        (451, "", "WAF blocked", "waf_blocked"),
    ],
)
def test_classify_response_keeps_auth_and_waf_boundaries_explicit(status, location, body, expected):
    assert classify_response(status, location=location, body=body) == expected


def test_probe_budget_stops_at_thirty_and_on_waf():
    budget = ProbeBudget(max_requests=30, min_interval_seconds=2)
    for _ in range(30):
        assert budget.allow(now=100.0 + _ * 2) is True
        budget.record(now=100.0 + _ * 2)
    assert budget.allow(now=200.0) is False
    budget = ProbeBudget(max_requests=30, min_interval_seconds=2)
    budget.record(now=100.0)
    budget.stop("waf_blocked")
    assert budget.allow(now=200.0) is False
    assert budget.stop_reason == "waf_blocked"


def test_auth_blocker_is_compact_and_never_contains_credentials():
    result = compact_auth_blocker(
        login_url="https://portal.example.com/login",
        auth_provider="sso",
        redirect_chain=["https://login.example.test/authorize"],
        pre_auth_endpoints=["https://portal.example.com/api/public"],
        js_candidates=["https://portal.example.com/assets/auth.js"],
        tenant_clues=["tenantId"],
        public_candidates=["/health"],
        blocker_reason="account required",
        next_safe_action="analyze public endpoints",
    )
    assert result["auth_provider"] == "sso"
    assert "Cookie" not in str(result)
    assert "Authorization" not in str(result)


def test_preauth_probe_records_public_boundary_and_never_uses_disallowed_method(tmp_path):
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        CREATE TABLE target_assets(
          id INTEGER PRIMARY KEY, target_name TEXT, asset_value TEXT,
          scope_status TEXT, scope_class TEXT, authorization_state TEXT, live_status TEXT
        );
        CREATE TABLE entry_observations(
          id INTEGER PRIMARY KEY AUTOINCREMENT, target_name TEXT, asset_id INTEGER, url TEXT,
          entry_type TEXT, source TEXT, status TEXT, status_code INTEGER, confidence TEXT,
          response_class TEXT, evidence_refs_json TEXT, notes TEXT, observed_at TEXT,
          UNIQUE(target_name,asset_id,url,entry_type,source)
        );
        INSERT INTO target_assets VALUES(1,'demo','portal.example.com','in_scope','owned','inherited_target_scope','live');
        """
    )
    seen = []

    def fake_fetch(url, method):
        seen.append((url, method))
        return {"status_code": 200, "body": "public", "location": "", "content_type": "text/html"}

    result = run_preauth_probe(
        conn,
        target_name="demo",
        asset_id=1,
        base_url="https://portal.example.com",
        known_urls=["https://portal.example.com/login"],
        methods=("GET", "POST", "OPTIONS"),
        max_requests=2,
        min_interval_seconds=0,
        fetcher=fake_fetch,
    )
    assert result["status"] == "done"
    assert seen
    assert {method for _, method in seen} <= {"GET", "OPTIONS"}
    assert conn.execute("SELECT COUNT(*) FROM entry_observations").fetchone()[0] > 0
