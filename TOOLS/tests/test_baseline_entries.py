from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from recon.baseline_entries import run_baseline_entry_probe
from recon.recon_store import ensure_recon_schema

SCHEMA = Path(__file__).resolve().parents[1] / "db" / "schema.sql"


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        CREATE TABLE targets(target_name TEXT PRIMARY KEY, domain TEXT);
        CREATE TABLE target_assets(
            id INTEGER PRIMARY KEY, target_name TEXT, asset_value TEXT,
            scope_status TEXT, scope_class TEXT, authorization_state TEXT,
            known_urls_json TEXT DEFAULT '[]', tech_stack_json TEXT DEFAULT '[]'
        );
        CREATE TABLE work_items(id INTEGER PRIMARY KEY, target_name TEXT);
        CREATE TABLE pages(id INTEGER PRIMARY KEY, target_name TEXT);
        CREATE TABLE scan_state(target_name TEXT PRIMARY KEY);
        """
    )
    ensure_recon_schema(conn)
    conn.execute("INSERT INTO targets VALUES('T','example.test')")
    conn.executemany(
        """INSERT INTO target_assets
           (id,target_name,asset_value,scope_status,scope_class,authorization_state,known_urls_json,tech_stack_json)
           VALUES(?,?,?,?,?,?,?,?)""",
        [
            (
                1,
                "T",
                "https://app.example.test",
                "in_scope",
                "owned",
                "authorized",
                '["https://app.example.test/login"]',
                "[]",
            ),
            (2, "T", "https://review.example.test", "needs_review", "unknown", "unknown", "[]", "[]"),
            (3, "T", "https://vendor.example.test", "in_scope", "authorized_vendor", "authorized", "[]", "[]"),
        ],
    )
    conn.commit()
    return conn


def test_only_active_authorized_assets_and_allowed_entry_families_are_persisted():
    conn = _conn()
    calls: list[str] = []

    def fetcher(url: str, method: str = "GET"):
        calls.append(url)
        # Body varies per path so this is not a catch-all responder.
        return {"status_code": 200, "location": "", "body_hint": f"login password for {url}"}

    result = run_baseline_entry_probe(conn, target_name="T", fetcher=fetcher)
    rows = conn.execute("SELECT * FROM entry_observations ORDER BY asset_id,url").fetchall()
    assert result["assets_processed"] == 2
    assert {row["asset_id"] for row in rows} == {1, 3}
    assert {row["entry_type"] for row in rows} <= {"login", "admin", "api"}
    assert not any(row["entry_type"] == "register" for row in rows)
    assert all(row["source"] == "baseline_entry_probe" for row in rows)
    assert all("entry_observations:" in json.loads(row["evidence_refs_json"])[0] for row in rows)
    assert all("review.example.test" not in url for url in calls)


def test_fixed_per_asset_and_total_caps_do_not_recurse():
    conn = _conn()
    calls: list[str] = []

    def fetcher(url: str, method: str = "GET"):
        calls.append(url)
        return {"status_code": 404, "location": "", "body_hint": ""}

    result = run_baseline_entry_probe(conn, target_name="T", fetcher=fetcher, per_asset_cap=2, total_cap=3)
    assert len(calls) == 3
    assert result["requests"] == 3
    assert result["stop_reason"] == "total_cap"
    assert all(not any("/" + part in url for part in ("register", "signup")) for url in calls)


@pytest.mark.parametrize(
    "response,expected",
    [
        ({"status_code": 429, "body_hint": ""}, "rate_limited"),
        ({"status_code": 200, "body_hint": "Cloudflare WAF challenge"}, "waf_detected"),
    ],
)
def test_rate_limit_or_waf_stops_globally(response, expected):
    conn = _conn()
    calls: list[str] = []

    def fetcher(url: str, method: str = "GET"):
        calls.append(url)
        return response

    result = run_baseline_entry_probe(conn, target_name="T", fetcher=fetcher)
    assert result["stop_reason"] == expected
    assert len(calls) == 1
    assert result["status"] == "blocked"


def test_probe_does_not_touch_deep_tables_or_focus_state():
    conn = _conn()

    result = run_baseline_entry_probe(
        conn,
        target_name="T",
        assets=[
            {
                "id": 1,
                "asset_value": "https://app.example.test",
                "scope_status": "in_scope",
                "scope_class": "owned",
            }
        ],
        fetcher=lambda url, method="GET": {"status_code": 404, "body_hint": ""},
    )
    assert result["status"] == "done"
    assert conn.execute("SELECT COUNT(*) FROM work_items").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM pages").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM scan_state").fetchone()[0] == 0


def test_default_db_mode_uses_real_target_assets_columns():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA.read_text(encoding="utf-8"))
    conn.execute("INSERT INTO targets(target_name,domain) VALUES('real','example.test')")
    conn.execute(
        """INSERT INTO target_assets
           (target_name,asset_value,scope_status,scope_class,login_urls,last_tech_stack)
           VALUES('real','app.example.test','in_scope','owned','[\"/login\"]','Spring')"""
    )
    conn.commit()
    calls: list[str] = []

    result = run_baseline_entry_probe(
        conn,
        target_name="real",
        fetcher=lambda url, method="GET": calls.append(url) or {"status_code": 404, "body_hint": ""},
    )
    assert result["assets_processed"] == 1
    assert calls and all("register" not in url for url in calls)


def test_unbounded_body_field_is_ignored():
    conn = _conn()
    result = run_baseline_entry_probe(
        conn,
        target_name="T",
        assets=[
            {
                "id": 1,
                "asset_value": "https://app.example.test",
                "scope_status": "in_scope",
                "scope_class": "owned",
            }
        ],
        fetcher=lambda url, method="GET": {
            "status_code": 200,
            "body": "Cloudflare WAF challenge",
            "body_hint": "",
        },
        per_asset_cap=1,
    )
    assert result["status"] == "done"
    assert result["stop_reason"] is None


def test_transport_failure_is_not_recorded_as_an_observed_entry():
    """A host that never answers must not produce login facts."""
    conn = _conn()
    calls: list[str] = []

    def fetcher(url: str, method: str = "GET"):
        calls.append(url)
        return {"status_code": 0, "body_hint": "URLError"}

    result = run_baseline_entry_probe(conn, target_name="T", fetcher=fetcher)
    assert result["observations"] == 0
    assert result["no_response"] == 2
    assert result["status"] == "blocked"
    assert result["stop_reason"] == "no_response"
    assert conn.execute("SELECT COUNT(*) FROM entry_observations").fetchone()[0] == 0
    # One dead host must not spend the whole per-asset candidate budget.
    assert len(calls) == 2


def test_assets_known_unreachable_are_skipped_without_spending_budget():
    conn = _conn()
    calls: list[str] = []

    result = run_baseline_entry_probe(
        conn,
        target_name="T",
        assets=[
            {
                "id": 1,
                "target_name": "T",
                "asset_value": "https://gone.example.test",
                "scope_status": "in_scope",
                "scope_class": "owned",
                "live_status": "unreachable",
            },
            {
                "id": 2,
                "target_name": "T",
                "asset_value": "https://app.example.test",
                "scope_status": "in_scope",
                "scope_class": "owned",
                "live_status": "live",
            },
        ],
        fetcher=lambda url, method="GET": (
            calls.append(url)
            or {
                "status_code": 200,
                "body_hint": f"login password for {url}",
            }
        ),
    )
    assert result["skipped_unreachable"] == 1
    assert result["assets_processed"] == 1
    assert not any("gone.example.test" in url for url in calls)
    assert conn.execute("SELECT COUNT(*) FROM entry_observations").fetchone()[0] >= 1


def test_slash_normalisation_redirect_is_not_an_auth_redirect():
    """301 /login -> /login/ contains the word login but is path normalisation."""
    from entry_probe import classify_response

    normalised, _ = classify_response(301, "https://app.example.test/login/", "", request_url="https://app.example.test/login")
    assert normalised == "unknown"

    real_sso, confidence = classify_response(
        302, "https://sso.example.test/oauth?client=1", "", request_url="https://app.example.test/login"
    )
    assert real_sso == "auth_redirect"
    assert confidence == "high"


def test_catchall_responses_are_not_recorded_as_real_entries():
    """A responder that returns one fixed body for every path proves nothing."""
    conn = _conn()

    def fetcher(url: str, method: str = "GET"):
        return {"status_code": 200, "body_hint": "user not logged in"}

    result = run_baseline_entry_probe(conn, target_name="T", fetcher=fetcher)
    assert result["catchall_skipped"] > 0
    assert result["observations"] == 0
    assert conn.execute("SELECT COUNT(*) FROM entry_observations").fetchone()[0] == 0


def test_distinct_route_under_a_catchall_is_still_recorded():
    """Only responses that differ from the control count as entry evidence."""
    conn = _conn()

    def fetcher(url: str, method: str = "GET"):
        if url == "https://app.example.test/login":
            return {"status_code": 400, "body_hint": "method not allowed"}
        return {"status_code": 200, "body_hint": "not logged in"}

    result = run_baseline_entry_probe(conn, target_name="T", fetcher=fetcher)
    assert result["catchall_skipped"] > 0
    rows = [row[0] for row in conn.execute("SELECT url FROM entry_observations").fetchall()]
    assert rows == ["https://app.example.test/login"]
