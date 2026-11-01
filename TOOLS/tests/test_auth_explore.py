import sqlite3

import pytest
from auth.auth_explore import classify_auth_state, import_passive_observations


def _conn():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript("""
      CREATE TABLE targets(target_name TEXT); INSERT INTO targets VALUES('T');
      CREATE TABLE endpoint_observations(target_name TEXT,canonical_url TEXT UNIQUE,host TEXT,path TEXT,method TEXT,source TEXT,auth_state TEXT,evidence_refs_json TEXT);
      CREATE TABLE js_files(url TEXT UNIQUE,page_url TEXT,source_kind TEXT,extraction_status TEXT);
      CREATE TABLE recon_sources(target_name TEXT,source_kind TEXT,query TEXT,result_json TEXT,status TEXT, UNIQUE(target_name,source_kind,query));
      CREATE TABLE suspicious_points(id TEXT);
      CREATE TABLE work_items(id INTEGER);
    """)
    return conn


def test_har_fixture_imports_only_passive_compact_facts_and_m9_seed():
    conn = _conn()
    events = [
        {
            "resource_type": "xhr",
            "url": "https://app.example.test/api/me?token=",
            "method": "GET",
            "status": 200,
            "observed_with_session": False,
            "evidence_refs": ["har:1"],
        },
        {
            "resource_type": "fetch",
            "url": "https://app.example.test/Mobile/data",
            "status": 200,
            "observed_with_session": True,
            "evidence_refs": ["cdp:2"],
        },
        {"resource_type": "script", "url": "https://app.example.test/Mobile/app.js", "evidence_refs": ["cdp:3"]},
        {"resource_type": "xhr", "url": "https://other.test/api", "evidence_refs": ["cdp:4"]},
    ]
    result = import_passive_observations(conn, target_name="T", page_url="https://app.example.test/", events=events)
    assert result == {"endpoints": 2, "scripts": 1, "m9_seeds": 2, "blocked": 1, "network_request_count": 0}
    assert [row[0] for row in conn.execute("SELECT auth_state FROM endpoint_observations ORDER BY canonical_url")] == [
        "authenticated",
        "public",
    ]
    assert conn.execute("SELECT source_kind FROM js_files").fetchone()[0] == "browser_script"
    assert conn.execute("SELECT COUNT(*) FROM suspicious_points").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM work_items").fetchone()[0] == 0


def test_auth_state_requires_session_success_or_explicit_trusted_marking():
    assert classify_auth_state({"status": 200}) == "unknown"
    assert classify_auth_state({"status": 401}) == "unknown"
    assert classify_auth_state({"status": 403}) == "unknown"
    assert classify_auth_state({"login_redirect": True}) == "unknown"
    assert classify_auth_state({"status": 200, "observed_with_session": True}) == "authenticated"
    assert classify_auth_state({"status": 200, "observed_with_session": False}) == "public"
    assert classify_auth_state({"status": 200, "auth_state": "authenticated"}) == "unknown"
    assert classify_auth_state({"auth_state": "authenticated", "auth_state_trusted": True}) == "authenticated"


def test_sensitive_or_missing_evidence_fail_closed_and_missing_url_blocker_is_compact():
    conn = _conn()
    with pytest.raises(ValueError):
        import_passive_observations(
            conn,
            target_name="T",
            page_url="https://app.example.test/",
            events=[{"resource_type": "xhr", "url": "https://app.example.test/x", "evidence_refs": []}],
        )
    with pytest.raises(ValueError, match="credential"):
        import_passive_observations(
            conn,
            target_name="T",
            page_url="https://app.example.test/",
            events=[
                {
                    "resource_type": "xhr",
                    "url": "https://app.example.test/x",
                    "evidence_refs": ["Authorization: Bearer secret"],
                }
            ],
        )
    assert (
        import_passive_observations(
            conn,
            target_name="T",
            page_url="https://app.example.test/",
            events=[{"resource_type": "xhr", "blocker": "login"}],
        )["blocked"]
        == 1
    )


def test_import_is_atomic_when_a_later_event_is_invalid():
    conn = _conn()
    events = [
        {"resource_type": "xhr", "url": "https://app.example.test/api/1", "evidence_refs": ["har:1"]},
        {"resource_type": "xhr", "url": "https://app.example.test/api/2", "evidence_refs": []},
    ]
    with pytest.raises(ValueError):
        import_passive_observations(conn, target_name="T", page_url="https://app.example.test/", events=events)
    # Nothing from the batch may be written, even if the caller commits afterwards.
    conn.commit()
    assert conn.execute("SELECT COUNT(*) FROM endpoint_observations").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM js_files").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM recon_sources").fetchone()[0] == 0


def test_duplicate_import_counts_only_actually_inserted_rows():
    conn = _conn()
    events = [
        {"resource_type": "xhr", "url": "https://app.example.test/api/me", "method": "GET", "evidence_refs": ["har:1"]},
        {"resource_type": "script", "url": "https://app.example.test/app.js", "evidence_refs": ["cdp:2"]},
    ]
    first = import_passive_observations(conn, target_name="T", page_url="https://app.example.test/", events=events)
    second = import_passive_observations(conn, target_name="T", page_url="https://app.example.test/", events=events)
    assert first == {"endpoints": 1, "scripts": 1, "m9_seeds": 0, "blocked": 0, "network_request_count": 0}
    assert second == {"endpoints": 0, "scripts": 1, "m9_seeds": 0, "blocked": 0, "network_request_count": 0}
    assert conn.execute("SELECT COUNT(*) FROM endpoint_observations").fetchone()[0] == 1


def test_default_ports_are_normalized_before_cross_origin_check():
    conn = _conn()
    events = [
        {"resource_type": "xhr", "url": "https://a.test:443/api", "evidence_refs": ["har:1"]},
        {"resource_type": "xhr", "url": "http://a.test:80/plain", "evidence_refs": ["har:2"]},
    ]
    result = import_passive_observations(conn, target_name="T", page_url="https://a.test/", events=events)
    assert result["blocked"] == 1  # http vs https differ by scheme; same-scheme default port is not cross-origin
    assert conn.execute("SELECT COUNT(*) FROM endpoint_observations").fetchone()[0] == 1
    assert conn.execute("SELECT host FROM endpoint_observations").fetchone()[0] == "a.test"
