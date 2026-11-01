from __future__ import annotations

import json
import sqlite3
import sys

from db.db_query import init_db
from recon import ct_search
from recon.ct_search import persist_sslmate_ct_result, run_sslmate_ct_search


def _asset_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """CREATE TABLE target_assets (
            id INTEGER PRIMARY KEY, target_name TEXT, asset_type TEXT, asset_value TEXT, port INTEGER,
            protocol TEXT, source TEXT, status TEXT, scope_status TEXT, scope_class TEXT,
            authorization_state TEXT, relation_to_target TEXT, source_query TEXT, source_snapshot TEXT,
            UNIQUE(target_name, asset_value, port)
        );"""
    )
    return conn


def test_sslmate_ct_expands_names_and_keeps_only_same_root(monkeypatch):
    class Response:
        def read(self):
            return json.dumps(
                [
                    {
                        "id": 42,
                        "tbs_sha256": "tbs",
                        "cert_sha256": "cert",
                        "dns_names": ["api.example.test", "*.example.test", "outside.test"],
                        "issuer": {"friendly_name": "Example CA"},
                        "not_before": "2026-01-01T00:00:00Z",
                        "not_after": "2027-01-01T00:00:00Z",
                        "revoked": False,
                    }
                ]
            ).encode()

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

    seen = []
    monkeypatch.setattr("recon.ct_search.urllib.request.urlopen", lambda request, **_: seen.append(request) or Response())
    result = run_sslmate_ct_search("example.test", api_key="test-key")

    assert seen[0].get_header("Authorization") == "Bearer test-key"
    assert "include_subdomains=true" in seen[0].full_url
    assert result["candidate_hosts"] == ["api.example.test", "example.test"]
    assert result["items"][0]["issuer"] == "Example CA"
    assert result["next_after"] == 42


def test_sslmate_ct_missing_key_makes_no_request(monkeypatch):
    monkeypatch.setattr("recon.ct_search.urllib.request.urlopen", lambda *_: (_ for _ in ()).throw(AssertionError()))
    assert run_sslmate_ct_search("example.test") == {
        "status": "not_configured",
        "provider": "sslmate_ct",
        "domain": "example.test",
        "items": [],
    }


def test_sslmate_ct_persistence_keeps_candidates_review_only():
    conn = _asset_db()
    result = {
        "status": "observed",
        "provider": "sslmate_ct",
        "domain": "example.test",
        "items": [],
        "candidate_hosts": ["api.example.test", "outside.test"],
    }
    count = persist_sslmate_ct_result(conn, target_name="demo", domain="example.test", result=result)
    row = conn.execute("SELECT asset_value,status,scope_status FROM target_assets").fetchone()
    assert count == 1
    assert tuple(row) == ("api.example.test", "new", "needs_review")


def test_sslmate_cli_records_observed_result_and_resume_cursor(monkeypatch, tmp_path):
    db_path = tmp_path / "ct-ledger.db"
    init_db(str(db_path), "Demo")
    monkeypatch.setattr(
        ct_search,
        "run_sslmate_ct_search",
        lambda *_args, **_kwargs: {
            "status": "observed",
            "provider": "sslmate_ct",
            "domain": "example.test",
            "items": [{"id": 42, "dns_names": ["api.example.test"]}],
            "candidate_hosts": ["api.example.test"],
            "next_after": 42,
        },
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["ct_search", "--target", "Demo", "--db", str(db_path), "--domain", "example.test"],
    )

    assert ct_search.main() == 0

    with sqlite3.connect(db_path) as conn:
        row = conn.execute("SELECT source,status,cursor_json,budget_json,summary_json FROM recon_runs").fetchone()
        asset = conn.execute("SELECT scope_status,scope_class FROM target_assets WHERE asset_value='api.example.test'").fetchone()
    assert row[:2] == ("sslmate_ct", "succeeded")
    assert json.loads(row[2]) == {"after": 42, "completed": True, "items": 1}
    assert json.loads(row[3]) == {"timeout_seconds": 30}
    assert json.loads(row[4]) == {"adapter": "sslmate_ct", "reason": "succeeded", "source_status": "observed"}
    assert asset == ("needs_review", "unknown")


def test_sslmate_cli_records_not_configured_without_a_request(monkeypatch, tmp_path):
    db_path = tmp_path / "ct-not-configured.db"
    init_db(str(db_path), "Demo")
    monkeypatch.setattr(
        ct_search,
        "run_sslmate_ct_search",
        lambda *_args, **_kwargs: {
            "status": "not_configured",
            "provider": "sslmate_ct",
            "domain": "example.test",
            "items": [],
        },
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["ct_search", "--target", "Demo", "--db", str(db_path), "--domain", "example.test"],
    )

    assert ct_search.main() == 1

    with sqlite3.connect(db_path) as conn:
        row = conn.execute("SELECT status,cursor_json,summary_json FROM recon_runs").fetchone()
    assert row[0] == "blocked"
    assert json.loads(row[1]) == {"completed": False, "items": 0}
    assert json.loads(row[2])["reason"] == "not_configured"


def test_sslmate_cli_keeps_explicit_after_cursor_when_provider_is_limited(monkeypatch, tmp_path):
    db_path = tmp_path / "ct-limited.db"
    init_db(str(db_path), "Demo")
    monkeypatch.setattr(
        ct_search,
        "run_sslmate_ct_search",
        lambda *_args, **_kwargs: {
            "status": "provider_limited",
            "provider": "sslmate_ct",
            "domain": "example.test",
            "items": [],
        },
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["ct_search", "--target", "Demo", "--db", str(db_path), "--domain", "example.test", "--after", "41"],
    )

    assert ct_search.main() == 1

    with sqlite3.connect(db_path) as conn:
        row = conn.execute("SELECT status,cursor_json,summary_json FROM recon_runs").fetchone()
    assert row[0] == "blocked"
    assert json.loads(row[1]) == {"after": 41, "completed": False, "items": 0}
    assert json.loads(row[2])["reason"] == "rate_limited"


def test_sslmate_cli_rejects_target_not_in_explicit_db_before_query(monkeypatch, tmp_path):
    db_path = tmp_path / "ct-target.db"
    init_db(str(db_path), "Actual")
    monkeypatch.setattr(
        ct_search,
        "run_sslmate_ct_search",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError()),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["ct_search", "--target", "Other", "--db", str(db_path), "--domain", "example.test"],
    )

    assert ct_search.main() == 1
