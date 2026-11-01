from __future__ import annotations

import json
import sqlite3
import sys

from db.db_query import init_db
from recon import recon_intel
from recon.recon_intel import (
    resolve_fofa_capability,
    run_amass,
    run_asnmap,
    run_fofa,
    run_gau,
    run_securitytrails_passive_dns,
    run_subfinder,
    run_tianyan_company,
    run_uncover,
    run_virustotal_passive_dns,
    store_subfinder_candidates,
)
from recon.recon_store import record_source


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


def test_subfinder_cli_records_resumable_adapter_run(monkeypatch, tmp_path):
    """A source adapter records compact execution state separately from its facts."""
    db_path = tmp_path / "source-run.db"
    init_db(str(db_path), "Demo")
    monkeypatch.setattr(
        recon_intel,
        "run_subfinder",
        lambda domain, *, executable: {
            "status": "observed",
            "domain": domain,
            "items": [{"host": "api.example.test"}],
        },
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "recon_intel",
            "--target",
            "Demo",
            "--db",
            str(db_path),
            "--subfinder-domain",
            "example.test",
        ],
    )

    assert recon_intel.main() == 0

    with sqlite3.connect(db_path) as conn:
        row = conn.execute("SELECT source,status,cursor_json,budget_json,summary_json FROM recon_runs").fetchone()
    assert row[:2] == ("subfinder_passive", "succeeded")
    assert json.loads(row[2]) == {"completed": True, "items": 1}
    assert json.loads(row[3]) == {"timeout_seconds": 90}
    assert json.loads(row[4]) == {
        "adapter": "subfinder",
        "reason": "succeeded",
        "source_status": "observed",
    }


def test_subfinder_adapter_parses_jsonl_without_active_flags(monkeypatch):
    class Completed:
        returncode = 0
        stderr = ""
        stdout = json.dumps({"host": "api.example.test", "sources": ["crtsh", "github"]}) + "\nnot-json\n"

    monkeypatch.setattr("recon.recon_intel.shutil.which", lambda _: "subfinder")
    monkeypatch.setattr("recon.recon_intel.subprocess.run", lambda command, **_: Completed())
    result = run_subfinder("example.test")
    assert result["status"] == "observed"
    assert result["items"] == [{"host": "api.example.test", "sources": ["crtsh", "github"]}]


def test_tianyan_adapter_uses_compact_official_company_command(monkeypatch):
    class Completed:
        returncode = 0
        stderr = ""
        stdout = '{"name":"Example Co"}'

    seen: list[str] = []
    monkeypatch.setattr("recon.recon_intel.resolve_executable", lambda _: "tyc")
    monkeypatch.setattr("recon.recon_intel.subprocess.run", lambda command, **_: seen.extend(command) or Completed())
    result = run_tianyan_company("Example Co", kind="equity-tree")
    assert seen == ["tyc", "company", "equity-tree", "Example Co", "--compact"]
    assert result["result"] == {"name": "Example Co"}


def test_subfinder_candidates_stay_review_only_and_are_root_bounded():
    conn = _asset_db()
    source_id = record_source(conn, target_name="demo", source_kind="subfinder_passive", query="example.test", result={})
    count = store_subfinder_candidates(
        conn,
        target_name="demo",
        root_domain="example.test",
        source_id=source_id,
        result={"items": [{"host": "api.example.test"}, {"host": "example.test"}, {"host": "outside.test"}]},
    )
    rows = conn.execute("SELECT asset_value,status,scope_status,scope_class FROM target_assets ORDER BY asset_value").fetchall()
    assert count == 2
    assert [tuple(row) for row in rows] == [
        ("api.example.test", "new", "needs_review", "unknown"),
        ("example.test", "new", "needs_review", "unknown"),
    ]


def test_amass_adapter_stays_passive_and_parses_source_lines(monkeypatch):
    class Completed:
        returncode = 0
        stderr = ""
        stdout = "[Crtsh] api.example.test\nwww.example.test\n"

    seen: list[str] = []
    monkeypatch.setattr("recon.recon_intel.resolve_executable", lambda _: "amass")
    monkeypatch.setattr("recon.recon_intel.subprocess.run", lambda command, **_: seen.extend(command) or Completed())
    result = run_amass("example.test")
    assert "-active" not in seen and "-brute" not in seen and "-alts" not in seen
    assert result["items"] == [
        {"host": "api.example.test", "sources": ["Crtsh"]},
        {"host": "www.example.test", "sources": []},
    ]


def test_uncover_adapter_uses_one_engine_with_explicit_rate_limit(monkeypatch):
    class Completed:
        returncode = 0
        stderr = ""
        stdout = '{"host":"api.example.test","ip":"1.2.3.4","port":443}\n'

    seen: list[str] = []
    monkeypatch.setattr("recon.recon_intel.resolve_executable", lambda _: "uncover")
    monkeypatch.setattr("recon.recon_intel.subprocess.run", lambda command, **_: seen.extend(command) or Completed())
    result = run_uncover('domain="example.test"', engine="fofa", limit=10, rate_limit=1)
    assert seen == [
        "uncover",
        "-e",
        "fofa",
        "-q",
        'domain="example.test"',
        "-l",
        "10",
        "-rl",
        "1",
        "-j",
        "-silent",
        "-duc",
    ]
    assert result["items"] == [{"host": "api.example.test", "ip": "1.2.3.4", "port": 443}]


def test_uncover_adapter_reports_not_configured_when_engine_key_missing(monkeypatch):
    """uncover exits non-zero with 'requires keys' when the engine has no API key;
    the adapter must return not_configured (not tool_failed) so the caller records
    a clean status instead of echoing the raw English stderr as an error."""

    class Completed:
        returncode = 1
        stderr = "[FTL] Could not run enumeration: [uncover:RUNTIME] agents [fofa] requires keys but no keys were found"
        stdout = ""

    monkeypatch.setattr("recon.recon_intel.resolve_executable", lambda _: "uncover")
    monkeypatch.setattr("recon.recon_intel.subprocess.run", lambda *_, **__: Completed())
    result = run_uncover('domain="example.test"', engine="fofa", limit=10, rate_limit=1)
    assert result["status"] == "not_configured"
    assert result["items"] == []
    assert "requires keys" in result["error"]


def test_fofa_prefers_relay_when_uncover_provider_is_empty(monkeypatch, tmp_path):
    provider_config = tmp_path / "provider-config.yaml"
    provider_config.write_text("fofa: []\n", encoding="utf-8")
    capability = resolve_fofa_capability(environ={"FOFA_RELAY_KEY": "relay-test-key"}, provider_config_path=provider_config)
    assert capability == {
        "status": "available",
        "provider": "fofa",
        "adapter": "relay",
        "credential_source": "FOFA_RELAY_KEY",
        "policy": "relay_only",
    }

    monkeypatch.setattr(
        "recon.recon_intel.run_fofa_relay",
        lambda query, *, key, limit: {
            "status": "observed",
            "provider": "fofa",
            "adapter": "relay",
            "query": query,
            "items": [],
        },
    )
    monkeypatch.setattr(
        "recon.recon_intel.run_uncover",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError()),
    )
    result = run_fofa('domain="example.test"', limit=10, capability=capability, relay_key="relay-test-key")
    assert result["adapter"] == "relay"


def test_fofa_reports_single_safe_status_when_no_adapter_is_configured(tmp_path):
    provider_config = tmp_path / "provider-config.yaml"
    provider_config.write_text("fofa: [uncover-secret]\n", encoding="utf-8")
    capability = resolve_fofa_capability(environ={}, provider_config_path=provider_config)
    assert capability == {
        "status": "not_configured",
        "provider": "fofa",
        "adapter": None,
        "credential_source": None,
        "allowed_adapters": ["relay"],
        "policy": "relay_only",
    }
    assert run_fofa('domain="example.test"', limit=10, capability=capability) == capability | {
        "query": 'domain="example.test"',
        "items": [],
    }


def test_fofa_ignores_uncover_config_and_never_falls_back(monkeypatch, tmp_path):
    provider_config = tmp_path / "provider-config.yaml"
    provider_config.write_text("fofa: [uncover-secret]\n", encoding="utf-8")
    capability = resolve_fofa_capability(environ={}, provider_config_path=provider_config)
    monkeypatch.setattr(
        "recon.recon_intel.run_uncover",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("uncover must not run")),
    )
    result = run_fofa('domain="example.test"', limit=10, capability=capability)
    assert result["status"] == "not_configured"
    assert result["adapter"] is None
    assert result["policy"] == "relay_only"


def test_uncover_adapter_keeps_tool_failed_for_other_errors(monkeypatch):
    class Completed:
        returncode = 1
        stderr = "[FTL] network error: connection refused"
        stdout = ""

    monkeypatch.setattr("recon.recon_intel.resolve_executable", lambda _: "uncover")
    monkeypatch.setattr("recon.recon_intel.subprocess.run", lambda *_, **__: Completed())
    result = run_uncover('domain="example.test"', engine="fofa", limit=10, rate_limit=1)
    assert result["status"] == "tool_failed"
    assert "connection refused" in result["error"]


def test_gau_adapter_removes_query_values_from_archived_urls(monkeypatch):
    class Completed:
        returncode = 0
        stderr = ""
        stdout = '{"url":"https://api.example.test/v1/users?token=secret","source":"wayback"}\n'

    monkeypatch.setattr("recon.recon_intel.resolve_executable", lambda _: "gau")
    monkeypatch.setattr("recon.recon_intel.subprocess.run", lambda *_, **__: Completed())
    result = run_gau("example.test")
    assert result["items"] == [{"url": "https://api.example.test/v1/users", "source": "wayback"}]


def test_asnmap_adapter_accepts_only_org_or_asn_without_domain_or_ip_flags(monkeypatch):
    class Completed:
        returncode = 0
        stderr = ""
        stdout = '{"asn":"AS64500","org":"Example Co","cidr":"203.0.113.0/24"}\n'

    seen: list[str] = []
    monkeypatch.setattr("recon.recon_intel.resolve_executable", lambda _: "asnmap")
    monkeypatch.setattr("recon.recon_intel.subprocess.run", lambda command, **_: seen.extend(command) or Completed())
    result = run_asnmap("Example Co", lookup_type="org")
    assert seen == ["asnmap", "-org", "Example Co", "-j", "-silent", "-duc"]
    assert "-d" not in seen and "-i" not in seen
    assert result["items"] == [{"asn": "AS64500", "org": "Example Co", "cidr": "203.0.113.0/24"}]


def test_securitytrails_passive_dns_reads_history_only_when_configured(monkeypatch):
    class Response:
        def read(self):
            return b'{"records":[{"first_seen":"2024-01-01","last_seen":"2024-02-01","values":[{"ip":"203.0.113.8"}]}]}'

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

    seen = []
    monkeypatch.setattr("recon.recon_intel.urllib.request.urlopen", lambda request, **_: seen.append(request) or Response())
    result = run_securitytrails_passive_dns("example.test", api_key="secret")
    assert seen[0].full_url.endswith("/v1/history/example.test/dns/a")
    assert result == {
        "status": "observed",
        "provider": "securitytrails",
        "domain": "example.test",
        "items": [{"ip": "203.0.113.8", "first_seen": "2024-01-01", "last_seen": "2024-02-01"}],
    }


def test_virustotal_passive_dns_never_requests_without_a_key(monkeypatch):
    monkeypatch.setattr("recon.recon_intel.urllib.request.urlopen", lambda *_: (_ for _ in ()).throw(AssertionError()))
    result = run_virustotal_passive_dns("example.test")
    assert result == {"status": "not_configured", "provider": "virustotal", "domain": "example.test", "items": []}


def test_virustotal_passive_dns_normalizes_resolution_history(monkeypatch):
    class Response:
        def read(self):
            return b'{"data":[{"attributes":{"ip_address":"203.0.113.9","date":1700000000,"resolver":"dns"}}]}'

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

    monkeypatch.setattr("recon.recon_intel.urllib.request.urlopen", lambda *_args, **_kwargs: Response())
    result = run_virustotal_passive_dns("example.test", api_key="secret")
    assert result["items"] == [{"ip": "203.0.113.9", "observed_at": 1700000000, "resolver": "dns"}]
