from __future__ import annotations

import sqlite3

from entry_probe import classify_response, generate_candidates
from recon.network_profile import bounded_ports, run_nmap_service_probe
from recon.recon_intel import github_code_search
from recon.recon_store import compact_recon_summary, record_entry, record_origin, record_source


def test_entry_probe_generates_family_variants_without_crawling():
    candidates = generate_candidates(
        "https://example.test/",
        ["https://example.test/login"],
        ["webpack"],
    )
    urls = {item.url for item in candidates}
    assert "https://example.test/login" in urls
    assert "https://example.test/app/login" in urls
    assert "https://example.test/wx/login" in urls
    assert all(item.entry_type in {"login", "register", "admin", "api"} for item in candidates)


def test_entry_probe_classifies_redirect_restriction_and_not_found():
    assert classify_response(302, "/login") == ("auth_redirect", "high")
    assert classify_response(403) == ("restricted", "medium")
    assert classify_response(404) == ("not_found", "high")


def test_recon_store_is_idempotent_and_compact():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    record_source(conn, target_name="demo", source_kind="dns_history", query="demo.test", result={"ips": ["1.2.3.4"]})
    record_source(conn, target_name="demo", source_kind="dns_history", query="demo.test", result={"ips": ["1.2.3.4"]})
    record_origin(conn, target_name="demo", hostname="demo.test", candidate_ip="1.2.3.4", source="dns_history", score=40)
    record_origin(
        conn,
        target_name="demo",
        hostname="demo.test",
        candidate_ip="1.2.3.4",
        source="dns_history",
        score=80,
        confidence="high",
    )
    record_entry(
        conn,
        target_name="demo",
        url="https://demo.test/login",
        entry_type="login",
        source="entry_family",
        status="observed",
    )
    summary = compact_recon_summary(conn, target_name="demo")
    assert summary == {
        "target": "demo",
        "sources": 1,
        "origin_candidates": 1,
        "cdn_observations": 0,
        "network_observations": 0,
        "technology_observations": 0,
        "entry_observations": 1,
    }
    row = conn.execute("SELECT score, confidence FROM origin_candidates").fetchone()
    assert (row["score"], row["confidence"]) == (80, "high")


def test_network_probe_bounds_ports_and_degrades_when_nmap_missing(monkeypatch):
    assert bounded_ports([0, 22, 443, 70000, 443], allowed={22, 80, 443}) == [22, 443]
    monkeypatch.setattr("recon.network_profile.shutil.which", lambda _: None)
    result = run_nmap_service_probe("demo.test", [22, 443], allowed={443}, waf=True)
    assert result["status"] == "blocked"
    assert result["reason"] == "nmap_not_found"
    assert result["ports"] == [443]


def test_github_adapter_returns_compact_status_on_missing_network(monkeypatch):
    def fail(*args, **kwargs):
        raise OSError("offline")

    monkeypatch.setattr("recon.recon_intel.urllib.request.urlopen", fail)
    result = github_code_search("demo", "demo.test password")
    assert result["status"] == "unknown"
    assert result["items"] == []
    assert "offline" in result["error"]
