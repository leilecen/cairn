import json
import sqlite3
from datetime import datetime
from types import SimpleNamespace

import pipeline.init_scan as init_scan
import pytest


def _db(path):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        CREATE TABLE targets (
            target_name TEXT PRIMARY KEY, domain TEXT, ip TEXT,
            tech_stack TEXT, requires_auth INTEGER DEFAULT 0,
            auth_status TEXT DEFAULT 'not_logged_in'
        );
        CREATE TABLE pages (id INTEGER PRIMARY KEY, url TEXT, depth INTEGER, status TEXT);
        CREATE TABLE work_items (id INTEGER PRIMARY KEY, target_name TEXT, status TEXT);
        CREATE TABLE scan_state (id INTEGER PRIMARY KEY, seed_url TEXT, phase TEXT);
        CREATE TABLE hunt_sessions (id INTEGER PRIMARY KEY, target_name TEXT, status TEXT);
        INSERT INTO targets(target_name, domain) VALUES ('demo', 'demo.example');
        INSERT INTO hunt_sessions(target_name, status) VALUES ('demo', 'active');
        """
    )
    conn.commit()
    return conn


def test_baseline_scans_only_authorized_assets_and_has_no_deep_side_effects(tmp_path, monkeypatch):
    db_path = tmp_path / "demo.db"
    conn = _db(db_path)
    init_scan.ensure_asset_verification_schema(conn)
    conn.executemany(
        """INSERT INTO target_assets
        (target_name, asset_value, protocol, scope_status, scope_class)
        VALUES (?, ?, ?, ?, ?)""",
        [
            ("demo", "allowed.demo.example", "https", "in_scope", "owned"),
            ("demo", "review.example", "https", "needs_review", "unknown"),
            ("demo", "out.example", "https", "out_of_scope", "intel_only"),
        ],
    )
    conn.commit()
    conn.close()

    calls = []

    def fake_httpx(urls, *, start_index=0, budget=None):
        calls.append(urls)
        return {
            "status": "succeeded",
            "results": [
                {
                    "url": urls[0],
                    "status_code": 200,
                    "title": "Admin Login",
                    "host": "203.0.113.10",
                    "tech": ["Druid"],
                    "live": True,
                }
            ],
            "next_index": len(urls),
        }

    monkeypatch.setattr(init_scan, "find_db", lambda _target: db_path)
    monkeypatch.setattr(
        init_scan,
        "run_baseline_entry_probe",
        lambda conn, **kwargs: {"status": "done", "requests": 0, "observations": 0},
    )
    monkeypatch.setattr(init_scan, "run_httpx_baseline", fake_httpx)
    monkeypatch.setattr(init_scan.sys, "argv", ["init_scan", "--target", "demo", "--db", str(db_path), "--baseline"])

    init_scan.main()

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    assert calls == [["https://allowed.demo.example"]]
    row = conn.execute(
        "SELECT last_status_code, last_title, last_tech_stack, auth_entry_found FROM target_assets WHERE asset_value='allowed.demo.example'"
    ).fetchone()
    assert tuple(row) == (200, "Admin Login", "Druid", 1)
    assert conn.execute("SELECT COUNT(*) FROM pages WHERE status='queued'").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM work_items").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM scan_state").fetchone()[0] == 0
    run = conn.execute("SELECT status, cursor_json, budget_json, summary_json, last_success_at FROM recon_runs").fetchone()
    assert run[0] == "succeeded"
    assert json.loads(run[1]) == {"next_index": 1, "total": 1}
    assert json.loads(run[2])["max_assets"] == 100
    assert json.loads(run[3])["observed"] == 1
    assert datetime.fromisoformat(run[4])


def test_baseline_without_authorized_assets_is_blocked_not_succeeded(tmp_path, monkeypatch):
    db_path = tmp_path / "demo.db"
    conn = _db(db_path)
    init_scan.ensure_asset_verification_schema(conn)
    conn.commit()
    conn.close()

    monkeypatch.setattr(init_scan, "find_db", lambda _target: db_path)
    monkeypatch.setattr(
        init_scan,
        "run_httpx_baseline",
        lambda *_args, **_kwargs: pytest.fail("baseline must not invoke httpx without authorized assets"),
    )
    monkeypatch.setattr(init_scan.sys, "argv", ["init_scan", "--target", "demo", "--db", str(db_path), "--baseline"])

    init_scan.main()

    with sqlite3.connect(db_path) as conn:
        run = conn.execute("SELECT status,summary_json FROM recon_runs").fetchone()
    assert run[0] == "blocked"
    assert json.loads(run[1])["reason"] == "no_authorized_assets"


def test_baseline_uses_explicit_db_instead_of_target_lookup(tmp_path, monkeypatch):
    db_path = tmp_path / "demo.db"
    conn = _db(db_path)
    init_scan.ensure_asset_verification_schema(conn)
    conn.execute(
        """INSERT INTO target_assets(target_name,asset_value,protocol,scope_status,scope_class)
           VALUES ('demo','demo.example','https','in_scope','owned')"""
    )
    conn.commit()
    conn.close()
    monkeypatch.setattr(init_scan, "find_db", lambda _target: pytest.fail("must not resolve a historical target DB"))
    monkeypatch.setattr(
        init_scan,
        "run_httpx_baseline",
        lambda urls, **_kwargs: {"status": "succeeded", "results": [], "next_index": len(urls)},
    )
    monkeypatch.setattr(
        init_scan,
        "run_baseline_entry_probe",
        lambda *_args, **_kwargs: {"status": "done", "requests": 0, "observations": 0},
    )
    monkeypatch.setattr(
        init_scan.sys,
        "argv",
        ["init_scan", "--target", "demo", "--db", str(db_path), "--baseline"],
    )

    init_scan.main()


def test_baseline_httpx_nonzero_with_jsonl_is_partial(monkeypatch):
    monkeypatch.setattr(init_scan, "resolve_httpx_binary", lambda: "httpx")
    # 出口预检单独覆盖（test_init_scan_egress.py）；这里只验证批次/游标语义。
    monkeypatch.setattr(init_scan, "_egress_proxy_url", lambda: "http://127.0.0.1:8080")

    def fake_run(cmd, **_kwargs):
        with open(cmd[cmd.index("-o") + 1], "w", encoding="utf-8") as handle:
            handle.write('{"url":"https://a.example","status_code":200}\n')
        return SimpleNamespace(returncode=2, stdout="", stderr="boom")

    monkeypatch.setattr(init_scan.subprocess, "run", fake_run)
    result = init_scan.run_httpx_baseline(["https://a.example"])

    assert result["status"] == "partial"
    assert result["results"] == [{"url": "https://a.example", "status_code": 200}]
    assert result["next_index"] == 0
    assert result["error"] == "httpx_exit_2"


def test_baseline_httpx_zero_exit_without_jsonl_is_failed(tmp_path, monkeypatch):
    monkeypatch.setattr(init_scan, "resolve_httpx_binary", lambda: "httpx")
    monkeypatch.setattr(init_scan, "_egress_proxy_url", lambda: "http://127.0.0.1:8080")
    monkeypatch.setattr(
        init_scan.subprocess,
        "run",
        lambda _cmd, **_kwargs: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    result = init_scan.run_httpx_baseline(["https://missing.example"])

    assert result["status"] == "failed"
    assert result["results"] == []
    assert result["error"] == "missing_jsonl"


def test_baseline_resumes_partial_cursor_without_fingerprinting_urls(tmp_path, monkeypatch):
    db_path = tmp_path / "demo.db"
    conn = _db(db_path)
    init_scan.ensure_asset_verification_schema(conn)
    conn.executemany(
        """INSERT INTO target_assets
        (target_name, asset_value, protocol, scope_status, scope_class)
        VALUES (?, ?, ?, 'in_scope', 'owned')""",
        [("demo", f"a{i}.demo.example", "https") for i in range(3)],
    )
    conn.commit()
    conn.close()

    calls = []

    def fake_baseline(urls, *, start_index=0, budget=None):
        calls.append((urls, start_index, budget))
        if len(calls) == 1:
            return {
                "status": "partial",
                "results": [{"url": urls[start_index], "status_code": 200, "title": "A"}],
                "next_index": start_index + 1,
                "error": "httpx_exit_2",
            }
        return {
            "status": "succeeded",
            "results": [
                {"url": urls[start_index], "status_code": 200, "title": "B"},
                {"url": urls[start_index + 1], "status_code": 200, "title": "C"},
            ],
            "next_index": start_index + 2,
        }

    monkeypatch.setattr(init_scan, "find_db", lambda _target: db_path)
    monkeypatch.setattr(
        init_scan,
        "run_baseline_entry_probe",
        lambda conn, **kwargs: {"status": "done", "requests": 0, "observations": 0},
    )
    monkeypatch.setattr(init_scan, "run_httpx_baseline", fake_baseline)
    monkeypatch.setattr(init_scan.sys, "argv", ["init_scan", "--target", "demo", "--db", str(db_path), "--baseline"])
    init_scan.main()
    init_scan.main()

    assert calls[0][0] == [
        "https://a0.demo.example",
        "https://a1.demo.example",
        "https://a2.demo.example",
    ]
    assert calls[1][0] == calls[0][0]
    assert calls[1][1] == 1
    conn = sqlite3.connect(db_path)
    run = conn.execute("SELECT status, cursor_json, summary_json, next_retry_at, input_fingerprint FROM recon_runs").fetchone()
    assert run[0] == "succeeded"
    assert json.loads(run[1])["next_index"] == 3
    assert run[3] is None
    assert len(run[4]) == 64


def test_baseline_success_runs_bounded_entry_stage(tmp_path, monkeypatch):
    db_path = tmp_path / "demo.db"
    conn = _db(db_path)
    init_scan.ensure_asset_verification_schema(conn)
    conn.execute(
        """INSERT INTO target_assets
        (target_name, asset_value, protocol, scope_status, scope_class)
        VALUES ('demo', 'admin.demo.example', 'https', 'in_scope', 'owned')"""
    )
    conn.commit()
    conn.close()
    observed = {}

    monkeypatch.setattr(init_scan, "find_db", lambda _target: db_path)
    monkeypatch.setattr(
        init_scan,
        "run_httpx_baseline",
        lambda urls, *, start_index=0, budget=None: {
            "status": "succeeded",
            "results": [],
            "next_index": len(urls),
        },
    )

    def fake_entry(conn, *, target_name, fetcher, **kwargs):
        observed["target"] = target_name
        observed["fetch"] = fetcher("https://admin.demo.example/login", "GET")
        return {"status": "done", "assets_processed": 1, "requests": 1, "observations": 1}

    monkeypatch.setattr(init_scan, "run_baseline_entry_probe", fake_entry)
    monkeypatch.setattr(
        init_scan,
        "_baseline_entry_fetcher",
        lambda url, method: {"status_code": 200, "body_hint": "login"},
    )
    monkeypatch.setattr(init_scan.sys, "argv", ["init_scan", "--target", "demo", "--db", str(db_path), "--baseline"])
    init_scan.main()

    assert observed == {
        "target": "demo",
        "fetch": {"status_code": 200, "body_hint": "login"},
    }
    conn = sqlite3.connect(db_path)
    rows = conn.execute("SELECT source, status, summary_json FROM recon_runs ORDER BY id").fetchall()
    assert [(row[0], row[1]) for row in rows] == [
        ("init_scan_httpx_baseline", "succeeded"),
        ("init_scan_baseline_entries", "succeeded"),
    ]
    assert json.loads(rows[1][2])["observations"] == 1
    assert conn.execute("SELECT COUNT(*) FROM pages WHERE status='queued'").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM work_items").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM scan_state").fetchone()[0] == 0


def test_baseline_blocked_entry_keeps_httpx_success_and_records_retry(tmp_path, monkeypatch):
    db_path = tmp_path / "demo.db"
    conn = _db(db_path)
    init_scan.ensure_asset_verification_schema(conn)
    conn.execute(
        """INSERT INTO target_assets
        (target_name, asset_value, protocol, scope_status, scope_class)
        VALUES ('demo', 'admin.demo.example', 'https', 'in_scope', 'owned')"""
    )
    conn.commit()
    conn.close()
    monkeypatch.setattr(init_scan, "find_db", lambda _target: db_path)
    monkeypatch.setattr(
        init_scan,
        "run_httpx_baseline",
        lambda urls, *, start_index=0, budget=None: {
            "status": "succeeded",
            "results": [],
            "next_index": len(urls),
        },
    )
    monkeypatch.setattr(
        init_scan,
        "run_baseline_entry_probe",
        lambda conn, **kwargs: {
            "status": "blocked",
            "stop_reason": "waf_detected",
            "requests": 1,
            "observations": 1,
            "assets_processed": 1,
        },
    )
    monkeypatch.setattr(init_scan.sys, "argv", ["init_scan", "--target", "demo", "--db", str(db_path), "--baseline"])
    init_scan.main()

    conn = sqlite3.connect(db_path)
    rows = conn.execute("SELECT source, status, next_retry_at FROM recon_runs ORDER BY id").fetchall()
    assert rows[0][1] == "succeeded"
    assert rows[1][0] == "init_scan_baseline_entries"
    assert rows[1][1] == "blocked"
    assert rows[1][2] is not None
