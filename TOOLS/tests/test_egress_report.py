"""`TOOLS/db/egress_report.py`：出口强度声明（合规证据）的测试。

重点验证口径：10 秒可持续速率用于合规判定、突发只体现在 1 秒峰值、
刻意无抖动窗口被如实列出、不导出 query/body/cookie。
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from db import egress_report as er

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "TOOLS" / "db" / "schema.sql"


def _db(tmp_path: Path) -> Path:
    path = tmp_path / "t.db"
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA.read_text(encoding="utf-8"))
    conn.commit()
    conn.close()
    return path


def _row(
    conn,
    *,
    epoch: float,
    ts: str,
    host="a.test",
    path="/api",
    status=200,
    decision="sent",
    note="",
    stop="",
    identity="burp-chrome-win",
    mode="burp",
):
    conn.execute(
        "INSERT INTO egress_log (target_name, run_id, ts, epoch, identity, mode, host, method, url_path,"
        " status_code, elapsed_ms, planned_gap_ms, decision, stop_reason, note)"
        " VALUES ('目标A','r1',?,?,?,?,?,'GET',?,?,10,1000,?,?,?)",
        (ts, epoch, identity, mode, host, path, status, decision, stop, note),
    )


def test_load_rows_returns_empty_when_table_missing(tmp_path):
    path = tmp_path / "empty.db"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE targets (id INTEGER PRIMARY KEY)")
    conn.commit()
    conn.close()
    assert er.load_rows(path) == []


def test_load_rows_filters_by_target_and_run(tmp_path):
    path = _db(tmp_path)
    conn = sqlite3.connect(path)
    _row(conn, epoch=100.0, ts="2026-10-10 10:00:00")
    conn.execute(
        "INSERT INTO egress_log (target_name, run_id, ts, epoch, host, url_path, decision)"
        " VALUES ('目标B','r2','2026-10-10 11:00:00',200.0,'b.test','/x','sent')"
    )
    conn.commit()
    conn.close()
    assert len(er.load_rows(path)) == 2
    assert [r["target_name"] for r in er.load_rows(path, target="目标B")] == ["目标B"]
    assert len(er.load_rows(path, run_id="r1")) == 1


def test_report_uses_sustained_rate_for_compliance(tmp_path):
    """突发预算只应体现在 1s 峰值；合规判定看 10s 可持续速率。"""
    rows = [
        {
            "target_name": "目标A",
            "run_id": "r1",
            "ts": "2026-10-10 10:00:00",
            "epoch": 1000.0 + i * 2.0,
            "identity": "id",
            "mode": "burp",
            "host": "a.test",
            "method": "GET",
            "url_path": "/p",
            "status_code": 200,
            "elapsed_ms": 10,
            "planned_gap_ms": 2000,
            "decision": "sent",
            "stop_reason": "",
            "note": "",
        }
        for i in range(10)
    ]
    report = er.build_report(rows, declared_max_rps=0.5, declared_total_budget=10)
    assert report["counts"]["sent"] == 10
    assert report["rate"]["peak_rps_10s"] <= 0.6
    assert report["rate"]["within_declared"] is True
    assert report["budget"]["within_declared"] is True
    assert report["gaps"]["median_ms"] == pytest.approx(2000.0, abs=1.0)


def test_report_flags_burst_as_noncompliance_and_budget_overflow():
    rows = [
        {
            "target_name": "T",
            "run_id": "r",
            "ts": "2026-10-10 10:00:0%d" % i,
            "epoch": 1000.0 + i * 0.05,
            "identity": "id",
            "mode": "burp",
            "host": "a.test",
            "method": "GET",
            "url_path": "/p",
            "status_code": 200,
            "elapsed_ms": 1,
            "planned_gap_ms": 0,
            "decision": "sent",
            "stop_reason": "",
            "note": "unpaced:race-window",
        }
        for i in range(20)
    ]
    report = er.build_report(rows, declared_max_rps=0.5, declared_total_budget=5)
    assert report["rate"]["peak_rps_1s"] > report["rate"]["peak_rps_10s"]
    assert report["rate"]["within_declared"] is False
    assert report["budget"]["within_declared"] is False
    assert len(report["unpaced_windows"]) == 20


def test_report_counts_decisions_stop_reasons_and_hosts():
    rows = [
        {
            "target_name": "T",
            "run_id": "r",
            "ts": "2026-10-10 10:00:00",
            "epoch": 1.0,
            "identity": "id",
            "mode": "burp",
            "host": "a.test",
            "method": "GET",
            "url_path": "/p",
            "status_code": 200,
            "elapsed_ms": 5,
            "planned_gap_ms": 900,
            "decision": "sent",
            "stop_reason": "",
            "note": "",
        },
        {
            "target_name": "T",
            "run_id": "r",
            "ts": "2026-10-10 10:00:05",
            "epoch": 6.0,
            "identity": "id",
            "mode": "burp",
            "host": "b.test",
            "method": "POST",
            "url_path": "/q",
            "status_code": 429,
            "elapsed_ms": 5,
            "planned_gap_ms": 900,
            "decision": "sent",
            "stop_reason": "rate_limited",
            "note": "",
        },
        {
            "target_name": "T",
            "run_id": "r",
            "ts": "2026-10-10 10:00:06",
            "epoch": 7.0,
            "identity": "id",
            "mode": "burp",
            "host": "b.test",
            "method": "GET",
            "url_path": "/q",
            "status_code": 0,
            "elapsed_ms": 0,
            "planned_gap_ms": 0,
            "decision": "blocked",
            "stop_reason": "rate_limited",
            "note": "",
        },
    ]
    report = er.build_report(rows)
    assert report["counts"] == {"total": 3, "sent": 2, "blocked": 1, "skipped": 0, "errors": 0}
    assert report["stop_reasons"] == {"rate_limited": 2}
    assert report["hosts"] == {"a.test": 1, "b.test": 1}
    assert report["status_codes"] == {"200": 1, "429": 1}
    assert report["rate"]["within_declared"] is True, "未声明上限时不判违规"
    assert report["hourly"] == {"2026-10-10 10": 2}


def test_markdown_lists_unpaced_window_paths(tmp_path):
    path = _db(tmp_path)
    conn = sqlite3.connect(path)
    _row(conn, epoch=1.0, ts="2026-10-10 10:00:00", path="/api/items", note="unpaced:race-window")
    conn.commit()
    conn.close()
    markdown = er.render_markdown(er.build_report(er.load_rows(path)))
    assert "/api/items" in markdown
    assert "测试流量强度声明" in markdown
    assert "unpaced:race-window" in markdown


def test_egress_log_schema_stores_no_request_content(tmp_path):
    """合规证据靠「不记录敏感内容」实现，而不是靠事后删：表结构里不允许出现这些列。"""
    path = _db(tmp_path)
    conn = sqlite3.connect(path)
    columns = {row[1] for row in conn.execute("PRAGMA table_info(egress_log)")}
    conn.close()
    assert {"query", "body", "cookies", "headers", "payload", "authorization"} & columns == set()
    assert {"host", "url_path", "planned_gap_ms", "decision", "stop_reason"} <= columns


def test_cli_requires_explicit_target_or_db(capsys):
    assert er.main([]) == 2
    assert "--target" in capsys.readouterr().err


def test_cli_writes_markdown_and_exit_code_reflects_declaration(tmp_path):
    path = _db(tmp_path)
    conn = sqlite3.connect(path)
    for i in range(3):
        _row(conn, epoch=100.0 + i * 2, ts=f"2026-10-10 10:00:0{i}")
    conn.commit()
    conn.close()
    out = tmp_path / "report.md"
    assert er.main(["--db", str(path), "--markdown", "--out", str(out), "--declared-max-rps", "0.5"]) == 0
    assert "测试流量强度声明" in out.read_text(encoding="utf-8")
    # 声明上限低于实际速率 → 退出码 3（CI/门控可用）
    assert er.main(["--db", str(path), "--json", "--declared-max-rps", "0.01"]) == 3


def test_cli_missing_target_returns_one(tmp_path, capsys):
    assert er.main(["--db", str(tmp_path / "nope.db")]) == 1
    assert "error" in capsys.readouterr().err
