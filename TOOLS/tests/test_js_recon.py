"""`TOOLS/pipeline/js_recon.py` 的回归测试。

用本机 fixture JS + 真实二进制跑（工具缺失时跳过），验证：
1. jsluice 抓端点、jsluice secrets 抓密钥（只留类型不留原文）；
2. 空扫描（retire `data: []`）不算 blocker；
3. 落库到 js_signals/js_signal_clusters 且幂等、`signal_count` 是事实行数；
4. 密钥原文绝不进 summary/DB。
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from pipeline import js_recon

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "TOOLS" / "db" / "schema.sql"
BIN = ROOT / "TOOLS" / "bin"

FIXTURE_JS = """\
async function loadUser(id) {
  const r = await fetch("/api/user/detail?id=" + id);
  return r.json();
}
const INTERNAL = "https://internal.example.test:8443/admin/api/list";
const token = "AKIAIOSFODNN7EXAMPLE";
export { loadUser, INTERNAL, token };
"""


@pytest.fixture
def js_case(tmp_path):
    js_file = tmp_path / "app.js"
    js_file.write_text(FIXTURE_JS, encoding="utf-8")
    return js_file


@pytest.fixture
def case_dir(tmp_path, monkeypatch):
    """把 tmp/js_reverse 根指到 pytest 临时目录，避免污染仓库。"""
    monkeypatch.setattr(js_recon, "REVERSE_ROOT", tmp_path / "js_reverse")
    return tmp_path


def test_jsluice_url_rows_keep_params_and_method():
    payload = (
        '{"url":"/api/user/detail?id=EXPR","queryParams":["id"],"bodyParams":[],"method":"GET","type":"fetch"}'
        "\n"
        '{"url":"https://internal.example.test:8443/admin/api/list","queryParams":[],"bodyParams":[],"type":"stringLiteral"}'
        "\n"
    )
    rows = js_recon.jsluice_url_rows(payload)
    assert rows[0]["params"] == ["id"] and rows[0]["method"] == "GET" and rows[0]["kind"] == "fetch"
    assert rows[1]["url"].endswith("/admin/api/list") and rows[1]["method"] == "GET"


def test_jsluice_secret_rows_never_keep_plaintext():
    payload = '{"kind":"AWSAccessKey","data":{"key":"AKIAIOSFODNN7EXAMPLE"},"filename":"a.js","severity":"low","context":null}'
    rows = js_recon.jsluice_secret_rows(payload)
    assert rows == [{"kind": "AWSAccessKey", "severity": "low", "file": "a.js"}]
    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(rows)


def test_risk_for_path_weights_sensitive_keywords():
    assert js_recon.risk_for_path("/admin/api/list") > js_recon.risk_for_path("/api/user/detail")
    assert js_recon.risk_for_path("/") == 0


@pytest.mark.skipif(not (BIN / "jsluice.exe").is_file(), reason="需要本机 jsluice")
def test_analyze_js_file_runs_toolchain_and_reports_no_blocker(js_case, case_dir):
    summary = js_recon.analyze_js_file(js_case, case="t", target_name="", timeout=60)
    kinds = [signal["signal_type"] for signal in summary["signals"]]
    assert "js_endpoint" in kinds and "secret_candidate" in kinds
    assert summary["blockers"] == [], summary["blockers"]
    urls = [signal.get("url") or "" for signal in summary["signals"]]
    assert any("admin/api/list" in url for url in urls)
    # 密钥原文不得出现在任何 compact 输出里
    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(summary, ensure_ascii=False)
    # gitleaks 0 命中必须显式警告（实测该 build 会漏报）
    assert any("gitleaks" in warning for warning in summary["warnings"])


@pytest.mark.skipif(not (BIN / "jsluice.exe").is_file(), reason="需要本机 jsluice")
def test_store_signals_is_idempotent_and_reports_fact_counts(tmp_path, case_dir, monkeypatch):
    db = tmp_path / "t.db"
    conn = sqlite3.connect(db)
    conn.executescript(SCHEMA.read_text(encoding="utf-8"))
    conn.execute("INSERT INTO targets (target_name, domain) VALUES ('演示目标', 'demo.test')")
    conn.commit()
    conn.close()

    js_file = case_dir / "app.js"
    js_file.write_text(FIXTURE_JS, encoding="utf-8")
    summary = js_recon.analyze_js_file(js_file, case="store", target_name="演示目标", js_file_id=1, timeout=60)

    first = js_recon.store_signals(db, summary)
    second = js_recon.store_signals(db, summary)

    assert first["inserted"] >= 3
    assert second["inserted"] == 0 and second["duplicates"] >= 3

    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT COUNT(*) FROM js_signals WHERE js_file_id=1").fetchone()[0]
    clusters = conn.execute("SELECT COUNT(*) FROM js_signal_clusters").fetchone()[0]
    conn.close()
    assert rows == first["inserted"]
    assert clusters > 0
    # 第二次落库不得让事实表行数变化
    assert second["clusters"] == 0
