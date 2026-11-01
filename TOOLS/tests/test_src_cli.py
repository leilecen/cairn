from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from pathlib import Path

from db.work_queue import create_work_item

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = PROJECT_ROOT / "TOOLS" / "db" / "schema.sql"
SRC_CLI = PROJECT_ROOT / "TOOLS" / "src_cli.py"


def _db_path(tmp_path: Path) -> Path:
    db_path = tmp_path / "src_cli.db"
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    conn.execute("INSERT INTO targets (id, target_name, domain) VALUES (1, '中文目标', 'example.com')")
    conn.execute(
        """
        INSERT INTO target_assets (target_name, asset_type, asset_value, notes)
        VALUES ('中文目标', 'subdomain', 'test-admin.example.com', 'admin upload')
        """
    )
    create_work_item(
        conn,
        target_name="中文目标",
        lane="quick_scout",
        subject_table="pages",
        subject_id="1",
        title="待领取",
    )
    conn.close()
    return db_path


def _report_db_path(tmp_path: Path) -> Path:
    db_path = tmp_path / "src_report.db"
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    conn.execute("INSERT INTO targets (id, target_name, domain) VALUES (1, '中文目标', 'example.com')")
    conn.execute(
        """
        INSERT INTO findings (
            id, sp_id, target_id, type, url, param, method, payload, evidence, risk,
            remediation, confirmed_at, review_status, review_notes
        ) VALUES (
            'F-中文-1',
            NULL,
            1,
            '越权访问',
            'https://example.com/api/order?id=1',
            'id',
            'GET',
            'GET /api/order?id=2 HTTP/1.1\nHost: example.com\nX-Test: C:\\tmp\\payload',
            '响应返回其他用户订单\n包含手机号字段',
            'High',
            '服务端校验订单归属',
            '2026-07-26 10:00:00',
            'candidate',
            '修改 id 后可读取其他用户订单'
        )
        """
    )
    conn.execute(
        """
        INSERT INTO findings (
            id, sp_id, target_id, type, url, param, method, evidence, risk, confirmed_at
        ) VALUES (
            'F-MISSING',
            NULL,
            1,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            '2026-07-26 10:01:00'
        )
        """
    )
    conn.execute(
        """
        INSERT INTO evidence_refs (
            target_name, source_table, source_id, evidence_type, title, summary, ref_json, created_at
        ) VALUES
          (
            '中文目标', 'findings', 'F-中文-1', 'request',
            '原始请求', '保留中文与换行 payload', '{}', '2026-07-26 10:02:00'
          ),
          ('中文目标', 'findings', 'F-中文-1', 'response', '响应证据', '返回其他用户数据', '{}', '2026-07-26 10:03:00'),
          (
            '中文目标', 'findings', 'F-中文-1', 'screenshot',
            '订单页面截图', '展示越权后的订单详情', '{}', '2026-07-26 10:04:00'
          )
        """
    )
    conn.commit()
    conn.close()
    return db_path


def _run(*args: str, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        [sys.executable, str(SRC_CLI), *args],  # noqa: S607
        input=input_text,
        capture_output=True,
        text=True,
        encoding="utf-8",
        cwd=PROJECT_ROOT,
        check=False,
    )


def _json(stdout: str) -> dict:
    return json.loads(stdout)


def test_unified_cli_payload_file_preserves_chinese_quotes_newlines_and_backslashes(tmp_path):
    db_path = _db_path(tmp_path)
    claimed = _run(
        "--json",
        "work",
        "claim",
        "--db",
        str(db_path),
        "--target",
        "中文目标",
        "--agent-id",
        "agent-一",
    )
    assert claimed.returncode == 0
    work_item_id = _json(claimed.stdout)["data"]["items"][0]["id"]

    payload = {
        "summary": '中文 "quote"\n第二行 C:\\tmp\\payload.json',
        "path": "C:\\Windows\\Temp\\a\\b",
        "nested": {"line": "alpha\nbeta", "quote": '"双引号"'},
    }
    payload_path = tmp_path / "partial_payload.json"
    payload_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

    partial = _run(
        "--json",
        "work",
        "partial",
        "--db",
        str(db_path),
        "--work-item-id",
        str(work_item_id),
        "--agent-id",
        "agent-一",
        "--summary",
        "fallback",
        "--payload-file",
        str(payload_path),
    )

    assert partial.returncode == 0
    assert _json(partial.stdout)["ok"] is True

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    event = conn.execute(
        "SELECT payload_json FROM agent_events WHERE work_item_id = ? AND event_type = 'partial_result'",
        (work_item_id,),
    ).fetchone()
    conn.close()
    stored = json.loads(event["payload_json"])
    # v2 queue events expose the provider-neutral compact worker_result contract.
    assert stored["worker_result"]["status"] == "partial"
    assert '中文 "quote"' in stored["worker_result"]["conclusion"]
    assert "C:\\tmp\\payload.json" in stored["worker_result"]["conclusion"]


def test_unified_cli_payload_stdin_is_equivalent_to_payload_file_for_block(tmp_path):
    db_path = _db_path(tmp_path)
    claimed = _run(
        "--json",
        "work",
        "claim",
        "--db",
        str(db_path),
        "--target",
        "中文目标",
        "--agent-id",
        "agent-b",
    )
    work_item_id = _json(claimed.stdout)["data"]["items"][0]["id"]
    operator_payload = {
        "kind": "login_required",
        "title": "需要登录",
        "detail": "PowerShell stdin\n保留换行",
        "url": 'https://example.com/a\\b?x="1"',
    }

    blocked = _run(
        "--json",
        "work",
        "block",
        "--db",
        str(db_path),
        "--work-item-id",
        str(work_item_id),
        "--agent-id",
        "agent-b",
        "--reason",
        "需要操作员确认",
        "--blocker-class",
        "auth_barrier",
        "--payload-stdin",
        input_text=json.dumps(operator_payload, ensure_ascii=False),
    )

    assert blocked.returncode == 0
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    inbox = conn.execute("SELECT kind, title, detail, url FROM operator_inbox").fetchone()
    conn.close()
    assert dict(inbox) == operator_payload


def test_unified_cli_soft_targets_scores_but_does_not_auto_focus(tmp_path):
    db_path = _db_path(tmp_path)

    scored = _run("--json", "soft-targets", "score", "--db", str(db_path), "--target", "中文目标", "--top", "10")

    assert scored.returncode == 0
    payload = _json(scored.stdout)
    assert payload["data"]["results"]
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    statuses = [row["status"] for row in conn.execute("SELECT status FROM soft_targets ORDER BY rank")]
    conn.close()
    assert statuses
    assert set(statuses) == {"ranked"}


def test_unified_cli_errors_are_parseable_json_with_exit_1(tmp_path):
    db_path = _db_path(tmp_path)

    bad = _run(
        "--json",
        "work",
        "heartbeat",
        "--db",
        str(db_path),
        "--work-item-id",
        "999",
        "--agent-id",
        "agent-a",
    )

    assert bad.returncode == 1
    payload = _json(bad.stdout)
    assert payload["ok"] is False
    assert payload["type"] == "ValueError"
    assert "work_item not found" in payload["error"]


def test_report_generate_writes_one_utf8_markdown_file_per_finding(tmp_path):
    db_path = _report_db_path(tmp_path)
    out_root = tmp_path / "reports"

    generated = _run(
        "--json",
        "report",
        "generate",
        "--db",
        str(db_path),
        "--target",
        "中文目标",
        "--output-root",
        str(out_root),
    )

    assert generated.returncode == 0
    payload = _json(generated.stdout)
    assert payload["data"]["count"] == 2
    paths = [Path(item["output_path"]) for item in payload["data"]["reports"]]
    assert all(path.exists() for path in paths)
    assert {path.name for path in paths} == {"F-中文-1.md", "F-MISSING.md"}


def test_report_generate_preserves_chinese_newlines_backslashes_and_screenshot_placeholders(tmp_path):
    db_path = _report_db_path(tmp_path)
    out_root = tmp_path / "reports"

    generated = _run(
        "--json",
        "report",
        "generate",
        "--db",
        str(db_path),
        "--target",
        "中文目标",
        "--finding-id",
        "F-中文-1",
        "--output-root",
        str(out_root),
    )

    assert generated.returncode == 0
    output_path = Path(_json(generated.stdout)["data"]["reports"][0]["output_path"])
    content = output_path.read_text(encoding="utf-8")
    # 标题已改为"具体到端点/参数"（吸收 CyberStrike 的报告质量要求）：
    # 旧断言 `[High] 越权访问 - F-中文-1` 信息量为零，客户看不出改哪儿。
    assert "# [High] /api/order?id=1 的 `id` 参数存在 越权访问" in content
    assert "越权访问" in content
    assert "响应返回其他用户订单\n包含手机号字段" in content
    assert "GET /api/order?id=2 HTTP/1.1\nHost: example.com\nX-Test: C:\\tmp\\payload" in content
    assert "- [截图 1] 订单页面截图: 展示越权后的订单详情" in content
    assert "- [截图 2] 待人工补充" in content
    # 新增章节（吸收 Strix 反脆弱字段 + CyberStrike triage 规则）
    assert "## 定级依据" in content
    assert "## 反证（为什么不是误报）" in content
    assert "## 什么情况下该改这个等级" in content
    assert "## 前置条件" in content


def test_report_generate_uses_clear_placeholders_for_missing_fields(tmp_path):
    db_path = _report_db_path(tmp_path)
    out_root = tmp_path / "reports"

    generated = _run(
        "--json",
        "report",
        "generate",
        "--db",
        str(db_path),
        "--target",
        "中文目标",
        "--finding-id",
        "F-MISSING",
        "--output-root",
        str(out_root),
    )

    assert generated.returncode == 0
    output_path = Path(_json(generated.stdout)["data"]["reports"][0]["output_path"])
    content = output_path.read_text(encoding="utf-8")
    assert "待人工补充：URL" in content
    assert "待人工补充：方法" in content
    assert "待人工补充：漏洞类型" in content
    assert "待人工补充：风险等级" in content
    assert "待人工补充：PoC 请求、响应或证据" in content


def test_report_generate_missing_finding_returns_parseable_json_exit_1(tmp_path):
    db_path = _report_db_path(tmp_path)

    missing = _run(
        "--json",
        "report",
        "generate",
        "--db",
        str(db_path),
        "--target",
        "中文目标",
        "--finding-id",
        "F-NOT-FOUND",
    )

    assert missing.returncode == 1
    payload = _json(missing.stdout)
    assert payload["ok"] is False
    assert payload["type"] == "ValueError"
    assert "finding not found" in payload["error"]
