import json
import sqlite3
import subprocess
import sys
from pathlib import Path

from db.evidence_pack import generate_evidence_pack, queue_screenshot_inbox_for_source

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = PROJECT_ROOT / "TOOLS" / "db" / "schema.sql"
SCRIPT_PATH = PROJECT_ROOT / "TOOLS" / "db" / "evidence_pack.py"


def _conn():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    return conn


def _seed_base(conn: sqlite3.Connection) -> None:
    conn.execute("INSERT INTO targets (id, target_name, domain) VALUES (1, 'demo', 'example.com')")
    conn.execute(
        """
        INSERT INTO work_items (
            id, target_name, lane, subject_table, subject_id, title, status, created_at, updated_at
        ) VALUES
          (101, 'demo', 'vuln_review', 'suspicious_points', 'SP-1', 'review sp', 'done', '2026-07-14 10:00:00', '2026-07-14 10:00:00'),
          (102, 'demo', 'evidence_pack', 'findings', 'F-1', 'pack finding', 'queued', '2026-07-14 10:01:00', '2026-07-14 10:01:00')
        """
    )
    conn.execute(
        """
        INSERT INTO suspicious_points (
            id, page_url, url, param, method, test_type, evidence, source, reasoning, risk,
            test_status, created_at, response_summary
        ) VALUES (
            'SP-1',
            'https://example.com/order',
            'https://example.com/api/order/export?id=1',
            'id',
            'GET',
            'idor',
            'export response includes other user order fields',
            'auth_explore',
            'A/B replay returns another user order export',
            'High',
            'untested',
            '2026-07-14 10:02:00',
            'response contains name, phone, address'
        )
        """
    )
    conn.execute(
        """
        INSERT INTO findings (
            id, sp_id, target_id, type, url, param, method, evidence, risk, cvss, remediation,
            confirmed_at, review_status, review_notes, report_file, audit_status
        ) VALUES (
            'F-1',
            'SP-1',
            1,
            'idor',
            'https://example.com/api/order/export?id=1',
            'id',
            'GET',
            'confirmed by replay diff',
            'High',
            '8.0',
            'enforce object-level authz',
            '2026-07-14 10:03:00',
            'candidate',
            'exported another user order data',
            '',
            'pending'
        )
        """
    )
    conn.execute(
        """
        INSERT INTO evidence_refs (
            target_name, source_table, source_id, evidence_type, title, summary, ref_json, created_at
        ) VALUES
          ('demo', 'findings', 'F-1', 'request', 'orig request', 'GET export with id=1', '{}', '2026-07-14 10:04:00'),
          ('demo', 'findings', 'F-1', 'response', 'diff response', 'returned another user name and phone', '{}', '2026-07-14 10:05:00'),
          ('demo', 'findings', 'F-1', 'diff', 'A/B diff', 'user A and user B responses differ only by unauthorized object data', '{}', '2026-07-14 10:06:00')
        """
    )
    conn.execute(
        """
        INSERT INTO burp_actions (
            id, target_name, work_item_id, action_type, method, url, note, risk_class,
            repeater_tab_name, status, created_at
        ) VALUES (
            501,
            'demo',
            102,
            'send_to_repeater',
            'GET',
            'https://example.com/api/order/export?id=1',
            'F-1 original replay',
            'sensitive_read',
            'demo-102-orig',
            'sent',
            '2026-07-14 10:07:00'
        )
        """
    )
    conn.commit()


def _seed_non_sensitive_finding(conn: sqlite3.Connection) -> None:
    conn.execute("INSERT INTO targets (id, target_name, domain) VALUES (2, 'plain', 'plain.example.com')")
    conn.execute(
        """
        INSERT INTO work_items (
            id, target_name, lane, subject_table, subject_id, title, status, created_at, updated_at
        ) VALUES (
            201, 'plain', 'evidence_pack', 'findings', 'F-PLAIN', 'plain finding', 'queued',
            '2026-07-14 11:00:00', '2026-07-14 11:00:00'
        )
        """
    )
    conn.execute(
        """
        INSERT INTO findings (
            id, sp_id, target_id, type, url, param, method, evidence, risk, cvss, remediation,
            confirmed_at, review_status, review_notes, report_file, audit_status
        ) VALUES (
            'F-PLAIN',
            NULL,
            2,
            'cache_header',
            'https://plain.example.com/api/ping',
            '',
            'GET',
            'cache-control header is inconsistent across nodes',
            'Low',
            '2.0',
            '',
            '2026-07-14 11:01:00',
            'candidate',
            'response headers differ but no sensitive content exposed',
            '',
            'pending'
        )
        """
    )
    conn.execute(
        """
        INSERT INTO evidence_refs (
            target_name, source_table, source_id, evidence_type, title, summary, ref_json, created_at
        ) VALUES
          ('plain', 'findings', 'F-PLAIN', 'request', 'plain request', 'GET /api/ping', '{}', '2026-07-14 11:02:00'),
          ('plain', 'findings', 'F-PLAIN', 'response', 'plain response', 'header mismatch only, no personal data', '{}', '2026-07-14 11:03:00')
        """
    )
    conn.commit()


def test_generate_evidence_pack_from_finding_writes_markdown_and_inbox(tmp_path):
    conn = _conn()
    _seed_base(conn)

    result = generate_evidence_pack(
        conn,
        target_name="demo",
        finding_id="F-1",
        output_root=tmp_path,
    )

    output_path = Path(result["output_path"])
    content = output_path.read_text(encoding="utf-8")
    inbox = conn.execute("SELECT kind, title, url FROM operator_inbox").fetchone()

    assert output_path.exists()
    assert output_path.parent == tmp_path / "demo"
    assert "# idor - F-1" in content
    for title in (
        "## 一句话说明",
        "## 影响资产",
        "## 漏洞类型",
        "## 风险等级建议",
        "## 核心接口/URL",
        "## 复现条件",
        "## 复现步骤",
        "## 关键请求",
        "## 关键响应证据",
        "## 截图清单",
        "## 影响说明",
        "## 修复建议",
        "## 待人工补充",
    ):
        assert title in content
    assert "demo-102-orig" in content
    assert inbox["kind"] == "screenshot_needed"
    assert inbox["url"] == "https://example.com/api/order/export?id=1"


def test_generate_evidence_pack_from_suspicious_point_writes_markdown(tmp_path):
    conn = _conn()
    _seed_base(conn)

    result = generate_evidence_pack(
        conn,
        target_name="demo",
        sp_id="SP-1",
        output_root=tmp_path,
    )

    content = Path(result["output_path"]).read_text(encoding="utf-8")

    assert "# idor - SP-1" in content
    assert "A/B replay returns another user order export" in content
    assert "response contains name, phone, address" in content


def test_queue_screenshot_inbox_for_source_supports_review_phase_without_pack():
    conn = _conn()
    _seed_base(conn)

    first_needed = queue_screenshot_inbox_for_source(
        conn,
        target_name="demo",
        source_table="suspicious_points",
        source_id="SP-1",
    )
    second_needed = queue_screenshot_inbox_for_source(
        conn,
        target_name="demo",
        source_table="suspicious_points",
        source_id="SP-1",
    )

    inbox_rows = conn.execute(
        """
        SELECT kind, title, detail, url
        FROM operator_inbox
        WHERE target_name = 'demo'
        ORDER BY id
        """
    ).fetchall()

    assert first_needed is True
    assert second_needed is True
    assert len(inbox_rows) == 1
    assert inbox_rows[0]["kind"] == "screenshot_needed"
    assert "suspicious_points:SP-1" in inbox_rows[0]["detail"]
    assert inbox_rows[0]["url"] == "https://example.com/api/order/export?id=1"


def test_existing_screenshot_evidence_skips_operator_inbox(tmp_path):
    conn = _conn()
    _seed_base(conn)
    conn.execute(
        """
        INSERT INTO evidence_refs (
            target_name, source_table, source_id, evidence_type, title, summary, ref_json, created_at
        ) VALUES (
            'demo', 'findings', 'F-1', 'screenshot', 'order page screenshot', 'shows another user order in UI', '{}',
            '2026-07-14 10:08:00'
        )
        """
    )
    conn.commit()

    result = generate_evidence_pack(conn, target_name="demo", finding_id="F-1", output_root=tmp_path)
    content = Path(result["output_path"]).read_text(encoding="utf-8")
    inbox_count = conn.execute("SELECT COUNT(*) FROM operator_inbox").fetchone()[0]

    assert result["screenshot_needed"] is False
    assert "order page screenshot" in content
    assert inbox_count == 0


def test_non_sensitive_finding_without_screenshot_does_not_write_operator_inbox(tmp_path):
    conn = _conn()
    _seed_non_sensitive_finding(conn)

    result = generate_evidence_pack(conn, target_name="plain", finding_id="F-PLAIN", output_root=tmp_path)
    content = Path(result["output_path"]).read_text(encoding="utf-8")
    inbox_count = conn.execute("SELECT COUNT(*) FROM operator_inbox WHERE target_name = 'plain'").fetchone()[0]

    assert result["screenshot_needed"] is False
    assert "# cache_header - F-PLAIN" in content
    assert inbox_count == 0


def test_cli_supports_db_target_finding_id_and_output_root(tmp_path):
    db_path = tmp_path / "evidence.db"
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    _seed_base(conn)
    conn.close()

    out_root = tmp_path / "out"
    cmd = [
        sys.executable,
        str(SCRIPT_PATH),
        "--db",
        str(db_path),
        "--target",
        "demo",
        "--finding-id",
        "F-1",
        "--output-root",
        str(out_root),
    ]
    completed = subprocess.run(cmd, capture_output=True, text=True, check=True, cwd=PROJECT_ROOT)  # noqa: S603 -- 测试用 sys.executable 起本仓库脚本
    payload = json.loads(completed.stdout)

    output_path = Path(payload["output_path"])
    verify = sqlite3.connect(db_path)
    verify.row_factory = sqlite3.Row
    inbox = verify.execute("SELECT kind FROM operator_inbox").fetchone()
    verify.close()

    assert payload["source_table"] == "findings"
    assert payload["source_id"] == "F-1"
    assert output_path.exists()
    assert output_path.parent == out_root / "demo"
    assert inbox["kind"] == "screenshot_needed"
