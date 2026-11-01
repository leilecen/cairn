"""报告编写能力（吸收自两份开源评估）的回归。

覆盖：
- `lib/finding_grader.py`：triage 定级规则、中文类别别名、高估判定、证据质量门
- `db/report_summary.py`：汇总报告结构、排序、覆盖度章节、交付质量门
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from db.report_summary import (
    build_report_summary,
    render_summary_report,
    validate_for_delivery,
    write_summary_report,
)
from lib.finding_grader import (
    ceiling_for,
    grade_finding,
    has_precondition,
    validate_finding_quality,
)

SCHEMA = Path(__file__).resolve().parents[2] / "TOOLS" / "db" / "schema.sql"


def _conn():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA.read_text(encoding="utf-8"))
    conn.execute("INSERT INTO targets(id,target_name,domain) VALUES(1,'demo','example.com')")
    return conn


def _add_finding(conn, fid, vuln_type, risk, url="https://app.example.com/x", **extra):
    columns = ["id", "target_id", "type", "risk", "url"]
    values = [fid, 1, vuln_type, risk, url]
    for key, value in extra.items():
        columns.append(key)
        values.append(value)
    placeholders = ",".join("?" for _ in values)
    conn.execute(f"INSERT INTO findings({','.join(columns)}) VALUES({placeholders})", values)


# ------------------------------------------------------------- 定级规则


def test_ceiling_covers_english_and_chinese_types():
    assert ceiling_for("cors") == "low"
    assert ceiling_for("CORS配置错误") == "low"
    assert ceiling_for("缺失安全头") == "low"
    assert ceiling_for("存储型跨站脚本") == "high"
    assert ceiling_for("未授权访问") == "critical"
    # 未知类别不由工具猜
    assert ceiling_for("某个没见过的类型") is None


def test_cors_high_is_flagged_as_overclaim():
    grade = grade_finding({"type": "cors", "risk": "high", "evidence": "ACAO: *"})
    assert grade["ceiling"] == "low"
    assert grade["overclaims"], "CORS 报 high 必须被标记为高估"


def test_sqli_with_evidence_is_not_overclaim():
    grade = grade_finding({"type": "sqli", "risk": "critical", "evidence": "union select 返回用户表", "param": "id"})
    assert grade["overclaims"] == []


def test_high_without_evidence_is_overclaim():
    grade = grade_finding({"type": "idor", "risk": "high"})
    assert any("没有证据" in item for item in grade["overclaims"])


def test_idor_high_not_flagged_by_generic_rules():
    """IDOR 的类别上限是 high，不能因为通用规则被误判成高估。"""
    grade = grade_finding({"type": "idor", "risk": "high", "evidence": "读到他人订单", "param": "orderId"})
    assert grade["overclaims"] == []


def test_missing_header_medium_is_overclaim():
    grade = grade_finding({"type": "缺失安全头", "risk": "medium", "evidence": "无 XFO"})
    assert grade["ceiling"] == "low"


# ------------------------------------------------------------- 证据质量门


def test_quality_gate_lists_all_missing_pieces():
    problems = validate_finding_quality({"title": "XSS", "type": "xss", "risk": "high"})
    joined = "\n".join(problems)
    assert "URL" in joined
    assert "证据" in joined
    assert "标题" in joined
    assert "证伪" in joined
    assert "前置条件" in joined


def test_quality_gate_passes_a_complete_finding():
    complete = {
        "title": "/api/user 的 id 参数存在 SQL 注入",
        "url": "https://app.example.com/api/user?id=1",
        "evidence": "返回 3 条他人记录",
        "type": "sqli",
        "risk": "high",
        "param": "id",
        "counterevidence": "换参数后记录数变化，排除静态回显",
        "review_notes": "已登录普通用户，无需管理员",
    }
    assert validate_finding_quality(complete) == []


def test_negative_conclusion_is_rejected_as_finding():
    problems = validate_finding_quality(
        {
            "title": "/login 未发现 SQL 注入",
            "url": "https://app.example.com/login",
            "evidence": "无差异",
            "type": "sqli",
            "risk": "low",
            "counterevidence": "已测",
            "review_notes": "需要登录",
        }
    )
    assert any("否定" in item or "待验证" in item for item in problems)


def test_precondition_detection():
    assert has_precondition({"evidence": "需要管理员登录后访问"})
    assert not has_precondition({"evidence": "返回了数据"})


# ------------------------------------------------------------- 汇总报告


def test_summary_sorts_by_severity_and_includes_coverage():
    conn = _conn()
    _add_finding(conn, "F-1", "缺失安全头", "low", evidence="no xfo")
    _add_finding(conn, "F-2", "SQL注入", "high", param="id", evidence="dump")
    _add_finding(conn, "F-3", "IDOR", "critical", param="orderId", evidence="他人订单")
    conn.execute(
        "INSERT INTO coverage_ledger(target_name,item_key,status,category,blocker_reason,next_action) "
        "VALUES('demo','auth_login','unknown','auth','缺账号','要账号')"
    )
    conn.commit()

    summary = build_report_summary(conn, target_name="demo")
    order = [item["id"] for item in summary["findings"]]
    assert order[0] == "F-3", f"critical 应排最前，实际 {order}"
    assert order[-1] == "F-1"
    assert summary["coverage"]["open_items"][0]["key"] == "auth_login"

    markdown = render_summary_report(summary)
    assert "覆盖度与未测清单" in markdown
    assert "定级异常" in markdown
    assert "auth_login" in markdown


def test_summary_without_coverage_says_so():
    conn = _conn()
    _add_finding(conn, "F-1", "SQL注入", "high", evidence="dump", param="id")
    conn.commit()
    markdown = render_summary_report(build_report_summary(conn, target_name="demo"))
    assert "没有 coverage_ledger 记录" in markdown


def test_summary_table_escapes_pipes():
    conn = _conn()
    _add_finding(conn, "F-1", "SQL注入", "high", evidence="a|b", title="a|b 标题")
    conn.commit()
    markdown = render_summary_report(build_report_summary(conn, target_name="demo"))
    # 标题里的竖线必须转义，否则表格会散
    assert "a\\|b 标题" in markdown


def test_summary_reports_overclaims_separately():
    conn = _conn()
    _add_finding(conn, "F-1", "CORS配置错误", "high", evidence="ACAO: *")
    conn.commit()
    summary = build_report_summary(conn, target_name="demo")
    assert len(summary["overclaims"]) == 1
    assert summary["overclaims"][0]["id"] == "F-1"


def test_write_summary_report_creates_file(tmp_path):
    conn = _conn()
    _add_finding(conn, "F-1", "SQL注入", "high", evidence="dump", param="id")
    conn.commit()
    path = write_summary_report(conn, target_name="demo", output_root=tmp_path)
    assert path.exists()
    assert "demo" in path.name
    assert "安全评估报告" in path.read_text(encoding="utf-8")


def test_validate_for_delivery_flags_incomplete(tmp_path):
    conn = _conn()
    _add_finding(conn, "F-1", "XSS", "high")  # 缺证据、缺证伪
    conn.commit()
    result = validate_for_delivery(conn, target_name="demo")
    assert result["with_problems"] == 1
    assert result["items"][0]["id"] == "F-1"


def test_new_report_columns_exist_in_schema():
    """schema.sql 与 043 迁移必须同时提供这些列，否则报告只能显示占位符。"""
    conn = _conn()
    columns = {row[1] for row in conn.execute("PRAGMA table_info(findings)")}
    for column in (
        "title",
        "preconditions",
        "counterevidence",
        "confidence_rationale",
        "severity_change_conditions",
        "impact",
        "poc_description",
        "fix_verification",
    ):
        assert column in columns, f"findings 缺少报告字段 {column}"


def test_validate_for_delivery_falls_back_when_id_is_null():
    """历史库里 findings.id 可能是 NULL（早期导入遗留），质量门必须仍能定位到具体条目。

    实测 dbs/danss-work.db 的 findings.id 全是 NULL；早期版本会打印 `[None]`，
    人根本无法对应到哪条漏洞。
    """
    conn = _conn()
    conn.execute("INSERT INTO findings(id,target_id,type,risk,url) VALUES(NULL,1,'idor','high','/mng/user.do')")
    conn.commit()
    result = validate_for_delivery(conn, target_name="demo")
    assert result["with_problems"] == 1
    display = result["items"][0]["id"]
    assert display and "None" not in display
    assert "#1" in display or "idor" in display
