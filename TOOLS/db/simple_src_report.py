"""Generate lightweight UTF-8 Markdown SRC reports from findings."""
# ruff: noqa: S608

from __future__ import annotations

import re
import sqlite3
import sys
from pathlib import Path
from typing import Any

_TOOLS_DIR = Path(__file__).resolve().parent.parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

from lib.finding_grader import grade_finding  # noqa: E402

PLACEHOLDER_PREFIX = "待人工补充"


def generate_simple_src_reports(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    finding_id: str | None = None,
    output_root: Path | str | None = None,
) -> dict[str, Any]:
    rows = _load_findings(conn, target_name=target_name, finding_id=finding_id)
    if finding_id and not rows:
        raise ValueError(f"finding not found for target {target_name}: {finding_id}")
    if not rows:
        raise ValueError(f"no findings found for target: {target_name}")

    output_dir = _resolve_output_dir(output_root=output_root, target_name=target_name)
    output_dir.mkdir(parents=True, exist_ok=True)

    reports: list[dict[str, str]] = []
    for row in rows:
        evidence_refs = _load_evidence_refs(conn, target_name=target_name, finding=row)
        markdown = render_simple_src_report(row, target_name=target_name, evidence_refs=evidence_refs)
        output_path = output_dir / f"{_safe_filename(row['id'])}.md"
        output_path.write_text(markdown, encoding="utf-8", newline="\n")
        conn.execute("UPDATE findings SET report_file = ? WHERE id = ?", (str(output_path), row["id"]))
        reports.append({"finding_id": row["id"], "output_path": str(output_path)})

    conn.commit()
    return {"target": target_name, "count": len(reports), "reports": reports}


def render_simple_src_report(
    finding: sqlite3.Row,
    *,
    target_name: str,
    evidence_refs: list[sqlite3.Row],
) -> str:
    finding_id = _value(finding, "id")
    vuln_type = _value(finding, "type")
    risk = _value(finding, "risk")
    method = _value(finding, "method")
    url = _value(finding, "url")
    param = _value(finding, "param")
    payload = _value(finding, "payload")
    evidence = _value(finding, "evidence")
    remediation = _value(finding, "remediation")
    review_notes = _value(finding, "review_notes")
    # 标题优先级：库里的人工/LLM 标题 > 自动拼的"具体化"标题 > 旧模板
    title = _value(finding, "title") or _title(finding_id=finding_id, vuln_type=vuln_type, risk=risk, url=url, param=param)

    request_refs = _evidence_lines(evidence_refs, {"request", "repeater_tab"})
    response_refs = _evidence_lines(evidence_refs, {"response", "diff", "operator_note"})
    screenshot_refs = _evidence_lines(evidence_refs, {"screenshot"})

    poc_parts = []
    if method or url:
        poc_parts.append(f"{method or 'GET'} {url or _placeholder('URL')}")
    if param:
        poc_parts.append(f"关键参数: {param}")
    if payload:
        poc_parts.append("Payload:")
        poc_parts.append(_code_block(payload))
    if evidence:
        poc_parts.append("证据摘要:")
        poc_parts.append(_code_block(evidence))
    poc_parts.extend(request_refs)
    poc_parts.extend(response_refs)

    parts = [
        f"# {title}",
        "",
        "## 目标 / URL / 方法",
        "",
        f"- 目标: {target_name or _placeholder('目标')}",
        f"- URL: {url or _placeholder('URL')}",
        f"- 方法: {method or _placeholder('方法')}",
        f"- 关键参数: {param or _placeholder('关键参数')}",
        "",
        "## 漏洞类型与等级",
        "",
        f"- 类型: {vuln_type or _placeholder('漏洞类型')}",
        f"- 等级: {risk or _placeholder('风险等级')}",
        "",
        *_grading_section(finding),
        "## 简要描述 / 影响",
        "",
        review_notes or evidence or _placeholder("简要描述与实际影响"),
        "",
        "## 复现步骤",
        "",
        f"1. 准备具备访问目标 `{target_name or _placeholder('目标')}` 的测试环境、账号或未登录态。",
        f"2. 访问或重放 `{method or 'GET'} {url or _placeholder('URL')}`。",
        f"3. 调整 `{param or _placeholder('关键参数')}` 或请求体中的业务对象标识，观察响应差异。",
        "4. 结合下方 PoC 请求/响应或证据确认漏洞现象，并补齐截图编号。",
        "",
        "## PoC 请求 / 响应或证据",
        "",
        "\n".join(poc_parts) if poc_parts else _placeholder("PoC 请求、响应或证据"),
        "",
        "## 前置条件",
        "",
        _precondition_text(finding),
        "",
        *_fragile_sections(finding),
        "## 截图占位符",
        "",
        "\n".join(screenshot_refs) if screenshot_refs else "- [截图 1] 待人工补充：关键请求、页面结果或响应差异截图",
        "- [截图 2] 待人工补充：如有需要，补充对比账号/变体结果截图",
        "",
        "## 修复建议",
        "",
        remediation or _default_remediation(vuln_type),
        "",
    ]
    return "\n".join(parts)


# ---------------------------------------------------------------- 吸收件
# 以下三块吸收自两份开源评估（CyberStrike 的 triage 规则 / Strix 的反脆弱字段）：
#   _grading_section  —— 定级依据 + 高估风险（把 conclusions 的可反驳性写进报告）
#   _fragile_sections —— 反证 / 置信度理由 / 什么情况下该改等级
#   _title            —— 具体化标题（"XSS" 不算发现）


def _grading_section(finding: sqlite3.Row) -> list[str]:
    """「定级依据」小节：按 finding_grader 给出上限与高估提示。"""
    grade = grade_finding(_finding_dict(finding))
    lines = ["## 定级依据", ""]
    if grade["ceiling"]:
        lines.append(f"- 该类别在无可补充证据时的建议上限: **{grade['ceiling']}**")
    else:
        lines.append("- 未识别的漏洞类别：请人工按下述追问定级（不要默认给 high）")
    lines.extend(
        [
            "- 定级四问（缺一项就往低一档考虑）：",
            "  1. 是否需要受害者交互？",
            "  2. 是否触达「他人」的数据或会话？",
            "  3. 能否导致 RCE / 账号接管 / 数据泄露？",
            "  4. 是在实际配置下可利用，还是仅在理论配置下？",
        ]
    )
    if grade["overclaims"]:
        lines.append("")
        lines.append("> ⚠️ **高估风险**（交付前必须回应，否则建议降级）：")
        lines.extend(f"> - {item}" for item in grade["overclaims"])
    lines.append("")
    return lines


def _fragile_sections(finding: sqlite3.Row) -> list[str]:
    """反脆弱三件套：反证 / 置信度理由 / 什么情况下该改等级。

    这是 Strix 抗过度评级的核心：报告不只说"是什么"，还要说"我排除了什么"
    和"什么新事实会让我改主意"。
    """
    counter = _value(finding, "counterevidence")
    confidence_rationale = _value(finding, "confidence_rationale")
    change_conditions = _value(finding, "severity_change_conditions")

    lines: list[str] = []
    lines.extend(["## 反证（为什么不是误报）", "", counter or _placeholder("试过什么、排除了哪些误报可能"), ""])
    if confidence_rationale:
        lines.extend(["## 置信度理由", "", confidence_rationale, ""])
    lines.extend(
        [
            "## 什么情况下该改这个等级",
            "",
            change_conditions or "- 若证明可触达他人数据/可导致接管 → 上调；若证明仅影响本人或需管理员前置 → 下调。",
            "",
        ]
    )
    return lines


def _precondition_text(finding: sqlite3.Row) -> str:
    value = _value(finding, "preconditions") or _value(finding, "assumptions")
    if value:
        return value
    return _placeholder("前置条件：是否需登录、需要什么角色、是否需内网、是否需特定配置")


def _finding_dict(finding: sqlite3.Row) -> dict[str, Any]:
    """sqlite3.Row 没有 .get()，转成 dict 供 finding_grader 使用。"""
    try:
        return dict(finding)
    except (TypeError, ValueError):
        return {key: _value(finding, key) for key in ("type", "risk", "evidence", "param", "title", "url")}


def _load_findings(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    finding_id: str | None,
) -> list[sqlite3.Row]:
    sql = """
        SELECT f.*, t.target_name
        FROM findings f
        JOIN targets t ON t.id = f.target_id
        WHERE t.target_name = ?
    """
    params: list[Any] = [target_name]
    if finding_id:
        sql += " AND f.id = ?"
        params.append(finding_id)
    sql += " ORDER BY f.confirmed_at ASC, f.id ASC"
    return conn.execute(sql, params).fetchall()


def _load_evidence_refs(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    finding: sqlite3.Row,
) -> list[sqlite3.Row]:
    related_ids = [finding["id"]]
    if _value(finding, "sp_id"):
        related_ids.append(finding["sp_id"])
    placeholders = ", ".join("?" for _ in related_ids)
    sql = f"""
        SELECT *
        FROM evidence_refs
        WHERE target_name = ?
          AND (
              (source_table = 'findings' AND source_id IN ({placeholders}))
              OR (source_table = 'suspicious_points' AND source_id IN ({placeholders}))
        )
        ORDER BY created_at ASC, id ASC
    """
    return conn.execute(sql, [target_name, *related_ids, *related_ids]).fetchall()


def _resolve_output_dir(*, output_root: Path | str | None, target_name: str) -> Path:
    root = Path(output_root) if output_root is not None else Path("reports") / "src_reports"
    return root / _safe_filename(target_name)


def _evidence_lines(evidence_refs: list[sqlite3.Row], types: set[str]) -> list[str]:
    lines: list[str] = []
    for row in evidence_refs:
        if row["evidence_type"] not in types:
            continue
        title = row["title"] or row["evidence_type"]
        summary = row["summary"] or _placeholder("证据说明")
        if row["evidence_type"] == "screenshot":
            lines.append(f"- [截图 {len(lines) + 1}] {title}: {summary}")
        else:
            lines.append(f"- {title}: {summary}")
    return lines


def _title(*, finding_id: str, vuln_type: str, risk: str, url: str = "", param: str = "") -> str:
    """自动拼标题：必须具体到端点/参数。

    吸收自 CyberStrike 的报告质量要求 —— "Cross-Site Scripting (XSS)" 这种标题不算发现，
    客户拿去看不出改哪儿。旧实现是 `[高危] XSS - F-001`，信息量等于零；
    现在退化为 `[high] /api/profile 的 userName 参数存在 XSS`。
    """
    type_text = vuln_type or _placeholder("漏洞类型")
    risk_text = risk or _placeholder("风险等级")
    location = ""
    if url:
        # 只取路径，去掉 scheme/host，避免标题过长且泄露内网主机名
        path = re.sub(r"^[a-z]+://[^/]+", "", url.strip()) or url.strip()
        location = path
    detail = f"的 `{param}` 参数存在 {type_text}" if param else (f"存在 {type_text}" if type_text else "")
    if location:
        return f"[{risk_text}] {location} {detail}".strip()
    return f"[{risk_text}] {type_text}（{finding_id}，待补充受影响端点）"


def _default_remediation(vuln_type: str) -> str:
    if vuln_type:
        return f"围绕 {vuln_type} 补齐服务端鉴权、对象级访问控制、输入校验和审计日志。"
    return _placeholder("修复建议")


def _code_block(value: str) -> str:
    fence = "```"
    if fence in value:
        fence = "````"
    return f"{fence}\n{value}\n{fence}"


def _placeholder(field: str) -> str:
    return f"{PLACEHOLDER_PREFIX}：{field}"


def _value(row: sqlite3.Row, key: str) -> str:
    if key not in row.keys() or row[key] is None:
        return ""
    return str(row[key]).strip()


def _safe_filename(value: str) -> str:
    text = str(value).strip() or "unknown"
    text = re.sub(r"[\\/:*?\"<>|\s]+", "_", text)
    text = re.sub(r"_+", "_", text).strip("._")
    return text or "unknown"
