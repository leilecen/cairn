"""Generate minimal Markdown evidence packs for findings and suspicious points."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any

_TOOLS_DIR = Path(__file__).resolve().parent.parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

from db.db_utils import connect, find_db  # noqa: E402

SECTION_TITLES = [
    "一句话说明",
    "影响资产",
    "漏洞类型",
    "风险等级建议",
    "核心接口/URL",
    "复现条件",
    "复现步骤",
    "关键请求",
    "关键响应证据",
    "截图清单",
    "影响说明",
    "修复建议",
    "待人工补充",
]

SCREENSHOT_KEYWORDS = (
    "idor",
    "越权",
    "unauth",
    "unauthorized",
    "敏感",
    "upload",
    "download",
    "export",
    "导出",
    "下载",
    "上传",
    "file",
    "avatar",
    "profile",
    "token",
    "身份证",
    "手机号",
    "email",
)

NEGATED_SCREENSHOT_PHRASES = (
    "no sensitive",
    "not sensitive",
    "无敏感",
    "非敏感",
    "without sensitive",
)


def generate_evidence_pack(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    finding_id: str | None = None,
    sp_id: str | None = None,
    output_root: Path | str | None = None,
) -> dict[str, Any]:
    source_table, source_id = _resolve_source_id(finding_id=finding_id, sp_id=sp_id)
    entity = _load_entity(conn, target_name=target_name, source_table=source_table, source_id=source_id)
    evidence_refs = _load_evidence_refs(conn, target_name=target_name, source_table=source_table, source_id=source_id)
    burp_actions = _load_burp_actions(conn, target_name=target_name, source_table=source_table, source_id=source_id)

    output_dir = _resolve_output_dir(output_root=output_root, target_name=target_name)
    output_path = output_dir / f"{source_id}.md"
    output_dir.mkdir(parents=True, exist_ok=True)

    markdown = render_evidence_pack_markdown(
        entity=entity,
        target_name=target_name,
        source_id=source_id,
        evidence_refs=evidence_refs,
        burp_actions=burp_actions,
    )
    output_path.write_text(markdown, encoding="utf-8")

    screenshot_needed = ensure_screenshot_inbox(
        conn,
        target_name=target_name,
        source_table=source_table,
        source_id=source_id,
        entity=entity,
        evidence_refs=evidence_refs,
        burp_actions=burp_actions,
    )

    if source_table == "findings" and output_root is None:
        conn.execute("UPDATE findings SET report_file = ? WHERE id = ?", (str(output_path), source_id))
        conn.commit()

    return {
        "target": target_name,
        "source_table": source_table,
        "source_id": source_id,
        "output_path": str(output_path),
        "screenshot_needed": screenshot_needed,
    }


def queue_screenshot_inbox_for_source(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    source_table: str,
    source_id: str,
) -> bool:
    """Ensure a screenshot follow-up exists for review/discovery evidence.

    Returns True when a screenshot is still needed and an open inbox item exists
    or was created. Returns False when screenshot evidence already exists or the
    source does not need a screenshot.
    """
    if source_table not in {"findings", "suspicious_points"}:
        raise ValueError(f"unsupported screenshot source_table: {source_table}")
    entity = _load_entity(conn, target_name=target_name, source_table=source_table, source_id=source_id)
    evidence_refs = _load_evidence_refs(
        conn,
        target_name=target_name,
        source_table=source_table,
        source_id=source_id,
    )
    burp_actions = _load_burp_actions(
        conn,
        target_name=target_name,
        source_table=source_table,
        source_id=source_id,
    )
    return ensure_screenshot_inbox(
        conn,
        target_name=target_name,
        source_table=source_table,
        source_id=source_id,
        entity=entity,
        evidence_refs=evidence_refs,
        burp_actions=burp_actions,
    )


def render_evidence_pack_markdown(
    *,
    entity: sqlite3.Row,
    target_name: str,
    source_id: str,
    evidence_refs: list[sqlite3.Row],
    burp_actions: list[sqlite3.Row],
) -> str:
    title = _title_for_entity(entity, source_id=source_id)
    summary = _one_line_summary(entity)
    asset = _asset_text(entity, target_name=target_name)
    vuln_type = entity["type"] if "type" in entity.keys() and entity["type"] else entity["test_type"]
    risk = entity["risk"] or "待评估"
    url = entity["url"] or entity["page_url"] or "待人工补充"
    repro_condition = _repro_condition(entity)
    repro_steps = _repro_steps(entity, burp_actions=burp_actions)
    key_requests = _key_request_lines(entity, evidence_refs=evidence_refs, burp_actions=burp_actions)
    key_responses = _key_response_lines(entity, evidence_refs=evidence_refs)
    screenshots = _screenshot_lines(evidence_refs)
    impact = _impact_text(entity)
    remediation = _remediation_text(entity)
    manual = _manual_followups(entity, evidence_refs=evidence_refs)

    parts = [
        f"# {title}",
        "",
        f"## 一句话说明\n\n{summary}",
        "",
        f"## 影响资产\n\n{asset}",
        "",
        f"## 漏洞类型\n\n{vuln_type or '待人工补充'}",
        "",
        f"## 风险等级建议\n\n{risk}",
        "",
        f"## 核心接口/URL\n\n{url}",
        "",
        f"## 复现条件\n\n{repro_condition}",
        "",
        f"## 复现步骤\n\n{repro_steps}",
        "",
        f"## 关键请求\n\n{key_requests}",
        "",
        f"## 关键响应证据\n\n{key_responses}",
        "",
        f"## 截图清单\n\n{screenshots}",
        "",
        f"## 影响说明\n\n{impact}",
        "",
        f"## 修复建议\n\n{remediation}",
        "",
        f"## 待人工补充\n\n{manual}",
        "",
    ]
    return "\n".join(parts)


def ensure_screenshot_inbox(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    source_table: str,
    source_id: str,
    entity: sqlite3.Row,
    evidence_refs: list[sqlite3.Row],
    burp_actions: list[sqlite3.Row],
) -> bool:
    if _has_screenshot_evidence(evidence_refs):
        return False
    if not _needs_screenshot(entity, evidence_refs=evidence_refs, burp_actions=burp_actions):
        return False
    existing = conn.execute(
        """
        SELECT id
        FROM operator_inbox
        WHERE target_name = ?
          AND kind = 'screenshot_needed'
          AND status = 'open'
          AND detail LIKE ?
        LIMIT 1
        """,
        (target_name, f"%{source_table}:{source_id}%"),
    ).fetchone()
    if existing is not None:
        return True

    title = f"补截图证据 {source_id}"
    detail = f"{source_table}:{source_id} 缺少可视化截图证据，请围绕 {entity['url'] or entity['page_url'] or '相关页面'} 补充。"
    suggested_action = "登录对应角色后截图关键页面、对象详情、导出结果或上传/下载效果。"
    conn.execute(
        """
        INSERT INTO operator_inbox (
            target_name, related_work_item_id, kind, title, detail, suggested_action, url, status
        ) VALUES (?, NULL, 'screenshot_needed', ?, ?, ?, ?, 'open')
        """,
        (target_name, title, detail, suggested_action, entity["url"] or entity["page_url"]),
    )
    conn.commit()
    return True


def _resolve_source_id(*, finding_id: str | None, sp_id: str | None) -> tuple[str, str]:
    if bool(finding_id) == bool(sp_id):
        raise ValueError("exactly one of finding_id or sp_id is required")
    if finding_id:
        return "findings", finding_id
    return "suspicious_points", sp_id or ""


def _load_entity(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    source_table: str,
    source_id: str,
) -> sqlite3.Row:
    if source_table == "findings":
        row = conn.execute(
            """
            SELECT f.*, t.target_name
            FROM findings f
            JOIN targets t ON t.id = f.target_id
            WHERE t.target_name = ?
              AND f.id = ?
            """,
            (target_name, source_id),
        ).fetchone()
    else:
        row = conn.execute(
            """
            SELECT sp.*, ? AS target_name
            FROM suspicious_points sp
            WHERE sp.id = ?
            """,
            (target_name, source_id),
        ).fetchone()
    if row is None:
        raise ValueError(f"{source_table} not found for target {target_name}: {source_id}")
    return row


def _load_evidence_refs(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    source_table: str,
    source_id: str,
) -> list[sqlite3.Row]:
    related_ids = [source_id]
    if source_table == "findings":
        finding_row = conn.execute("SELECT sp_id FROM findings WHERE id = ?", (source_id,)).fetchone()
        if finding_row is not None and finding_row["sp_id"]:
            related_ids.append(finding_row["sp_id"])
    placeholders = ", ".join("?" for _ in related_ids)
    params: list[Any] = [target_name, source_table, *related_ids]
    sql = f"""
        SELECT *
        FROM evidence_refs
        WHERE target_name = ?
          AND (
              (source_table = ? AND source_id IN ({placeholders}))
              OR (source_table = 'suspicious_points' AND source_id IN ({placeholders}))
          )
        ORDER BY created_at ASC, id ASC
    """  # noqa: S608 -- 仅拼接 "?" 占位符，值全走参数绑定
    params.extend(related_ids)
    return conn.execute(sql, params).fetchall()


def _load_burp_actions(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    source_table: str,
    source_id: str,
) -> list[sqlite3.Row]:
    if source_table == "findings":
        row = conn.execute("SELECT sp_id FROM findings WHERE id = ?", (source_id,)).fetchone()
        subject_ids = [source_id]
        if row is not None and row["sp_id"]:
            subject_ids.append(row["sp_id"])
    else:
        subject_ids = [source_id]
    placeholders = ", ".join("?" for _ in subject_ids)
    sql = f"""
        SELECT b.*
        FROM burp_actions b
        LEFT JOIN work_items w ON w.id = b.work_item_id
        WHERE b.target_name = ?
          AND (
              w.subject_id IN ({placeholders})
              OR COALESCE(b.note, '') LIKE ?
          )
        ORDER BY b.created_at ASC, b.id ASC
    """  # noqa: S608 -- 仅拼接 "?" 占位符，值全走参数绑定
    params: list[Any] = [target_name, *subject_ids, f"%{source_id}%"]
    return conn.execute(sql, params).fetchall()


def _resolve_output_dir(*, output_root: Path | str | None, target_name: str) -> Path:
    if output_root is None:
        return Path("reports") / "evidence_packs" / target_name
    return Path(output_root) / target_name


def _title_for_entity(entity: sqlite3.Row, *, source_id: str) -> str:
    if _row_value(entity, "type"):
        return f"{entity['type']} - {source_id}"
    if _row_value(entity, "test_type"):
        return f"{entity['test_type']} - {source_id}"
    return source_id


def _one_line_summary(entity: sqlite3.Row) -> str:
    text = _row_value(entity, "reasoning") or _row_value(entity, "review_notes") or _row_value(entity, "evidence", "")
    if text:
        return text
    url = entity["url"] or entity["page_url"] or "相关接口"
    vuln_type = entity["type"] if "type" in entity.keys() and entity["type"] else entity["test_type"] or "可疑点"
    return f"{url} 存在与 {vuln_type} 相关的异常表现，需结合请求和响应证据人工复核。"


def _asset_text(entity: sqlite3.Row, *, target_name: str) -> str:
    url = _row_value(entity, "url") or _row_value(entity, "page_url") or ""
    return url if url else target_name


def _repro_condition(entity: sqlite3.Row) -> str:
    bits = []
    if "review_status" in entity.keys():
        bits.append(f"当前状态: {_row_value(entity, 'review_status') or 'candidate'}")
    if _row_value(entity, "method"):
        bits.append(f"请求方式: {entity['method']}")
    if _row_value(entity, "param"):
        bits.append(f"关键参数: {entity['param']}")
    return "；".join(bits) if bits else "待人工补充账号、角色和前置数据。"


def _repro_steps(entity: sqlite3.Row, *, burp_actions: list[sqlite3.Row]) -> str:
    steps = [
        "1. 准备可访问目标资产的账号、角色或未登录态。",
        f"2. 打开或重放 `{_row_value(entity, 'url') or _row_value(entity, 'page_url') or '目标接口'}`，并代入关键参数。",
        "3. 对比原始请求与变体请求的响应差异，确认是否出现越权、敏感信息泄露或异常结果。",
    ]
    if burp_actions:
        tab_names = [row["repeater_tab_name"] for row in burp_actions if row["repeater_tab_name"]]
        if tab_names:
            steps.append(f"4. 参考已有 Repeater tab: {', '.join(tab_names)}。")
    return "\n".join(steps)


def _key_request_lines(
    entity: sqlite3.Row,
    *,
    evidence_refs: list[sqlite3.Row],
    burp_actions: list[sqlite3.Row],
) -> str:
    lines: list[str] = []
    method = _row_value(entity, "method") or "GET"
    url = _row_value(entity, "url") or _row_value(entity, "page_url")
    if url:
        lines.append(f"- `{method} {url}`")
    if _row_value(entity, "param"):
        lines.append(f"- 关键参数: `{entity['param']}`")
    for row in evidence_refs:
        if row["evidence_type"] in {"request", "repeater_tab"}:
            lines.append(f"- {row['title'] or row['evidence_type']}: {row['summary'] or '待人工补充'}")
    for row in burp_actions:
        if row["url"]:
            label = row["repeater_tab_name"] or f"burp_action#{row['id']}"
            lines.append(f"- {label}: `{row['method'] or 'GET'} {row['url']}`")
    return "\n".join(_dedupe(lines)) or "- 待人工补充原始请求与变体请求。"


def _key_response_lines(entity: sqlite3.Row, *, evidence_refs: list[sqlite3.Row]) -> str:
    lines: list[str] = []
    if _row_value(entity, "evidence"):
        lines.append(f"- {entity['evidence']}")
    if _row_value(entity, "response_summary"):
        lines.append(f"- {entity['response_summary']}")
    for row in evidence_refs:
        if row["evidence_type"] in {"response", "diff", "operator_note"}:
            lines.append(f"- {row['title'] or row['evidence_type']}: {row['summary'] or '待人工补充'}")
    return "\n".join(_dedupe(lines)) or "- 待人工补充关键响应差异。"


def _screenshot_lines(evidence_refs: list[sqlite3.Row]) -> str:
    lines = [
        f"- {row['title'] or 'screenshot'}: {row['summary'] or '已附截图'}" for row in evidence_refs if row["evidence_type"] == "screenshot"
    ]
    return "\n".join(lines) if lines else "- 当前缺少截图证据，需操作员补充。"


def _impact_text(entity: sqlite3.Row) -> str:
    if _row_value(entity, "review_notes"):
        return entity["review_notes"]
    vuln_type = _row_value(entity, "type") or _row_value(entity, "test_type") or "异常行为"
    return f"该问题可能导致与 {vuln_type} 相关的业务对象被越权读取、修改或导出，影响需结合真实返回内容人工补充。"


def _remediation_text(entity: sqlite3.Row) -> str:
    if _row_value(entity, "remediation"):
        return entity["remediation"]
    return "补齐服务端鉴权、对象级访问控制与敏感字段最小化返回，并为关键接口增加审计日志。"


def _manual_followups(entity: sqlite3.Row, *, evidence_refs: list[sqlite3.Row]) -> str:
    notes = [
        "- 确认操作员最终复核结论，confirmed finding 仍需人工确认。",
        "- 补充账号角色、请求前置条件、截图编号和实际影响范围。",
    ]
    if not _has_screenshot_evidence(evidence_refs):
        notes.append("- 当前无 screenshot evidence，需要补页面级或文件级可视证据。")
    if _row_value(entity, "cvss"):
        notes.append(f"- 现有 CVSS 参考值: {entity['cvss']}")
    return "\n".join(notes)


def _has_screenshot_evidence(evidence_refs: list[sqlite3.Row]) -> bool:
    return any(row["evidence_type"] == "screenshot" for row in evidence_refs)


def _needs_screenshot(
    entity: sqlite3.Row,
    *,
    evidence_refs: list[sqlite3.Row],
    burp_actions: list[sqlite3.Row],
) -> bool:
    corpus = [
        _row_value(entity, "type", ""),
        _row_value(entity, "test_type", ""),
        _row_value(entity, "risk", ""),
        _row_value(entity, "url", ""),
        _row_value(entity, "page_url", ""),
        _row_value(entity, "reasoning", ""),
        _row_value(entity, "review_notes", ""),
        _row_value(entity, "evidence", ""),
        _row_value(entity, "response_summary", ""),
        _row_value(entity, "param", ""),
    ]
    corpus.extend((row["title"] or "") for row in evidence_refs)
    corpus.extend((row["summary"] or "") for row in evidence_refs)
    corpus.extend((row["note"] or "") for row in burp_actions)
    corpus.extend((row["url"] or "") for row in burp_actions)
    text = " ".join(part.lower() for part in corpus if part)
    if any(phrase in text for phrase in NEGATED_SCREENSHOT_PHRASES):
        text = " ".join(segment for segment in text.split() if segment not in {"sensitive", "敏感"})
    if "critical" in text:
        return True
    if any(keyword in text for keyword in SCREENSHOT_KEYWORDS):
        return True
    return False


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _row_value(row: sqlite3.Row, key: str, default: Any = None) -> Any:
    return row[key] if key in row.keys() else default


def _resolve_db_path(args: argparse.Namespace) -> Path:
    if args.db:
        return Path(args.db)
    return find_db(args.target)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a minimal Markdown evidence pack")
    parser.add_argument("--db", help="explicit DB path")
    parser.add_argument("--target", required=True, help="target_name in the DB")
    parser.add_argument("--finding-id", help="finding id")
    parser.add_argument("--sp-id", help="suspicious point id")
    parser.add_argument("--output-root", help="override output root for tests or temp runs")
    args = parser.parse_args()

    conn = connect(_resolve_db_path(args))
    try:
        result = generate_evidence_pack(
            conn,
            target_name=args.target,
            finding_id=args.finding_id,
            sp_id=args.sp_id,
            output_root=Path(args.output_root) if args.output_root else None,
        )
    finally:
        conn.close()

    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
