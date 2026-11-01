"""补天标准 Word 报告生成器（officecli 驱动，.docx 输出）。

从 DB findings 读取漏洞数据，按补天平台提交字段生成 .docx 报告：
标题 + 信息表(漏洞类别/漏洞URL/漏洞类型/漏洞等级) + 简要描述 +
详细细节(漏洞概述/利用链/PoC) + 修复方案 + 截图占位段落。

设计依据：
- 字段结构对齐项目既有补天 docx（reports/<client>/补天_中危_08_*.docx 等）
- 样式简单：正文 Normal + 标题 Heading + 代码等宽字体，无花哨装饰
- 数据缺失字段留「待人工补充」占位，截图用文字占位段落

用法:
  uv run python TOOLS/db/butian_docx_report.py --target "example-client"                     # 全部非 refuted finding
  uv run python TOOLS/db/butian_docx_report.py --target "example-client" --finding-id F-001  # 单个 finding
  uv run python TOOLS/db/butian_docx_report.py --target "example-client" --output-dir tmp/bt
  uv run python TOOLS/db/butian_docx_report.py --target "example-client" --include-refuted   # 含 refuted（调试用）

依赖：officecli（`officecli --version` 自检）；生成 .docx 不需要 Office 安装。
"""
# ruff: noqa: S607 -- officecli 是固定工具名（同 S603 部分路径惯例）
# ruff: noqa: S608 -- placeholders 由受控 id 列表生成（同 simple_src_report 惯例）

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Any

_TOOLS_DIR = Path(__file__).resolve().parent.parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

from db.db_utils import connect, find_db, force_utf8_stdout  # noqa: E402

PLACEHOLDER_PREFIX = "待人工补充"

# 补天信息表固定字段（值从 finding 推导，缺省留占位）
INFO_FIELDS = ("漏洞类别", "漏洞URL", "漏洞类型", "漏洞等级")

# 常见漏洞类型 -> 补天漏洞类别
TYPE_CATEGORY = {
    "rce": "Web安全",
    "rce_unauthorized": "Web安全",
    "command_execution": "Web安全",
    "sqli": "Web安全",
    "sql_injection": "Web安全",
    "ssrf": "Web安全",
    "ssrf_lfi": "Web安全",
    "xss": "Web安全",
    "csrf": "Web安全",
    "file_upload": "Web安全",
    "path_traversal": "Web安全",
    "lfi": "Web安全",
    "unauth_access": "Web安全",
    "unauthorized_access": "Web安全",
    "auth_bypass": "Web安全",
    "authz_bypass": "Web安全",
    "idor": "Web安全",
    "user_enumeration": "Web安全",
    "information_disclosure": "Web安全",
    "info_disclosure": "Web安全",
    "weak_password": "口令安全",
    "default_credential": "口令安全",
    "ip_whitelist_bypass": "Web安全",
    "logic": "业务逻辑",
    "race_condition": "业务逻辑",
    "business_logic": "业务逻辑",
    "denial_of_service": "可用性",
}


def _run_officecli(args: list[str], *, check: bool = True) -> subprocess.CompletedProcess:
    """调用 officecli，统一编码处理。"""
    proc = subprocess.run(  # noqa: S603 -- fixed tool binary
        ["officecli", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if check and proc.returncode != 0:
        raise RuntimeError(f"officecli {' '.join(args[:4])}... failed: {proc.stderr.strip()[:400]}")
    return proc


def _officecli_available() -> bool:
    try:
        proc = _run_officecli(["--version"], check=False)
        return proc.returncode == 0
    except FileNotFoundError:
        return False


# ---------------------------------------------------------------------------
# DB 读取
# ---------------------------------------------------------------------------


def _load_findings(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    finding_id: str | None = None,
    include_refuted: bool = False,
) -> list[sqlite3.Row]:
    # findings 无 target_name 列：优先走 targets JOIN（target_id），部分历史行 target_id 为 NULL
    # 则退化为全表按 id 过滤（调用方已限定目标库）
    sql = """
        SELECT f.*, t.target_name AS tgt_name
        FROM findings f
        LEFT JOIN targets t ON t.id = f.target_id
        WHERE (t.target_name IS NULL OR t.target_name = ?)
    """
    params: list[Any] = [target_name]
    if finding_id:
        sql += " AND f.id = ?"
        params.append(finding_id)
    if not include_refuted:
        sql += " AND (f.review_status IS NULL OR f.review_status NOT IN ('refuted'))"
    sql += " ORDER BY f.confirmed_at ASC, f.id ASC"
    return conn.execute(sql, params).fetchall()


def _load_evidence_refs(conn: sqlite3.Connection, *, target_name: str, finding: sqlite3.Row) -> list[sqlite3.Row]:
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


def _evidence_parsed(finding: sqlite3.Row) -> dict[str, Any]:
    try:
        value = json.loads(_value(finding, "evidence") or "{}")
        return value if isinstance(value, dict) else {}
    except json.JSONDecodeError:
        return {}


def _extract_brief(finding: sqlite3.Row, evidence: dict[str, Any]) -> str:
    """简要描述 = review_notes / evidence.summary / evidence 原文。"""
    for key in ("review_notes", "summary"):
        val = _value(finding, key)
        if val:
            return val
    for key in ("summary", "conclusion", "description"):
        if evidence.get(key):
            return str(evidence[key])
    return _placeholder("简要描述")


def _extract_overview(finding: sqlite3.Row, evidence: dict[str, Any]) -> str:
    """漏洞概述 = evidence.overview / sp_evidence 或 review_notes 展开。"""
    for key in ("overview", "impact", "description"):
        if evidence.get(key):
            val = evidence[key]
            return str(val) if isinstance(val, str) else json.dumps(val, ensure_ascii=False)
    sp = evidence.get("sp_evidence")
    if isinstance(sp, dict):
        parts = []
        for k in ("unauth", "ssrf", "file_read", "path_leak", "oracle", "in0_semantics"):
            if sp.get(k):
                parts.append(f"{k}: {sp[k]}")
        if parts:
            return "；".join(parts)
    if _value(finding, "review_notes"):
        return _value(finding, "review_notes")
    return _extract_brief(finding, evidence)


def _extract_chain(finding: sqlite3.Row, evidence: dict[str, Any]) -> list[str]:
    """利用链 = 分步复现步骤。有 evidence 明细就展开，否则通用占位。"""
    steps: list[str] = []
    method = _value(finding, "method")
    url = _value(finding, "url")
    param = _value(finding, "param")

    if method or url:
        steps.append("第 1 步 — 发送请求")
        steps.append(f"{method or 'GET'} {url or _placeholder('URL')}")
        if param:
            steps.append(f"关键参数: {param}")
    if _value(finding, "payload"):
        steps.append("第 2 步 — 携带 PoC Payload")
        steps.append(_value(finding, "payload"))

    sp = evidence.get("sp_evidence")
    if isinstance(sp, dict):
        for key, label in (
            ("ops_tested", "已测试操作"),
            ("unauth", "未授权状态"),
            ("ssrf", "SSRF"),
            ("file_read", "文件读取"),
            ("path_leak", "路径泄露"),
            ("oracle", "响应差异"),
        ):
            if sp.get(key):
                steps.append(f"{label}: {sp[key]}")

    if evidence.get("affected"):
        steps.append(f"受影响资产: {evidence['affected']}")
    if evidence.get("impact"):
        steps.append(f"影响: {evidence['impact']}")

    if not steps:
        steps.append(_placeholder("利用链 / 复现步骤"))
    return steps


def _extract_poc(finding: sqlite3.Row, evidence: dict[str, Any], refs: list[sqlite3.Row]) -> str:
    """PoC = payload / 请求证据 / 响应证据拼装。"""
    parts: list[str] = []
    if _value(finding, "payload"):
        parts.append(_value(finding, "payload"))
    reqs = [r for r in refs if r["evidence_type"] in ("request", "repeater_tab")]
    resps = [r for r in refs if r["evidence_type"] in ("response", "diff")]
    for r in reqs:
        parts.append(_req_response_block(r, is_request=True))
    for r in resps:
        parts.append(_req_response_block(r, is_request=False))
    if parts:
        return "\n\n".join(parts)
    return _placeholder("PoC 请求 / 响应")


def _req_response_block(row: sqlite3.Row, *, is_request: bool) -> str:
    title = row["title"] or ("请求" if is_request else "响应")
    summary = row["summary"] or ""
    ref = row["ref_json"] or ""
    block = f"--- {title} ---"
    if summary:
        block += f"\n{summary}"
    if ref:
        try:
            j = json.loads(ref)
            if isinstance(j, dict) and j:
                block += f"\n{json.dumps(j, ensure_ascii=False, indent=2)}"
        except json.JSONDecodeError:
            block += f"\n{ref}"
    return block


def _extract_remediation(finding: sqlite3.Row) -> str:
    if _value(finding, "remediation"):
        return _value(finding, "remediation")
    return _default_remediation(_value(finding, "type"))


def _extract_screenshots(refs: list[sqlite3.Row]) -> list[str]:
    """截图占位：有 screenshot 证据就给标题，否则通用占位。"""
    shots = [r for r in refs if r["evidence_type"] == "screenshot"]
    if shots:
        return [f"{r['title'] or '截图证据'}（{r['summary'] or '待补充说明'}）" for r in shots]
    return []


def _category_of(finding: sqlite3.Row) -> str:
    vuln_type = _value(finding, "type").lower()
    if vuln_type in TYPE_CATEGORY:
        return TYPE_CATEGORY[vuln_type]
    for key, cat in TYPE_CATEGORY.items():
        if key in vuln_type:
            return cat
    return "Web安全"


def _risk_zh(risk: str) -> str:
    mapping = {
        "critical": "严重",
        "high": "高危",
        "medium": "中危",
        "low": "低危",
        "info": "提示",
    }
    return mapping.get(str(risk).lower(), risk or _placeholder("风险等级"))


def _title(finding: sqlite3.Row, target_name: str) -> str:
    vuln_type = _value(finding, "type") or _placeholder("漏洞类型")
    risk = _risk_zh(_value(finding, "risk"))
    url = _value(finding, "url") or ""
    # 标题：风险 + 类型 + 主机/URL 摘要
    host = ""
    if url:
        m = re.search(r"https?://([^/]+)", url)
        if m:
            host = m.group(1)
    suffix = f"（{host}）" if host else ""
    return f"{risk} {vuln_type}{suffix}"


# ---------------------------------------------------------------------------
# docx 生成（officecli batch）
# ---------------------------------------------------------------------------


def _add_para(ops: list[dict], text: str, *, style: str = "Normal", font: str | None = None) -> None:
    props: dict[str, Any] = {"text": text}
    if style != "Normal":
        props["style"] = style
    if font:
        props["font"] = font
    ops.append({"command": "add", "parent": "/body", "type": "paragraph", "props": props})


def _add_code(ops: list[dict], text: str) -> None:
    """代码块：等宽字体段落（样式简单，不加底色边框）。"""
    for line in text.splitlines() or [""]:
        props: dict[str, Any] = {"text": line, "font": "Consolas", "size": "9pt"}
        ops.append({"command": "add", "parent": "/body", "type": "paragraph", "props": props})


def _add_info_table(ops: list[dict], rows: list[tuple[str, str]]) -> None:
    ops.append(
        {
            "command": "add",
            "parent": "/body",
            "type": "table",
            "props": {"rows": len(rows), "cols": 2, "colWidths": "3200,5200"},
        }
    )
    # 每份报告是新文档且只有这一张表，固定 /body/tbl[1]；逐 cell 写入
    for i, (label, value) in enumerate(rows, start=1):
        ops.append({"command": "set", "path": f"/body/tbl[1]/tr[{i}]/tc[1]", "props": {"text": label, "bold": "true"}})
        ops.append({"command": "set", "path": f"/body/tbl[1]/tr[{i}]/tc[2]", "props": {"text": value}})


def _build_batch_ops(finding: sqlite3.Row, *, target_name: str, refs: list[sqlite3.Row]) -> list[dict]:
    ops: list[dict] = []
    evidence = _evidence_parsed(finding)
    vuln_type = _value(finding, "type") or _placeholder("漏洞类型")
    url = _value(finding, "url") or _placeholder("URL")
    risk = _risk_zh(_value(finding, "risk"))

    # 标题
    _add_para(ops, _title(finding, target_name), style="Heading1")

    # 信息表
    _add_info_table(
        ops,
        [
            ("漏洞类别", _category_of(finding)),
            ("漏洞URL", url),
            ("漏洞类型", vuln_type),
            ("漏洞等级", risk),
        ],
    )

    # 简要描述
    _add_para(ops, "简要描述", style="Heading2")
    _add_para(ops, _extract_brief(finding, evidence))

    # 详细细节
    _add_para(ops, "详细细节", style="Heading2")
    _add_para(ops, "漏洞概述", style="Heading3")
    _add_para(ops, _extract_overview(finding, evidence))

    _add_para(ops, "利用链", style="Heading3")
    for step in _extract_chain(finding, evidence):
        _add_para(ops, step)

    _add_para(ops, "PoC", style="Heading3")
    _add_code(ops, _extract_poc(finding, evidence, refs))

    # 截图占位
    shots = _extract_screenshots(refs)
    if shots:
        _add_para(ops, "截图证据", style="Heading3")
        for i, s in enumerate(shots, start=1):
            _add_para(ops, f"【截图 {i}】{s}")
            _add_para(ops, _placeholder("此处插入截图"))
    else:
        _add_para(ops, "截图证据", style="Heading3")
        _add_para(ops, "【截图 1】待人工补充：关键请求、页面结果或响应差异截图")
        _add_para(ops, "【截图 2】待人工补充：如有需要，补充对比账号/变体结果截图")

    # 修复方案
    _add_para(ops, "修复方案", style="Heading2")
    _add_para(ops, _extract_remediation(finding))

    return ops


def generate_butian_docx(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    finding_id: str | None = None,
    output_root: Path | str | None = None,
    include_refuted: bool = False,
) -> dict[str, Any]:
    """为 findings 生成补天 .docx 报告，返回 [{finding_id, output_path}]。"""
    if not _officecli_available():
        raise RuntimeError("officecli 未安装或不在 PATH — 先运行: irm https://d.officecli.ai/install.ps1 | iex")

    rows = _load_findings(conn, target_name=target_name, finding_id=finding_id, include_refuted=include_refuted)
    if finding_id and not rows:
        raise ValueError(f"finding not found for target {target_name}: {finding_id}")
    if not rows:
        raise ValueError(f"no findings found for target: {target_name}")

    root = Path(output_root) if output_root is not None else Path("reports") / "butian_docx"
    output_dir = root / _safe_filename(target_name)
    output_dir.mkdir(parents=True, exist_ok=True)

    reports: list[dict[str, str]] = []
    for row in rows:
        refs = _load_evidence_refs(conn, target_name=target_name, finding=row)
        ops = _build_batch_ops(row, target_name=target_name, refs=refs)
        stem = row["id"] or f"{_value(row, 'type') or 'finding'}_{_risk_zh(_value(row, 'risk'))}"
        output_path = output_dir / f"{_safe_filename(stem)}.docx"
        _run_officecli_batch(output_path, ops)
        conn.execute("UPDATE findings SET report_file = ? WHERE id = ?", (str(output_path), row["id"]))
        reports.append({"finding_id": row["id"], "output_path": str(output_path)})

    conn.commit()
    return {"target": target_name, "count": len(reports), "reports": reports}


def _run_officecli_batch(output_path: Path, ops: list[dict]) -> None:
    """batch 建文档：create → batch → close。"""
    _run_officecli(["create", str(output_path)])
    payload = json.dumps(ops, ensure_ascii=False)
    proc = subprocess.run(  # noqa: S603 -- fixed tool binary
        ["officecli", "batch", str(output_path), "--commands", payload],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if proc.returncode != 0:
        raise RuntimeError(f"officecli batch failed: {proc.stderr.strip()[:500]}")
    _run_officecli(["close", str(output_path)], check=False)


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------


def _default_remediation(vuln_type: str) -> str:
    if vuln_type:
        return f"围绕 {vuln_type} 补齐服务端鉴权、对象级访问控制、输入校验和审计日志；修复后复测确认。"
    return _placeholder("修复建议")


def _placeholder(field: str) -> str:
    return f"{PLACEHOLDER_PREFIX}：{field}"


def _value(row: sqlite3.Row, key: str) -> str:
    try:
        if key not in row.keys() or row[key] is None:
            return ""
        return str(row[key]).strip()
    except (IndexError, TypeError):
        return ""


def _safe_filename(value: str) -> str:
    text = str(value).strip() or "unknown"
    text = re.sub(r"[\\/:*?\"<>|\s]+", "_", text)
    text = re.sub(r"_+", "_", text).strip("._")
    return text or "unknown"


def main() -> int:
    force_utf8_stdout()
    parser = argparse.ArgumentParser(description="补天标准 Word 报告生成器（officecli → .docx）")
    parser.add_argument("--target", help="target_name in the DB")
    parser.add_argument("--db", help="explicit DB path")
    parser.add_argument("--finding-id", help="单个 finding id（默认全部非 refuted）")
    parser.add_argument("--output-dir", help="输出目录（默认 reports/butian_docx/<target>）")
    parser.add_argument("--include-refuted", action="store_true", help="包含 refuted finding（调试用）")
    args = parser.parse_args()

    if not args.target and not args.db:
        parser.print_help()
        raise SystemExit("必须指定 --target 或 --db")

    if args.db:
        conn = connect(args.db)
        if not args.target:
            row = conn.execute("SELECT target_name FROM targets ORDER BY id LIMIT 1").fetchone()
            args.target = row["target_name"] if row else None
    else:
        conn = connect(find_db(args.target))
    try:
        if not args.target:
            raise SystemExit(f"无法从 DB 解析 target_name: {args.db}")
        result = generate_butian_docx(
            conn,
            target_name=args.target,
            finding_id=args.finding_id,
            output_root=args.output_dir,
            include_refuted=args.include_refuted,
        )
    finally:
        conn.close()

    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
