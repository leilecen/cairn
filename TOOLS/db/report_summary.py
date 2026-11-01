"""生成目标级汇总报告（面向客户/操作员的一次性总览）。

为什么需要
----------
`simple_src_report.py` 只能一条 finding 一份报告。此前所有"这个目标整体怎么样"
只能靠人翻 DB 手工拼——这正是 CyberStrike `generate-report` 解决的事（9 段式
结构化 Markdown + 3 段必须由模型写的 AI 段落），而 Strix 的 `coverage.json`
则证明"负空间"（测过什么、哪些没测）必须单独成章。

本模块把两者能落地到本项目数据库的部分做成确定性输出：

  1. 执行摘要数据块：按等级计数、最高风险、覆盖度（来自 coverage_ledger）
  2. 漏洞总表：按等级排序，带"该类别建议上限"以便一眼看出高估
  3. 覆盖度与未测清单：直接读 coverage_ledger 的 unknown/uncovered/blocked
     （本项目数据比 Strix 细，不要退化成只有确认项）
  4. 定级异常：声明等级 > 该类别上限的条目单列（交付前必须回应）

"AI 段落"（总体研判、修复优先级）不在这里自动生成——那是模型/人的活，本模块
只留出明确位置与所需数据，避免让模板假装会思考。
"""

from __future__ import annotations

import sqlite3
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

_TOOLS_DIR = Path(__file__).resolve().parent.parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

from lib.finding_grader import LEVELS, grade_finding, validate_finding_quality  # noqa: E402

# 越严重的等级排越前（critical 最大），用于表格排序
RISK_ORDER = {level: index for index, level in enumerate(LEVELS)}


def build_report_summary(conn: sqlite3.Connection, *, target_name: str) -> dict[str, Any]:
    """收集汇总报告所需的全部数据（只读）。"""
    findings = [dict(row) for row in _load_findings(conn, target_name)]
    coverage = _load_coverage(conn, target_name)

    by_risk = Counter((item.get("risk") or "unknown").strip().lower() for item in findings)
    graded = []
    overclaims = []
    for item in findings:
        grade = grade_finding(item)
        graded.append({**item, "_grade": grade})
        if grade["overclaims"]:
            overclaims.append({**item, "_grade": grade})

    graded.sort(key=lambda item: RISK_ORDER.get(str(item.get("risk") or "").lower(), -1), reverse=True)

    return {
        "target": target_name,
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "total": len(findings),
        "by_risk": dict(sorted(by_risk.items(), key=lambda kv: RISK_ORDER.get(kv[0], -1), reverse=True)),
        "findings": graded,
        "overclaims": overclaims,
        "coverage": coverage,
    }


def render_summary_report(summary: dict[str, Any]) -> str:
    """把汇总数据渲染成 Markdown（确定性部分；AI 段落留空位）。"""
    target = summary["target"]
    lines: list[str] = [
        f"# {target} 安全评估报告",
        "",
        f"- 生成时间: {summary['generated_at']}",
        f"- 已确认发现: {summary['total']} 条",
        "",
        "> 本报告的「执行摘要」与「修复优先级」两节需要按下方数据人工/由模型撰写，",
        "> 其余章节为数据库事实的确定性输出，可直接复核。",
        "",
        "## 一、执行摘要",
        "",
        "<!-- 待撰写：基于下方计数与最高风险，2-3 段说明整体风险面、关键攻击链、评估完整度 -->",
        "",
        _risk_table(summary),
        "",
        "## 二、漏洞总表",
        "",
        _findings_table(summary),
        "",
        "## 三、定级异常（交付前必须回应）",
        "",
        _overclaim_block(summary),
        "",
        "## 四、覆盖度与未测清单",
        "",
        _coverage_block(summary),
        "",
        "## 五、修复优先级",
        "",
        "<!-- 待撰写：按「最高风险 × 修复成本」排序；区分 quick win 与长期改造 -->",
        "",
        "## 六、评估局限",
        "",
        "<!-- 待撰写：未覆盖的面、被 WAF 拦住的部分、缺少的账号/权限 -->",
        "",
    ]
    return "\n".join(lines)


def write_summary_report(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    output_root: Path | str | None = None,
) -> Path:
    summary = build_report_summary(conn, target_name=target_name)
    markdown = render_summary_report(summary)
    root = Path(output_root) if output_root else Path("reports")
    out_dir = root / target_name
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d")
    path = out_dir / f"{target_name}_汇总报告_{stamp}.md"
    path.write_text(markdown, encoding="utf-8", newline="\n")
    return path


# ---------------------------------------------------------------- 渲染分块


def _risk_table(summary: dict[str, Any]) -> str:
    rows = ["| 等级 | 数量 |", "|---|---|"]
    for level in ("critical", "high", "medium", "low", "info", "unknown"):
        count = summary["by_risk"].get(level, 0)
        if count or level != "unknown":
            rows.append(f"| {level} | {count} |")
    return "\n".join(rows)


def _findings_table(summary: dict[str, Any]) -> str:
    if not summary["findings"]:
        return "_没有已确认的发现。_"
    rows = ["| # | 等级 | 类型 | 位置 | 标题 | 该类别建议上限 |", "|---|---|---|---|---|---|"]
    for index, item in enumerate(summary["findings"], 1):
        title = item.get("title") or _auto_title(item)
        location = item.get("url") or ""
        param = item.get("param") or ""
        where = f"`{location}`" + (f" （{param}）" if param else "")
        ceiling = item["_grade"]["ceiling"] or "-"
        rows.append(f"| {index} | {item.get('risk') or '?'} | {item.get('type') or '?'} | {where} | {_escape_cell(title)} | {ceiling} |")
    return "\n".join(rows)


def _overclaim_block(summary: dict[str, Any]) -> str:
    if not summary["overclaims"]:
        return "_没有检出明显的高估（声明等级均未超过该类别上限）。_"
    lines = [
        f"共 {len(summary['overclaims'])} 条声明等级高于该类别的合理上限。",
        "按 triage 规则，这些条目要么补齐证据与前提，要么下调等级；否则客户侧通常会被驳回。",
        "",
    ]
    for item in summary["overclaims"]:
        lines.append(f"- **{item.get('id')}** {item.get('type')}（声明 {item.get('risk')}）")
        for reason in item["_grade"]["overclaims"]:
            lines.append(f"  - {reason}")
    return "\n".join(lines)


def _coverage_block(summary: dict[str, Any]) -> str:
    coverage = summary["coverage"]
    if not coverage["total"]:
        return (
            "_没有 coverage_ledger 记录_：说明本轮没有系统记录「测过什么/没测什么」，"
            "本报告只能说明「发现了什么」，不能说明「哪些面是干净的」。"
        )
    lines = [
        f"账本共 {coverage['total']} 条，状态分布：" + "、".join(f"{k}={v}" for k, v in coverage["by_status"].items()),
        "",
    ]
    if coverage["open_items"]:
        lines.append("### 尚未闭环的条目（unknown / uncovered / blocked）")
        lines.append("")
        rows = ["| 条目 | 状态 | 阻塞原因 | 下一步 |", "|---|---|---|---|"]
        for item in coverage["open_items"]:
            rows.append(
                f"| {_escape_cell(item['key'])} | {item['status']} | {_escape_cell(item['blocker'])} | {_escape_cell(item['next'])} |"
            )
        lines.append("\n".join(rows))
    else:
        lines.append("_账本里没有未闭环条目（全部 covered / 已说明）。_")
    return "\n".join(lines)


# ---------------------------------------------------------------- 数据装载


def _load_findings(conn: sqlite3.Connection, target_name: str) -> list[sqlite3.Row]:
    return conn.execute(
        """
        SELECT f.*
        FROM findings f
        JOIN targets t ON t.id = f.target_id
        WHERE t.target_name = ?
        ORDER BY f.confirmed_at ASC, f.id ASC
        """,
        (target_name,),
    ).fetchall()


OPEN_STATUSES = ("unknown", "uncovered", "blocked", "partial")


def _load_coverage(conn: sqlite3.Connection, target_name: str) -> dict[str, Any]:
    try:
        rows = conn.execute(
            "SELECT item_key, status, blocker_reason, next_action FROM coverage_ledger WHERE target_name=?",
            (target_name,),
        ).fetchall()
    except sqlite3.Error:
        return {"total": 0, "by_status": {}, "open_items": []}

    by_status = Counter((row["status"] or "unknown") for row in rows)
    open_items = [
        {
            "key": row["item_key"],
            "status": row["status"],
            "blocker": row["blocker_reason"] or "",
            "next": row["next_action"] or "",
        }
        for row in rows
        if (row["status"] or "") in OPEN_STATUSES
    ]
    return {"total": len(rows), "by_status": dict(by_status), "open_items": open_items}


def _auto_title(item: dict[str, Any]) -> str:
    vuln_type = item.get("type") or "未知类型"
    url = item.get("url") or ""
    param = item.get("param") or ""
    path = url.split("://", 1)[-1]
    path = path.split("/", 1)[-1] if "/" in path else path
    where = f"/{path}" if path else ""
    if param:
        return f"{where} 的 {param} 参数存在 {vuln_type}".strip()
    return f"{where} 存在 {vuln_type}".strip()


def _escape_cell(value: str) -> str:
    """表格单元格转义：竖线会破坏 Markdown 表格；换行会破坏整行。"""
    return (value or "").replace("|", "\\|").replace("\n", " ").strip()


def validate_for_delivery(conn: sqlite3.Connection, *, target_name: str) -> dict[str, Any]:
    """交付前质量门：逐条跑 validate_finding_quality，汇总问题。

    注意：历史库里 `findings.id` 可能是 NULL（早期导入遗留），所以展示用标识
    必须回退到 sp_id / 行号，不能直接打印 `None`——那样人根本定位不到是哪条。
    """
    findings = [dict(row) for row in _load_findings(conn, target_name)]
    report = []
    for index, item in enumerate(findings, 1):
        problems = validate_finding_quality(item)
        if problems:
            report.append(
                {
                    "id": _display_id(item, index),
                    "type": item.get("type") or "",
                    "url": item.get("url") or "",
                    "problems": problems,
                }
            )
    return {"target": target_name, "total": len(findings), "with_problems": len(report), "items": report}


def _display_id(item: dict[str, Any], index: int) -> str:
    """给一条 finding 一个稳定可引用的展示标识。"""
    for key in ("id", "sp_id"):
        value = str(item.get(key) or "").strip()
        if value:
            return value
    url = str(item.get("url") or "").strip()
    vuln_type = str(item.get("type") or "").strip()
    if url or vuln_type:
        return f"#{index} {vuln_type}@{url}" if url else f"#{index} {vuln_type}"
    return f"#{index}"


def main(argv: list[str] | None = None) -> int:
    """CLI：生成汇总报告，或只跑交付质量门。

    用法：
        python TOOLS/db/report_summary.py --db dbs/<target>.db --target "<目标名>"
        python TOOLS/db/report_summary.py --db dbs/<target>.db --target "<目标名>" --check
        python TOOLS/db/report_summary.py --db dbs/<target>.db --target "<目标名>" --check --report <md>

    `--check` 现在做**两道**门：
      1. 数据层（findings 字段完整度）
      2. 可复现性层（对成品 Markdown 做静态检查）
    第二道默认自动挑 `reports/<target>/` 下最新的 .md 来查——否则门禁永远不会
    作用在真正交付的那份文件上（实测教训：数据门看 findings 表 0 条就静默放行，
    而报告是从 suspicious_points 写的，等于什么都没查）。
    """
    import argparse

    from db.db_utils import connect, force_utf8_stdout  # 延迟导入：本模块可独立被测试导入
    from lib.report_repro_gate import check_report_file, format_findings, is_deliverable

    parser = argparse.ArgumentParser(description="生成目标级汇总报告 / 交付质量门")
    parser.add_argument("--db", required=True, help="目标库路径")
    parser.add_argument("--target", required=True, help="目标名")
    parser.add_argument("--out", help="报告输出根目录（默认 reports/）")
    parser.add_argument("--check", action="store_true", help="只跑交付质量门，不写文件")
    parser.add_argument("--report", help="指定的成品 Markdown 报告路径（默认自动挑最新）")
    parser.add_argument("--no-report-check", action="store_true", help="跳过可复现性检查")
    args = parser.parse_args(argv)

    force_utf8_stdout()
    conn = connect(args.db)
    try:
        if args.check:
            result = validate_for_delivery(conn, target_name=args.target)
            print(f"目标: {result['target']} | 发现 {result['total']} 条 | 有问题的 {result['with_problems']} 条")
            for item in result["items"]:
                print(f"\n[{item['id']}] {item.get('type') or ''}")
                for problem in item["problems"]:
                    print(f"  - {problem}")

            data_blocked = bool(result["with_problems"])

            # ---- 第二道：可复现性（作用在真正交付的 Markdown 上）----
            repro_blocked = False
            if not args.no_report_check:
                report_path = _resolve_report_path(args.report, args.target, args.out)
                if report_path is None:
                    print("\n[WARN] 未找到成品报告（reports/<target>/*.md），可复现性门未生效。")
                else:
                    print(f"\n===== 可复现性门：{report_path} =====")
                    issues = check_report_file(report_path)
                    print(format_findings(issues))
                    repro_blocked = not is_deliverable(issues)

            return 1 if (data_blocked or repro_blocked) else 0
        path = write_summary_report(conn, target_name=args.target, output_root=args.out)
        print(f"[OK] 汇总报告已生成: {path}")
        return 0
    finally:
        conn.close()


def _resolve_report_path(explicit: str | None, target: str, out: str | None) -> Path | None:
    """定位要检查的成品报告：显式指定 > reports/<target>/ 下最新 .md。"""
    if explicit:
        candidate = Path(explicit)
        return candidate if candidate.exists() else None
    root = Path(out) if out else Path("reports")
    target_dir = root / target
    if not target_dir.is_dir():
        return None
    candidates = [p for p in target_dir.glob("*.md") if p.is_file()]
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime)


if __name__ == "__main__":
    raise SystemExit(main())
