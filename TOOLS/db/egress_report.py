"""出口强度声明：把 `egress_log` 变成可交给委托方的合规证据。

用途（`docs/modules/egress-traffic-shaping.md` P4）：证明本轮测试的流量强度落在委托声明
范围内，并**显式列出刻意没有抖动的时间窗**（竞态等 `unpaced:` 窗口），而不是只报一个好看的均值。

刻意不做的事：
- 不导出 query/body/cookie（`egress_log` 本身就不记），报告只出现 host + path；
- 不把本报告当作「痕迹清除」的替代——目标侧日志一律不动。

用法:
  python TOOLS/db/egress_report.py --target "example-client"
  python TOOLS/db/egress_report.py --db dbs/xxx.db --markdown --out tmp/egress-report.md
  python TOOLS/db/egress_report.py --target "example-client" --declared-max-rps 0.5 --json
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import statistics
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

_TOOLS_DIR = Path(__file__).resolve().parent.parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

from db.db_utils import find_db_or_none, force_utf8_stdout, session  # noqa: E402

# 1 秒窗口内的上限＝`PacingPolicy.burst`（页面/接口的天然连发）；10 秒窗口＝可持续速率。
BURST_WINDOW_S = 1.0
SUSTAINED_WINDOW_S = 10.0
SHORT_GAP_MS = 200.0


def load_rows(
    db_path: Path | str,
    *,
    target: str | None = None,
    run_id: str | None = None,
) -> list[dict[str, Any]]:
    """读取 `egress_log`（只读）。表不存在时返回空列表，不抛错。"""
    query = (
        "SELECT target_name, run_id, ts, epoch, identity, mode, host, method, url_path,"
        " status_code, elapsed_ms, planned_gap_ms, decision, stop_reason, note"
        " FROM egress_log"
    )
    clauses: list[str] = []
    params: list[Any] = []
    if target:
        clauses.append("target_name = ?")
        params.append(target)
    if run_id:
        clauses.append("run_id = ?")
        params.append(run_id)
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY epoch ASC, id ASC"
    if not Path(db_path).is_file():
        raise ValueError(f"database file not found: {db_path}")
    with session(db_path, read_only=True) as conn:
        if not _has_egress_log(conn):
            return []
        return [dict(row) for row in conn.execute(query, params).fetchall()]


def _has_egress_log(conn: sqlite3.Connection) -> bool:
    row = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='egress_log'").fetchone()
    return row is not None


def _peak_rate(stamps: Sequence[float], window_s: float) -> float:
    """滑动窗口内最大请求数 / 窗口长度（包/秒）。"""
    if not stamps:
        return 0.0
    peak = 0
    for index, start in enumerate(stamps):
        count = 0
        for later in stamps[index:]:
            if later - start < window_s:  # 严格小于：窗口内「能发起」的请求数
                count += 1
            else:
                break
        peak = max(peak, count)
    return peak / window_s


def _gap_stats(stamps: Sequence[float]) -> dict[str, float]:
    gaps = [round((b - a) * 1000.0, 1) for a, b in zip(stamps, stamps[1:], strict=False) if b >= a]
    if not gaps:
        return {"count": 0, "min_ms": 0.0, "median_ms": 0.0, "p90_ms": 0.0, "max_ms": 0.0}
    ordered = sorted(gaps)
    return {
        "count": len(ordered),
        "min_ms": ordered[0],
        "median_ms": round(statistics.median(ordered), 1),
        "p90_ms": ordered[min(len(ordered) - 1, int(len(ordered) * 0.9))],
        "max_ms": ordered[-1],
    }


def build_report(
    rows: Iterable[Mapping[str, Any]],
    *,
    declared_max_rps: float | None = None,
    declared_total_budget: int | None = None,
) -> dict[str, Any]:
    """把台账行汇总成强度声明（口径固定，供报告/审计复用）。"""
    records = [dict(row) for row in rows]
    sent = [r for r in records if str(r.get("decision")) == "sent"]
    stamps = sorted(float(r.get("epoch") or 0.0) for r in sent if float(r.get("epoch") or 0.0) > 0)
    hosts: dict[str, int] = {}
    statuses: dict[str, int] = {}
    for row in sent:
        hosts[str(row.get("host") or "")] = hosts.get(str(row.get("host") or ""), 0) + 1
        statuses[str(row.get("status_code") or 0)] = statuses.get(str(row.get("status_code") or 0), 0) + 1
    hourly: dict[str, int] = {}
    for row in sent:
        stamp = str(row.get("ts") or "")
        if len(stamp) >= 13:
            hourly[stamp[:13]] = hourly.get(stamp[:13], 0) + 1
    unpaced = [r for r in records if str(r.get("note") or "").startswith("unpaced:")]
    stop_reasons: dict[str, int] = {}
    for row in records:
        reason = str(row.get("stop_reason") or "")
        if reason:
            stop_reasons[reason] = stop_reasons.get(reason, 0) + 1
    planned = sorted(float(r.get("planned_gap_ms") or 0.0) for r in sent)

    peak_rps = _peak_rate(stamps, BURST_WINDOW_S)
    sustained = _peak_rate(stamps, SUSTAINED_WINDOW_S)
    verdict_ok = declared_max_rps is None or sustained <= declared_max_rps + 1e-9
    budget_ok = declared_total_budget is None or len(sent) <= declared_total_budget

    return {
        "target": next((str(r.get("target_name")) for r in records if r.get("target_name")), ""),
        "run_ids": sorted({str(r.get("run_id")) for r in records if r.get("run_id")}),
        "identities": sorted({str(r.get("identity")) for r in records if r.get("identity")}),
        "modes": sorted({str(r.get("mode")) for r in records if r.get("mode")}),
        "window": {
            "first_ts": str(sent[0].get("ts")) if sent else "",
            "last_ts": str(sent[-1].get("ts")) if sent else "",
            "duration_s": round(stamps[-1] - stamps[0], 1) if len(stamps) > 1 else 0.0,
        },
        "counts": {
            "total": len(records),
            "sent": len(sent),
            "blocked": sum(1 for r in records if str(r.get("decision")) == "blocked"),
            "skipped": sum(1 for r in records if str(r.get("decision")) == "skipped"),
            "errors": sum(1 for r in records if str(r.get("decision")) == "error"),
        },
        "rate": {
            "peak_rps_1s": round(peak_rps, 2),
            "peak_rps_10s": round(sustained, 2),
            "declared_max_rps": declared_max_rps,
            "within_declared": verdict_ok,
        },
        "budget": {
            "declared_total": declared_total_budget,
            "within_declared": budget_ok,
        },
        "gaps": _gap_stats(stamps),
        "planned_gap_ms": {
            "min": planned[0] if planned else 0.0,
            "median": round(statistics.median(planned), 1) if planned else 0.0,
            "max": planned[-1] if planned else 0.0,
        },
        "hosts": hosts,
        "status_codes": statuses,
        "hourly": dict(sorted(hourly.items())),
        "stop_reasons": stop_reasons,
        "unpaced_windows": [
            {
                "ts": str(r.get("ts")),
                "host": str(r.get("host")),
                "path": str(r.get("url_path")),
                "note": str(r.get("note")),
            }
            for r in unpaced
        ],
        "notes": [
            "台账不记录 query/body/cookie；报告只含 host + path。",
            "1 秒峰值对应突发预算（`PacingPolicy.burst`）；合规判定用 10 秒可持续速率。",
            "`unpaced_windows` 是刻意关闭抖动的窗口（竞态等），要求显式登记，这里如实列出。",
        ],
    }


def render_markdown(report: Mapping[str, Any]) -> str:
    """渲染为可直接粘进报告的 Markdown 小节。"""
    counts = report["counts"]
    rate = report["rate"]
    gaps = report["gaps"]
    lines = [
        "## 测试流量强度声明",
        "",
        f"- 目标：`{report['target'] or '-'}`；身份：{', '.join(report['identities']) or '-'}；"
        f"出口模式：{', '.join(report['modes']) or '-'}",
        f"- 时间窗：{report['window']['first_ts'] or '-'} ~ {report['window']['last_ts'] or '-'}（{report['window']['duration_s']}s）",
        f"- 请求总数 **{counts['sent']}**（熔断拦截 {counts['blocked']}，跳过 {counts['skipped']}，失败 {counts['errors']}）",
        f"- 峰值速率：1s {rate['peak_rps_1s']} rps（突发预算）／10s {rate['peak_rps_10s']} rps（可持续）"
        + (
            f"；委托上限 {rate['declared_max_rps']} rps → **{'符合' if rate['within_declared'] else '超出'}**"
            if rate["declared_max_rps"]
            else ""
        ),
        f"- 实际间隔分位（ms）：min {gaps['min_ms']}／median {gaps['median_ms']}／p90 {gaps['p90_ms']}／max {gaps['max_ms']}",
        f"- 停止原因：{json.dumps(report['stop_reasons'], ensure_ascii=False) if report['stop_reasons'] else '无（未触发限速/WAF 熔断）'}",
        "",
        "| 主机 | 请求数 |",
        "| --- | --- |",
    ]
    lines += [f"| {host} | {count} |" for host, count in sorted(report["hosts"].items(), key=lambda kv: -kv[1])]
    lines += ["", "| 小时 | 请求数 |", "| --- | --- |"]
    lines += [f"| {hour} | {count} |" for hour, count in report["hourly"].items()]
    if report["unpaced_windows"]:
        lines += [
            "",
            "### 刻意关闭抖动的窗口（竞态等，已显式登记）",
            "",
            "| 时间 | 主机 | 路径 | 原因 |",
            "| --- | --- | --- | --- |",
        ]
        lines += [f"| {item['ts']} | {item['host']} | `{item['path']}` | {item['note']} |" for item in report["unpaced_windows"][:50]]
    lines += ["", "> " + "；".join(report["notes"]), ""]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="出口强度声明（读 egress_log，只读）")
    parser.add_argument("--target", help="目标名（解析 dbs/{slug}.db）")
    parser.add_argument("--db", help="直接指定 DB 路径（与 --target 二选一）")
    parser.add_argument("--run-id", help="只看某一次运行（egress_log.run_id）")
    parser.add_argument("--declared-max-rps", type=float, help="委托声明的可持续速率上限（rps）")
    parser.add_argument("--declared-total", type=int, help="委托声明的请求总预算")
    parser.add_argument("--markdown", action="store_true", help="输出 Markdown 小节")
    parser.add_argument("--out", help="写入文件（默认 stdout）")
    parser.add_argument("--json", action="store_true", help="输出 JSON（默认在有 --markdown 时输出 Markdown）")
    args = parser.parse_args(argv)
    force_utf8_stdout()

    if not args.target and not args.db:
        print(json.dumps({"error": "--target 或 --db 必须显式指定"}, ensure_ascii=False), file=sys.stderr)
        return 2
    db_path = Path(args.db) if args.db else find_db_or_none(args.target)
    if db_path is None:
        print(json.dumps({"error": f"未找到目标 DB: {args.target}"}, ensure_ascii=False), file=sys.stderr)
        return 1
    try:
        rows = load_rows(db_path, target=args.target, run_id=args.run_id)
    except (OSError, sqlite3.Error, ValueError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 1

    report = build_report(
        rows,
        declared_max_rps=args.declared_max_rps,
        declared_total_budget=args.declared_total,
    )
    report["generated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report["db"] = str(db_path)
    text = json.dumps(report, ensure_ascii=False, indent=2) if args.json or not args.markdown else render_markdown(report)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(text, encoding="utf-8")
        print(json.dumps({"ok": True, "out": args.out, "sent": report["counts"]["sent"]}, ensure_ascii=False))
    else:
        print(text)
    return 0 if (report["rate"]["within_declared"] and report["budget"]["within_declared"]) else 3


if __name__ == "__main__":
    raise SystemExit(main())
