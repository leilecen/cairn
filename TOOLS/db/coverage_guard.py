"""历史负结论查询（coverage_guard）— 防止把已验证不可利用的攻击面当新发现重复升级。

任何路径在生成 suspicious_points、升级 operator 门或写 finding 之前，必须先查
`coverage_ledger` 的历史结论：`covered`（已验证，含负结论）与 `blocked`（无法测/被阻塞）
表示"该攻击面已处理，不要重复当新发现"；`uncovered`（显式观察到未防护边界）与
`unknown` 不抑制。

匹配依据：调用方提供的关键词（通常来自 suspicious_points 的 test_type/signal_reason/
reasoning/evidence 或 js_reverse 推导的攻击面语义，如 "fastjson"、"@type"）命中
coverage_ledger 的 item_key / category / summary / blocker_reason。
"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
from pathlib import Path
from typing import Any, Iterable

# 视为"负结论/已处理"的状态；uncovered/unknown 不抑制
NEGATIVE_STATUSES = ("covered", "blocked")


def _kw(value: str | None) -> str:
    return (value or "").strip().lower()


def _compact_evidence_refs(raw: str | None) -> list[Any]:
    """解析 evidence_refs_json，兼容 list / dict / 非法 JSON，返回最多 10 项列表。"""
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return []
    if isinstance(data, list):
        return data[:10]
    if isinstance(data, dict):
        for key in ("refs", "evidence", "evidence_refs", "items"):
            value = data.get(key)
            if isinstance(value, list):
                return value[:10]
        return [str(data)][:10]
    return [str(data)][:10]


def sp_keywords(
    *,
    test_type: str = "",
    signal_reason: str = "",
    reasoning: str = "",
    evidence: str = "",
    explicit: Iterable[str] = (),
) -> list[str]:
    """从 suspicious_points 字段提取去重关键词（小写，长度>=3）。"""
    words: set[str] = set()
    for chunk in (test_type, signal_reason, reasoning, (evidence or "")[:300], *explicit):
        for part in re.split(r"[\s,;:_|/\\()[\]{}\"'=]+", _kw(chunk)):
            part = part.strip()
            if len(part) >= 3 and not part.isdigit():
                words.add(part)
    return sorted(words)


def find_negative_coverage(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    keywords: Iterable[str] = (),
    statuses: Iterable[str] = NEGATIVE_STATUSES,
    limit: int = 5,
) -> list[dict[str, Any]]:
    """返回命中的历史负结论 coverage 记录（compact 字段）。

    无 coverage_ledger 表（旧库）时返回空列表；匹配是包含式关键词命中。
    """
    has_table = any(row[0] == "coverage_ledger" for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall())
    if not has_table:
        return []
    status_filter = tuple(statuses)
    placeholders = ",".join("?" * len(status_filter))
    rows = conn.execute(
        f"""SELECT id, item_key, category, status, summary, evidence_refs_json, blocker_reason
            FROM coverage_ledger
            WHERE target_name=? AND status IN ({placeholders})
            ORDER BY updated_at DESC, id DESC LIMIT 200""",  # noqa: S608 - placeholders are parameterized
        (target_name, *status_filter),
    ).fetchall()
    kw = [_kw(k) for k in keywords if len(_kw(k)) >= 3]
    hits: list[dict[str, Any]] = []
    for row in rows:
        haystack = " ".join(_kw(v) for v in (row["item_key"], row["category"], row["summary"], row["blocker_reason"]) if v)
        matched = [k for k in kw if k in haystack]
        if not matched:
            continue
        hits.append(
            {
                "coverage_id": int(row["id"]),
                "item_key": row["item_key"],
                "category": row["category"],
                "status": row["status"],
                "matched_keywords": matched[:5],
                "summary": (row["summary"] or "")[:300],
                "blocker_reason": (row["blocker_reason"] or "")[:300],
                "evidence_refs": _compact_evidence_refs(row["evidence_refs_json"]),
            }
        )
        if len(hits) >= limit:
            break
    return hits


def _connect(db_path: str | Path) -> sqlite3.Connection:
    try:
        from db.db_utils import connect  # noqa: PLC0415
    except ImportError:
        sys_path = Path(__file__).resolve().parent.parent
        import sys

        sys.path.insert(0, str(sys_path))
        from db.db_utils import connect  # noqa: PLC0415
    return connect(db_path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="查询 coverage_ledger 历史负结论（升级前必查）")
    parser.add_argument("--target", required=True, help="target_name")
    parser.add_argument("--db", required=True, help="DB 路径")
    parser.add_argument("--keyword", action="append", default=[], help="匹配关键词（可重复，如 --keyword fastjson --keyword @type）")
    parser.add_argument("--test-type", default="", help="suspicious_points.test_type（自动提词）")
    parser.add_argument("--signal-reason", default="", help="suspicious_points.signal_reason（自动提词）")
    parser.add_argument("--reasoning", default="", help="suspicious_points.reasoning（自动提词）")
    parser.add_argument("--evidence", default="", help="suspicious_points.evidence 前 300 字符（自动提词）")
    args = parser.parse_args(argv)

    conn = _connect(args.db)
    conn.row_factory = sqlite3.Row
    try:
        keywords = sp_keywords(
            test_type=args.test_type,
            signal_reason=args.signal_reason,
            reasoning=args.reasoning,
            evidence=args.evidence,
            explicit=args.keyword,
        )
        hits = find_negative_coverage(conn, target_name=args.target, keywords=keywords)
        print(
            json.dumps(
                {"target": args.target, "keywords": keywords, "negative_coverage": hits, "count": len(hits)},
                ensure_ascii=False,
            )
        )
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
