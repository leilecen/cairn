"""Query normalized review candidates without hand-written SQL."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
TOOLS_DIR = PROJECT_ROOT / "TOOLS"
sys.path.insert(0, str(TOOLS_DIR))

from db.db_utils import connect, find_db  # noqa: E402


def query_candidates(conn: sqlite3.Connection, limit: int = 10, offset: int = 0) -> list[dict]:
    rows = conn.execute(
        """
        SELECT
            source_table,
            source_id,
            source,
            url,
            method,
            fingerprint,
            reason,
            risk_score,
            next_action,
            status,
            created_at,
            burp_history_id
        FROM review_candidates
        ORDER BY risk_score DESC, created_at ASC
        LIMIT ? OFFSET ?
        """,
        (limit, offset),
    ).fetchall()
    return [dict(row) for row in rows]


def main() -> None:
    parser = argparse.ArgumentParser(description="Query review_candidates view")
    parser.add_argument("--target", required=True, help="目标名（匹配 dbs/{target}*.db）")
    parser.add_argument("--limit", type=int, default=10, help="返回候选数量")
    parser.add_argument("--offset", type=int, default=0, help="结果偏移量")
    parser.add_argument("--json", action="store_true", help="JSON 输出")
    args = parser.parse_args()

    db_path = find_db(args.target)
    conn = connect(db_path)
    try:
        rows = query_candidates(conn, limit=args.limit, offset=args.offset)
    finally:
        conn.close()

    if args.json:
        print(json.dumps({"target": args.target, "candidates": rows}, ensure_ascii=False, indent=2))
        return

    for row in rows:
        action = row["next_action"]
        if row.get("burp_history_id"):
            action = f"{action},down_drill_burp_detail"
        print(
            f"[{row['source_table']}] {row['source_id']} score={row['risk_score']} "
            f"{row['method']} {row['url']} ({row['reason']}; next={action})"
        )


if __name__ == "__main__":
    main()
