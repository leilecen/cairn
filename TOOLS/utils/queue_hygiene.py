"""Dry-run/apply cleanup for noisy hunt_queue entries."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from collections import defaultdict
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(TOOLS_DIR))

from db.db_utils import connect, find_db  # noqa: E402
from utils.signal_filter import build_endpoint_signal_payload, canonicalize_url  # noqa: E402


def _full_url(row: sqlite3.Row) -> str:
    url = row["url"] or ""
    query = row["query_string"] or ""
    if query and "?" not in url:
        return f"{url}?{query}"
    return url


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}


def _select_queue_rows(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    columns = _table_columns(conn, "hunt_queue")
    sql = """
        SELECT
            id,
            method,
            url,
            query_string,
            status,
            notes,
            {source_col},
            {noise_reason_col},
            {risk_score_col},
            {signal_value_col},
            {signal_reason_col},
            {canonical_url_col}
        FROM hunt_queue
        WHERE status='queued'
        ORDER BY id
    """
    query = sql.format(
        source_col="source" if "source" in columns else "NULL AS source",
        noise_reason_col="noise_reason" if "noise_reason" in columns else "NULL AS noise_reason",
        risk_score_col="risk_score" if "risk_score" in columns else "NULL AS risk_score",
        signal_value_col="signal_value" if "signal_value" in columns else "NULL AS signal_value",
        signal_reason_col="signal_reason" if "signal_reason" in columns else "NULL AS signal_reason",
        canonical_url_col="canonical_url" if "canonical_url" in columns else "NULL AS canonical_url",
    )
    return conn.execute(query).fetchall()


def analyze_queue(conn: sqlite3.Connection, *, include_manual: bool = False) -> dict:
    rows = _select_queue_rows(conn)
    duplicate_groups: dict[str, list[int]] = defaultdict(list)
    low_value_rows = []
    random_duplicates = 0
    top_candidates = []
    risk_distribution: dict[str, int] = defaultdict(int)

    for row in rows:
        full_url = _full_url(row)
        payload = build_endpoint_signal_payload(full_url, row["method"] or "GET")
        canonical = payload["canonical_url"] or canonicalize_url(full_url)
        key = f"{(row['method'] or 'GET').upper()} {canonical}"
        duplicate_groups[key].append(row["id"])
        source = row["source"] or "auto"
        is_manual = source == "manual_replay"
        effective_risk = int(row["risk_score"] or payload["risk_score"] or 0)
        risk_bucket = _bucket_risk_score(effective_risk)
        risk_distribution[risk_bucket] += 1

        low_value = payload["signal_value"] in ("low_value", "ignore") or bool(payload["noise_reason"])
        if low_value and (include_manual or not is_manual):
            low_value_rows.append(
                {
                    "id": row["id"],
                    "url": full_url,
                    "source": source,
                    "signal_value": payload["signal_value"],
                    "signal_reason": payload["signal_reason"],
                    "noise_reason": payload["noise_reason"] or payload["signal_reason"],
                }
            )

        if payload["is_candidate"] and not payload["noise_reason"]:
            top_candidates.append(
                {
                    "id": row["id"],
                    "method": (row["method"] or "GET").upper(),
                    "url": full_url,
                    "risk_score": effective_risk,
                    "signal_value": payload["signal_value"],
                    "signal_reason": payload["signal_reason"],
                }
            )

    duplicates = {key: ids for key, ids in duplicate_groups.items() if len(ids) > 1}
    random_duplicates = sum(len(ids) - 1 for ids in duplicates.values())
    noise_marked = 0
    if "noise_reason" in _table_columns(conn, "hunt_queue"):
        noise_marked = conn.execute("SELECT COUNT(*) FROM hunt_queue WHERE COALESCE(noise_reason, '') != ''").fetchone()[0]

    top_candidates.sort(key=lambda item: (-item["risk_score"], item["id"]))
    return {
        "queued": len(rows),
        "duplicate_groups": [
            {"key": key, "ids": ids[:10], "count": len(ids)}
            for key, ids in sorted(duplicates.items(), key=lambda item: (-len(item[1]), item[0]))
        ][:20],
        "random_param_duplicates": random_duplicates,
        "low_value_queued": len(low_value_rows),
        "noise_marked": noise_marked,
        "low_value_ids": [item["id"] for item in low_value_rows],
        "low_value_rows": low_value_rows,
        "low_value_sample": low_value_rows[:20],
        "top_candidate_sample": top_candidates[:5],
        "risk_score_distribution": dict(sorted(risk_distribution.items())),
    }


def _bucket_risk_score(score: int) -> str:
    if score >= 60:
        return "60+"
    if score >= 30:
        return "30-59"
    if score > 0:
        return "1-29"
    return "0"


def apply_low_value(conn: sqlite3.Connection, rows: list[dict]) -> int:
    if not rows:
        return 0
    columns = _table_columns(conn, "hunt_queue")
    updated = 0
    for row in rows:
        noise_reason = row.get("noise_reason") or "queue_hygiene_low_value"
        params = {
            "id": row["id"],
            "noise_reason": noise_reason,
        }
        if "noise_reason" in columns:
            cur = conn.execute(
                """
                UPDATE hunt_queue
                SET status='tested',
                    notes=COALESCE(notes || ' | ', '') || 'queue_hygiene: low_value endpoint',
                    noise_reason=:noise_reason,
                    tested_at=datetime('now','localtime')
                WHERE id=:id AND status='queued'
                """,
                params,
            )
        else:
            cur = conn.execute(
                """
                UPDATE hunt_queue
                SET status='tested',
                    notes=COALESCE(notes || ' | ', '') || 'queue_hygiene: low_value endpoint',
                    tested_at=datetime('now','localtime')
                WHERE id=:id AND status='queued'
                """,
                params,
            )
        updated += cur.rowcount
    conn.commit()
    return updated


def main() -> None:
    parser = argparse.ArgumentParser(description="hunt_queue signal/noise hygiene")
    parser.add_argument("--target", required=True)
    parser.add_argument("--dry-run", action="store_true", help="analyze only; this is the default")
    parser.add_argument("--apply", action="store_true", help="mark low-value queued entries as tested")
    parser.add_argument(
        "--include-manual",
        action="store_true",
        help="include source='manual_replay' rows in low-value marking",
    )
    args = parser.parse_args()

    db_path = find_db(args.target)
    conn = connect(db_path)
    try:
        summary = analyze_queue(conn, include_manual=args.include_manual)
        summary["applied"] = apply_low_value(conn, summary["low_value_rows"]) if args.apply else 0
        summary["mode"] = "apply" if args.apply else "dry-run"
        summary["include_manual"] = args.include_manual
        summary.pop("low_value_rows", None)
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    finally:
        conn.close()


if __name__ == "__main__":
    main()
