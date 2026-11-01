"""Read-only, compact health audit for one explicitly selected target DB."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any

TOOLS_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(TOOLS_DIR))

from db.db_utils import find_db  # noqa: E402


def _read_only_connection(path: Path) -> sqlite3.Connection:
    resolved = path.resolve()
    if not resolved.is_file():
        raise FileNotFoundError(f"DB 不存在: {path}")
    conn = sqlite3.connect(f"file:{resolved.as_posix()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only=ON")
    return conn


def _tables(conn: sqlite3.Connection) -> set[str]:
    return {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in conn.execute(f'PRAGMA table_info("{table}")')}


def _unavailable(*, tables: list[str] | None = None, columns: list[str] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "not_available"}
    if tables:
        result["missing_tables"] = sorted(tables)
    if columns:
        result["missing_columns"] = sorted(columns)
    return result


def _guard(
    conn: sqlite3.Connection,
    existing: set[str],
    required: dict[str, set[str]],
) -> dict[str, Any] | None:
    missing_tables = [table for table in required if table not in existing]
    if missing_tables:
        return _unavailable(tables=missing_tables)
    missing_columns = [f"{table}.{column}" for table, columns in required.items() for column in columns - _columns(conn, table)]
    return _unavailable(columns=missing_columns) if missing_columns else None


def _status_distribution(
    conn: sqlite3.Connection,
    target: str | None,
    domain: str,
) -> dict[str, Any]:
    rows = conn.execute(
        """
        SELECT status, COUNT(*) AS n
        FROM coverage_ledger
        WHERE (? IS NULL OR target_name=?)
          AND (
            ?='all'
            OR (?='system' AND (category='system' OR item_key LIKE 'system:%'))
            OR (?='public_exposure' AND (
                category='public_exposure' OR item_key LIKE 'public_exposure:%'
            ))
            OR (?='entry_recursion' AND (
                category='entry_recursion' OR item_key LIKE 'entry:%'
                OR item_key='endpoint:param_semantic_classification'
            ))
          )
        GROUP BY status
        ORDER BY status
        """,
        (target, target, domain, domain, domain, domain),
    ).fetchall()
    by_status = {str(row["status"]): int(row["n"]) for row in rows}
    return {"status": "available", "total": sum(by_status.values()), "by_status": by_status}


def _resolve_target(conn: sqlite3.Connection, existing: set[str], requested: str | None) -> str | None:
    if "targets" not in existing or "target_name" not in _columns(conn, "targets"):
        return requested
    names = [str(row[0]) for row in conn.execute("SELECT DISTINCT target_name FROM targets WHERE target_name IS NOT NULL")]
    if requested:
        if requested not in names:
            raise ValueError(f"目标 {requested!r} 与 DB 内 targets.target_name 不匹配")
        return requested
    if len(names) == 1:
        return names[0]
    if len(names) > 1:
        raise ValueError("该 DB 包含多个 target_name，无法从 --file 唯一推断")
    return None


def collect_health(path: Path | str, target: str | None = None) -> dict[str, Any]:
    """Collect health facts without creating a DB, WAL, table, or row."""
    db_path = Path(path)
    with _read_only_connection(db_path) as conn:
        existing = _tables(conn)
        actual_target = _resolve_target(conn, existing, target)
        result: dict[str, Any] = {
            "db": str(db_path),
            "target": actual_target,
            "read_only": True,
        }

        unavailable = _guard(
            conn,
            existing,
            {"work_items": {"target_name", "lane", "status"}},
        )
        if unavailable:
            result["asset_triage"] = unavailable
        else:
            queued = conn.execute(
                """
                SELECT COUNT(*)
                FROM work_items
                WHERE lane='asset_triage' AND status='queued'
                  AND (? IS NULL OR target_name=?)
                """,
                (actual_target, actual_target),
            ).fetchone()[0]
            result["asset_triage"] = {"status": "available", "queued": int(queued)}

        coverage_guard = _guard(
            conn,
            existing,
            {"coverage_ledger": {"target_name", "item_key", "category", "status"}},
        )
        if coverage_guard:
            result["coverage"] = coverage_guard
            result["coverage_domains"] = {name: dict(coverage_guard) for name in ("system", "public_exposure", "entry_recursion")}
        else:
            result["coverage"] = _status_distribution(conn, actual_target, "all")
            result["coverage_domains"] = {
                name: _status_distribution(conn, actual_target, name) for name in ("system", "public_exposure", "entry_recursion")
            }

        confirmed_guard = _guard(
            conn,
            existing,
            {
                "suspicious_points": {"id", "test_status"},
                "findings": {"sp_id"},
                "work_items": {"id", "target_name", "lane", "subject_table", "subject_id", "status", "summary"},
                "operator_inbox": {"target_name", "related_work_item_id", "status"},
            },
        )
        if confirmed_guard:
            result["confirmed_sp"] = confirmed_guard
        else:
            total = conn.execute("SELECT COUNT(*) FROM suspicious_points WHERE test_status='confirmed'").fetchone()[0]
            without = conn.execute(
                """
                SELECT COUNT(*)
                FROM suspicious_points sp
                WHERE sp.test_status='confirmed'
                  AND NOT EXISTS (
                    SELECT 1 FROM findings f
                    WHERE sp.id IS NOT NULL AND sp.id<>'' AND f.sp_id=sp.id
                  )
                  AND NOT EXISTS (
                    SELECT 1
                    FROM work_items wi
                    WHERE wi.subject_table='suspicious_points'
                      AND sp.id IS NOT NULL AND sp.id<>'' AND wi.subject_id=sp.id
                      AND (? IS NULL OR wi.target_name=?)
                      AND (
                        (
                          wi.lane='vuln_review'
                          AND (
                            wi.status IN ('failed','cancelled')
                            OR (
                              wi.status='done'
                              AND (
                                lower(COALESCE(wi.summary,'')) LIKE '%refut%'
                                OR lower(COALESCE(wi.summary,'')) LIKE '%reject%'
                                OR lower(COALESCE(wi.summary,'')) LIKE '%insufficient%'
                                OR COALESCE(wi.summary,'') LIKE '%退回%'
                                OR COALESCE(wi.summary,'') LIKE '%证据不足%'
                              )
                            )
                          )
                        )
                        OR EXISTS (
                          SELECT 1 FROM operator_inbox oi
                          WHERE oi.related_work_item_id=wi.id
                            AND oi.status<>'cancelled'
                            AND (? IS NULL OR oi.target_name=?)
                        )
                      )
                  )
                """,
                (actual_target, actual_target, actual_target, actual_target),
            ).fetchone()[0]
            result["confirmed_sp"] = {
                "status": "available",
                "total": int(total),
                "without_disposition": int(without),
            }

        blocked_guard = _guard(
            conn,
            existing,
            {
                "work_items": {"target_name", "status", "attack_thread_id"},
                "attack_threads": {"id", "status", "evaluation_status"},
            },
        )
        if blocked_guard:
            result["blocked_work_items"] = blocked_guard
        else:
            work_columns = _columns(conn, "work_items")
            row = conn.execute(
                """
                SELECT COUNT(*) AS total,
                       SUM(CASE WHEN at.id IS NULL
                                     OR at.status<>'parked'
                                     OR at.evaluation_status<>'blocked'
                                THEN 1 ELSE 0 END) AS missing_thread
                FROM work_items wi
                LEFT JOIN attack_threads at ON at.id=wi.attack_thread_id
                WHERE wi.status='blocked'
                  AND (? IS NULL OR wi.target_name=?)
                """,
                (actual_target, actual_target),
            ).fetchone()
            missing_classification = (
                conn.execute(
                    """
                    SELECT COUNT(*) FROM work_items
                    WHERE status='blocked'
                      AND (blocker_class IS NULL OR trim(blocker_class)='')
                      AND (? IS NULL OR target_name=?)
                    """,
                    (actual_target, actual_target),
                ).fetchone()[0]
                if "blocker_class" in work_columns
                else row["total"]
            )
            event_columns = _columns(conn, "attack_thread_events") if "attack_thread_events" in existing else set()
            if {"attack_thread_id", "event_type", "payload_json"}.issubset(event_columns):
                without_parked_event = conn.execute(
                    """
                    SELECT COUNT(*) FROM work_items wi
                    WHERE wi.status='blocked' AND (? IS NULL OR wi.target_name=?)
                      AND NOT EXISTS (
                        SELECT 1 FROM attack_thread_events ate
                        WHERE ate.attack_thread_id=wi.attack_thread_id
                          AND ate.event_type='parked'
                          AND json_extract(ate.payload_json, '$.work_item_id')=wi.id
                      )
                    """,
                    (actual_target, actual_target),
                ).fetchone()[0]
            else:
                without_parked_event = row["total"]
            inbox_columns = _columns(conn, "operator_inbox") if "operator_inbox" in existing else set()
            if {"target_name", "related_work_item_id", "kind"}.issubset(inbox_columns):
                without_decision_card = conn.execute(
                    """
                    SELECT COUNT(*) FROM work_items wi
                    WHERE wi.status='blocked' AND (? IS NULL OR wi.target_name=?)
                      AND NOT EXISTS (
                        SELECT 1 FROM operator_inbox oi
                        WHERE oi.target_name=wi.target_name
                          AND oi.related_work_item_id=wi.id
                          AND oi.kind='blocked_decision'
                      )
                    """,
                    (actual_target, actual_target),
                ).fetchone()[0]
            else:
                without_decision_card = row["total"]
            result["blocked_work_items"] = {
                "status": "available",
                "total": int(row["total"]),
                "without_blocked_thread": int(row["missing_thread"] or 0),
                "without_classification": int(missing_classification or 0),
                "classification_column": "available" if "blocker_class" in work_columns else "missing",
                "without_parked_event": int(without_parked_event or 0),
                "without_decision_card": int(without_decision_card or 0),
            }

        notes_guard = _guard(
            conn,
            existing,
            {"target_assets": {"target_name", "notes"}},
        )
        if notes_guard:
            result["asset_notes"] = notes_guard
        else:
            row = conn.execute(
                """
                SELECT COUNT(*) AS total,
                       SUM(CASE WHEN notes IS NULL OR trim(notes)='' THEN 1 ELSE 0 END) AS empty
                FROM target_assets
                WHERE (? IS NULL OR target_name=?)
                """,
                (actual_target, actual_target),
            ).fetchone()
            total, empty = int(row["total"]), int(row["empty"] or 0)
            result["asset_notes"] = {
                "status": "available",
                "total": total,
                "empty": empty,
                "empty_ratio": empty / total if total else 0.0,
            }

        ids_guard = _guard(conn, existing, {"suspicious_points": {"id", "test_status"}})
        if ids_guard:
            result["sp_ids"] = ids_guard
        else:
            row = conn.execute(
                """
                SELECT SUM(CASE WHEN id IS NULL OR id='' THEN 1 ELSE 0 END) AS all_empty,
                       SUM(
                         CASE WHEN test_status='confirmed' AND (id IS NULL OR id='') THEN 1 ELSE 0 END
                       ) AS confirmed_empty
                FROM suspicious_points
                """
            ).fetchone()
            result["sp_ids"] = {
                "status": "available",
                "all_empty": int(row["all_empty"] or 0),
                "confirmed_empty": int(row["confirmed_empty"] or 0),
            }

        return result


def _selected_path(args: argparse.Namespace) -> Path:
    if bool(args.target) == bool(args.file):
        raise SystemExit("必须且只能指定 --target 或 --file")
    return Path(args.file) if args.file else find_db(args.target)


def main() -> int:
    parser = argparse.ArgumentParser(description="单目标 SQLite 只读健康审计")
    parser.add_argument("--target", help="显式 target_name")
    parser.add_argument("--file", help="显式 DB 路径")
    parser.add_argument("--json", action="store_true", help="输出紧凑 JSON")
    args = parser.parse_args()
    try:
        result = collect_health(_selected_path(args), args.target)
    except (FileNotFoundError, sqlite3.Error, ValueError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False))
        return 1
    print(json.dumps(result, ensure_ascii=False, default=str, indent=None if args.json else 2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
