"""Deterministically backfill empty suspicious_points IDs without exposing evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
import sys
from pathlib import Path
from typing import Any

TOOLS_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(TOOLS_DIR))

from db.db_utils import connect, find_db  # noqa: E402


def _slug(test_type: Any) -> str:
    value = re.sub(r"[^a-z0-9]+", "-", str(test_type or "unknown").lower()).strip("-")
    return (value or "unknown")[:48]


def _candidate(row: sqlite3.Row, occupied: set[str]) -> tuple[str, bool]:
    material = "|".join(str(row[key] or "") for key in ("url", "param", "method", "source")) + f"|{row['rowid']}"
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
    prefix = f"sp-{_slug(row['test_type'])}-"
    for length in range(12, len(digest) + 1):
        value = prefix + digest[:length]
        if value not in occupied:
            return value, length > 12
    suffix = 2
    while f"{prefix}{digest}-{suffix}" in occupied:
        suffix += 1
    return f"{prefix}{digest}-{suffix}", True


def _validate_target(conn: sqlite3.Connection, target_name: str) -> None:
    table = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='targets'").fetchone()
    if table is None:
        raise ValueError("target validation requires the targets table")
    exact = conn.execute("SELECT 1 FROM targets WHERE target_name=? LIMIT 1", (target_name,)).fetchone()
    if exact is None:
        raise ValueError("target_name does not exactly match the database targets")


def backfill_sp_ids(db_path: str | Path, *, target_name: str | None = None, apply: bool = False) -> dict[str, Any]:
    """Preview or atomically fill every NULL/blank suspicious point ID."""
    conn = connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        if apply:
            conn.execute("BEGIN IMMEDIATE")
        if target_name is not None:
            _validate_target(conn, target_name)
        table = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='suspicious_points'").fetchone()
        if table is None:
            raise ValueError("suspicious_points table is missing")

        rows = conn.execute(
            """SELECT rowid,url,param,method,test_type,source
               FROM suspicious_points
               WHERE id IS NULL OR trim(id)=''
               ORDER BY rowid"""
        ).fetchall()
        occupied = {str(row[0]) for row in conn.execute("SELECT id FROM suspicious_points WHERE id IS NOT NULL AND trim(id)<>''")}
        assignments: list[tuple[str, int]] = []
        collision_count = 0
        for row in rows:
            value, collided = _candidate(row, occupied)
            occupied.add(value)
            assignments.append((value, int(row["rowid"])))
            collision_count += int(collided)

        remaining = len(assignments)
        if apply:
            for value, rowid in assignments:
                changed = conn.execute(
                    """UPDATE suspicious_points SET id=?
                       WHERE rowid=? AND (id IS NULL OR trim(id)='')""",
                    (value, rowid),
                ).rowcount
                if changed != 1:
                    raise RuntimeError("suspicious point changed during backfill")
            remaining = conn.execute("SELECT count(*) FROM suspicious_points WHERE id IS NULL OR trim(id)=''").fetchone()[0]
            if remaining:
                raise RuntimeError("empty suspicious point IDs remain after backfill")
            conn.commit()

        return {
            "mode": "apply" if apply else "preview",
            "count": len(assignments),
            "candidate_ids": [value for value, _ in assignments],
            "collision_count": collision_count,
            "remaining_empty_ids": remaining,
        }
    except Exception:
        if apply and conn.in_transaction:
            conn.rollback()
        raise
    finally:
        conn.close()


def _error(message: object) -> None:
    print(
        json.dumps({"error": str(message)}, ensure_ascii=False, separators=(",", ":")),
        file=sys.stderr,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Backfill empty suspicious_points IDs")
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--target", help="exact target_name")
    selection.add_argument("--file", help="explicit SQLite file")
    parser.add_argument("--apply", action="store_true", help="persist updates; default is preview")
    args = parser.parse_args()

    try:
        path = find_db(args.target) if args.target else Path(args.file).expanduser()
        if not path.is_file():
            raise FileNotFoundError("database file does not exist")
        result = backfill_sp_ids(path, target_name=args.target, apply=args.apply)
    except SystemExit as exc:
        _error(exc.code)
        return 1
    except Exception as exc:
        _error(exc)
        return 1
    print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
