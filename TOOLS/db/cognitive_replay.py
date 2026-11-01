"""Offline preview/apply for cognitive migration; never performs network I/O."""

from __future__ import annotations

import argparse
import json
import shutil
import sqlite3
import sys
from datetime import datetime
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent.parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))
from db.cognitive_contract import normalize_auth_state  # noqa: E402 -- 必须排在 sys.path bootstrap 之后
from db.db_backup import DEFAULT_BACKUP_DIR, backup_one  # noqa: E402 -- 必须排在 sys.path bootstrap 之后
from db.db_utils import connect, find_db  # noqa: E402 -- 必须排在 sys.path bootstrap 之后
from db.migrate import (  # noqa: E402 -- 必须排在 sys.path bootstrap 之后
    apply_migration,
    ensure_schema_version,
    get_current_version,
)


def _count(conn, table):
    try:
        return int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])  # noqa: S608 -- table 只来自本模块内的常量表名列表
    except sqlite3.Error:
        return 0


def _table_exists(conn, table: str) -> bool:
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone() is not None


def _columns(conn, table: str) -> set[str]:
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}


def _has_response_evidence(row: sqlite3.Row, columns: set[str]) -> bool:
    if "status_code" in columns and row["status_code"] is not None:
        return True
    raw = row["evidence_refs_json"] if "evidence_refs_json" in columns else "[]"
    try:
        refs = json.loads(raw or "[]")
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid evidence_refs_json during cognitive replay") from exc
    return isinstance(refs, list) and bool(refs)


def _convert_auth_states(conn: sqlite3.Connection) -> dict[str, int]:
    counts = {"endpoint_observations": 0, "entry_observations": 0, "passive_hint": 0}
    for table, state_col in (("endpoint_observations", "auth_state"), ("entry_observations", "response_class")):
        if not _table_exists(conn, table):
            continue
        columns = _columns(conn, table)
        required = {state_col}
        if not required.issubset(columns):
            raise RuntimeError(f"{table} lacks required response evidence columns")
        select_cols = (
            f"rowid AS _rowid,{state_col}"
            + (",status_code" if "status_code" in columns else "")
            + (",evidence_refs_json" if "evidence_refs_json" in columns else "")
        )
        rows = conn.execute(f"SELECT {select_cols} FROM {table}").fetchall()  # noqa: S608 -- 标识符取自 PRAGMA/schema，值全走参数绑定
        for row in rows:
            has_evidence = _has_response_evidence(row, columns)
            state = normalize_auth_state(row[state_col], has_response_evidence=has_evidence)
            if table == "entry_observations" and not has_evidence:
                state = "passive_hint"
            if state != str(row[state_col] or "unknown"):
                conn.execute(f"UPDATE {table} SET {state_col}=? WHERE rowid=?", (state, row["_rowid"]))  # noqa: S608 -- 标识符取自 PRAGMA/schema，值全走参数绑定
                counts[table] += 1
                if table == "entry_observations" and state == "passive_hint":
                    counts["passive_hint"] += 1
    return counts


def _upgrade_legacy_endpoint_constraint(conn: sqlite3.Connection) -> bool:
    """Rebuild the pre-v32 endpoint table when its CHECK rejects new states."""
    row = conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='endpoint_observations'").fetchone()
    if not row:
        return False
    sql = str(row[0])
    if (
        "auth_state IN ('public','login_redirect','auth_required','token_required','role_required','unknown','blocked_by_waf','not_tested')"
        not in sql
    ):
        return False
    columns = [row[1] for row in conn.execute("PRAGMA table_info(endpoint_observations)").fetchall()]
    quoted = ", ".join('"' + name.replace('"', '""') + '"' for name in columns)
    legacy = "endpoint_observations_legacy_cognitive"
    temp = "endpoint_observations_cognitive_new"
    rebuilt = sql.replace("CREATE TABLE endpoint_observations", f"CREATE TABLE {temp}", 1)
    rebuilt = rebuilt.replace(
        "auth_state IN ('public','login_redirect','auth_required','token_required','role_required','unknown','blocked_by_waf','not_tested')",
        "auth_state IN ('public','auth_redirect','auth_required','restricted','waf_blocked','not_found','spa_shell','unknown','passive_hint','login_redirect','token_required','role_required','not_tested')",
    )
    conn.execute(f"ALTER TABLE endpoint_observations RENAME TO {legacy}")
    conn.execute(rebuilt)
    conn.execute(f"INSERT INTO {temp} ({quoted}) SELECT {quoted} FROM {legacy}")  # noqa: S608 -- 表名/列名均为本模块常量与 schema introspection
    conn.execute(f"DROP TABLE {legacy}")
    conn.execute(f"ALTER TABLE {temp} RENAME TO endpoint_observations")
    new_columns = set(columns)
    if {"target_name", "asset_id", "auth_state", "test_status"}.issubset(new_columns):
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_endpoint_observations_asset ON endpoint_observations(target_name, asset_id, auth_state, test_status)"
        )
    if {"host", "path", "method"}.issubset(new_columns):
        conn.execute("CREATE INDEX IF NOT EXISTS idx_endpoint_observations_host_path ON endpoint_observations(host, path, method)")
    if {"target_name", "resolution_status", "scope_class", "auth_state"}.issubset(new_columns):
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_endpoint_resolution ON endpoint_observations(target_name, resolution_status, scope_class, auth_state)"
        )
    return True


def _park_broad_queue(conn: sqlite3.Connection, *, target_name: str) -> int:
    if not _table_exists(conn, "work_items"):
        raise RuntimeError("work_items table is required for cognitive replay")
    columns = _columns(conn, "work_items")
    if "dispatch_state" not in columns:
        raise RuntimeError("work_items.dispatch_state is required for reversible parking")
    set_clause = "dispatch_state='parked'"
    if "updated_at" in columns:
        set_clause += ", updated_at=datetime('now','localtime')"
    cursor = conn.execute(
        f"UPDATE work_items SET {set_clause} WHERE target_name=? AND lane='asset_triage' AND status IN ('queued','claimed','partial') AND COALESCE(dispatch_state,'active')='active'",  # noqa: S608 -- SET 子句按 schema 列存在性拼接，值走参数绑定
        (target_name,),
    )
    return cursor.rowcount


def preview(db_path: Path, *, target_name: str) -> dict:
    conn = connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("BEGIN")
        rebuilt = _upgrade_legacy_endpoint_constraint(conn)
        conversions = _convert_auth_states(conn)
        conn.rollback()
        return {
            "target": target_name,
            "db": str(db_path),
            "schema_version": get_current_version(conn) if _has_schema_version(conn) else 0,
            "schema_changes": ["032_cognitive_hunt_loop"],
            "legacy_endpoint_rebuild_required": rebuilt,
            "auth_state_conversions": conversions["endpoint_observations"] + conversions["entry_observations"],
            "entries_to_passive_hint": conversions["passive_hint"],
            "broad_work_items_proposed_for_parking": _count_where(
                conn,
                "work_items",
                "lane='asset_triage' AND status IN ('queued','claimed','partial') AND COALESCE(dispatch_state,'active')='active'",
            ),
            "facts_before": _count(conn, "endpoint_observations") + _count(conn, "entry_observations"),
            "evidence_before": _count(conn, "evidence_refs"),
            "work_items_before": _count(conn, "work_items"),
            "network_operation_count": 0,
            "focused_session_created": False,
        }
    finally:
        conn.close()


def apply(db_path: Path, *, target_name: str, backup_dir: Path = DEFAULT_BACKUP_DIR) -> dict:
    try:
        backup = backup_one(db_path, backup_dir, keep=5)
    except (OSError, ValueError, sqlite3.Error):
        backup = {"status": "failed", "reason": "backup helper failed"}
    if backup.get("status") != "ok":
        backup_dir.mkdir(parents=True, exist_ok=True)
        fallback = backup_dir / f"{db_path.stem}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
        shutil.copy2(db_path, fallback)
        backup = {"status": "ok", "backup": str(fallback), "method": "copy_fallback"}
    conn = connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("BEGIN")
        ensure_schema_version(conn)
        if get_current_version(conn) < 32:
            path = Path(__file__).parents[2] / "migrations/032_cognitive_hunt_loop.sql"
            if not apply_migration(conn, 32, str(path)):
                raise RuntimeError("migration 032 failed")
        rebuilt = _upgrade_legacy_endpoint_constraint(conn)
        conversions = _convert_auth_states(conn)
        parked = _park_broad_queue(conn, target_name=target_name)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return {
        "target": target_name,
        "status": "ok",
        "backup": backup,
        "legacy_endpoint_rebuilt": rebuilt,
        "auth_state_conversions": conversions["endpoint_observations"] + conversions["entry_observations"],
        "entries_to_passive_hint": conversions["passive_hint"],
        "broad_work_items_parked": parked,
        "network_operation_count": 0,
        "focused_session_created": False,
    }


def _has_schema_version(c):
    return c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_version'").fetchone() is not None


def _count_where(c, table, where):
    try:
        return int(c.execute(f"SELECT COUNT(*) FROM {table} WHERE {where}").fetchone()[0])  # noqa: S608 -- table/where 均为本模块内静态常量字符串
    except sqlite3.Error:
        return 0


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--target", required=True)
    p.add_argument("--db")
    p.add_argument("--preview", action="store_true")
    p.add_argument("--apply", action="store_true")
    p.add_argument("--backup-dir", default=str(DEFAULT_BACKUP_DIR))
    p.add_argument("--json", action="store_true")
    a = p.parse_args(argv)
    path = (Path(a.db) if a.db else find_db(a.target)).resolve() if (a.db or find_db(a.target)) else None
    if not path:
        raise SystemExit(f"未找到目标 DB: {a.target}")
    backup_dir = Path(a.backup_dir)
    if not backup_dir.is_absolute():
        backup_dir = Path(__file__).parents[2] / backup_dir
    result = preview(path, target_name=a.target) if not a.apply else apply(path, target_name=a.target, backup_dir=backup_dir)
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    main()
