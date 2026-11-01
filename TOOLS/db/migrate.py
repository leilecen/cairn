"""DB 迁移工具 — 按编号顺序执行 migrations/ 目录下的 .sql 文件。

用法:
  python3 TOOLS/migrate.py --target "example-client"           # 升级到最新
  python3 TOOLS/migrate.py --target "example-client" --status   # 查看当前版本
  python3 TOOLS/migrate.py --file path/to/db.db           # 直接指定 DB 文件
"""

import argparse
import json
import os
import re
import sqlite3
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent  # db/ → TOOLS/ → SRC/
MIGRATIONS_DIR = PROJECT_ROOT / "migrations"
DBS_DIR = PROJECT_ROOT / "dbs"

_TOOLS_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_TOOLS_DIR))
from db.db_utils import connect, find_db_or_none  # noqa: E402
from db.sp_id_backfill import backfill_sp_ids  # noqa: E402


def _split_sql_statements(sql: str) -> list[str]:
    statements: list[str] = []
    buffer = ""
    for line in sql.splitlines():
        buffer += line + "\n"
        if sqlite3.complete_statement(buffer):
            statement = buffer.strip()
            if statement:
                statements.append(statement)
            buffer = ""
    tail = buffer.strip()
    if tail:
        statements.append(tail)
    return statements


def find_target_db(target_name: str) -> str | None:
    """目标解析统一走 db_utils（规范 dbs/{slug}.db + 历史命名兼容）。"""
    path = find_db_or_none(target_name, db_dir=DBS_DIR)
    return str(path) if path else None


def ensure_schema_version(conn: sqlite3.Connection) -> None:
    conn.execute(
        """CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY,
            applied_at TEXT DEFAULT (datetime('now', 'localtime')),
            description TEXT
        )"""
    )
    conn.commit()


def get_current_version(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()
    return row[0] if row and row[0] else 0


def detect_legacy_db(conn: sqlite3.Connection) -> bool:
    """若 DB 已有业务表但 schema_version 为空，判定为旧 DB。"""
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    return "targets" in tables or "pages" in tables


def list_migrations() -> list[tuple[int, str, str]]:
    """返回 [(version, filename, filepath), ...] 按 version 排序。"""
    results = []
    for f in sorted(MIGRATIONS_DIR.glob("*.sql")):
        m = re.match(r"^(\d+)_", f.name)
        if m:
            version = int(m.group(1))
            results.append((version, f.name, str(f)))
    results.sort(key=lambda x: x[0])
    return results


def _snapshot_rebuilt_table_objects(conn: sqlite3.Connection) -> list[tuple[str, str]]:
    """Keep explicitly named indexes/triggers when migration 034 rebuilds its tables.

    SQLite drops dependent objects together with the old table.  The 034 SQL
    recreates the project-owned indexes, but a target DB may also contain
    earlier migration indexes or audit triggers.  Preserve those objects
    verbatim and restore only names the migration did not recreate itself.
    """
    rows = conn.execute(
        """
        SELECT name, sql
        FROM sqlite_master
        WHERE type IN ('index', 'trigger')
          AND tbl_name IN ('operator_inbox', 'suspicious_points')
          AND sql IS NOT NULL
        ORDER BY type, name
        """
    ).fetchall()
    return [(str(row[0]), str(row[1])) for row in rows]


def _restore_rebuilt_table_objects(conn: sqlite3.Connection, objects: list[tuple[str, str]]) -> None:
    for name, sql in objects:
        exists = conn.execute("SELECT 1 FROM sqlite_master WHERE name=?", (name,)).fetchone()
        if exists is None:
            conn.execute(sql)


def apply_migration(conn: sqlite3.Connection, version: int, filepath: str) -> bool:
    sql = Path(filepath).read_text(encoding="utf-8").strip()
    if not sql or sql.startswith("--") and "\n" not in sql:
        # comment-only file = marker migration, still record as applied
        conn.execute(
            "INSERT OR IGNORE INTO schema_version (version, description) VALUES (?, ?)",
            (version, Path(filepath).stem),
        )
        conn.commit()
        return True

    foreign_keys = int(conn.execute("PRAGMA foreign_keys").fetchone()[0])
    legacy_alter_table = int(conn.execute("PRAGMA legacy_alter_table").fetchone()[0])
    transactional = version == 34
    rebuilt_objects = _snapshot_rebuilt_table_objects(conn) if transactional else []
    if transactional:
        conn.commit()
        conn.execute("PRAGMA foreign_keys=OFF")
        conn.execute("SAVEPOINT migration_034")
    try:
        for statement in _split_sql_statements(sql):
            if transactional and re.match(r"^PRAGMA\s+foreign_keys\s*=", statement, re.IGNORECASE):
                continue
            try:
                conn.execute(statement)
            except sqlite3.OperationalError as e:
                e_str = str(e)
                # Accept only known idempotent errors and continue with later statements.
                if re.search(r"duplicate column name|table .+ already exists", e_str, re.IGNORECASE):
                    continue
                print(f"  [ERROR] v{version}: {e}", file=sys.stderr)
                if transactional:
                    conn.execute("ROLLBACK TO migration_034")
                    conn.execute("RELEASE migration_034")
                return False
        conn.execute(
            "INSERT OR IGNORE INTO schema_version (version, description) VALUES (?, ?)",
            (version, Path(filepath).stem),
        )
        if transactional:
            _restore_rebuilt_table_objects(conn, rebuilt_objects)
        if transactional:
            conn.execute("RELEASE migration_034")
        conn.commit()
        return True
    except sqlite3.DatabaseError as e:
        if transactional:
            try:
                conn.execute("ROLLBACK TO migration_034")
                conn.execute("RELEASE migration_034")
            except sqlite3.DatabaseError:
                conn.rollback()
        print(f"  [ERROR] v{version}: {e}", file=sys.stderr)
        return False
    finally:
        if transactional:
            conn.execute(f"PRAGMA foreign_keys={foreign_keys}")
            conn.execute(f"PRAGMA legacy_alter_table={legacy_alter_table}")


def do_migrate(db_path: str) -> dict:
    conn = connect(db_path)
    try:
        ensure_schema_version(conn)
        current = get_current_version(conn)

        # 旧 DB 标记：表已存在但 schema_version 为空
        if current == 0 and detect_legacy_db(conn):
            conn.execute("INSERT OR IGNORE INTO schema_version (version, description) VALUES (1, '001_initial_schema')")
            conn.commit()
            current = 1

        migrations = list_migrations()
        pending = [(v, fn, fp) for v, fn, fp in migrations if v > current]

        if not pending:
            return {
                "db": db_path,
                "current_version": current,
                "applied": [],
                "message": "已是最新版本",
            }

        applied: list[dict[str, Any]] = []
        pre_hooks: list[dict[str, Any]] = []
        for ver, fname, fpath in pending:
            if ver == 34:
                try:
                    hook_result = backfill_sp_ids(db_path, apply=True)
                except Exception as exc:
                    return {
                        "db": db_path,
                        "current_version": get_current_version(conn),
                        "applied": applied,
                        "pre_hooks": pre_hooks,
                        "error": f"迁移 v34 pre-hook 失败: {exc}",
                    }
                candidate_ids = hook_result.pop("candidate_ids", [])
                hook_result["candidate_id_sample"] = candidate_ids[:20]
                hook_result["candidate_ids_omitted"] = max(0, len(candidate_ids) - 20)
                pre_hooks.append({"version": 34, "name": "sp_id_backfill", "result": hook_result})
            ok = apply_migration(conn, ver, fpath)
            if ok:
                applied.append({"version": ver, "file": fname})
            else:
                return {
                    "db": db_path,
                    "current_version": current,
                    "applied": applied,
                    "pre_hooks": pre_hooks,
                    "error": f"迁移 v{ver} ({fname}) 失败",
                }

        return {
            "db": db_path,
            "current_version": get_current_version(conn),
            "applied": applied,
            "pre_hooks": pre_hooks,
            "message": "迁移完成",
        }
    finally:
        conn.close()


def do_status(db_path: str) -> dict:
    conn = connect(db_path)
    try:
        ensure_schema_version(conn)
        current = get_current_version(conn)

        if current == 0 and detect_legacy_db(conn):
            conn.execute("INSERT OR IGNORE INTO schema_version (version, description) VALUES (1, '001_initial_schema')")
            conn.commit()
            current = 1

        migrations = list_migrations()
        history = conn.execute("SELECT version, applied_at, description FROM schema_version ORDER BY version").fetchall()

        return {
            "db": db_path,
            "current_version": current,
            "total_migrations": len(migrations),
            "pending": [fn for v, fn, _ in migrations if v > current],
            "history": [{"version": r[0], "applied_at": r[1], "description": r[2]} for r in history],
        }
    finally:
        conn.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="DB 迁移工具")
    parser.add_argument("--target", help="目标名（自动匹配 dbs/{target}_*.db）")
    parser.add_argument("--file", help="直接指定 DB 文件路径")
    parser.add_argument("--status", action="store_true", help="仅查看迁移状态，不执行")
    args = parser.parse_args()

    if args.file:
        db_path = os.path.expandvars(args.file)
    elif args.target:
        db_path = find_target_db(args.target)
        if db_path is None:
            print(json.dumps({"error": f"未找到目标 DB: {args.target}"}, ensure_ascii=False))
            return 1
    else:
        parser.print_help()
        return 1

    if not os.path.exists(db_path):
        print(json.dumps({"error": f"DB 文件不存在: {db_path}"}, ensure_ascii=False))
        return 1

    try:
        result = do_status(db_path) if args.status else do_migrate(db_path)
    except Exception as exc:
        result = {"error": str(exc)}

    print(json.dumps(result, ensure_ascii=False, default=str))
    return 1 if "error" in result else 0


if __name__ == "__main__":
    raise SystemExit(main())
