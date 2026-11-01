"""单目标 DB 统一查询工具。替代内联 uv run python -c sqlite3 模板。

用法:
  uv run python TOOLS/db/db_query.py --list                     列出所有目标库（替代 ls dbs/）
  uv run python TOOLS/db/db_query.py --schema                   全量表结构（落库前先看这个）
  uv run python TOOLS/db/db_query.py --schema <表名>            单表结构
  uv run python TOOLS/db/db_query.py <sql>                     SELECT → JSON 数组
  uv run python TOOLS/db/db_query.py <sql> --params '["val1"]' 带参数查询
  uv run python TOOLS/db/db_query.py <sql> --write              INSERT/UPDATE/DELETE → {changes: N}
  uv run python TOOLS/db/db_query.py <sql> --write --params '...'
  uv run python TOOLS/db/db_query.py -t <表名>                  描述表结构（含 NOT NULL / DEFAULT）
  uv run python TOOLS/db/db_query.py --check                    DB 健康检查
  uv run python TOOLS/db/db_query.py --file 路径.db <sql>       指定其他数据库文件
  uv run python TOOLS/db/db_query.py --target "目标名" <sql>    解析目标 DB 并查询
  uv run python TOOLS/db/db_query.py --target "目标名" --init    初始化新目标 DB（dbs/{slug}.db）

DB 路径优先级: --file > --target；不再存在隐式默认 DB
目标解析统一走 db.db_utils.find_db_or_none（规范 dbs/{slug}.db，兼容历史日期后缀/中文名）
输出格式: JSON 到 stdout, 错误到 stderr

示例:
  uv run python TOOLS/db/db_query.py --list
  uv run python TOOLS/db/db_query.py --schema target_assets
  uv run python TOOLS/db/db_query.py --target "example-client" "SELECT * FROM targets"
  uv run python TOOLS/db/db_query.py "SELECT url, depth FROM pages WHERE status='queued'"
  uv run python TOOLS/db/db_query.py \
    "INSERT INTO pages (url, depth, status) VALUES (?, ?, 'queued')" \
    --write --params '["https://t.com/x", 1]'
  uv run python TOOLS/db/db_query.py -t pages
  uv run python TOOLS/db/db_query.py --check
  uv run python TOOLS/db/db_query.py --target "example-client" --init
"""

import argparse
import json
import os
import re
import sqlite3
import sys
from pathlib import Path
from typing import Any

_TOOLS_DIR = Path(__file__).resolve().parent.parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

from db.db_utils import (  # noqa: E402
    connect,
    find_db_or_none,
    force_utf8_stdout,
    list_target_dbs,
    session,
    target_db_path,
)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent  # db/ → TOOLS/ → SRC/
DBS_DIR = _PROJECT_ROOT / "dbs"
DEFAULT_DB = None


def _json_safe(value: Any) -> Any:
    """Normalize SQLite values before JSON serialization without losing Unicode."""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return value


def do_select(conn, sql, params):
    cur = conn.execute(sql, params)
    return [_json_safe(dict(row)) for row in cur.fetchall()]


def do_write(conn, sql, params):
    cur = conn.execute(sql, params)
    conn.commit()
    return {"changes": cur.rowcount, "lastrowid": cur.lastrowid}


def describe_table(conn, table_name):
    cur = conn.execute('PRAGMA table_info("{}")'.format(table_name.replace('"', '""')))
    cols = [dict(r) for r in cur.fetchall()]
    if not cols:
        raise ValueError(f"表 '{table_name}' 不存在")
    return cols


def _col_flags(col: dict) -> str:
    flags = []
    if col.get("pk"):
        flags.append("PK")
    if col.get("notnull"):
        flags.append("NOT NULL")
    if col.get("dflt_value") is not None:
        flags.append(f"DEFAULT {col['dflt_value']}")
    return " ".join(flags)


def schema_text(conn, table_name: str | None = None) -> str:
    """紧凑输出表结构，供落库前一次性查看，避免逐表 -t 查询。"""
    if table_name:
        cols = describe_table(conn, table_name)
        lines = [f"{table_name} ("]
        for c in cols:
            flag = _col_flags(c)
            lines.append(f"  {c['name']:<34}{c['type']:<12}{flag}")
        lines.append(")")
        return "\n".join(lines)

    names = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
    lines = []
    for tbl in names:
        cols = [dict(r) for r in conn.execute(f'PRAGMA table_info("{tbl}")')]
        lines.append(f"{tbl} ({len(cols)} cols)")
        for c in cols:
            flag = _col_flags(c)
            lines.append(f"  {c['name']:<32}{c['type']:<12}{flag}".rstrip())
        lines.append("")
    lines.append(f"-- {len(names)} tables")
    return "\n".join(lines)


# 目标解析统一走 db.db_utils，避免各脚本自带一套不一致的命名约定。
find_target_db = find_db_or_none


def make_target_db_path(target_name):
    """目标 DB 规范路径 dbs/{slug}.db，与 db_admin init 使用同一约定。"""
    return str(target_db_path(target_name, DBS_DIR))


def health_check(conn):
    info = {}

    # scan_state
    cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scan_state'")
    if cur.fetchone():
        cur = conn.execute("SELECT phase, seed_url, total_pages, total_js, total_suspicious FROM scan_state WHERE id=1")
        row = cur.fetchone()
        info["scan_state"] = dict(row) if row else None
    else:
        info["scan_state"] = None

    # counts
    for table in ("pages", "js_files", "suspicious_points", "findings"):
        try:
            cur = conn.execute(f'SELECT count(*) as cnt FROM "{table}"')
            info[table] = cur.fetchone()["cnt"]
        except sqlite3.OperationalError:
            info[table] = None

    # queue
    try:
        cur = conn.execute("SELECT status, count(*) as cnt FROM pages GROUP BY status")
        info["queue"] = {r["status"]: r["cnt"] for r in cur.fetchall()}
    except sqlite3.OperationalError:
        info["queue"] = None

    # auth
    try:
        cur = conn.execute("SELECT count(*) as cnt FROM auth_sessions WHERE is_active=1")
        info["active_sessions"] = cur.fetchone()["cnt"]
    except sqlite3.OperationalError:
        info["active_sessions"] = 0

    # DB file size
    db_path = Path(conn.execute("PRAGMA database_list").fetchone()["file"])
    if db_path.exists():
        info["db_size_kb"] = db_path.stat().st_size // 1024

    return info


def init_db(db_path, target_name, domain=""):
    """初始化新库；仅登记实际存在结构的 migration，禁止虚假 schema 版本。"""
    schema_path = Path(__file__).parent / "schema.sql"
    conn = connect(db_path)
    try:
        conn.executescript(schema_path.read_text(encoding="utf-8"))
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "INSERT INTO targets (target_name, domain) SELECT ?, ? WHERE NOT EXISTS (SELECT 1 FROM targets WHERE target_name=?)",
            (target_name, domain or "", target_name),
        )
        # schema.sql 是 fresh DB 的物理基线。历史实现无条件登记 migrations，
        # 会把缺少 033 操作卡字段的新库伪装成 v33。
        migrations_dir = Path(__file__).resolve().parent.parent.parent / "migrations"
        if migrations_dir.is_dir():
            for f in sorted(migrations_dir.glob("*.sql")):
                m = re.match(r"^(\d+)_", f.name)
                if m:
                    ver = int(m.group(1))
                    if ver >= 33:
                        required = {
                            "target_systems": {"id", "system_key", "canonical_url"},
                            "system_asset_links": {"system_id", "asset_id", "relationship"},
                            "hunt_sessions": {"system_id", "recon_readiness_snapshot_json", "operator_acknowledged_at"},
                            "work_items": {"system_id", "park_reason"},
                            "operator_inbox": {
                                "system_id",
                                "action_key",
                                "steps_json",
                                "report_back_format",
                                "blocking",
                            },
                        }
                        missing = []
                        for table, columns in required.items():
                            actual = {row[1] for row in conn.execute(f'PRAGMA table_info("{table}")')}
                            missing.extend(f"{table}.{column}" for column in columns - actual)
                        if missing:
                            raise RuntimeError("schema.sql incomplete for migration 033: " + ", ".join(sorted(missing)))
                    conn.execute(
                        "INSERT OR IGNORE INTO schema_version (version, description) VALUES (?, ?)",
                        (ver, f.stem),
                    )
        conn.commit()
    finally:
        conn.close()
    return db_path


def _describe_check_values(conn, table_name):
    """解析 CREATE TABLE 里的 CHECK(... IN (...)) 枚举，返回 {列: [允许值]}。"""
    row = conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table_name,)).fetchone()
    if not row or not row["sql"]:
        return {}
    allowed = {}
    pat = re.compile(r"\b(\w+)\s+[^,]*?CHECK\s*\(\s*(?:\w+\s+)?IN\s*\(([^)]*)\)", re.IGNORECASE)
    for m in pat.finditer(row["sql"]):
        col, vals = m.group(1), m.group(2)
        vals = re.findall(r"'([^']*)'", vals)
        if col and vals:
            allowed[col] = vals
    return allowed


def _annotate_error(conn, sql, exc):
    """给 IntegrityError 附上 CHECK 合法值 / NOT NULL 提示。"""
    msg = str(exc)
    m = re.search(r"\btable\s+(\w+)(?:\.\w+)*", str(exc), re.IGNORECASE)
    if not m:
        m = re.search(r"\b(?:into|update)\s+(\w+)", sql, re.IGNORECASE)
    if m:
        table = m.group(1)
        try:
            allowed = _describe_check_values(conn, table)
            if allowed:
                hint_parts = [c + "∈{" + ",".join(v) + "}" for c, v in allowed.items()]
                msg += "\n合法值提示: " + "; ".join(hint_parts)
        except sqlite3.Error:
            pass
    if "NOT NULL constraint failed" in msg:
        msg += "\n提示: 该列 NOT NULL 且无默认值，需显式提供（TEXT 主键需自造 id，如 sp-xxx）"
    return msg


def main():
    force_utf8_stdout()
    parser = argparse.ArgumentParser(
        prog="db_query.py",
        description="单目标 DB 统一查询工具",
        epilog='示例: uv run python TOOLS/db/db_query.py "SELECT * FROM targets" --target 目标名',
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("sql", nargs="?", help="SQL 语句（SELECT/INSERT/UPDATE/DELETE）")
    parser.add_argument("--params", default=None, help="参数 JSON，如 '[\"v1\"]'")
    parser.add_argument("--write", action="store_true", help="写操作（INSERT/UPDATE/DELETE）")
    parser.add_argument("-t", "--table", metavar="表名", help="描述表结构")
    parser.add_argument("--schema", nargs="?", const="", metavar="表名", help="输出表结构；不带表名则输出全量表结构")
    parser.add_argument("--list", action="store_true", help="列出 dbs/ 下所有目标库")
    parser.add_argument("--check", action="store_true", help="DB 健康检查")
    parser.add_argument("--target", metavar="目标名", help="解析 dbs/ 下的目标 DB")
    parser.add_argument("--file", metavar="路径.db", help="指定数据库文件")
    parser.add_argument("--init", action="store_true", help="配合 --target 初始化新目标 DB")
    parser.add_argument("--domain", default="", help="初始化时可选根域")
    a = parser.parse_args()

    # --list 不依赖任何目标，优先处理
    if a.list:
        rows = list_target_dbs(DBS_DIR)
        print(
            json.dumps(
                [
                    {
                        "db": r["db"],
                        "target": r["target"],
                        "schema": r["schema"],
                        "size_kb": r["size_kb"],
                        **({"error": r["error"]} if r.get("error") else {}),
                    }
                    for r in rows
                ],
                ensure_ascii=False,
                indent=1,
            )
        )
        return

    params = json.loads(a.params) if a.params else []
    db_path = None
    if a.file:
        db_path = os.path.expandvars(a.file)
    elif a.target:
        if a.init:
            db_path = make_target_db_path(a.target)
        else:
            db_path = find_target_db(a.target)
            if db_path is None:
                print(
                    json.dumps(
                        {"error": f'未找到目标 DB: {a.target}；请先 --target "{a.target}" --init 初始化'},
                        ensure_ascii=False,
                    )
                )
                sys.exit(1)
    else:
        err = "必须显式指定 --target 或 --file；禁止从环境变量/默认 agent DB 推断目标"
        print(json.dumps({"error": err}, ensure_ascii=False))
        sys.exit(1)

    if a.init:
        if not a.target:
            print(json.dumps({"error": "--init 需要配合 --target 使用"}, ensure_ascii=False))
            sys.exit(1)
        init_db(db_path, a.target, a.domain)
        print(json.dumps({"init": "ok", "db_path": str(db_path)}, ensure_ascii=False))
        return

    if not os.path.exists(db_path):
        print(json.dumps({"error": f"数据库不存在: {db_path}"}, ensure_ascii=False))
        sys.exit(1)

    # --schema 输出紧凑文本，便于落库前一次性查看
    if a.schema is not None:
        try:
            with session(db_path) as conn:
                print(schema_text(conn, a.schema or None))
        except Exception as e:
            print(json.dumps({"error": str(e)}, ensure_ascii=False))
            sys.exit(1)
        return

    conn = connect(db_path)
    try:
        if a.check:
            result = health_check(conn)
        elif a.table:
            result = describe_table(conn, a.table)
        elif a.sql and a.write:
            result = do_write(conn, a.sql, params)
        elif a.sql:
            result = do_select(conn, a.sql, params)
        else:
            result = {"error": "未指定 SQL 或操作"}
    except sqlite3.IntegrityError as e:
        result = {"error": _annotate_error(conn, a.sql or "", e), "sql": a.sql}
    except Exception as e:
        result = {"error": str(e), "sql": a.sql}

    conn.close()
    print(json.dumps(_json_safe(result), ensure_ascii=False, default=str))

    if isinstance(result, dict) and "error" in result:
        sys.exit(1)


if __name__ == "__main__":
    main()
