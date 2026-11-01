"""落库助手 — 把踩过的 schema 坑一次性固化，供所有 tmp/<target>/*.py 脚本导入。

设计目标（对应 2026-09-23 example-target 项目踩过的 5 类坑）：

1. **不要猜列**：`columns()` / `require_columns()` 先查 PRAGMA，写错列立刻报错并列出可用列，
   而不是让字段静默丢失（本项目 `suspicious_points.reasoning` 曾被静默吞掉）。
2. **不要显式传默认值列**：`insert()` 自动剔除带 DEFAULT 且值为 None 的列，
   避免 `created_at` 这类列触发 KeyError / NOT NULL 报错。
3. **枚举约束前置校验**：`insert()` 读 `sqlite_master.sql` 解析 CHECK 约束，
   写入前校验枚举值，报错时直接列出合法值（本项目 `evidence_type='recon'`、
   `operator_inbox.kind='provide_credential'`、`coverage_ledger.status='partial'` 都栽过）。
4. **唯一约束去重**：`upsert()` 按目标表的 UNIQUE 索引做「存在则更新、不存在则插入」，
   避免 `js_signals` 那类复合唯一约束冲突导致整批失败。
5. **原子提交 + 完整性自检**：`apply()` 里所有写入在一个事务内提交；
   `check_integrity()` 落库后自动扫描空关键字段（reasoning/evidence/evidence_refs_json 等）。

用法：

    from lib.store_kit import StoreKit

    with StoreKit('example-target') as db:
        db.upsert('suspicious_points', {
            'id': 'tnt-xxx',
            'reasoning': '...',
            'evidence': 'tmp/tnt/xxx.json',
            'risk': 'low',
            'test_status': 'confirmed_low',
        }, key=['id'])
        db.check_integrity()
"""

from __future__ import annotations

import re
import sqlite3
import sys
from pathlib import Path
from typing import Any, Iterable, Literal, Sequence

# 允许脚本以两种方式导入：作为包内模块，或直接把 lib/ 加进 sys.path
_TOOLS_DIR = Path(__file__).resolve().parent.parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

from db.db_utils import connect, find_db, find_db_or_none, force_utf8_stdout  # noqa: E402

__all__ = [
    "StoreKit",
    "SchemaError",
    "EnumViolation",
    "check_integrity",
    "INTEGRITY_RULES",
]


class SchemaError(RuntimeError):
    """列不存在 / 约束不满足。消息里带可用列或合法枚举值。"""


class EnumViolation(SchemaError):
    """CHECK 约束枚举违规。"""


# ---------------------------------------------------------------- CHECK 约束解析

# 匹配 CHECK (col IN ('a','b',...))
_CHECK_IN = re.compile(
    r"""CHECK\s*\(\s*["'`\[]?(\w+)["'`\]]?\s+IN\s*\(([^)]*)\)\s*\)""",
    re.I | re.S,
)
_STR_LITERAL = re.compile(r"'((?:[^']|'')*)'")


def _parse_check_enums(create_sql: str) -> dict[str, set[str]]:
    """从 CREATE TABLE 语句里解析 `col IN ('a','b')` 形式的枚举约束。"""
    out: dict[str, set[str]] = {}
    for col, body in _CHECK_IN.findall(create_sql or ""):
        values = {m.group(1).replace("''", "'") for m in _STR_LITERAL.finditer(body)}
        if values:
            out.setdefault(col.lower(), set()).update(values)
    return out


# ---------------------------------------------------------------- 完整性自检规则

# 表 → 不允许为空的关键列（用于落库后自检）
INTEGRITY_RULES: dict[str, tuple[str, ...]] = {
    "suspicious_points": ("reasoning", "evidence"),
    "js_signals": ("evidence_snippet",),
    "endpoint_observations": ("business_hint",),
    "evidence_refs": ("title", "summary"),
    # 只用 JSON 列做判据的表：空元组留在此处（列名见 _JSON_EMPTY_COLS）
    "coverage_ledger": (),
}

# 需要检查「JSON 空数组也算缺」的列（作用于所有含该列的表）
_JSON_EMPTY_COLS = ("evidence_refs_json",)


class StoreKit:
    """一个有 schema 感知能力的落库会话。

    作为 context manager 使用；退出时自动 commit（异常则 rollback 并关闭）。
    """

    def __init__(self, target: str | None = None, db_path: Path | str | None = None, *, verbose: bool = True):
        force_utf8_stdout()
        if db_path is None:
            if target is None:
                raise ValueError("必须提供 target 或 db_path")
            db_path = find_db(target)
        self.db_path = Path(db_path)
        self.target = target or self._target_name_from_db()
        self.verbose = verbose
        self.conn: sqlite3.Connection | None = None
        self._cols_cache: dict[str, list[dict]] = {}
        self._enum_cache: dict[str, dict[str, set[str]]] = {}
        self._unique_cache: dict[str, list[tuple[str, ...]]] = {}
        self.log_lines: list[str] = []

    # ------------------------------------------------------------ 生命周期

    def __enter__(self) -> "StoreKit":
        self.conn = connect(self.db_path)
        return self

    def __exit__(self, exc_type, exc, tb) -> Literal[False]:
        # 不用 assert：`python -O` 会整条剥掉 assert，随后的 self.conn.commit() 会抛
        # AttributeError 并跳过 finally，连接就永远关不掉。
        if self.conn is None:
            raise RuntimeError("StoreKit.__exit__ 被调用，但没有进入过 with 块")
        try:
            if exc_type is None:
                self.conn.commit()
                if self.verbose:
                    for line in self.log_lines:
                        print(line)
            elif issubclass(exc_type, (SystemExit, KeyboardInterrupt)):
                self.conn.rollback()  # 正常退出/中断，不打噪音日志
            else:
                self.conn.rollback()
                print(f"[store_kit] 异常回滚：{exc_type.__name__}: {exc}", file=sys.stderr)
        finally:
            self.conn.close()
            self.conn = None
        return False

    @property
    def cur(self) -> sqlite3.Cursor:
        if self.conn is None:
            raise RuntimeError("StoreKit 必须在 with 块内使用")
        return self.conn.cursor()

    def _log(self, msg: str) -> None:
        """累积日志，由 __exit__ 统一输出。

        不要在这里 print —— 否则 verbose 模式下日志会在写入时打一遍、
        退出时再打一遍（本项目曾出现计数输出重复）。
        """
        self.log_lines.append(msg)

    def _target_name_from_db(self) -> str | None:
        try:
            with connect(self.db_path) as c:
                row = c.execute("SELECT target_name FROM targets LIMIT 1").fetchone()
                return row[0] if row else None
        except sqlite3.Error:
            return None

    def target_id(self) -> int | None:
        try:
            row = self.cur.execute("SELECT id FROM targets WHERE target_name=? LIMIT 1", (self.target,)).fetchone()
            return row[0] if row else None
        except sqlite3.Error:
            return None

    # ------------------------------------------------------------ schema 感知

    def columns(self, table: str) -> list[dict]:
        """返回 PRAGMA table_info 结果（带缓存）。"""
        if table not in self._cols_cache:
            rows = self.cur.execute(f'PRAGMA table_info("{table}")').fetchall()
            if not rows:
                raise SchemaError(f"表不存在：{table}")
            self._cols_cache[table] = [{"name": r[1], "type": r[2], "notnull": bool(r[3]), "default": r[4], "pk": bool(r[5])} for r in rows]
        return self._cols_cache[table]

    def column_names(self, table: str) -> list[str]:
        return [c["name"] for c in self.columns(table)]

    def default_columns(self, table: str) -> set[str]:
        """有 DEFAULT 且非主键的列 —— 这些列不该显式传 None。"""
        return {c["name"] for c in self.columns(table) if c["default"] is not None and not c["pk"]}

    def notnull_columns(self, table: str) -> set[str]:
        return {c["name"] for c in self.columns(table) if c["notnull"]}

    def enums(self, table: str) -> dict[str, set[str]]:
        """解析表的 CHECK 枚举约束（带缓存）。"""
        if table not in self._enum_cache:
            row = self.cur.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
            self._enum_cache[table] = _parse_check_enums(row[0] if row else "")
        return self._enum_cache[table]

    def unique_keys(self, table: str) -> list[tuple[str, ...]]:
        """返回该表所有 UNIQUE 索引的列组合（含主键）。"""
        if table in self._unique_cache:
            return self._unique_cache[table]
        keys: list[tuple[str, ...]] = []
        for r in self.cur.execute(f'PRAGMA index_list("{table}")'):
            # r: seq, name, unique, origin, partial
            if not r[2]:
                continue
            cols = tuple(c[2] for c in self.cur.execute(f'PRAGMA index_info("{r[1]}")'))
            if cols:
                keys.append(cols)
        self._unique_cache[table] = keys
        return keys

    # ------------------------------------------------------------ 校验

    def validate(self, table: str, record: dict[str, Any]) -> dict[str, Any]:
        """校验并清洗一条记录：
        - 未知列 → SchemaError（列出可用列）
        - 枚举违规 → EnumViolation（列出合法值）
        - DEFAULT 列为 None → 剔除（让数据库用默认值）
        - 非 DEFAULT 的 NOT NULL 列为 None 且无值 → SchemaError
        返回清洗后的副本。
        """
        cols = self.column_names(table)
        unknown = [k for k in record if k not in cols]
        if unknown:
            raise SchemaError(f"{table} 不存在列 {unknown}；可用列：{cols}")

        enums = self.enums(table)
        for col, allowed in enums.items():
            if col in record and record[col] is not None:
                val = record[col]
                if isinstance(val, str) and val not in allowed:
                    raise EnumViolation(f"{table}.{col} = {val!r} 不在允许集合；合法值：{sorted(allowed)}")

        defaults = self.default_columns(table)
        pk = {c["name"] for c in self.columns(table) if c["pk"]}
        notnull = self.notnull_columns(table)

        clean: dict[str, Any] = {}
        for k, v in record.items():
            if v is None:
                if k in defaults or k in pk:
                    continue  # 交给 DB 默认值
                if k in notnull:
                    raise SchemaError(f"{table}.{k} 是 NOT NULL 且无默认值，不能传 None；该类列：{sorted(notnull - defaults - pk)}")
                clean[k] = None
                continue
            clean[k] = v

        missing = (notnull - defaults - pk) - set(clean)
        if missing:
            raise SchemaError(f"{table} 缺少必填列 {sorted(missing)}（NOT NULL 且无默认值）")
        return clean

    # ------------------------------------------------------------ 写入

    def insert(self, table: str, record: dict[str, Any], *, log: bool = True) -> int:
        clean = self.validate(table, record)
        if not clean:
            raise SchemaError(f"{table} 插入记录为空（全部字段被默认值剔除）")
        cols = list(clean)
        ph = ",".join("?" for _ in cols)
        sql = f'INSERT INTO "{table}" ({",".join(cols)}) VALUES ({ph})'  # noqa: S608 -- 列名经 StoreKit.validate 用 PRAGMA 白名单过滤
        cur = self.cur
        cur.execute(sql, [clean[c] for c in cols])
        if log:
            self._log(f"[{table}][insert] {self._brief(table, clean)}")
        return cur.lastrowid or 0

    def upsert(self, table: str, record: dict[str, Any], *, key: Sequence[str], log: bool = True) -> str:
        """按 key 列存在则 UPDATE、不存在则 INSERT。返回 'insert' / 'update'。

        key 应是表上真实存在的 UNIQUE 索引列组合；本方法不做约束推导，
        但会在写入前用 validate 拦住非法列与枚举值。
        """
        clean = self.validate(table, record)
        missing_key = [k for k in key if k not in clean]
        if missing_key:
            raise SchemaError(f"{table}.upsert 缺少 key 列 {missing_key}")
        where = " AND ".join(f'"{k}" IS ?' for k in key)
        cur = self.cur
        exists = cur.execute(f'SELECT 1 FROM "{table}" WHERE {where} LIMIT 1', [clean[k] for k in key]).fetchone()  # noqa: S608 -- 表/列名同 insert，值全走参数绑定

        if exists:
            upd = {k: v for k, v in clean.items() if k not in key}
            if upd:
                sets = ",".join(f'"{k}"=?' for k in upd)
                cur.execute(
                    f'UPDATE "{table}" SET {sets} WHERE {where}',  # noqa: S608 -- 表/列名同 insert，值全走参数绑定
                    [upd[k] for k in upd] + [clean[k] for k in key],
                )
            if log:
                self._log(f"[{table}][update] {self._brief(table, clean)}")
            return "update"

        cols = list(clean)
        ph = ",".join("?" for _ in cols)
        cur.execute(f'INSERT INTO "{table}" ({",".join(cols)}) VALUES ({ph})', [clean[c] for c in cols])  # noqa: S608 -- 列名经 StoreKit.validate 用 PRAGMA 白名单过滤
        if log:
            self._log(f"[{table}][insert] {self._brief(table, clean)}")
        return "insert"

    def upsert_many(self, table: str, records: Iterable[dict[str, Any]], *, key: Sequence[str], log: bool = True) -> dict[str, int]:
        """批量 upsert；返回 {'insert': n, 'update': n}。任一失败整批回滚。"""
        stats = {"insert": 0, "update": 0}
        for r in records:
            stats[self.upsert(table, r, key=key, log=log)] += 1
        self._log(f"[{table}] 批量完成 insert={stats['insert']} update={stats['update']}")
        return stats

    def backup(self, *, suffix: str = "bak") -> Path | None:
        """写库前备份（幂等：同名备份已存在则跳过）。"""
        if not self.db_path.is_file():
            return None
        dst = self.db_path.with_suffix(f".{suffix}.db")
        if dst.exists():
            return dst
        with connect(self.db_path) as src:
            with sqlite3.connect(str(dst)) as out:
                src.backup(out)
        self._log(f"[store_kit] 已备份 → {dst.name}")
        return dst

    # ------------------------------------------------------------ 自检

    def check_integrity(
        self, *, rules: dict[str, tuple[str, ...]] | None = None, raise_on_fail: bool = False, limit: int = 0
    ) -> dict[str, list[tuple]]:
        """扫描关键字段是否为空。

        limit=0（默认）表示查全部 —— 不要设小值，否则会漏报（本项目曾因 LIMIT 50
        只看到 50 条空记录，而实际是 102 条）。需要采样时显式传 limit。

        返回 {table: [(行标识, 列名), ...]}；默认只报告不抛异常。
        """
        rules = rules or INTEGRITY_RULES
        problems: dict[str, list[tuple]] = {}
        cur = self.cur
        for table, cols in rules.items():
            try:
                available = set(self.column_names(table))
            except SchemaError:
                continue
            usable = [c for c in cols if c in available]
            json_cols = [c for c in _JSON_EMPTY_COLS if c in available]
            # 规则列和 JSON 列都为空时才跳过（只按 JSON 判据的表也要能被检查）
            if not usable and not json_cols:
                continue
            # 逐列构造「空值」条件：
            #   - 所有列都算 NULL / 空串
            #   - JSON 类列额外把 '[]' 也算作缺（真库里 evidence_refs_json 有 DEFAULT '[]'，
            #     不能因为"有默认值"就跳过检查，否则空引用会被漏掉）
            json_cols = [c for c in _JSON_EMPTY_COLS if c in available]
            conds: list[str] = []
            for c in usable:
                conds.append(f'("{c}" IS NULL OR "{c}"=\'\')')
            for c in json_cols:
                if c not in usable:
                    conds.append(f"(\"{c}\" IS NULL OR \"{c}\" IN ('[]', ''))")
                else:
                    conds.append(f"\"{c}\"='[]'")
            where = " OR ".join(conds)

            # 检查的列 = 规则列 + JSON 列（去重保序）
            check_cols = list(dict.fromkeys([*usable, *json_cols]))
            id_col = "id" if "id" in available else "rowid"
            tail = f" LIMIT {int(limit)}" if limit and limit > 0 else ""
            try:
                rows = cur.execute(
                    f'SELECT {id_col}, {", ".join(check_cols)} FROM "{table}" WHERE {where}{tail}'  # noqa: S608 -- 标识符取自 PRAGMA/schema，值全走参数绑定（limit 已 int() 强转）
                ).fetchall()
            except sqlite3.Error:
                continue
            if rows:
                bad: list[tuple] = []
                seen: set[tuple] = set()
                for r in rows:
                    for i, c in enumerate(check_cols, start=1):
                        v = r[i]
                        if v is None or v == "" or (c in json_cols and v == "[]"):
                            key = (r[0], c)
                            if key not in seen:  # 同一行同一列只报一次
                                seen.add(key)
                                bad.append(key)
                if bad:
                    problems[table] = bad

        total = sum(len(v) for v in problems.values())
        if total == 0:
            self._log("[store_kit] ✓ 完整性自检通过（0 处空关键字段）")
        else:
            for table, bad in problems.items():
                self._log(f"[store_kit] ✗ {table} 有 {len(bad)} 处空关键字段：")
                for rid, col in bad[:10]:
                    self._log(f"          {rid} → {col} 为空")
            if raise_on_fail:
                raise SchemaError(f"完整性自检失败：{problems}")
        return problems

    # ------------------------------------------------------------ 便捷查询

    def scalar(self, sql: str, params: Sequence[Any] = ()) -> Any:
        row = self.cur.execute(sql, params).fetchone()
        return row[0] if row else None

    def counts(self, tables: Sequence[str]) -> dict[str, int]:
        out = {}
        for t in tables:
            try:
                out[t] = self.scalar(f'SELECT COUNT(*) FROM "{t}"') or 0  # noqa: S608 -- 表名来自调用方传入的固定表列表
            except sqlite3.Error:
                out[t] = -1
        return out

    def report_counts(self, tables: Sequence[str]) -> None:
        self._log("=== 落库计数 ===")
        for t, n in self.counts(tables).items():
            self._log(f"  {t:28s} {n:5d}")

    # ------------------------------------------------------------ 内部

    def _brief(self, table: str, rec: dict) -> str:
        for k in ("id", "item_key", "title", "canonical_url", "path", "asset_value"):
            if k in rec and rec[k]:
                return str(rec[k])[:70]
        first = next(iter(rec.items()), ("?", "?"))
        return f"{first[0]}={str(first[1])[:50]}"


# ---------------------------------------------------------------- 模块级便捷函数


def check_integrity(target_or_path: str | Path, *, rules: dict[str, tuple[str, ...]] | None = None) -> dict[str, list[tuple]]:
    """对已存在的库做一次性完整性检查（只读）。"""
    p = Path(target_or_path)
    if not p.is_file():
        found = find_db_or_none(str(target_or_path))
        if found is None:
            raise FileNotFoundError(f"找不到 DB：{target_or_path}")
        p = found
    with StoreKit(db_path=p) as db:
        return db.check_integrity(rules=rules)


if __name__ == "__main__":
    # CLI：python lib/store_kit.py <target|db_path> [--counts]
    import argparse

    ap = argparse.ArgumentParser(description="落库完整性自检")
    ap.add_argument("target", help="target_name 或 db 文件路径")
    ap.add_argument("--counts", action="store_true", help="同时打印各表计数")
    args = ap.parse_args()

    path = Path(args.target)
    if not path.is_file():
        path = find_db(args.target) if find_db_or_none(args.target) else Path(args.target)

    with StoreKit(db_path=path) as db:
        print(f"DB: {db.db_path}")
        if args.counts:
            db.report_counts(
                [
                    "target_assets",
                    "endpoint_observations",
                    "js_files",
                    "js_signals",
                    "js_signal_clusters",
                    "coverage_ledger",
                    "evidence_refs",
                    "suspicious_points",
                    "operator_inbox",
                    "recon_sources",
                ]
            )
        problems = db.check_integrity()
        sys.exit(1 if problems else 0)
