"""共享 DB helper — 所有 TOOLS pipeline 脚本统一导入，消除复制粘贴。

DB 文件命名约定（唯一规范）：`dbs/{slug}.db`，slug 由 safe_db_stem(target) 生成。
同时兼容历史遗留的 `dbs/{slug}_{YYYY-MM-DD}.db` 与中文名文件，由 find_db 统一解析。
"""

import contextlib
import hashlib
import re
import sqlite3
import sys
from pathlib import Path
from typing import Iterator


def force_utf8_stdout() -> None:
    """Make CLI text output deterministic UTF-8 on Windows and redirected pipes."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace", newline="\n")  # type: ignore[union-attr]  # 非常规流可能没有 reconfigure，外层已 catch AttributeError
        except (AttributeError, TypeError, ValueError):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]  # 非常规流可能没有 reconfigure，外层已 catch AttributeError
            except (AttributeError, TypeError, ValueError):
                pass


# db/ → TOOLS/ → SRC/
_TOOLS_DIR = Path(__file__).resolve().parent.parent
_PROJECT_ROOT = _TOOLS_DIR.parent
DBS_DIR = _PROJECT_ROOT / "dbs"


def safe_db_stem(target: str) -> str:
    """Return an ASCII-only stable filename stem for a target display name."""
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", str(target)).strip(".-")
    if slug:
        return slug[:80]
    digest = hashlib.sha256(str(target).encode("utf-8")).hexdigest()[:12]
    return f"target-{digest}"


def target_db_path(target: str, db_dir: Path | str | None = None) -> Path:
    """规范 DB 路径：dbs/{safe_db_stem(target)}.db。

    init 场景必须走这里，禁止各脚本自行拼文件名——两套命名约定会产生重复库。
    """
    root = Path(db_dir) if db_dir is not None else DBS_DIR
    return root / f"{safe_db_stem(target)}.db"


def connect(db_path: "Path | str") -> sqlite3.Connection:
    """打开 SQLite 连接，启用 WAL + busy_timeout + row_factory。"""
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.row_factory = sqlite3.Row
    return conn


@contextlib.contextmanager
def session(db_path: "Path | str", *, read_only: bool = False) -> Iterator[sqlite3.Connection]:
    """读写会话，退出时必定关闭连接。

    必须用这个而不是 `with sqlite3.connect(...)`：后者只提交/回滚事务，不关闭连接，
    会泄漏文件句柄并长期占住 WAL 的 -shm/-wal。
    """
    if read_only:
        conn = sqlite3.connect(f"file:{Path(db_path).as_posix()}?mode=ro", uri=True, timeout=5)
        conn.row_factory = sqlite3.Row
    else:
        conn = connect(db_path)
    try:
        yield conn
    finally:
        conn.close()


def _newest(paths: list[Path]) -> Path | None:
    existing = [p for p in paths if p.is_file()]
    if not existing:
        return None
    return max(existing, key=lambda p: p.stat().st_mtime)


def find_db_or_none(target: str, *, db_dir: Path | str | None = None) -> Path | None:
    """按显式目标名解析 DB，找不到返回 None。不读取环境变量，也不猜测其他目标。

    解析优先级（同级按 mtime 取最新）：
      1. dbs/{slug}.db              — 唯一规范形式
      2. dbs/{slug}_*.db            — 历史日期后缀形式
      3. dbs/{原始目标名}_*.db       — 历史中文文件名形式
      4. 全目录扫描 targets.target_name 精确匹配（只读打开，显式关闭）
    """
    root = Path(db_dir) if db_dir is not None else DBS_DIR
    if not root.is_dir():
        return None
    stem = safe_db_stem(target)

    direct = [root / f"{stem}.db", *root.glob(f"{stem}_*.db"), *root.glob(f"{target}_*.db")]
    hit = _newest(direct)
    if hit:
        return hit

    # 元数据回退：只按 targets.target_name 精确匹配。
    for candidate in sorted(root.glob("*.db"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            with session(candidate, read_only=True) as conn:
                row = conn.execute("SELECT 1 FROM targets WHERE target_name=? LIMIT 1", (target,)).fetchone()
        except sqlite3.Error:
            continue
        if row:
            return candidate
    return None


def find_db(target: str) -> Path:
    """按显式目标名返回 DB；找不到时终止进程。"""
    path = find_db_or_none(target)
    if path is None:
        sys.exit(f"[error] 找不到目标 DB: {target}；请显式 --target 或 --file")
    return path


def list_target_dbs(db_dir: Path | str | None = None) -> list[dict]:
    """列出 dbs/ 下所有目标库摘要，供 --list 使用。

    只读打开，失败不抛异常。返回按文件名排序的列表。
    """
    root = Path(db_dir) if db_dir is not None else DBS_DIR
    out: list[dict] = []
    if not root.is_dir():
        return out
    for db in sorted(root.glob("*.db")):
        rec: dict = {"db": db.name, "path": db, "size_kb": db.stat().st_size // 1024, "target": "", "schema": 0}
        try:
            with session(db, read_only=True) as conn:
                has = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='targets'").fetchone()
                if has:
                    rows = conn.execute("SELECT DISTINCT target_name FROM targets WHERE target_name IS NOT NULL ORDER BY 1").fetchall()
                    rec["target"] = ", ".join(r[0] for r in rows)
                sv = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_version'").fetchone()
                if sv:
                    rec["schema"] = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0] or 0
        except sqlite3.Error as exc:
            rec["error"] = str(exc)
        out.append(rec)
    return out
