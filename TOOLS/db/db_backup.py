"""SQLite DB 安全备份，支持 WAL 模式。

用法:
  python3 TOOLS/db_backup.py --target "example-client"            # 备份指定目标
  python3 TOOLS/db_backup.py --list                           # 列出已有备份
  python3 TOOLS/db_backup.py --list --target "example-client"     # 列出指定目标的备份
"""

import argparse
import json
import sqlite3
import subprocess
import sys
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent  # db/ → TOOLS/ → SRC/
DBS_DIR = PROJECT_ROOT / "dbs"
DEFAULT_BACKUP_DIR = DBS_DIR / ".backups"

_TOOLS_DIR = Path(__file__).resolve().parent.parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))
from db.db_utils import find_db_or_none, session  # noqa: E402


def find_all_dbs() -> list[Path]:
    return sorted(DBS_DIR.glob("*.db"), key=lambda p: p.stat().st_mtime, reverse=True)


def find_target_db(target: str) -> Path | None:
    """目标解析统一走 db_utils（规范 dbs/{slug}.db + 历史命名兼容）。"""
    return find_db_or_none(target, db_dir=DBS_DIR)


def sqlite3_backup(src: Path, dst: Path) -> bool:
    """使用 sqlite3 .backup 命令安全备份 WAL 模式 DB。"""
    dst.parent.mkdir(parents=True, exist_ok=True)
    try:
        result = subprocess.run(
            ["sqlite3", str(src), f".backup '{dst}'"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0 and _valid_backup(dst):
            return True
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return _python_backup(src, dst)


def _valid_backup(path: Path) -> bool:
    if not path.is_file() or path.stat().st_size == 0:
        return False
    try:
        with path.open("rb") as handle:
            if handle.read(16) != b"SQLite format 3\x00":
                return False
        with session(path, read_only=True) as conn:
            return conn.execute("PRAGMA quick_check").fetchone()[0] == "ok"
    except (OSError, sqlite3.Error):
        return False


def _python_backup(src: Path, dst: Path) -> bool:
    """使用 SQLite backup API 降级；包含 WAL 已提交页，不做裸文件拷贝。"""
    try:
        if dst.exists():
            dst.unlink()
        with session(src, read_only=True) as source:
            with session(dst) as destination:
                source.backup(destination)
        if _valid_backup(dst):
            return True
    except (OSError, sqlite3.Error):
        pass
    try:
        if dst.exists():
            dst.unlink()
    except OSError:
        pass
    return False


def list_backups(backup_dir: Path, target: str | None = None) -> list[dict]:
    if not backup_dir.exists():
        return []

    backups = []
    for f in sorted(backup_dir.glob("*.db"), key=lambda p: p.stat().st_mtime, reverse=True):
        name = f.stem
        if target and not name.startswith(target):
            continue
        stat = f.stat()
        backups.append(
            {
                "file": str(f.relative_to(PROJECT_ROOT)),
                "size_kb": round(stat.st_size / 1024, 1),
                "time": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
            }
        )
    return backups


def rotate_backups(backup_dir: Path, target: str, keep: int) -> int:
    """保留最近 keep 份，删除旧的。返回删除数量。"""
    existing = sorted(backup_dir.glob(f"{target}_*.db"), key=lambda p: p.stat().st_mtime, reverse=True)
    removed = 0
    for f in existing[keep:]:
        try:
            f.unlink()
            removed += 1
        except OSError:
            pass
    return removed


def backup_one(db_path: Path, backup_dir: Path, keep: int) -> dict:
    target_name = db_path.stem.rsplit("_", 1)[0]
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    dst = backup_dir / f"{target_name}_{ts}.db"

    ok = sqlite3_backup(db_path, dst)
    if not ok:
        return {"db": str(db_path.name), "status": "failed", "reason": "备份写入失败"}

    stat = dst.stat()
    removed = rotate_backups(backup_dir, target_name, keep)

    return {
        "db": str(db_path.name),
        "status": "ok",
        "backup": str(dst.relative_to(PROJECT_ROOT)),
        "size_kb": round(stat.st_size / 1024, 1),
        "rotated": removed,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="SQLite DB 备份")
    parser.add_argument("--target", help="显式目标名称")
    parser.add_argument("--all", action="store_true", help="已废弃：当前工作区只允许显式备份一个目标")
    parser.add_argument("--list", action="store_true", help="列出已有备份")
    parser.add_argument("--backup-dir", default=str(DEFAULT_BACKUP_DIR), help="备份目录")
    parser.add_argument("--keep", type=int, default=5, help="每 DB 保留最近 N 份备份 (默认 5)")
    args = parser.parse_args()

    backup_dir = Path(args.backup_dir)
    if not backup_dir.is_absolute():
        backup_dir = PROJECT_ROOT / backup_dir

    if args.list:
        backups = list_backups(backup_dir, args.target)
        if not backups:
            print(json.dumps({"msg": "无备份记录"}, ensure_ascii=False))
        else:
            print(json.dumps({"backups": backups}, ensure_ascii=False, indent=2))
        return 0

    if args.target:
        db_path = find_target_db(args.target)
        if db_path is None:
            print(json.dumps({"error": f"未找到目标 DB: {args.target}"}, ensure_ascii=False))
            sys.exit(1)
        dbs = [db_path]
    elif args.all:
        print(json.dumps({"error": "--all 已禁用；请使用 --target 显式指定一个目标"}, ensure_ascii=False))
        sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)

    results = []
    for db_path in dbs:
        result = backup_one(db_path, backup_dir, args.keep)
        results.append(result)
        status = "OK" if result["status"] == "ok" else "FAIL"
        print(f"[{status}] {result['db']} → {result.get('backup', result.get('reason', ''))}", file=sys.stderr)

    ok_count = sum(1 for r in results if r["status"] == "ok")
    summary = {
        "backed_up": ok_count,
        "failed": len(results) - ok_count,
        "backup_dir": str(backup_dir),
        "results": results,
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
