"""单目标 DB 管理入口。

用法:
  uv run python TOOLS/db/db_admin.py --target "example-client" status
  uv run python TOOLS/db/db_admin.py --file dbs/<target>_YYYY-MM-DD.db migrate
  uv run python TOOLS/db/db_admin.py --target "example-client" rebuild
  uv run python TOOLS/db/db_admin.py --target "example-client" verify

目标必须显式指定；本脚本不读取 SRC_TARGET 或其他环境变量。
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(TOOLS_DIR))

from db.db_query import init_db  # noqa: E402
from db.db_utils import find_db, force_utf8_stdout, session  # noqa: E402
from db.migrate import do_migrate, do_status  # noqa: E402
from db.rebuild_target_db import rebuild  # noqa: E402

_SAFE_SLUG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")


def init_target_db(*, target_name: str, slug: str, domain: str = "", db_dir: Path | None = None) -> dict:
    """Create or reuse one explicit target DB without network/runtime rows."""
    if not target_name or not str(target_name).strip():
        raise ValueError("target is required")
    if not _SAFE_SLUG.fullmatch(slug or "") or slug in {".", ".."}:
        raise ValueError("slug must be ASCII and path-safe")
    root = Path(db_dir) if db_dir is not None else Path(__file__).resolve().parent.parent.parent / "dbs"
    root.mkdir(parents=True, exist_ok=True)
    path = (root / f"{slug}.db").resolve()
    if path.parent != root.resolve():
        raise ValueError("slug must stay inside db directory")
    is_new_db = not path.exists()
    init_db(str(path), target_name, domain)
    if domain and is_new_db:
        # Supplying a root domain to the explicit init command is the operator's
        # scope declaration for this target. Keep that provenance on the
        # asset itself so L0 baseline has one auditable, authorized seed and
        # never needs to infer scope from an environment default.
        with session(path) as conn:
            conn.execute(
                """INSERT INTO target_assets(
                       target_name,asset_type,asset_value,protocol,
                       scope_status,scope_class,authorization_state,scope_reason
                   ) VALUES(?, 'domain', ?, 'https', 'in_scope', 'owned', 'explicit_init', 'explicit_init_domain')
                   ON CONFLICT(target_name, asset_value, COALESCE(port, 443)) DO NOTHING""",
                (target_name, domain),
            )
            conn.commit()
    return {"init": "ok", "db_path": str(path), "target": target_name}


def _path(args: argparse.Namespace) -> Path:
    if bool(args.target) == bool(args.file):
        raise SystemExit("必须且只能指定 --target 或 --file")
    path = Path(args.file) if args.file else find_db(args.target)
    if not path.is_file():
        raise SystemExit(f"DB 文件不存在: {path}")
    return path


def verify(path: Path, target: str | None) -> dict:
    with session(path) as conn:
        row = conn.execute("SELECT MAX(version) AS version FROM schema_version").fetchone()
        actual_target = target or conn.execute("SELECT target_name FROM targets ORDER BY id LIMIT 1").fetchone()[0]
        required = {
            name: conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone()[0]
            for name in (
                "recon_sources",
                "recon_runs",
                "cdn_observations",
                "system_type_observations",
                "endpoint_observations",
                "page_asset_links",
                "js_asset_links",
                "asset_relationships",
                "preauth_probe_runs",
                # migration 035: 业务状态机 4 张表（逻辑漏洞按图索骥）
                "business_flows",
                "business_flow_steps",
                "business_flow_progress",
                "business_flow_templates",
            )
        }
        scope = conn.execute(
            "SELECT scope_status, COUNT(*) AS n FROM target_assets WHERE target_name=? GROUP BY scope_status",
            (actual_target,),
        ).fetchall()
        scope_class = conn.execute(
            "SELECT scope_class, COUNT(*) AS n FROM target_assets WHERE target_name=? GROUP BY scope_class",
            (actual_target,),
        ).fetchall()
        resolution = conn.execute(
            """SELECT resolution_status, scope_class, COUNT(*) AS n
               FROM endpoint_observations
               WHERE target_name=?
               GROUP BY resolution_status, scope_class""",
            (actual_target,),
        ).fetchall()
        return {
            "db": str(path),
            "target": actual_target,
            "schema_version": row["version"] if row else 0,
            "required_tables": required,
            "scope": {r["scope_status"]: r["n"] for r in scope},
            "scope_class": {r["scope_class"]: r["n"] for r in scope_class},
            "endpoint_resolution": [dict(r) for r in resolution],
            "endpoint_observations": conn.execute(
                "SELECT COUNT(*) FROM endpoint_observations WHERE target_name=?", (actual_target,)
            ).fetchone()[0],
        }


def main() -> int:
    force_utf8_stdout()
    parser = argparse.ArgumentParser(description="单目标 DB 管理")
    parser.add_argument("--target", help="显式 target_name")
    parser.add_argument("--file", help="显式 DB 路径")
    parser.add_argument("command", choices=("status", "migrate", "rebuild", "verify", "init"))
    parser.add_argument("--slug", help="init 专用 ASCII 文件名 slug")
    parser.add_argument("--domain", default="", help="init 专用根域")
    args = parser.parse_args()
    try:
        if args.command == "init":
            if not args.target or args.file:
                raise SystemExit("init 必须且只能指定 --target")
            if not args.slug:
                raise SystemExit("init 必须指定 --slug")
            result = init_target_db(target_name=args.target, slug=args.slug, domain=args.domain)
            print(json.dumps(result, ensure_ascii=False))
            return 0
        path = _path(args)
        if args.command == "status":
            result = do_status(str(path))
        elif args.command == "migrate":
            result = do_migrate(str(path))
        elif args.command == "rebuild":
            with session(path) as conn:
                target = args.target or conn.execute("SELECT target_name FROM targets ORDER BY id LIMIT 1").fetchone()[0]
                result = rebuild(conn, target)
        else:
            result = verify(path, args.target)
    except SystemExit as exc:
        result = {"error": str(exc.code)}
    except Exception as exc:
        result = {"error": str(exc)}
    print(json.dumps(result, ensure_ascii=False, default=str, indent=2))
    return 1 if "error" in result else 0


if __name__ == "__main__":
    raise SystemExit(main())
