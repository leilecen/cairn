"""One main-session blackboard scheduling tick."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any

_TOOLS_DIR = Path(__file__).resolve().parent.parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

from db.blackboard_seed import apply_seed  # noqa: E402
from db.blackboard_view import build_blackboard_view, format_blackboard_text  # noqa: E402
from db.db_utils import connect, find_db  # noqa: E402
from db.work_queue import reclaim_expired  # noqa: E402


def run_blackboard_tick(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    seed: bool = True,
    reclaim: bool = True,
) -> dict[str, Any]:
    seed_summary = apply_seed(conn, target_name=target_name, dry_run=False) if seed else None
    reclaim_summary = reclaim_expired(conn) if reclaim else None
    view = build_blackboard_view(conn, target_name=target_name)
    return {
        "target": target_name,
        "seed": seed_summary,
        "reclaim": reclaim_summary,
        "view": view,
    }


def _resolve_db_path(args: argparse.Namespace) -> Path:
    if args.db:
        return Path(args.db)
    return find_db(args.target)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run one main-session blackboard scheduling tick")
    parser.add_argument("--target", required=True, help="target_name in the DB")
    parser.add_argument("--db", help="explicit DB path")
    parser.add_argument("--no-seed", action="store_true", help="skip candidate seeding")
    parser.add_argument("--no-reclaim", action="store_true", help="skip expired work item reclaim")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    conn = connect(_resolve_db_path(args))
    try:
        payload = run_blackboard_tick(
            conn,
            target_name=args.target,
            seed=not args.no_seed,
            reclaim=not args.no_reclaim,
        )
    finally:
        conn.close()

    if args.json:
        print(json.dumps(payload, ensure_ascii=False))
    else:
        seed_summary = payload["seed"]
        reclaim_summary = payload["reclaim"]
        if seed_summary is not None:
            print(f"[SEED] created={seed_summary['created']} skipped_existing={seed_summary['skipped_existing']}")
        if reclaim_summary is not None:
            print(
                "[RECLAIM] "
                f"requeued={reclaim_summary['requeued']} "
                f"partial_released={reclaim_summary['partial_released']} "
                f"total={reclaim_summary['total']}"
            )
        print("")
        print(format_blackboard_text(payload["view"]))


if __name__ == "__main__":
    main()
