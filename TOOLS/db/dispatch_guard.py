"""Guard main-session stops while dispatchable worker work is queued."""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path
from typing import Any

_TOOLS_DIR = Path(__file__).resolve().parent.parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

from db.db_utils import DBS_DIR, connect, find_db  # noqa: E402
from db.dispatcher import LANE_DISPATCH, build_dispatch_plan  # noqa: E402


def queued_dispatchable_items(conn: sqlite3.Connection, *, target_name: str) -> list[dict[str, Any]]:
    """Return unclaimed, retryable work that must be handed to a worker."""
    if _human_focus_enabled(conn):
        plan = build_dispatch_plan(conn, target_name=target_name, limit=100)
        return [
            {
                "id": item["work_item_id"],
                "lane": item["lane"],
                "title": item.get("title", ""),
                "priority": item.get("priority", 0),
                "status": item.get("status", "queued"),
                "timebox_minutes": item.get("timebox_minutes"),
                "heartbeat_minutes": item.get("heartbeat_minutes"),
            }
            for item in plan.get("tasks", [])
        ]
    lanes = tuple(lane for lane, mapping in LANE_DISPATCH.items() if mapping.get("dispatchable"))
    # Lane names come from the static dispatcher mapping, never from user input.
    placeholders = ", ".join("?" for _ in lanes)
    rows = conn.execute(
        f"""
        SELECT id, lane, title, priority, status, timebox_minutes, heartbeat_minutes
        FROM work_items
        WHERE target_name = ?
          AND status IN ('queued', 'partial')
          AND claimed_by IS NULL
          AND attempt_count < max_attempts
          AND lane IN ({placeholders})
        ORDER BY priority DESC, created_at ASC, id ASC
        """,  # noqa: S608 -- 仅拼接 "?" 占位符；lane 名来自 LANE_DISPATCH 静态映射
        (target_name, *lanes),
    ).fetchall()
    return [dict(row) for row in rows]


def _human_focus_enabled(conn: sqlite3.Connection) -> bool:
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    return {"schema_version", "target_systems", "hunt_sessions"} <= tables and conn.execute(
        "SELECT 1 FROM schema_version WHERE version>=33 LIMIT 1"
    ).fetchone() is not None


def resolve_target(payload: dict[str, Any]) -> str | None:
    for key in ("target", "target_name"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def resolve_database(payload: dict[str, Any]) -> tuple[str, Path] | None:
    """Resolve only an explicit target; never infer a DB from environment or queue state."""
    target_name = resolve_target(payload)
    if target_name:
        try:
            path = find_db(target_name)
        except SystemExit:
            return None
        return target_name, path

    return None


def pending_target_names() -> list[str]:
    """Return target names with any retryable queued worker work."""
    names: set[str] = set()
    lanes = tuple(lane for lane, mapping in LANE_DISPATCH.items() if mapping.get("dispatchable"))
    if len(lanes) != 11:
        raise RuntimeError("dispatch guard lane mapping changed; update its SQL placeholders")
    for path in DBS_DIR.glob("*.db"):
        try:
            conn = connect(path)
            rows = conn.execute(
                """
                SELECT DISTINCT target_name FROM work_items
                WHERE status IN ('queued', 'partial') AND claimed_by IS NULL
                  AND attempt_count < max_attempts
                  AND lane IN (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                lanes,
            ).fetchall()
        except sqlite3.Error:
            continue
        finally:
            try:
                conn.close()
            except UnboundLocalError:
                pass
        names.update(str(row[0]) for row in rows)
    return sorted(names)


def check_payload(payload: dict[str, Any], *, db_path: Path | None = None) -> str | None:
    """Return a blocking reason, or None when the main session may stop."""
    if payload.get("stop_hook_active") is True:
        return None
    if db_path is not None:
        target_name = resolve_target(payload) or ""
        path = db_path
    else:
        resolved = resolve_database(payload)
        if not resolved:
            names = pending_target_names()
            if names:
                shown = ", ".join(names[:5])
                suffix = " …" if len(names) > 5 else ""
                return (
                    "未能结束主 session：检测到 queued/partial subagent 任务，但当前 hook 没有明确目标。"
                    f"请在当前 session 显式传入 --target/target_name（候选: {shown}{suffix}），"
                    "再运行 sprint_tick 并派发 subagent；禁止设置环境变量猜测目标。"
                )
            return None
        target_name, path = resolved
    if not path or not Path(path).exists():
        return None
    conn = connect(path)
    try:
        items = queued_dispatchable_items(conn, target_name=target_name)
    finally:
        conn.close()
    if not items:
        return None
    first = items[0]
    return (
        f"未能结束主 session：目标 {target_name} 仍有 {len(items)} 个可派发 subagent work_item。"
        f" 请先运行 sprint_tick 并按 dispatch_plan 派发 #{first['id']} ({first['lane']})，"
        "或明确处理/取消该任务后再结束。"
    )


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, OSError):
        return 0
    if not isinstance(payload, dict):
        return 0
    reason = check_payload(payload)
    if reason:
        print(reason, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
