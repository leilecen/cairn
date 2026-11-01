"""经验库写读入口:capture / list / search / bump / effect。

经验库表(experience_entries)沉淀 harvest 灵感得来结构化知识,可跨 session/目标复用。
harvest 一个灵感时将其经验写入本表(source_inspiration_id 溯源),之后按 category /
target / trigger_signal 检索复用。写操作走 db_utils.connect,list/search 只读。

用法见 --help。
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
from pathlib import Path
from typing import Any, Optional

_TOOLS_DIR = Path(__file__).resolve().parent.parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

from db.db_utils import connect, force_utf8_stdout  # noqa: E402

VALID_EFFECTIVENESS = ("untested", "validated", "mixed", "invalid")


def _get_conn(target: str, db: str):
    path = Path(db)
    if not path.is_file():
        raise ValueError(f"database file not found: {path}")
    conn = connect(path)
    if conn.execute("SELECT 1 FROM targets WHERE target_name=? LIMIT 1", (target,)).fetchone() is None:
        conn.close()
        raise ValueError("target is not present in the explicit database")
    return conn


def _now() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def capture(
    conn,
    category: str,
    title: str,
    body: str,
    *,
    target_name: Optional[str] = None,
    trigger_signal: str = "",
    source_inspiration_id: Optional[int] = None,
    notes: str = "",
) -> int:
    """写入一条经验,返回新 id。effectiveness 默认 'untested'。"""
    if not category or not title or not body:
        raise ValueError("category/title/body 都是必填项")
    cur = conn.execute(
        """INSERT INTO experience_entries(target_name, category, title, body, trigger_signal,
             source_inspiration_id, effectiveness, notes)
           VALUES(?,?,?,?,?,?,?,?)""",
        (target_name, category, title, body, trigger_signal or None, source_inspiration_id, "untested", notes or None),
    )
    conn.commit()
    return int(cur.lastrowid)


def list_entries(conn, *, target: str = "", category: str = "") -> list[dict[str, Any]]:
    """按 target / category 过滤;两者都可传空。都不传时要求至少一个条件,否则返回空。"""
    if not target and not category:
        return []
    q = "SELECT * FROM experience_entries WHERE 1=1"
    args: list[Any] = []
    if target:
        q += " AND target_name=?"
        args.append(target)
    if category:
        q += " AND category=?"
        args.append(category)
    q += " ORDER BY id DESC"
    return [dict(r) for r in conn.execute(q, args).fetchall()]


def search(conn, *, query: str = "") -> list[dict[str, Any]]:
    """LIKE 匹配 title/body/trigger_signal/category。query 为空时返回全量。"""
    q = "SELECT * FROM experience_entries WHERE 1=1"
    args: list[Any] = []
    if query:
        like = f"%{query}%"
        q += " AND (title LIKE ? OR body LIKE ? OR trigger_signal LIKE ? OR category LIKE ?)"
        args += [like, like, like, like]
    q += " ORDER BY id DESC"
    return [dict(r) for r in conn.execute(q, args).fetchall()]


def bump_reuse(conn, entry_id: int) -> None:
    """经验被复用时 reuse_count +1。"""
    conn.execute(
        "UPDATE experience_entries SET reuse_count = reuse_count + 1, updated_at=? WHERE id=?",
        (_now(), entry_id),
    )
    conn.commit()


def _require_active_l3_work_item(conn, *, target_name: str, work_item_id: int):
    """Require the exact focused L3 planning context before experience reuse."""
    item = conn.execute(
        "SELECT id,target_name,system_id FROM work_items WHERE id=? AND target_name=?",
        (work_item_id, target_name),
    ).fetchone()
    if item is None or item["system_id"] is None:
        raise PermissionError("a target-bound L3 work item is required")
    focus = conn.execute(
        """SELECT 1 FROM hunt_sessions WHERE target_name=? AND system_id=?
           AND status='active' AND operator_acknowledged_at IS NOT NULL LIMIT 1""",
        (target_name, item["system_id"]),
    ).fetchone()
    if focus is None:
        raise PermissionError("an operator-acknowledged active focus is required")
    return item


def _require_terminal_evidence_result(conn, *, target_name: str, work_item_id: int) -> None:
    """Require an evidence-backed terminal result before learning from L3 reuse."""
    item = _require_active_l3_work_item(conn, target_name=target_name, work_item_id=work_item_id)
    if item["id"] is None:
        raise ValueError("L3 work item is required")
    status = conn.execute("SELECT status FROM work_items WHERE id=?", (work_item_id,)).fetchone()
    if status is None or status["status"] not in {"done", "blocked"}:
        raise ValueError("experience effectiveness requires a terminal L3 work item")
    latest = conn.execute(
        "SELECT payload_json FROM agent_events WHERE work_item_id=? ORDER BY id DESC LIMIT 1",
        (work_item_id,),
    ).fetchone()
    try:
        worker_result = json.loads(latest["payload_json"]).get("worker_result", {}) if latest else {}
    except (TypeError, json.JSONDecodeError):
        worker_result = {}
    if not isinstance(worker_result, dict) or not worker_result.get("evidence_refs"):
        raise ValueError("experience effectiveness requires evidence_refs from the terminal result")


def set_effectiveness_for_l3(
    conn,
    *,
    target_name: str,
    work_item_id: int,
    entry_id: int,
    effectiveness: str,
) -> None:
    """Record effectiveness only after a focused, evidence-backed L3 outcome."""
    if effectiveness not in VALID_EFFECTIVENESS:
        raise ValueError(f"invalid effectiveness: {effectiveness}")
    _require_terminal_evidence_result(conn, target_name=target_name, work_item_id=work_item_id)
    entry = conn.execute(
        "SELECT id FROM experience_entries WHERE id=? AND (target_name=? OR target_name IS NULL)",
        (entry_id, target_name),
    ).fetchone()
    if entry is None:
        raise ValueError("experience entry is unavailable for this target")
    conn.execute(
        "UPDATE experience_entries SET effectiveness=?, updated_at=? WHERE id=?",
        (effectiveness, _now(), entry_id),
    )
    conn.commit()


def l3_candidates(
    conn,
    *,
    target_name: str,
    work_item_id: int,
    trigger: str = "",
    category: str = "",
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Read a compact, explicit reuse shortlist; never writes during L0/L1."""
    _require_active_l3_work_item(conn, target_name=target_name, work_item_id=work_item_id)
    if not trigger and not category:
        raise ValueError("trigger or category is required for L3 experience lookup")
    limit = max(1, min(int(limit), 20))
    clauses = ["(target_name=? OR target_name IS NULL)"]
    params: list[Any] = [target_name]
    if category:
        clauses.append("category=?")
        params.append(category)
    if trigger:
        clauses.append("(trigger_signal LIKE ? OR title LIKE ?)")
        like = f"%{trigger[:160]}%"
        params.extend([like, like])
    query = (  # noqa: S608 - clauses are static predicates; values use SQLite parameters.
        "SELECT id,category,title,trigger_signal,effectiveness,reuse_count,source_inspiration_id "
        "FROM experience_entries WHERE " + " AND ".join(clauses) + " ORDER BY reuse_count DESC,id DESC LIMIT ?"
    )
    rows = conn.execute(
        query,
        [*params, limit],
    ).fetchall()
    return [dict(row) for row in rows]


def adopt_for_l3(conn, *, target_name: str, work_item_id: int, experience_id: int) -> None:
    """Record a main-session explicit reuse decision for the active focused system."""
    _require_active_l3_work_item(conn, target_name=target_name, work_item_id=work_item_id)
    entry = conn.execute(
        "SELECT id FROM experience_entries WHERE id=? AND (target_name=? OR target_name IS NULL)",
        (experience_id, target_name),
    ).fetchone()
    if entry is None:
        raise ValueError("experience entry is unavailable for this target")
    bump_reuse(conn, experience_id)


def harvest_insight(
    conn,
    *,
    target_name: str,
    insight_id: int,
    category: str,
    title: str,
    body: str,
    trigger_signal: str = "",
    notes: str = "",
) -> dict[str, int]:
    """Atomically turn one settled insight into a traceable experience entry.

    This is deliberately an operator-only CLI operation.  L0/L1 and workers
    do not invoke it; a pending insight cannot affect the experience corpus.
    """
    insight = conn.execute(
        "SELECT id,status FROM inspirations WHERE id=? AND target_name=?",
        (insight_id, target_name),
    ).fetchone()
    if insight is None:
        raise ValueError("insight does not belong to target")
    if insight["status"] not in {"verified", "refuted"}:
        raise ValueError("only verified or refuted insights may be harvested")
    conn.execute("SAVEPOINT harvest_insight")
    try:
        cur = conn.execute(
            """INSERT INTO experience_entries(target_name, category, title, body, trigger_signal,
                 source_inspiration_id, effectiveness, notes)
               VALUES(?,?,?,?,?,?, 'untested',?)""",
            (target_name, category, title, body, trigger_signal or None, insight_id, notes or None),
        )
        experience_id = int(cur.lastrowid)
        updated = conn.execute(
            """UPDATE inspirations
               SET status='harvested', harvest_id=?, harvest_note=COALESCE(?, harvest_note), updated_at=?
               WHERE id=? AND target_name=? AND status IN ('verified','refuted')""",
            (f"experience_entry:{experience_id}", notes or None, _now(), insight_id, target_name),
        )
        if updated.rowcount != 1:
            raise ValueError("insight changed before harvest could complete")
        conn.execute("RELEASE SAVEPOINT harvest_insight")
        conn.commit()
    except Exception:
        conn.execute("ROLLBACK TO SAVEPOINT harvest_insight")
        conn.execute("RELEASE SAVEPOINT harvest_insight")
        conn.rollback()
        raise
    return {"experience_id": experience_id, "insight_id": insight_id}


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="经验库写读入口")
    p.add_argument("--target", required=True, help="显式 target_name")
    p.add_argument("--db", required=True, help="显式 target SQLite DB")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("capture", help="写入一条经验")
    c.add_argument("--category", required=True)
    c.add_argument("--title", required=True)
    c.add_argument("--body", required=True)
    c.add_argument("--trigger-signal", default="")
    c.add_argument("--source-inspiration-id", type=int)
    c.add_argument("--notes", default="")

    l = sub.add_parser("list", help="按 target/category 过滤查看(至少一个条件)")  # noqa: E741
    l.add_argument("--category", default="")

    s = sub.add_parser("search", help="按关键词 LIKE 检索 title/body/signal/category")
    s.add_argument("--query", default="")
    s.add_argument("--work-item-id", type=int, required=True)
    s.add_argument("--category", default="")
    s.add_argument("--limit", type=int, default=10)

    b = sub.add_parser("bump", help="经验复用计数 +1")
    b.add_argument("--id", dest="entry_id", required=True, type=int)
    b.add_argument("--work-item-id", type=int, required=True)

    e = sub.add_parser("effect", help="设置经验有效性")
    e.add_argument("--id", dest="entry_id", required=True, type=int)
    e.add_argument("--effectiveness", required=True, choices=VALID_EFFECTIVENESS)
    e.add_argument("--work-item-id", type=int, required=True)

    h = sub.add_parser("harvest", help="操作员确认后原子收割一条已结论灵感")
    h.add_argument("--insight-id", required=True, type=int)
    h.add_argument("--category", required=True)
    h.add_argument("--title", required=True)
    h.add_argument("--body", required=True)
    h.add_argument("--trigger-signal", default="")
    h.add_argument("--notes", default="")
    return p


def main() -> int:
    force_utf8_stdout()
    args = _build_parser().parse_args()
    conn = _get_conn(args.target, args.db)
    try:
        if args.cmd == "capture":
            eid = capture(
                conn,
                args.category,
                args.title,
                args.body,
                target_name=args.target,
                trigger_signal=args.trigger_signal,
                source_inspiration_id=args.source_inspiration_id,
                notes=args.notes,
            )
            print(json.dumps({"id": eid, "category": args.category}, ensure_ascii=False))
        elif args.cmd == "list":
            rows = list_entries(conn, target=args.target, category=args.category)
            print(json.dumps(rows, ensure_ascii=False, indent=2))
        elif args.cmd == "search":
            rows = l3_candidates(
                conn,
                target_name=args.target,
                work_item_id=args.work_item_id,
                trigger=args.query,
                category=args.category,
                limit=args.limit,
            )
            print(json.dumps(rows, ensure_ascii=False, indent=2))
        elif args.cmd == "bump":
            adopt_for_l3(conn, target_name=args.target, work_item_id=args.work_item_id, experience_id=args.entry_id)
            print(json.dumps({"id": args.entry_id, "reuse": "bumped"}, ensure_ascii=False))
        elif args.cmd == "harvest":
            result = harvest_insight(
                conn,
                target_name=args.target,
                insight_id=args.insight_id,
                category=args.category,
                title=args.title,
                body=args.body,
                trigger_signal=args.trigger_signal,
                notes=args.notes,
            )
            print(json.dumps(result, ensure_ascii=False))
        else:
            set_effectiveness_for_l3(
                conn,
                target_name=args.target,
                work_item_id=args.work_item_id,
                entry_id=args.entry_id,
                effectiveness=args.effectiveness,
            )
            print(json.dumps({"id": args.entry_id, "effectiveness": args.effectiveness}, ensure_ascii=False))
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
