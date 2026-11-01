"""灵感写入口(唯一):gleam/refine/add/transit/list。

灵感不是 work_item,无 claim/heartbeat,是轻量落笔记——独立工具、不挂 dispatcher。
「做不下去时反思」:堵点在 system 已记录的阻塞信号(blocked/unknown/中间态)出现时,
由 agent 顺手 gleam 落库,或人复盘 add/refine 补录。经验收割(harvested)纯人工。

用法见 --help;写操作强制 --target,落库走 db_utils.connect。
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
from db.work_queue import create_work_item  # noqa: E402

VALID_STAGE = ("gleam", "clue")
VALID_SOURCE = ("agent", "human", "harvest")
VALID_CONFIDENCE = ("low", "medium", "high")
VALID_STATUS = ("open", "queued", "verified", "refuted", "harvested", "discarded")


def _get_conn(target: str, db: str):
    """Open only the DB the operator explicitly named, never a same-name fallback."""
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


def _parse_blocked_on(value: str) -> tuple[Optional[str], Optional[str]]:
    """'work_item:123' -> ('work_item', '123'); 'suspicious_point:sp-abc' -> ('suspicious_point', 'sp-abc')。

    id 保留原文(str):实体 id 可能是整数(work_item/coverage_ledger)也可能是文本
    (suspicious_point 如 sp-ssrf-001);SQLite INTEGER 亲和列对非数字自动按 TEXT 存,
    故 blocked_on_id 可容纳两者。非法返回 (None, None)。
    """
    if not value:
        return None, None
    if ":" not in value:
        return value.strip(), None
    kind, _, sid = value.partition(":")
    return kind.strip(), sid.strip() or None


def capture_gleam(
    conn,
    target: str,
    content: str,
    *,
    source: str = "human",
    trigger: str = "",
    confidence: str = "low",
    blocked_on: str = "",
    asset_id: Optional[int] = None,
    agent_id: str = "",
    session_id: str = "",
) -> int:
    if source not in VALID_SOURCE:
        raise ValueError(f"invalid source: {source}")
    if confidence not in VALID_CONFIDENCE:
        raise ValueError(f"invalid confidence: {confidence}")
    kind, bid = _parse_blocked_on(blocked_on)
    cur = conn.execute(
        """INSERT INTO inspirations(target_name, stage, content, trigger, source,
             agent_id, session_id, confidence, status, blocked_on_kind, blocked_on_id, asset_id)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            target,
            "gleam",
            content,
            trigger or None,
            source,
            agent_id or None,
            session_id or None,
            confidence,
            "open",
            kind,
            bid,
            asset_id,
        ),
    )
    conn.commit()
    return int(cur.lastrowid)


def refine(conn, target: str, from_id: int, content: str, *, confidence: str = "medium", note: str = "") -> int:
    cur = conn.execute(
        """INSERT INTO inspirations(target_name, stage, content, source, confidence,
             status, refined_from_id, notes)
           SELECT target_name, 'clue', ?, 'human', ?, 'open', ?, ? FROM inspirations WHERE id=? AND target_name=?""",
        (content, confidence, from_id, note or None, from_id, target),
    )
    conn.commit()
    return int(cur.lastrowid)


def add(
    conn,
    target: str,
    content: str,
    *,
    trigger: str = "",
    source: str = "human",
    blocked_on: str = "",
    asset_id: Optional[int] = None,
    confidence: str = "low",
) -> int:
    if source not in VALID_SOURCE:
        raise ValueError(f"invalid source: {source}")
    if confidence not in VALID_CONFIDENCE:
        raise ValueError(f"invalid confidence: {confidence}")
    kind, bid = _parse_blocked_on(blocked_on)
    cur = conn.execute(
        """INSERT INTO inspirations(target_name, stage, content, trigger, source,
             confidence, status, blocked_on_kind, blocked_on_id, asset_id)
           VALUES(?,?,?,?,?,?,?,?,?,?)""",
        (target, "clue", content, trigger or None, source, confidence, "open", kind, bid, asset_id),
    )
    conn.commit()
    return int(cur.lastrowid)


def accept_proposal(
    conn,
    target: str,
    source_work_item_id: int,
    *,
    proposal_index: int = 0,
) -> dict[str, int]:
    """Promote one latest compact worker proposal after every L3 scope check.

    This is intentionally a main-session operation, not a worker callback.  It
    only accepts a proposal from the *latest* event of a same-system work item
    while an operator-acknowledged focus is active.  Validation failure occurs
    before any write; the insight and its safe-passive validation item commit
    together.
    """
    if proposal_index < 0:
        raise ValueError("proposal_index must be non-negative")

    source = conn.execute(
        "SELECT id,target_name,system_id FROM work_items WHERE id=? AND target_name=?",
        (source_work_item_id, target),
    ).fetchone()
    if source is None:
        raise ValueError("source work_item does not belong to target")
    if source["system_id"] is None:
        raise PermissionError("source work_item is not L3 system-bound")

    focus = conn.execute(
        """SELECT system_id FROM hunt_sessions
           WHERE target_name=? AND status='active' AND system_id IS NOT NULL
             AND operator_acknowledged_at IS NOT NULL
           ORDER BY id DESC LIMIT 1""",
        (target,),
    ).fetchone()
    if focus is None:
        raise PermissionError("operator-acknowledged active focus is required")
    system_id = int(focus["system_id"])
    if int(source["system_id"]) != system_id:
        raise PermissionError("source work_item belongs to a different system than active focus")

    event = conn.execute(
        """SELECT agent_id,payload_json FROM agent_events
           WHERE work_item_id=? ORDER BY id DESC LIMIT 1""",
        (source_work_item_id,),
    ).fetchone()
    if event is None:
        raise ValueError("source work_item has no agent event")
    try:
        payload = json.loads(event["payload_json"])
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("latest agent event payload is invalid") from exc
    worker_result = payload.get("worker_result") if isinstance(payload, dict) else None
    proposals = worker_result.get("insight_proposals") if isinstance(worker_result, dict) else None
    if not isinstance(proposals, list) or proposal_index >= len(proposals):
        raise ValueError("latest agent event has no selected insight proposal")
    proposal = proposals[proposal_index]
    if not isinstance(proposal, dict):
        raise ValueError("selected insight proposal is invalid")
    asset_id = proposal.get("asset_id")
    summary = proposal.get("summary")
    if not isinstance(asset_id, int) or asset_id <= 0 or not isinstance(summary, str) or not summary.strip():
        raise ValueError("selected insight proposal lacks a valid asset_id or summary")
    if len(summary) > 320:
        raise ValueError("selected insight proposal summary exceeds compact limit")
    trigger = proposal.get("trigger") or ""
    next_action = proposal.get("next_action") or ""
    if not isinstance(trigger, str) or not isinstance(next_action, str):
        raise ValueError("selected insight proposal text fields are invalid")

    asset = conn.execute(
        """SELECT a.id FROM target_assets a
           JOIN system_asset_links l ON l.asset_id=a.id AND l.target_name=a.target_name
           JOIN target_systems s ON s.id=l.system_id AND s.target_name=l.target_name
           WHERE a.id=? AND a.target_name=? AND l.system_id=?
             AND a.scope_status='in_scope'
             AND a.scope_class IN ('owned','authorized_vendor')
             AND lower(COALESCE(a.authorization_state,'')) IN ('active','authorized','confirmed')
             AND s.scope_class IN ('owned','authorized_vendor')
           LIMIT 1""",
        (asset_id, target, system_id),
    ).fetchone()
    if asset is None:
        raise PermissionError("proposal asset is not linked, in scope, and authorized for active system")

    existing = conn.execute(
        """SELECT id FROM inspirations
           WHERE target_name=? AND blocked_on_kind='work_item' AND blocked_on_id=?
             AND asset_id=? AND content=? LIMIT 1""",
        (target, source_work_item_id, asset_id, summary.strip()),
    ).fetchone()
    if existing is not None:
        raise ValueError("selected insight proposal was already accepted")

    evidence_refs = proposal.get("evidence_refs", [])
    if not isinstance(evidence_refs, list) or any(not isinstance(ref, str) or len(ref) > 160 for ref in evidence_refs):
        raise ValueError("selected insight proposal evidence_refs are invalid")
    notes = json.dumps(
        {"proposal_index": proposal_index, "evidence_refs": evidence_refs[:8]},
        ensure_ascii=False,
        separators=(",", ":"),
    )
    conn.execute("SAVEPOINT accept_insight_proposal")
    try:
        cur = conn.execute(
            """INSERT INTO inspirations(
                target_name,stage,content,trigger,source,agent_id,confidence,status,
                blocked_on_kind,blocked_on_id,asset_id,notes
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                target,
                "clue",
                summary.strip(),
                trigger.strip()[:160] or None,
                "agent",
                event["agent_id"],
                "medium",
                "queued",
                "work_item",
                source_work_item_id,
                asset_id,
                notes,
            ),
        )
        inspiration_id = int(cur.lastrowid)
        validation_work_item_id = create_work_item(
            conn,
            target_name=target,
            system_id=system_id,
            lane="quick_scout",
            subtype="insight_validation",
            subject_table="inspirations",
            subject_id=str(inspiration_id),
            title="Validate accepted insight",
            objective=(next_action.strip()[:240] or summary.strip()),
            priority=55,
            auth_requirement="none",
            risk_class="safe_passive",
            commit=False,
        )
        conn.execute(
            "UPDATE inspirations SET promoted_wi_id=?,updated_at=? WHERE id=? AND target_name=?",
            (validation_work_item_id, _now(), inspiration_id, target),
        )
        conn.execute("RELEASE SAVEPOINT accept_insight_proposal")
        conn.commit()
    except Exception:
        conn.execute("ROLLBACK TO SAVEPOINT accept_insight_proposal")
        conn.execute("RELEASE SAVEPOINT accept_insight_proposal")
        conn.rollback()
        raise
    return {"inspiration_id": inspiration_id, "validation_work_item_id": validation_work_item_id}


def transit(
    conn,
    target: str,
    insight_id: int,
    status: str,
    *,
    sp_id: Optional[int] = None,
    wi_id: Optional[int] = None,
    harvest_id: str = "",
    harvest_note: str = "",
) -> None:
    if status not in VALID_STATUS:
        raise ValueError(f"invalid status: {status}")
    insight = conn.execute(
        "SELECT promoted_wi_id,status FROM inspirations WHERE id=? AND target_name=?",
        (insight_id, target),
    ).fetchone()
    if insight is None:
        raise ValueError("insight does not belong to target")
    validation_work_item_id = insight["promoted_wi_id"]
    if status == "queued" and validation_work_item_id is None:
        raise ValueError("queued insight requires an accepted validation work item")
    if status in {"verified", "refuted"}:
        if validation_work_item_id is None:
            raise ValueError("verified/refuted insight requires an accepted validation outcome")
        work_item = conn.execute(
            "SELECT status,target_name FROM work_items WHERE id=?",
            (validation_work_item_id,),
        ).fetchone()
        if work_item is None or work_item["target_name"] != target or work_item["status"] not in {"done", "blocked"}:
            raise ValueError("verified/refuted insight requires a terminal validation outcome")
        latest = conn.execute(
            "SELECT payload_json FROM agent_events WHERE work_item_id=? ORDER BY id DESC LIMIT 1",
            (validation_work_item_id,),
        ).fetchone()
        try:
            worker_result = json.loads(latest["payload_json"]).get("worker_result", {}) if latest else {}
        except (TypeError, json.JSONDecodeError):
            worker_result = {}
        if not isinstance(worker_result, dict) or not worker_result.get("evidence_refs"):
            raise ValueError("verified/refuted insight requires validation evidence refs")
    conn.execute(
        """UPDATE inspirations SET status=?, promoted_sp_id=COALESCE(?, promoted_sp_id),
             promoted_wi_id=COALESCE(?, promoted_wi_id),
             harvest_id=COALESCE(?, harvest_id), harvest_note=COALESCE(?, harvest_note), updated_at=?
           WHERE id=? AND target_name=?""",
        (status, sp_id, wi_id, harvest_id or None, harvest_note or None, _now(), insight_id, target),
    )
    conn.commit()


def list_insights(conn, target: str, *, stage: str = "", status: str = "") -> list[dict[str, Any]]:
    q = "SELECT * FROM inspirations WHERE target_name=?"
    args: list[Any] = [target]
    if stage:
        q += " AND stage=?"
        args.append(stage)
    if status:
        q += " AND status=?"
        args.append(status)
    q += " ORDER BY id DESC"
    return [dict(r) for r in conn.execute(q, args).fetchall()]


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="灵感写入口(唯一)")
    p.add_argument("--target", required=True, help="显式 target_name")
    p.add_argument("--db", required=True, help="显式 target SQLite DB")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gleam", help="捕捉原始灵光")
    g.add_argument("--content", required=True)
    g.add_argument("--trigger", default="")
    g.add_argument("--source", default="human", choices=VALID_SOURCE)
    g.add_argument("--confidence", default="low", choices=VALID_CONFIDENCE)
    g.add_argument("--blocked-on", default="")
    g.add_argument("--asset", help="所属资产 id(target_assets.id),显式指定", type=int)
    g.add_argument("--agent-id", default="")
    g.add_argument("--session-id", default="")

    r = sub.add_parser("refine", help="灵光→线索")
    r.add_argument("--from", dest="from_id", required=True, type=int)
    r.add_argument("--content", required=True)
    r.add_argument("--confidence", default="medium", choices=VALID_CONFIDENCE)
    r.add_argument("--note", default="")

    a = sub.add_parser("add", help="人直接手录一条(直接当线索)")
    a.add_argument("--content", required=True)
    a.add_argument("--trigger", default="")
    a.add_argument("--source", default="human", choices=VALID_SOURCE)
    a.add_argument("--blocked-on", default="")
    a.add_argument("--asset", help="所属资产 id(target_assets.id),显式指定", type=int)
    a.add_argument("--confidence", default="low", choices=VALID_CONFIDENCE)

    accept = sub.add_parser("accept", help="主会话接纳最新 worker 的一个 L3 灵感提案")
    accept.add_argument("--work-item-id", required=True, type=int)
    accept.add_argument("--proposal-index", default=0, type=int)

    t = sub.add_parser("transit", help="流转状态")
    t.add_argument("--id", dest="insight_id", required=True, type=int)
    t.add_argument("--status", required=True, choices=VALID_STATUS)
    t.add_argument("--sp-id", type=int)
    t.add_argument("--wi-id", type=int)
    t.add_argument("--harvest-id", default="")
    t.add_argument("--harvest-note", default="")

    l = sub.add_parser("list", help="只读查看")  # noqa: E741
    l.add_argument("--stage", choices=VALID_STAGE, default="")
    l.add_argument("--status", choices=VALID_STATUS, default="")
    return p


def main() -> int:
    force_utf8_stdout()
    args = _build_parser().parse_args()
    conn = _get_conn(args.target, args.db)
    try:
        if args.cmd == "gleam":
            iid = capture_gleam(
                conn,
                args.target,
                args.content,
                source=args.source,
                trigger=args.trigger,
                confidence=args.confidence,
                blocked_on=args.blocked_on,
                asset_id=args.asset,
                agent_id=args.agent_id,
                session_id=args.session_id,
            )
            print(json.dumps({"id": iid, "stage": "gleam"}, ensure_ascii=False))
        elif args.cmd == "refine":
            iid = refine(conn, args.target, args.from_id, args.content, confidence=args.confidence, note=args.note)
            print(json.dumps({"id": iid, "stage": "clue", "refined_from": args.from_id}, ensure_ascii=False))
        elif args.cmd == "add":
            iid = add(
                conn,
                args.target,
                args.content,
                trigger=args.trigger,
                source=args.source,
                blocked_on=args.blocked_on,
                asset_id=args.asset,
                confidence=args.confidence,
            )
            print(json.dumps({"id": iid, "stage": "clue"}, ensure_ascii=False))
        elif args.cmd == "accept":
            accepted = accept_proposal(
                conn,
                args.target,
                args.work_item_id,
                proposal_index=args.proposal_index,
            )
            print(json.dumps({"ok": True, **accepted}, ensure_ascii=False))
        elif args.cmd == "transit":
            transit(
                conn,
                args.target,
                args.insight_id,
                args.status,
                sp_id=args.sp_id,
                wi_id=args.wi_id,
                harvest_id=args.harvest_id,
                harvest_note=args.harvest_note,
            )
            print(json.dumps({"id": args.insight_id, "status": args.status}, ensure_ascii=False))
        else:
            rows = list_insights(conn, args.target, stage=args.stage, status=args.status)
            print(json.dumps(rows, ensure_ascii=False, indent=2))
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
