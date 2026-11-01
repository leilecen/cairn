"""Unified SRC CLI with UTF-8 and PowerShell-safe payload handling."""

from __future__ import annotations

import argparse
import io
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any

_TOOLS_DIR = Path(__file__).resolve().parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

from db.db_utils import connect, find_db  # noqa: E402
from db.simple_src_report import generate_simple_src_reports  # noqa: E402
from db.soft_target_scorer import (  # noqa: E402
    focus_soft_target,
    format_focus_list,
    format_text,
    list_soft_targets,
    run_scorer,
    transition_soft_target,
)
from db.sprint_tick import run_sprint_tick  # noqa: E402
from db.work_queue import (  # noqa: E402
    block_work_item,
    claim_by_id,
    claim_next,
    complete_work_item,
    create_work_item,
    heartbeat,
    partial_result,
)


def _force_utf8() -> None:
    """Keep Windows PowerShell/GBK terminals from corrupting Chinese JSON/text."""
    if hasattr(sys.stdout, "buffer"):
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace", newline="\n")
    if hasattr(sys.stderr, "buffer"):
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace", newline="\n")
    if hasattr(sys.stdin, "buffer"):
        sys.stdin = io.TextIOWrapper(sys.stdin.buffer, encoding="utf-8", errors="strict", newline=None)


def _resolve_db(args: argparse.Namespace) -> Path:
    if getattr(args, "db", None):
        return Path(args.db)
    target = getattr(args, "target", None)
    if not target:
        raise ValueError("--db or --target is required")
    return find_db(target)


def _json_dumps(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)


def _read_payload(args: argparse.Namespace) -> dict[str, Any]:
    raw = getattr(args, "payload", None)
    payload_file = getattr(args, "payload_file", None)
    payload_stdin = getattr(args, "payload_stdin", False)
    sources = [bool(raw), bool(payload_file), bool(payload_stdin)]
    if sum(sources) > 1:
        raise ValueError("use only one of --payload, --payload-file, or --payload-stdin")
    if payload_file:
        raw = Path(payload_file).read_text(encoding="utf-8")
    elif payload_stdin:
        raw = sys.stdin.read()
    if not raw:
        return {}
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("payload must be a JSON object")
    return value


def _open_conn(args: argparse.Namespace) -> sqlite3.Connection:
    return connect(_resolve_db(args))


def _cmd_soft_targets(args: argparse.Namespace) -> dict[str, Any]:
    conn = _open_conn(args)
    try:
        if args.action == "score":
            return run_scorer(conn, target_name=args.target, top=args.top or None)
        if args.action == "list":
            return list_soft_targets(conn, target_name=args.target, top=args.top or None)
        if args.action == "focus":
            return focus_soft_target(conn, target_name=args.target, soft_target_id=args.id, actor=args.actor)
        if args.action in {"fail", "park"}:
            return transition_soft_target(
                conn,
                target_name=args.target,
                soft_target_id=args.id,
                status="failed" if args.action == "fail" else "parked",
                reason=args.reason or ("focus_failed" if args.action == "fail" else "operator_parked"),
                actor=args.actor,
            )
        raise ValueError(f"unknown soft-targets action: {args.action}")
    finally:
        conn.close()


def _cmd_sprint_tick(args: argparse.Namespace) -> dict[str, Any]:
    conn = _open_conn(args)
    try:
        return run_sprint_tick(
            conn,
            target_name=args.target,
            sprint_id=args.sprint_id,
            seed=not args.no_seed,
            reclaim=not args.no_reclaim,
        )
    finally:
        conn.close()


def _cmd_work(args: argparse.Namespace) -> dict[str, Any]:
    conn = _open_conn(args)
    try:
        if args.action == "create":
            payload = _read_payload(args)
            fields = {
                "target_name": args.target,
                "lane": args.lane,
                "subject_table": args.subject_table,
                "subject_id": args.subject_id,
                "subtype": args.subtype,
                "attack_thread_id": args.attack_thread_id,
                "title": args.title or "",
                "objective": args.objective or "",
                "priority": args.priority,
                "model_tier": args.model_tier,
                "reasoning_tier": args.reasoning_tier,
                "auth_requirement": args.auth_requirement,
                "risk_class": args.risk_class,
                "timebox_minutes": args.timebox_minutes,
                "heartbeat_minutes": args.heartbeat_minutes,
            }
            fields.update(payload)
            return {"ok": True, "work_item_id": create_work_item(conn, **fields)}

        if args.action == "claim":
            lanes = [item for item in (args.lanes or "").split(",") if item]
            if args.work_item_id is not None:
                item = claim_by_id(
                    conn,
                    work_item_id=args.work_item_id,
                    agent_id=args.agent_id,
                    target_name=args.target,
                    lease_minutes=args.lease_minutes,
                )
                if item is None:
                    raise ValueError(f"work_item {args.work_item_id} is not claimable")
                return {"ok": True, "items": [item]}
            return {
                "ok": True,
                "items": claim_next(
                    conn,
                    target_name=args.target,
                    agent_id=args.agent_id,
                    lanes=lanes or None,
                    limit=args.limit,
                    lease_minutes=args.lease_minutes,
                ),
            }

        if args.action == "heartbeat":
            heartbeat(conn, work_item_id=args.work_item_id, agent_id=args.agent_id, payload=_read_payload(args))
            return {"ok": True, "work_item_id": args.work_item_id}

        if args.action == "partial":
            payload = _read_payload(args)
            payload.setdefault("summary", args.summary)
            partial_result(conn, work_item_id=args.work_item_id, agent_id=args.agent_id, payload=payload)
            return {"ok": True, "work_item_id": args.work_item_id}

        if args.action == "complete":
            complete_work_item(
                conn,
                work_item_id=args.work_item_id,
                agent_id=args.agent_id,
                summary=args.summary,
                next_action=args.next_action or "",
            )
            return {"ok": True, "work_item_id": args.work_item_id}

        if args.action == "block":
            operator_payload = _read_payload(args) or None
            block_work_item(
                conn,
                work_item_id=args.work_item_id,
                agent_id=args.agent_id,
                reason=args.reason,
                blocker_class=args.blocker_class,
                operator_payload=operator_payload,
            )
            return {"ok": True, "work_item_id": args.work_item_id}

        raise ValueError(f"unknown work action: {args.action}")
    finally:
        conn.close()


def _cmd_report(args: argparse.Namespace) -> dict[str, Any]:
    conn = _open_conn(args)
    try:
        if args.action == "generate":
            return generate_simple_src_reports(
                conn,
                target_name=args.target,
                finding_id=args.finding_id,
                output_root=Path(args.output_root) if args.output_root else None,
            )
        raise ValueError(f"unknown report action: {args.action}")
    finally:
        conn.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SRC unified CLI")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON, including errors")
    subparsers = parser.add_subparsers(dest="command", required=True)

    soft = subparsers.add_parser("soft-targets", help="score/list/focus/fail/park soft targets")
    soft.add_argument("action", choices=["score", "list", "focus", "fail", "park"])
    soft.add_argument("--target", required=True)
    soft.add_argument("--db")
    soft.add_argument("--top", type=int, default=0)
    soft.add_argument("--id", type=int, help="soft_targets.id for focus/fail/park")
    soft.add_argument("--reason", default="")
    soft.add_argument("--actor", default="operator")
    soft.set_defaults(func=_cmd_soft_targets)

    sprint = subparsers.add_parser("sprint-tick", help="run one main-session sprint tick")
    sprint.add_argument("--target", required=True)
    sprint.add_argument("--db")
    sprint.add_argument("--sprint-id")
    sprint.add_argument("--no-seed", action="store_true")
    sprint.add_argument("--no-reclaim", action="store_true")
    sprint.set_defaults(func=_cmd_sprint_tick)

    work = subparsers.add_parser("work", help="claim and update blackboard work_items")
    work_sub = work.add_subparsers(dest="action", required=True)

    create = work_sub.add_parser("create")
    create.add_argument("--target", required=True)
    create.add_argument("--lane", required=True)
    create.add_argument("--subject-table", required=True)
    create.add_argument("--subject-id", required=True)
    create.add_argument("--subtype")
    create.add_argument("--attack-thread-id", type=int)
    create.add_argument("--title")
    create.add_argument("--objective")
    create.add_argument("--priority", type=int, default=50)
    create.add_argument("--model-tier", default="sonnet")
    create.add_argument("--reasoning-tier", default="low")
    create.add_argument("--auth-requirement", default="unknown")
    create.add_argument("--risk-class", default="safe_passive")
    create.add_argument("--timebox-minutes", type=int, default=10)
    create.add_argument("--heartbeat-minutes", type=int, default=5)
    create.add_argument("--db")
    create.add_argument("--payload")
    create.add_argument("--payload-file")
    create.add_argument("--payload-stdin", action="store_true")
    create.set_defaults(func=_cmd_work)

    claim = work_sub.add_parser("claim")
    claim.add_argument("--target", required=True)
    claim.add_argument("--agent-id", required=True)
    claim.add_argument("--lanes")
    claim.add_argument("--work-item-id", type=int)
    claim.add_argument("--limit", type=int, default=1)
    claim.add_argument("--lease-minutes", type=int)
    claim.add_argument("--db")
    claim.set_defaults(func=_cmd_work)

    for name in ("heartbeat", "partial", "complete", "block"):
        sub = work_sub.add_parser(name)
        sub.add_argument("--work-item-id", required=True, type=int)
        sub.add_argument("--agent-id", required=True)
        sub.add_argument("--db")
        sub.add_argument("--target")
        if name in {"heartbeat", "partial", "block"}:
            sub.add_argument("--payload")
            sub.add_argument("--payload-file")
            sub.add_argument("--payload-stdin", action="store_true")
        if name == "partial":
            sub.add_argument("--summary", required=True)
        elif name == "complete":
            sub.add_argument("--summary", required=True)
            sub.add_argument("--next-action")
        elif name == "block":
            sub.add_argument("--reason", required=True)
            sub.add_argument("--blocker-class", required=True)
        sub.set_defaults(func=_cmd_work)

    report = subparsers.add_parser("report", help="generate lightweight UTF-8 SRC Markdown reports")
    report_sub = report.add_subparsers(dest="action", required=True)
    generate = report_sub.add_parser("generate")
    generate.add_argument("--target", required=True)
    generate.add_argument("--db")
    generate.add_argument("--finding-id", help="generate one finding; omit to generate all findings for target")
    generate.add_argument("--output-root", help="override output root; defaults to reports/src_reports")
    generate.set_defaults(func=_cmd_report)

    return parser


def _format_text(args: argparse.Namespace, payload: dict[str, Any]) -> str:
    if args.command == "soft-targets" and args.action == "score":
        return format_text(payload)
    if args.command == "soft-targets" and args.action == "list":
        return format_focus_list(payload)
    return _json_dumps(payload)


def main() -> None:
    _force_utf8()
    parser = build_parser()
    args = parser.parse_args()
    try:
        payload = args.func(args)
    except Exception as exc:
        print(_json_dumps({"ok": False, "error": str(exc), "type": exc.__class__.__name__}))
        raise SystemExit(1) from exc

    if args.json:
        print(_json_dumps({"ok": True, "data": payload}))
    else:
        print(_format_text(args, payload))


if __name__ == "__main__":
    main()
