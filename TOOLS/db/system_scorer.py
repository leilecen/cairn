"""Rank target systems using pre-result facts only."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from db.db_utils import connect, find_db  # noqa: E402

AUTHORIZED = {"active", "authorized", "confirmed"}


def _build(conn: sqlite3.Connection, target_name: str) -> list[dict]:
    if not str(target_name or "").strip():
        raise ValueError("target_name is required")
    if not conn.execute("SELECT 1 FROM targets WHERE target_name=?", (target_name,)).fetchone():
        raise ValueError(f"target not found: {target_name}")
    systems = conn.execute(
        "SELECT id,system_key,canonical_url FROM target_systems WHERE target_name=? ORDER BY system_key,id",
        (target_name,),
    ).fetchall()
    results = []
    for system in systems:
        assets = conn.execute(
            """SELECT a.id,a.scope_status,a.scope_class,a.authorization_state,a.auth_entry_found
               FROM system_asset_links l JOIN target_assets a ON a.id=l.asset_id
               WHERE l.target_name=? AND l.system_id=? AND a.target_name=? ORDER BY a.id""",
            (target_name, system["id"], target_name),
        ).fetchall()
        if not assets:
            eligibility, reason = "needs_review", "system has no target-scoped assets"
        elif any(row["scope_status"] != "in_scope" or row["scope_class"] not in {"owned", "authorized_vendor"} for row in assets):
            eligibility, reason = "scope_blocked", "all linked assets must be explicitly in scope"
        elif any(str(row["authorization_state"] or "").lower() not in AUTHORIZED for row in assets):
            eligibility, reason = "authz_blocked", "all linked assets require explicit authorization"
        else:
            eligibility, reason = "eligible", "scope and authorization are explicit"
        ids = [int(row["id"]) for row in assets]
        asset_ids_json = json.dumps(ids, separators=(",", ":"))
        authenticated = business = tech = login = register = 0
        if ids:
            authenticated, business = conn.execute(
                """SELECT count(*),
                           sum(CASE WHEN business_hint IS NOT NULL AND trim(business_hint)<>'' THEN 1 ELSE 0 END)
                    FROM endpoint_observations
                    WHERE target_name=? AND asset_id IN (SELECT value FROM json_each(?))
                      AND auth_state='authenticated'""",
                (target_name, asset_ids_json),
            ).fetchone()
            tech = conn.execute(
                """SELECT count(*) FROM technology_observations
                    WHERE target_name=? AND asset_id IN (SELECT value FROM json_each(?))
                      AND confidence IN ('medium','high')""",
                (target_name, asset_ids_json),
            ).fetchone()[0]
            login, register = conn.execute(
                """SELECT sum(CASE WHEN entry_type='login' THEN 1 ELSE 0 END),
                           sum(CASE WHEN entry_type='register' THEN 1 ELSE 0 END)
                    FROM asset_auth_entries
                    WHERE target_name=? AND asset_id IN (SELECT value FROM json_each(?))""",
                (target_name, asset_ids_json),
            ).fetchone()
        authenticated, business, login, register = map(lambda value: int(value or 0), (authenticated, business, login, register))
        richness = min(60, authenticated * 5 + business * 2)
        focus = min(
            40,
            int(tech or 0) * 5 + login * 5 + register * 15 + sum(int(row["auth_entry_found"] or 0) for row in assets) * 2,
        )
        # A register entry is only a lead, not evidence that registration works.
        login_access = "operator_required" if register or login or any(row["auth_entry_found"] for row in assets) else "none"
        results.append(
            {
                "system_id": int(system["id"]),
                "system_key": system["system_key"],
                "canonical_url": system["canonical_url"],
                "eligibility_status": eligibility,
                "eligibility_reason": reason,
                "login_access": login_access,
                "business_richness_score": richness,
                "focus_value_score": focus,
                "total_score": richness + focus,
                "dimension_scores": {
                    "authenticated_routes": authenticated,
                    "business_routes": business,
                    "product_evidence": int(tech or 0),
                },
                "evidence": [],
            }
        )
    results.sort(key=lambda row: (-row["total_score"], row["system_key"], row["system_id"]))
    for rank, row in enumerate(results, 1):
        row["rank"] = rank
        row["tier"] = "high" if row["total_score"] >= 60 else "medium" if row["total_score"] >= 25 else "low"
    return results


def _table(conn: sqlite3.Connection, name: str) -> bool:
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None


def _apply_downgrade_stop(conn: sqlite3.Connection, target_name: str, items: list[dict]) -> dict[str, int]:
    """Atomically park focus/session/queued work for systems that lost eligibility.

    Runs inside the caller's apply transaction. Idempotent: only systems whose
    stored eligibility was 'eligible' and that are being written as non-eligible
    trigger a stop; repeated scoring with unchanged eligibility is a no-op.
    """
    empty = {"systems": 0, "sessions": 0, "work_items": 0, "decisions": 0}
    if not _table(conn, "system_soft_targets"):
        return empty
    before = {
        int(row["system_id"]): str(row["eligibility_status"])
        for row in conn.execute(
            "SELECT system_id, eligibility_status FROM system_soft_targets WHERE target_name=?", (target_name,)
        ).fetchall()
    }
    downgraded = [row for row in items if row["eligibility_status"] != "eligible" and before.get(int(row["system_id"])) == "eligible"]
    if not downgraded:
        return empty
    system_ids = [int(row["system_id"]) for row in downgraded]
    placeholders = ",".join("?" for _ in system_ids)
    target_params = (target_name, *system_ids)
    summary: dict[str, int] = dict(empty)
    if _table(conn, "system_soft_targets"):
        summary["systems"] = conn.execute(
            f"""UPDATE system_soft_targets SET status='parked', timebox_until=NULL,
                updated_at=datetime('now','localtime')
                WHERE target_name=? AND status='focused' AND system_id IN ({placeholders})""",  # noqa: S608 -- 仅拼接 "?" 占位符，值全走参数绑定
            target_params,
        ).rowcount
    if _table(conn, "target_systems"):
        conn.execute(
            f"""UPDATE target_systems SET lifecycle_state='parked', updated_at=datetime('now','localtime')
                WHERE target_name=? AND lifecycle_state IN ('mapping','testing') AND id IN ({placeholders})""",  # noqa: S608 -- 仅拼接 "?" 占位符，值全走参数绑定
            target_params,
        )
    if _table(conn, "hunt_sessions"):
        summary["sessions"] = conn.execute(
            f"""UPDATE hunt_sessions SET status='paused', updated_at=datetime('now','localtime')
                WHERE target_name=? AND status='active' AND system_id IN ({placeholders})""",  # noqa: S608 -- 仅拼接 "?" 占位符，值全走参数绑定
            target_params,
        ).rowcount
    if _table(conn, "work_items"):
        summary["work_items"] = conn.execute(
            f"""UPDATE work_items SET dispatch_state='parked',
                park_reason='system authorization or scope downgraded; not execution-eligible',
                updated_at=datetime('now','localtime')
                WHERE target_name=? AND status IN ('queued','partial')
                  AND COALESCE(dispatch_state,'active')='active' AND system_id IN ({placeholders})""",  # noqa: S608 -- 仅拼接 "?" 占位符，值全走参数绑定
            target_params,
        ).rowcount
    if _table(conn, "decision_events"):
        for row in downgraded:
            conn.execute(
                """INSERT INTO decision_events(target_name,hunt_session_id,actor,decision_type,
                   compact_snapshot_json,chosen_action,rationale,expected_change)
                   VALUES(?,NULL,'system_scorer','park',?,?,?,?)""",
                (
                    target_name,
                    json.dumps(
                        {"system_id": int(row["system_id"]), "from": "eligible", "to": row["eligibility_status"]},
                        separators=(",", ":"),
                    ),
                    f"stop system {row['system_id']}",
                    f"eligibility downgraded to {row['eligibility_status']}: {row['eligibility_reason']}",
                    "no dispatch until operator restores scope/authorization",
                ),
            )
        summary["decisions"] = len(downgraded)
    return summary


def score_systems(conn: sqlite3.Connection, target_name: str, *, apply: bool = False) -> dict:
    try:
        if apply:
            conn.execute("BEGIN IMMEDIATE")
        items = _build(conn, target_name)
        downgrade_stop = {"systems": 0, "sessions": 0, "work_items": 0, "decisions": 0}
        if apply:
            downgrade_stop = _apply_downgrade_stop(conn, target_name, items)
            for row in items:
                conn.execute(
                    """INSERT INTO system_soft_targets(
                         target_name,system_id,eligibility_status,eligibility_reason,login_access,
                         business_richness_score,focus_value_score,total_score,tier,rank,
                         dimension_scores_json,evidence_json
                       )
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(target_name,system_id) DO UPDATE SET
                         eligibility_status=excluded.eligibility_status,eligibility_reason=excluded.eligibility_reason,
                         login_access=excluded.login_access,business_richness_score=excluded.business_richness_score,
                         focus_value_score=excluded.focus_value_score,total_score=excluded.total_score,tier=excluded.tier,
                         rank=excluded.rank,dimension_scores_json=excluded.dimension_scores_json,
                         evidence_json=excluded.evidence_json,updated_at=datetime('now','localtime')""",
                    (
                        target_name,
                        row["system_id"],
                        row["eligibility_status"],
                        row["eligibility_reason"],
                        row["login_access"],
                        row["business_richness_score"],
                        row["focus_value_score"],
                        row["total_score"],
                        row["tier"],
                        row["rank"],
                        json.dumps(row["dimension_scores"], separators=(",", ":")),
                        "[]",
                    ),
                )
            conn.commit()
        return {"target_name": target_name, "count": len(items), "items": items, "downgrade_stop": downgrade_stop}
    except Exception:
        if apply:
            conn.rollback()
        raise


def _path(args: argparse.Namespace) -> Path:
    if bool(args.file) == bool(args.target):
        raise ValueError("exactly one of --target or --file is required")
    if args.file:
        path = Path(args.file)
        if not path.is_file():
            raise ValueError(f"database file not found: {path}")
        return path
    return find_db(args.target)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target")
    parser.add_argument("--file")
    parser.add_argument("--target-name")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    try:
        path = _path(args)
        target = args.target_name or args.target
        if not target:
            raise ValueError("--target-name is required with --file")
        conn = connect(path)
        try:
            result = score_systems(conn, target, apply=args.apply)
        finally:
            conn.close()
        items = result.pop("items")
        print(
            json.dumps(
                {**result, "ok": True, "applied": args.apply, "sample": items[:10], "omitted": max(0, len(items) - 10)},
                ensure_ascii=True,
                separators=(",", ":"),
            )
        )
        return 0
    except (ValueError, RuntimeError, sqlite3.Error) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=True, separators=(",", ":")))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
