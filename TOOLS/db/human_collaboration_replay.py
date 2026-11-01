"""Offline preview/apply for human-focus schema and reconciliation."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sqlite3
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

TOOLS_DIR = Path(__file__).resolve().parent.parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from db.db_backup import DEFAULT_BACKUP_DIR  # noqa: E402 -- 必须排在 sys.path bootstrap 之后
from db.db_utils import connect, find_db, session  # noqa: E402 -- 必须排在 sys.path bootstrap 之后
from db.migrate import (  # noqa: E402 -- 必须排在 sys.path bootstrap 之后
    apply_migration,
    ensure_schema_version,
    get_current_version,
)

ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "migrations" / "033_human_focus_control.sql"


def _table(conn: sqlite3.Connection, name: str) -> bool:
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None


def _count(conn: sqlite3.Connection, table: str) -> int:
    return int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]) if _table(conn, table) else 0  # noqa: S608 -- table 只在本模块常量表名内使用


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def preview(db_path: Path, *, target_name: str) -> dict:
    conn = connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        proposals = [{k: v for k, v in item.items() if k != "members"} for item in _build_system_proposals(conn, target_name=target_name)]
        version = (
            int(conn.execute("SELECT COALESCE(MAX(version),0) FROM schema_version").fetchone()[0]) if _table(conn, "schema_version") else 0
        )
        wi_cols = {row[1] for row in conn.execute("PRAGMA table_info(work_items)")} if _table(conn, "work_items") else set()
        orphan = (
            conn.execute(
                "SELECT COUNT(*) FROM work_items WHERE target_name=? AND lane='operator_task' AND status IN ('queued','partial','blocked')",
                (target_name,),
            ).fetchone()[0]
            if {"lane", "status"}.issubset(wi_cols)
            else 0
        )
        broad = (
            conn.execute(
                "SELECT COUNT(*) FROM work_items WHERE target_name=? AND lane='asset_triage' AND status IN ('queued','claimed','partial') AND COALESCE(dispatch_state,'active')='active'",
                (target_name,),
            ).fetchone()[0]
            if {"lane", "status"}.issubset(wi_cols)
            else 0
        )
        return {
            "target": target_name,
            "db": str(db_path),
            "schema_version": version,
            "schema_changes": ["033_human_focus_control"],
            "proposed_systems": proposals,
            "focus_divergence": _count(conn, "decision_events") if _table(conn, "decision_events") else 0,
            "orphan_operator_tasks": int(orphan),
            "proposed_broad_work_parking": int(broad),
            "facts_before": _count(conn, "facts"),
            "findings_before": _count(conn, "findings"),
            "reports_before": _count(conn, "evidence_packs"),
            "events_before": _count(conn, "agent_events"),
            "network_operation_count": 0,
            "apply_mutations": False,
        }
    finally:
        conn.close()


def apply(db_path: Path, *, target_name: str, backup_dir: Path) -> dict:
    backup_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    backup_path = backup_dir / f"{db_path.stem}_human_focus_{stamp}.db"
    shutil.copy2(db_path, backup_path)
    # Readability check before touching the source.
    with session(str(backup_path), read_only=True) as check:
        check.execute("PRAGMA quick_check").fetchone()
    conn = connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        ensure_schema_version(conn)
        before = get_current_version(conn)
        applied = apply_migration(conn, 33, str(MIGRATION)) if before < 33 else False
        after = get_current_version(conn)
        reconciliation = _reconcile(conn, target_name=target_name)
        conn.commit()
    finally:
        conn.close()
    return {
        "target": target_name,
        "status": "ok",
        "schema_before": before,
        "schema_after": after,
        "applied": applied,
        "reconciliation": reconciliation,
        "backup": str(backup_path),
        "backup_sha256": _sha(backup_path),
        "network_operation_count": 0,
    }


def _reconcile(conn: sqlite3.Connection, *, target_name: str) -> dict[str, int]:
    """Reconstruct a small set of human-readable system proposals.

    A hostname is an asset, not automatically a business system.  Historical
    replay groups assets by registrable domain and keeps all resulting systems
    discovered/proposed; only an operator can activate one.
    """
    from db.operator_actions import create_action_card

    mutations_before = conn.total_changes
    systems = system_updates = links = link_updates = cards = card_updates = 0
    legacy_cards_normalized = parked = focus_proposals = legacy_collapsed = 0
    asset_cols = {row[1] for row in conn.execute("PRAGMA table_info(target_assets)")}
    required_asset_cols = {"id", "asset_value", "scope_class", "scope_status"}
    assets = (
        conn.execute(
            """
        SELECT a.id,a.asset_value,a.protocol,a.port,a.scope_class,
               MAX(CASE WHEN s.status='focused' THEN 1 ELSE 0 END) AS focused
        FROM target_assets a JOIN soft_targets s ON s.asset_id=a.id
        WHERE a.target_name=? AND s.target_name=? AND a.scope_status='in_scope'
        GROUP BY a.id,a.asset_value,a.protocol,a.port,a.scope_class
    """,
            (target_name, target_name),
        ).fetchall()
        if required_asset_cols.issubset(asset_cols)
        else []
    )
    proposals = _build_system_proposals(conn, target_name=target_name, assets=assets)
    for proposal in proposals:
        members = proposal["members"]
        if not members:
            continue
        key = proposal["system_key"]
        url = proposal["canonical_url"]
        display = proposal["display_name"]
        member_ids = {int(x["id"]) for x in members}
        scopes = {str(x["scope_class"]).lower() for x in members}
        scope_class = (
            "owned"
            if "owned" in scopes
            else ("authorized_vendor" if "authorized" in scopes or "authorized_vendor" in scopes else "intel_only")
        )
        description = f"历史 replay 候选系统，聚合 {len(members)} 个资产；需操作员确认业务归属"
        row = conn.execute("SELECT id FROM target_systems WHERE target_name=? AND system_key=?", (target_name, key)).fetchone()
        if row is None:
            cur = conn.execute(
                "INSERT INTO target_systems(target_name,system_key,display_name,canonical_url,description,scope_class,lifecycle_state,created_by) VALUES(?,?,?,?,?,?,?,?)",
                (target_name, key, display, url, description, scope_class, "discovered", "replay_proposal"),
            )
            system_id = int(cur.lastrowid or 0)
            systems += 1
        else:
            system_id = int(row[0])
            # A focus lifecycle changes soft-target rankings, not a system's
            # identity.  Reuse the existing primary asset when it is still a
            # member so a parked/focused transition cannot move canonical_url.
            existing_primary = conn.execute(
                "SELECT asset_id FROM system_asset_links WHERE system_id=? AND relationship='primary' AND asset_id IN ({}) ORDER BY id LIMIT 1".format(  # noqa: S608 -- 仅拼接 "?" 占位符，值全走参数绑定
                    ",".join("?" for _ in member_ids)
                ),
                (system_id, *sorted(member_ids)),
            ).fetchone()
            if existing_primary is not None:
                representative = next(item for item in members if int(item["id"]) == int(existing_primary["asset_id"]))
                url = _canonical_asset_url(representative)
            cur = conn.execute(
                """UPDATE target_systems
                   SET display_name=?,canonical_url=?,scope_class=?,description=?,updated_at=datetime('now','localtime')
                   WHERE id=? AND (display_name IS NOT ? OR canonical_url IS NOT ?
                       OR scope_class IS NOT ? OR description IS NOT ?)""",
                (display, url, scope_class, description, system_id, display, url, scope_class, description),
            )
            system_updates += int(cur.rowcount)
        existing_primaries = conn.execute(
            "SELECT id,asset_id FROM system_asset_links WHERE system_id=? AND relationship='primary' ORDER BY id",
            (system_id,),
        ).fetchall()
        stable_primary = next((x for x in existing_primaries if int(x["asset_id"]) in member_ids), None)
        if stable_primary:
            representative = next(x for x in members if int(x["id"]) == int(stable_primary["asset_id"]))
        else:
            ranked = sorted(
                members,
                key=lambda x: (
                    int(x["focused"] or 0) if "focused" in x.keys() else 0,
                    str(x["scope_class"]).lower() in {"owned", "authorized_vendor", "authorized"},
                    str(x["scope_class"]).lower() == "owned",
                    int(x["id"]),
                ),
                reverse=True,
            )
            representative = ranked[0]
        for old_primary in existing_primaries:
            if int(old_primary["asset_id"]) != int(representative["id"]):
                link_updates += int(conn.execute("DELETE FROM system_asset_links WHERE id=?", (old_primary["id"],)).rowcount)
        for member in members:
            relation = "primary" if int(member["id"]) == int(representative["id"]) else "related"
            created, updated = _set_membership(
                conn, target_name=target_name, system_id=system_id, asset_id=int(member["id"]), relationship=relation
            )
            links += created
            link_updates += updated
        # Repair pre-existing duplicate primaries deterministically.
        primaries = conn.execute(
            "SELECT id FROM system_asset_links WHERE system_id=? AND relationship='primary' ORDER BY id", (system_id,)
        ).fetchall()
        for duplicate in primaries[1:]:
            link_updates += int(conn.execute("DELETE FROM system_asset_links WHERE id=?", (duplicate[0],)).rowcount)
        focused = conn.execute(
            "SELECT 1 FROM soft_targets WHERE target_name=? AND asset_id IN ({}) AND status='focused' LIMIT 1".format(  # noqa: S608 -- 仅拼接 "?" 占位符，值全走参数绑定
                ",".join("?" for _ in members)
            ),
            (target_name, *[x["id"] for x in members]),
        ).fetchone()
        if focused:
            # Replay may promote a newly discovered proposal to mapping, but
            # must never regress an operator-controlled testing/parked state.
            system_updates += int(
                conn.execute(
                    "UPDATE target_systems SET lifecycle_state='mapping',updated_at=datetime('now','localtime') "
                    "WHERE id=? AND lifecycle_state IN ('discovered','mapping') AND lifecycle_state IS NOT 'mapping'",
                    (system_id,),
                ).rowcount
            )
            existing_focus = conn.execute(
                "SELECT 1 FROM hunt_sessions WHERE target_name=? AND system_id=? AND status IN ('proposed','active','paused') LIMIT 1",
                (target_name, system_id),
            ).fetchone()
            if existing_focus is None:
                conn.execute(
                    "INSERT INTO hunt_sessions(target_name,soft_target_id,focus_subject_table,focus_subject_id,goal,success_criteria_json,stop_conditions_json,status,selected_by,system_id,recon_readiness_snapshot_json) SELECT ?,id,'target_systems',?, 'reconstructed historical focus','[]','[]','proposed','replay',?, '{{}}' FROM soft_targets WHERE target_name=? AND asset_id IN ({}) AND status='focused' LIMIT 1".format(  # noqa: S608 -- 仅拼接 "?" 占位符，值全走参数绑定
                        ",".join("?" for _ in members)
                    ),
                    (target_name, str(system_id), system_id, target_name, *[x["id"] for x in members]),
                )
                focus_proposals += 1
    legacy_collapsed = _collapse_legacy_asset_systems(conn, target_name=target_name)
    wi_cols = {row[1] for row in conn.execute("PRAGMA table_info(work_items)")}
    work_select = "id,title,objective" + (",system_id" if "system_id" in wi_cols else "")
    rows = (
        conn.execute(
            f"SELECT {work_select} FROM work_items WHERE target_name=? AND lane='operator_task' AND status IN ('queued','partial','blocked')",  # noqa: S608 -- 标识符取自 PRAGMA/schema，值全走参数绑定
            (target_name,),
        ).fetchall()
        if {"title", "objective", "lane", "status"}.issubset(wi_cols)
        else []
    )
    active_system_ids = (
        [
            int(x[0])
            for x in conn.execute(
                "SELECT system_id FROM hunt_sessions WHERE target_name=? AND status='active' AND system_id IS NOT NULL",
                (target_name,),
            ).fetchall()
        ]
        if _table(conn, "hunt_sessions")
        else []
    )
    history_sql = "SELECT system_id FROM hunt_sessions WHERE target_name=? AND status IN ('proposed','paused') AND system_id IS NOT NULL"
    history_args: list[Any] = [target_name]
    if active_system_ids:
        history_sql += " AND system_id NOT IN (" + ",".join("?" for _ in active_system_ids) + ")"
        history_args.extend(active_system_ids)
    history_sql += " ORDER BY CASE status WHEN 'proposed' THEN 0 ELSE 1 END,id DESC LIMIT 1"
    historical_system = conn.execute(history_sql, history_args).fetchone() if _table(conn, "hunt_sessions") else None
    historical_system_id = int(historical_system[0]) if historical_system else None
    for row in rows:
        card_system_id = int(row["system_id"]) if "system_id" in row.keys() and row["system_id"] is not None else historical_system_id
        existing = conn.execute(
            "SELECT id,action_key FROM operator_inbox WHERE target_name=? AND related_work_item_id=? AND status='open'",
            (target_name, row["id"]),
        ).fetchone()
        if existing:
            existing_cols = {item[1] for item in conn.execute("PRAGMA table_info(operator_inbox)")}
            existing_key = str(existing["action_key"] or "") if "action_key" in existing.keys() else ""
            if "action_key" in existing_cols and (not existing_key or existing_key.startswith("legacy-incomplete:")):
                action_key = f"legacy-incomplete:{row['id']}"
                label = f"补全人工任务 #{row['id']}"
                why_needed = f"历史任务资料不足：{row['objective'] or '请由操作员补全证据、URL、步骤和预期'}"
                cur = conn.execute(
                    """UPDATE operator_inbox
                       SET system_id=?,action_key=?,action_label=?,why_needed=?,steps_json='[]',
                           expected_observation='',report_back_format='',url=NULL,suggested_action=NULL,blocking=0
                       WHERE id=? AND (system_id IS NOT ? OR action_key IS NOT ? OR action_label IS NOT ?
                           OR why_needed IS NOT ? OR steps_json IS NOT '[]' OR expected_observation IS NOT ''
                           OR report_back_format IS NOT '' OR url IS NOT NULL OR suggested_action IS NOT NULL
                           OR blocking IS NOT 0)""",
                    (
                        card_system_id,
                        action_key,
                        label,
                        why_needed,
                        existing["id"],
                        card_system_id,
                        action_key,
                        label,
                        why_needed,
                    ),
                )
                card_updates += int(cur.rowcount)
            continue
        create_action_card(
            conn,
            target_name=target_name,
            system_id=card_system_id,
            kind="evidence_capture",
            action_key=f"legacy-incomplete:{row['id']}",
            action_label=f"补全人工任务 #{row['id']}",
            why_needed=f"历史任务资料不足：{row['objective'] or '请由操作员补全证据、URL、步骤和预期'}",
            steps=[],
            expected_observation="",
            report_back_format=None,
            related_work_item_id=int(row["id"]),
            blocking=False,
            incomplete=True,
        )
        cards += 1
    # Normalize every legacy open card, not only cards linked to operator_task.
    if _table(conn, "operator_inbox"):
        card_cols = {row[1] for row in conn.execute("PRAGMA table_info(operator_inbox)")}
        for card in (
            conn.execute(
                "SELECT id,title,detail,kind FROM operator_inbox WHERE target_name=? AND status='open' AND (action_key IS NULL OR action_key='')",
                (target_name,),
            ).fetchall()
            if "action_key" in card_cols
            else []
        ):
            cur = conn.execute(
                "UPDATE operator_inbox SET system_id=COALESCE(system_id,?),action_key=?,action_label=?,why_needed=?,steps_json='[]',expected_observation='',report_back_format='',url=NULL,suggested_action=NULL,blocking=0 WHERE id=?",
                (
                    historical_system_id,
                    f"legacy-card:{card['id']}",
                    card["title"] or "补全历史人工卡",
                    f"历史行动卡未结构化：{card['detail'] or '请操作员补全证据、URL、步骤和预期'}",
                    card["id"],
                ),
            )
            legacy_cards_normalized += int(cur.rowcount)
    if {"lane", "status", "dispatch_state", "park_reason"}.issubset(wi_cols):
        cur = conn.execute(
            "UPDATE work_items SET dispatch_state='parked',park_reason='human-focus replay: broad historical queue parked' WHERE target_name=? AND lane='asset_triage' AND status IN ('queued','claimed','partial') AND COALESCE(dispatch_state,'active')='active'",
            (target_name,),
        )
        parked = int(cur.rowcount)
    violations = conn.execute(
        """SELECT COUNT(*) FROM (SELECT system_id,COUNT(*) n FROM system_asset_links WHERE relationship='primary' GROUP BY system_id HAVING n>1)"""
    ).fetchone()[0]
    conflicts = conn.execute(
        """SELECT COUNT(*) FROM (SELECT system_id,asset_id,COUNT(DISTINCT relationship) n FROM system_asset_links GROUP BY system_id,asset_id HAVING n>1)"""
    ).fetchone()[0]
    return {
        "systems_created": systems,
        "systems_updated": system_updates,
        "system_asset_links_created": links,
        "system_asset_links_updated": link_updates,
        "incomplete_action_cards_created": cards,
        "incomplete_action_cards_updated": card_updates,
        "legacy_action_cards_normalized": legacy_cards_normalized,
        "broad_work_items_parked": parked,
        "focus_proposals": focus_proposals,
        "legacy_systems_collapsed": legacy_collapsed,
        "primary_invariant_violations": int(violations),
        "relationship_conflicts": int(conflicts),
        "reconciliation_mutations": conn.total_changes - mutations_before,
    }


def _set_membership(conn: sqlite3.Connection, *, target_name: str, system_id: int, asset_id: int, relationship: str) -> tuple[int, int]:
    """Keep one relationship per system/asset and make relationship changes explicit."""
    rows = conn.execute("SELECT id,relationship FROM system_asset_links WHERE system_id=? AND asset_id=?", (system_id, asset_id)).fetchall()
    if len(rows) == 1 and str(rows[0]["relationship"]) == relationship:
        return 0, 0
    if rows:
        conn.execute("DELETE FROM system_asset_links WHERE system_id=? AND asset_id=?", (system_id, asset_id))
        created, updated = 0, 1
    else:
        created, updated = 1, 0
    confidence = "high" if relationship == "primary" else "medium"
    conn.execute(
        "INSERT INTO system_asset_links(target_name,system_id,asset_id,relationship,confidence,evidence_refs_json) VALUES(?,?,?,?,?,?)",
        (target_name, system_id, asset_id, relationship, confidence, "[]"),
    )
    return created, updated


def _build_system_proposals(conn: sqlite3.Connection, *, target_name: str, assets=None) -> list[dict]:
    """Build the exact deterministic plan consumed by preview and apply."""
    if assets is None:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(target_assets)")}
        if not _table(conn, "soft_targets"):
            return []
        if not {"id", "asset_value", "scope_class", "scope_status"}.issubset(cols):
            return [
                {
                    "system_key": str(x["asset_value"]).lower().replace(".", "-"),
                    "display_name": str(x["asset_value"]),
                    "canonical_url": f"https://{x['asset_value']}",
                    "source": "soft_target_compat",
                    "proposed_only": True,
                    "root": str(x["asset_value"]),
                    "family": "compat",
                    "scope_class": "unknown",
                    "asset_ids": [],
                    "members": [],
                }
                for x in conn.execute(
                    "SELECT asset_value FROM soft_targets WHERE target_name=? ORDER BY rank,id LIMIT 20", (target_name,)
                ).fetchall()
                if x["asset_value"]
            ]
        assets = conn.execute(
            """SELECT a.id,a.asset_value,a.protocol,a.port,a.scope_class,
                MAX(CASE WHEN s.status='focused' THEN 1 ELSE 0 END) AS focused
            FROM target_assets a JOIN soft_targets s ON s.asset_id=a.id
            WHERE a.target_name=? AND s.target_name=? AND a.scope_status='in_scope'
            GROUP BY a.id,a.asset_value,a.protocol,a.port,a.scope_class""",
            (target_name, target_name),
        ).fetchall()
    groups: dict[tuple[str, str], list[Any]] = {}
    for asset in assets:
        host = str(asset["asset_value"] or "").strip().lower()
        if not _looks_like_host(host):
            continue
        root = _registrable_domain(host)
        label = host.split(".", 1)[0]
        if label.endswith("-sandbox") or label == "sandbox":
            family = "sandbox"
        elif label.startswith("api") or label in {"gateway", "openapi", "oapi"}:
            family = "api"
        elif label.startswith(("static", "cdn")) or label in {"download", "downloads", "assets"}:
            family = "static"
        elif label.startswith("blog"):
            family = "blog"
        elif label.startswith(("dev", "developer")):
            family = "dev"
        elif label.startswith(("contract", "docs", "portal")):
            family = "contracts"
        elif label in {"www", "web"}:
            family = "www"
        elif label in {root.split(".", 1)[0], "home", "main"}:
            family = "core"
        else:
            family = "other"
        groups.setdefault((root, family), []).append(asset)
    proposals = []
    for (root, family), members in sorted(groups.items()):
        ranked = sorted(
            members,
            key=lambda x: (
                int(x["focused"] or 0) if "focused" in x.keys() else 0,
                str(x["scope_class"]).lower() in {"owned", "authorized_vendor", "authorized"},
                str(x["scope_class"]).lower() == "owned",
                int(x["id"]),
            ),
            reverse=True,
        )
        representative = ranked[0]
        key = f"proposal-{root.replace('.', '-')}-{family.replace('.', '-')[:40]}"
        proto = representative["protocol"] or "https"
        host = str(representative["asset_value"]).strip().lower()
        port = representative["port"]
        url = f"{proto}://{host}" + (f":{port}" if port and int(port) not in (80, 443) else "")
        scopes = {str(x["scope_class"]).lower() for x in members}
        scope = "owned" if "owned" in scopes else ("authorized_vendor" if {"authorized_vendor", "authorized"} & scopes else "intel_only")
        display = _system_display_name(root) if family == "www" else f"{_system_display_name(root)} / {family}"
        proposals.append(
            {
                "system_key": key,
                "display_name": display,
                "canonical_url": url,
                "source": "profile_or_service_family",
                "proposed_only": True,
                "root": root,
                "family": family,
                "scope_class": scope,
                "asset_ids": [int(x["id"]) for x in members],
                "members": members,
            }
        )
    return proposals


def _collapse_legacy_asset_systems(conn: sqlite3.Connection, *, target_name: str) -> int:
    legacy = conn.execute(
        "SELECT id FROM target_systems WHERE target_name=? AND created_by='replay' AND system_key LIKE 'asset-%' AND lifecycle_state IN ('discovered','mapping')",
        (target_name,),
    ).fetchall()
    collapsed = 0
    for row in legacy:
        system_id = int(row[0])
        asset_rows = conn.execute("SELECT asset_id FROM system_asset_links WHERE system_id=?", (system_id,)).fetchall()
        if not asset_rows:
            conn.execute("DELETE FROM target_systems WHERE id=?", (system_id,))
            collapsed += 1
            continue
        asset_id = int(asset_rows[0][0])
        asset = conn.execute("SELECT asset_value FROM target_assets WHERE id=?", (asset_id,)).fetchone()
        if asset is None:
            continue
        root = _registrable_domain(str(asset[0]))
        aggregate = conn.execute(
            "SELECT id FROM target_systems WHERE target_name=? AND system_key=?",
            (target_name, f"proposal-{root.replace('.', '-')[:80]}"),
        ).fetchone()
        if aggregate is None:
            conn.execute("DELETE FROM system_asset_links WHERE system_id=?", (system_id,))
            conn.execute("DELETE FROM target_systems WHERE id=?", (system_id,))
            collapsed += 1
            continue
        new_id = int(aggregate[0])
        for table in ("hunt_sessions", "work_items", "operator_inbox"):
            if _table(conn, table):
                cols = {x[1] for x in conn.execute(f"PRAGMA table_info({table})")}
                if "system_id" in cols:
                    conn.execute(f"UPDATE {table} SET system_id=? WHERE system_id=?", (new_id, system_id))  # noqa: S608 -- 表名来自本模块固定三元组，值走参数绑定
        conn.execute("DELETE FROM system_asset_links WHERE system_id=?", (system_id,))
        conn.execute("DELETE FROM target_systems WHERE id=?", (system_id,))
        collapsed += 1
    return collapsed


def _registrable_domain(host: str) -> str:
    value = host.lower().strip().split("/", 1)[0].split(":", 1)[0]
    parts = [part for part in value.split(".") if part]
    return ".".join(parts[-2:]) if len(parts) >= 2 else value


def _looks_like_host(value: str) -> bool:
    return bool(re.fullmatch(r"(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", value.strip()))


def _display_names_path() -> Path:
    return Path(__file__).resolve().parent.parent / "dicts" / "system_display_names.json"


def _system_display_name(root: str) -> str:
    """系统的可读名。

    已知映射放在**不入库的本地字典**里按委托维护（`TOOLS/dicts/system_display_names.json`，
    形如 `{"example.com": "示例系统"}`）；字典缺失时回退到通用名称，不硬编码任何真实目标域名。
    """
    try:
        data = json.loads(_display_names_path().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        data = None
    names = {str(k).lower(): str(v) for k, v in data.items()} if isinstance(data, dict) else {}
    return names.get(root, f"历史候选系统（{root}）")


def _canonical_asset_url(asset: sqlite3.Row) -> str:
    protocol = asset["protocol"] or "https"
    host = str(asset["asset_value"]).strip().lower()
    port = asset["port"]
    return f"{protocol}://{host}" + (f":{port}" if port and int(port) not in (80, 443) else "")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Offline human-focus replay")
    p.add_argument("--target", required=True)
    p.add_argument("--db")
    p.add_argument("--preview", action="store_true")
    p.add_argument("--apply", action="store_true")
    p.add_argument("--backup-dir", default=str(DEFAULT_BACKUP_DIR))
    p.add_argument("--json", action="store_true")
    a = p.parse_args(argv)
    path = Path(a.db).resolve() if a.db else find_db(a.target)
    result = (
        preview(path, target_name=a.target) if not a.apply else apply(path, target_name=a.target, backup_dir=Path(a.backup_dir).resolve())
    )
    print(json.dumps(result, ensure_ascii=False, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
