"""Seed first-pass blackboard work items from fact tables."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

_TOOLS_DIR = Path(__file__).resolve().parent.parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

from db.coverage_backfill import normalize_url  # noqa: E402
from db.coverage_guard import find_negative_coverage, sp_keywords  # noqa: E402
from db.db_utils import connect, find_db  # noqa: E402
from db.system_contract import COLLECTION_LANES  # noqa: E402
from db.work_queue import create_work_item  # noqa: E402
from db.worker_result import compact_public_text  # noqa: E402
from recon.recon_store import ensure_recon_schema  # noqa: E402


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    return bool(conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1", (table,)).fetchone())


def plan_seed_work_items(conn: sqlite3.Connection, *, target_name: str) -> list[dict[str, Any]]:
    ensure_recon_schema(conn)
    items: list[dict[str, Any]] = []
    items.extend(_plan_assets(conn, target_name=target_name))
    items.extend(_plan_recon(conn, target_name=target_name))
    items.extend(_plan_observed_entries(conn, target_name=target_name))
    items.extend(_plan_pages(conn, target_name=target_name))
    items.extend(_plan_js_files(conn, target_name=target_name, limit=15))
    items.extend(_plan_semantic_profiles(conn, target_name=target_name))
    items.extend(_plan_js_clusters(conn, target_name=target_name))
    items.extend(_plan_hunt_queue(conn, target_name=target_name))
    items.extend(_plan_suspicious_points(conn, target_name=target_name))
    items.extend(_plan_findings(conn, target_name=target_name))
    items.extend(_plan_coverage_ledger(conn, target_name=target_name, limit=5))
    return items


def _plan_coverage_ledger(conn: sqlite3.Connection, *, target_name: str, limit: int) -> list[dict[str, Any]]:
    """Derive at most ``limit`` bounded tasks/cards from unresolved coverage."""
    if not _table_exists(conn, "coverage_ledger"):
        return []
    rows = conn.execute(
        """SELECT id,item_key,category,status,summary,next_action
           FROM coverage_ledger
           WHERE target_name=? AND status IN ('unknown','uncovered')
           ORDER BY CASE status WHEN 'uncovered' THEN 0 ELSE 1 END,id""",
        (target_name,),
    ).fetchall()
    planned: list[dict[str, Any]] = []
    for row in rows:
        if len(planned) >= limit:
            break
        ledger_id = str(row["id"])
        subtype = f"coverage:{row['category']}"
        action_key = f"coverage:{ledger_id}"
        if _coverage_derivation_exists(
            conn,
            target_name=target_name,
            ledger_id=ledger_id,
            subtype=subtype,
            action_key=action_key,
        ):
            continue
        item_key = str(row["item_key"])
        category = str(row["category"])
        next_step = row["next_action"] or row["summary"] or "collect evidence"
        objective = compact_public_text(f"coverage={item_key} status={row['status']} next={next_step}", max_chars=400)
        if item_key.startswith("asset:") and category == "asset_liveness":
            asset_value = item_key.split(":", 1)[1]
            asset = conn.execute(
                "SELECT id FROM target_assets WHERE target_name=? AND asset_value=? ORDER BY id LIMIT 1",
                (target_name, asset_value),
            ).fetchone()
            if asset:
                planned.append(
                    _item(
                        lane="asset_triage",
                        subtype=subtype,
                        subject_table="coverage_ledger",
                        subject_id=ledger_id,
                        title=f"Resolve asset coverage #{ledger_id}",
                        objective=objective,
                        priority=58,
                        risk_class="safe_passive",
                    )
                )
            continue
        if item_key.startswith("endpoint:") and category == "endpoint_recon":
            endpoint_url = item_key.split(":", 1)[1]
            endpoint = None
            endpoint_rows = conn.execute(
                """SELECT e.id,e.asset_id,e.canonical_url,
                          a.scope_status,a.scope_class,a.authorization_state
                   FROM endpoint_observations e
                   LEFT JOIN target_assets a ON a.id=e.asset_id AND a.target_name=e.target_name
                   WHERE e.target_name=? ORDER BY e.id""",
                (target_name,),
            ).fetchall()
            for candidate in endpoint_rows:
                if normalize_url(candidate["canonical_url"]) == endpoint_url:
                    endpoint = candidate
                    break
            active_scope = bool(
                endpoint
                and endpoint["asset_id"] is not None
                and endpoint["scope_status"] == "in_scope"
                and endpoint["scope_class"] in {"owned", "authorized_vendor"}
                and endpoint["authorization_state"] == "authorized"
            )
            if active_scope:
                planned.append(
                    _item(
                        lane="quick_scout",
                        subtype=subtype,
                        subject_table="coverage_ledger",
                        subject_id=ledger_id,
                        title=f"Resolve endpoint coverage #{ledger_id}",
                        objective=objective,
                        priority=62,
                        risk_class="safe_passive",
                    )
                )
            else:
                planned.append(
                    _coverage_action_item(
                        row,
                        kind="confirm_scope",
                        reason=("Endpoint is not linked to an explicitly authorized in-scope asset; no active lane may be queued."),
                    )
                )
            continue
        if item_key.startswith("sp:") or category == "vuln_probe" or category.startswith("lane:logic_probe"):
            planned.append(
                _coverage_action_item(
                    row,
                    kind="manual_review",
                    reason="Active probe coverage requires an operator decision; no probe work item was queued.",
                )
            )
    return planned


def _coverage_action_item(row: sqlite3.Row, *, kind: str, reason: str) -> dict[str, Any]:
    return {
        "action_only": True,
        "action_kind": kind,
        "action_key": f"coverage:{row['id']}",
        "action_label": f"Review coverage item #{row['id']}",
        "why_needed": reason,
        "steps": ["Review compact coverage state and scope", "Choose a bounded next action or leave blocked"],
        "expected_observation": "A recorded operator decision with scope and risk boundaries",
        "report_back_format": "coverage_id=<id>; decision=<queue|block|skip>; reason=<compact reason>",
        "blocking": True,
        "coverage_id": str(row["id"]),
    }


def _coverage_derivation_exists(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    ledger_id: str,
    subtype: str,
    action_key: str,
) -> bool:
    work = conn.execute(
        """SELECT 1 FROM work_items
           WHERE target_name=? AND subject_table='coverage_ledger' AND subject_id=?
             AND COALESCE(subtype,'')=? LIMIT 1""",
        (target_name, ledger_id, subtype),
    ).fetchone()
    if work:
        return True
    columns = {row[1] for row in conn.execute("PRAGMA table_info(operator_inbox)")} if _table_exists(conn, "operator_inbox") else set()
    if "action_key" not in columns:
        return False
    return (
        conn.execute(
            "SELECT 1 FROM operator_inbox WHERE target_name=? AND action_key=? LIMIT 1",
            (target_name, action_key),
        ).fetchone()
        is not None
    )


def _plan_recon(conn: sqlite3.Connection, *, target_name: str) -> list[dict[str, Any]]:
    """Create L3 recon tasks only for assets linked to the active deep-focus system."""
    items: list[dict[str, Any]] = []
    active_system_id = _active_system_id(conn, target_name=target_name)
    if active_system_id is None:
        # L0 remains external (asset facts/source adapters); this planner must not
        # turn a broad asset set into AI collection work without a deep session.
        return items
    assets = conn.execute(
        """SELECT id, asset_value, resolved_ip, live_status, last_tech_stack,
                  scope_status, scope_class, authorization_state
           FROM target_assets WHERE target_name=?
           ORDER BY priority DESC, id ASC""",
        (target_name,),
    ).fetchall()
    for row in assets:
        if row["live_status"] not in {"live", "unknown"}:
            continue
        asset = row["asset_value"]
        active_scope = (
            row["scope_status"] == "in_scope"
            and row["scope_class"] in {"owned", "authorized_vendor"}
            and row["authorization_state"] == "authorized"
        )
        if not active_scope:
            continue
        # A system may only operate on a uniquely linked asset. Unlinked and
        # cross-system ambiguous assets stay out of the L3 queue.
        links = (
            conn.execute(
                """SELECT DISTINCT system_id FROM system_asset_links
               WHERE target_name=? AND asset_id=?""",
                (target_name, row["id"]),
            ).fetchall()
            if _table_exists(conn, "system_asset_links")
            else []
        )
        linked_systems = {int(link[0]) for link in links if link[0] is not None}
        if linked_systems != {active_system_id}:
            continue
        if not row["resolved_ip"]:
            items.append(
                _item(
                    lane="source_intel",
                    subtype="asset_intel",
                    subject_table="target_assets",
                    subject_id=str(row["id"]),
                    title=f"Expand public intel for {asset}",
                    objective=("Collect passive DNS, certificate, sibling/C-range, source-code and public search evidence."),
                    priority=78,
                    model_tier="haiku",
                    reasoning_tier="low",
                    timebox_minutes=8,
                    system_id=active_system_id,
                )
            )
        items.append(
            _item(
                lane="network_profile",
                subtype="network_profile",
                subject_table="target_assets",
                subject_id=str(row["id"]),
                title=f"Profile network surface {asset}",
                objective=("Run bounded authorized TCP/service/WAF observations; missing tools must return blocked/unknown."),
                priority=76,
                model_tier="haiku",
                reasoning_tier="low",
                risk_class="safe_replay",
                timebox_minutes=8,
                system_id=active_system_id,
            )
        )
        items.append(
            _item(
                lane="entry_probe",
                subtype="entry_family",
                subject_table="target_assets",
                subject_id=str(row["id"]),
                title=f"Enumerate equivalent entries {asset}",
                objective=("Generate and low-volume probe login/register/admin/api/docs route families without site crawling."),
                priority=82,
                model_tier="haiku",
                reasoning_tier="low",
                risk_class="safe_replay",
                timebox_minutes=6,
                system_id=active_system_id,
            )
        )
        items.append(
            _item(
                lane="preauth_probe",
                subtype="asset_boundary",
                subject_table="target_assets",
                subject_id=str(row["id"]),
                title=f"Measure pre-auth boundary {asset}",
                objective=("Measure public/auth redirect/restricted/WAF states with a bounded GET/HEAD/OPTIONS budget."),
                priority=86,
                model_tier="haiku",
                reasoning_tier="low",
                risk_class="safe_replay",
                timebox_minutes=8,
                system_id=active_system_id,
            )
        )
        if row["resolved_ip"]:
            items.append(
                _item(
                    lane="origin_verify",
                    subtype="origin_verify",
                    subject_table="target_assets",
                    subject_id=str(row["id"]),
                    title=f"Verify origin candidates {asset}",
                    objective="Verify only in-scope high-confidence origin candidates using Host/SNI-aware checks.",
                    priority=84,
                    model_tier="sonnet",
                    reasoning_tier="low",
                    risk_class="sensitive_read",
                    timebox_minutes=8,
                    system_id=active_system_id,
                )
            )
    return items


def _plan_observed_entries(conn: sqlite3.Connection, *, target_name: str) -> list[dict[str, Any]]:
    """Route observed entry facts into bounded exploration tasks."""
    if not _table_exists(conn, "entry_observations"):
        return []
    rows = conn.execute(
        """SELECT id, url, entry_type, status, confidence, response_class
           FROM entry_observations
           WHERE target_name=? AND status IN ('observed', 'restricted')
             AND entry_type IN ('login','register','admin','api')
           ORDER BY id ASC""",
        (target_name,),
    ).fetchall()
    return [
        _item(
            lane="entry_explore",
            subtype="observed_entry",
            subject_table="entry_observations",
            subject_id=str(row["id"]),
            title=f"Explore observed {row['entry_type']} entry {row['url']}",
            objective=row["response_class"] or row["confidence"] or "observed entry",
            priority=72 if row["entry_type"] in {"login", "admin"} else 60,
            model_tier="haiku",
            reasoning_tier="low",
            risk_class="safe_passive",
            timebox_minutes=10,
        )
        for row in rows
    ]


def apply_seed(conn: sqlite3.Connection, *, target_name: str, dry_run: bool) -> dict[str, Any]:
    plan = plan_seed_work_items(conn, target_name=target_name)
    # dict 里 int 与 dict 混存，需要显式联合类型，否则 mypy 退化成 object 导致后续 += / items() 报错
    summary: dict[str, Any] = {"created": 0, "skipped_existing": 0, "action_cards_created": 0, "by_lane": {}}
    active_system_id = _active_system_id(conn, target_name=target_name)
    if _requires_active_system(conn, target_name=target_name) and active_system_id is None:
        # Without an operator-focused system only collection/recon lanes may seed:
        # test lanes must not turn historical, unassigned facts into executable
        # work before a focus exists. Collection lanes keep running so recon can
        # gather across many systems (see system_contract.COLLECTION_LANES).
        test_items = [item for item in plan if item.get("lane") not in COLLECTION_LANES]
        if test_items:
            summary["blocked_reason"] = "active_system_required"
            summary["blocked_test_lane_count"] = len(test_items)
            plan = [item for item in plan if item.get("lane") in COLLECTION_LANES]
    if not dry_run:
        summary["action_cards_reconciled"] = _reconcile_orphan_operator_tasks(conn, target_name=target_name, system_id=active_system_id)

    for item in plan:
        if item.get("action_only"):
            summary["created"] += 1
            if dry_run:
                continue
            from db.operator_actions import create_action_card

            create_action_card(
                conn,
                target_name=target_name,
                system_id=active_system_id,
                kind=item["action_kind"],
                action_key=item["action_key"],
                action_label=item["action_label"],
                why_needed=item["why_needed"],
                steps=item["steps"],
                expected_observation=item["expected_observation"],
                report_back_format=item["report_back_format"],
                blocking=item["blocking"],
            )
            summary["action_cards_created"] += 1
            continue
        lane = item["lane"]
        if active_system_id is not None and lane in {"asset_triage", "operator_task"}:
            summary["skipped_existing"] += 1
            continue
        summary["by_lane"].setdefault(lane, 0)
        if _work_item_exists(
            conn,
            target_name=target_name,
            lane=lane,
            subject_table=item["subject_table"],
            subject_id=item["subject_id"],
            subtype=item.get("subtype"),
        ):
            summary["skipped_existing"] += 1
            continue

        summary["created"] += 1
        summary["by_lane"][lane] += 1
        if dry_run:
            continue

        create_work_item(
            conn,
            target_name=target_name,
            lane=lane,
            subtype=item.get("subtype"),
            subject_table=item["subject_table"],
            subject_id=item["subject_id"],
            title=item.get("title", ""),
            objective=item.get("objective", ""),
            priority=item.get("priority", 50),
            model_tier=item.get("model_tier", "sonnet"),
            reasoning_tier=item.get("reasoning_tier", "low"),
            auth_requirement=item.get("auth_requirement", "unknown"),
            risk_class=item.get("risk_class", "safe_passive"),
            timebox_minutes=item.get("timebox_minutes", 10),
            heartbeat_minutes=item.get("heartbeat_minutes", 5),
            system_id=item.get("system_id"),
        )

    summary["by_lane"] = {lane: count for lane, count in sorted(summary["by_lane"].items()) if count > 0}
    return summary


def _reconcile_orphan_operator_tasks(conn: sqlite3.Connection, *, target_name: str, system_id: int | None) -> int:
    columns = {row[1] for row in conn.execute("PRAGMA table_info(operator_inbox)")} if _table_exists(conn, "operator_inbox") else set()
    if "action_key" not in columns or not _table_exists(conn, "work_items"):
        return 0
    from db.operator_actions import create_action_card

    rows = conn.execute(
        """SELECT id,title,objective FROM work_items
           WHERE target_name=? AND lane='operator_task'
             AND status IN ('queued','partial','blocked')""",
        (target_name,),
    ).fetchall()
    created = 0
    for row in rows:
        exists = conn.execute(
            "SELECT 1 FROM operator_inbox WHERE target_name=? AND related_work_item_id=? AND status='open'",
            (target_name, row["id"]),
        ).fetchone()
        if exists:
            continue
        create_action_card(
            conn,
            target_name=target_name,
            system_id=system_id,
            kind="evidence_capture",
            action_key=f"legacy-incomplete:{row['id']}",
            action_label=f"补全人工任务 #{row['id']}",
            why_needed=f"历史 operator task 缺少结构化行动卡：{row['objective'] or '请补全目标、URL、步骤和回填格式'}",
            steps=[],
            expected_observation="",
            report_back_format="",
            url=None,
            related_work_item_id=int(row["id"]),
            blocking=True,
            incomplete=True,
        )
        created += 1
    return created


def _active_system_id(conn: sqlite3.Connection, *, target_name: str) -> int | None:
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    if "schema_version" not in tables or "hunt_sessions" not in tables or "target_systems" not in tables:
        return None
    if conn.execute("SELECT 1 FROM schema_version WHERE version>=33 LIMIT 1").fetchone() is None:
        return None
    row = conn.execute(
        "SELECT system_id FROM hunt_sessions WHERE target_name=? AND status='active' ORDER BY id DESC LIMIT 1",
        (target_name,),
    ).fetchone()
    return int(row[0]) if row and row[0] is not None else None


def _requires_active_system(conn: sqlite3.Connection, *, target_name: str) -> bool:
    if not _table_exists(conn, "schema_version") or not _table_exists(conn, "target_systems"):
        return False
    if conn.execute("SELECT 1 FROM schema_version WHERE version>=33 LIMIT 1").fetchone() is None:
        return False
    row = conn.execute("SELECT 1 FROM target_systems WHERE target_name=? LIMIT 1", (target_name,)).fetchone()
    return row is not None


def _plan_assets(conn: sqlite3.Connection, *, target_name: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for row in conn.execute(
        """
        SELECT id, target_name, domain, notes
        FROM targets
        WHERE target_name = ?
        """,
        (target_name,),
    ).fetchall():
        items.append(
            _item(
                lane="asset_triage",
                subject_table="targets",
                subject_id=str(row["id"]),
                title=f"Asset triage target {target_name}",
                objective=row["domain"] or row["notes"] or "triage target root",
                priority=60,
            )
        )

    for row in conn.execute(
        """
        SELECT id, asset_type, asset_value, status, priority, notes
        FROM target_assets
        WHERE target_name = ?
          AND COALESCE(status, 'new') IN ('new', 'validated', 'queued')
        ORDER BY priority DESC, id ASC
        """,
        (target_name,),
    ).fetchall():
        items.append(
            _item(
                lane="asset_triage",
                subject_table="target_assets",
                subject_id=str(row["id"]),
                title=f"Asset triage {row['asset_value']}",
                objective=row["notes"] or row["asset_type"] or "triage asset",
                priority=max(40, int(row["priority"] or 0) + 40),
            )
        )
    return items


def _plan_semantic_profiles(conn: sqlite3.Connection, *, target_name: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    rows = conn.execute(
        """
        SELECT st.id, st.asset_value, st.tier, st.total_score, st.status
        FROM soft_targets st
        WHERE st.target_name = ?
          AND st.status = 'focused'
          AND NOT EXISTS (
              SELECT 1
              FROM attack_surface_profiles p
              WHERE p.target_name = st.target_name
                AND p.subject_table = 'soft_targets'
                AND p.subject_id = CAST(st.id AS TEXT)
                AND p.status IN ('draft', 'active')
          )
        ORDER BY st.focused_at DESC, st.total_score DESC, st.id DESC
        """,
        (target_name,),
    ).fetchall()
    for row in rows:
        items.append(
            _item(
                lane="semantic_profile",
                subject_table="soft_targets",
                subject_id=str(row["id"]),
                subtype="focused_target_profile",
                title=f"Profile focused target {row['asset_value']}",
                objective=(
                    "Create compact open-ended attack surface semantic profile and coverage ledger; "
                    "preserve unknown, uncovered and blocked items."
                ),
                priority=max(68, int(row["total_score"] or 0)),
                model_tier="sonnet",
                reasoning_tier="low",
                auth_requirement="unknown",
                risk_class="safe_passive",
                timebox_minutes=12,
            )
        )
    return items


def _plan_pages(conn: sqlite3.Connection, *, target_name: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    url_scope = _target_url_scope(conn, target_name=target_name)
    page_rows = conn.execute(
        """
        SELECT id, url, status, title, js_files_json, api_calls_json, signal_value, signal_reason
        FROM pages
        ORDER BY id
        """
    ).fetchall()
    page_js_index = _page_js_index(conn)

    for row in page_rows:
        if not _url_in_scope(row["url"], url_scope):
            continue
        signal_value = row["signal_value"] or ""
        signal_reason = row["signal_reason"] or ""
        status = row["status"] or ""
        is_blank = not (row["title"] or "").strip()
        js_rich = _is_js_rich_page(row, page_js_index.get(row["url"], []))

        if js_rich and is_blank:
            items.append(
                _item(
                    lane="js_reverse",
                    subject_table="pages",
                    subject_id=str(row["id"]),
                    subtype="api_extract",
                    title=f"Reverse blank JS-rich page {row['url']}",
                    objective=signal_reason or "blank page with strong JS/API clues",
                    priority=75,
                )
            )
            continue

        if status == "queued":
            items.append(
                _item(
                    lane="quick_scout",
                    subject_table="pages",
                    subject_id=str(row["id"]),
                    title=f"Quick scout {row['url']}",
                    objective=signal_reason or "queued page exploration",
                    priority=55 if signal_value == "high_value" else 45,
                )
            )
            continue

        if signal_value in {"high_value", "medium_value"} and signal_reason != "public_or_configuration_signal":
            items.append(
                _item(
                    lane="entry_explore",
                    subject_table="pages",
                    subject_id=str(row["id"]),
                    title=f"Explore page {row['url']}",
                    objective=signal_reason or signal_value,
                    priority=65 if signal_value == "high_value" else 50,
                )
            )
    return items


def _plan_js_files(conn: sqlite3.Connection, *, target_name: str, limit: int = 15) -> list[dict[str, Any]]:
    """New-pipeline js_reverse tasks: one work_item per captured js_files row (subject_table=js_files).

    The new JS pipeline (Playwright capture -> TOOLS/pipeline/js_recon.py -> js_reverse
    deep-read) consumes ``js_files`` rows with a ``local_path`` (raw JS on disk). The
    js-reversing-helper lane contract resolves the file via ``js_files.id``, so the
    work_item subject MUST point at ``js_files`` — not the legacy ``pages`` /
    ``js_signal_clusters`` ids that the old planner emitted (those break Step 2 of the
    lane definition and the subagent falls back to reading JS by hand instead of
    running the toolchain). Skipped subjects: rows with no local content yet
    (``local_path`` empty / extraction not collected), and rows already covered by a
    js_reverse work_item (dedup in apply_seed via _work_item_exists).

    ``limit`` caps the rows planned per seed call (highest signal_count first); seed is
    idempotent so later ticks pick up the remaining rows, avoiding a one-shot flood of
    hundreds of queued js_reverse items.
    """
    if not _table_exists(conn, "js_files"):
        return []
    url_scope = _target_url_scope(conn, target_name=target_name)
    rows = conn.execute(
        """
        SELECT id, url, page_url, local_path, source_kind, extraction_status,
               signal_count, source_map_status
        FROM js_files
        ORDER BY COALESCE(signal_count, 0) DESC, id ASC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    items: list[dict[str, Any]] = []
    for row in rows:
        if not _url_in_scope(row["url"], url_scope) and not _url_in_scope(row["page_url"], url_scope):
            continue
        local_path = str(row["local_path"] or "").strip()
        extraction_status = str(row["extraction_status"] or "").strip()
        # Only rows whose content is actually on disk / already extracted are runnable.
        if not local_path and extraction_status not in {"collected", "extracted"}:
            continue
        source_kind = str(row["source_kind"] or "").strip()
        signal_count = int(row["signal_count"] or 0)
        priority = 60 + min(15, signal_count // 2)
        subtype = "api_extract"
        if source_kind == "source_map_source":
            subtype = "business_api"
        items.append(
            _item(
                lane="js_reverse",
                subject_table="js_files",
                subject_id=str(row["id"]),
                subtype=subtype,
                title=f"Reverse JS file {row['url']}",
                objective=(
                    f"run the JS toolchain on js_files#{row['id']} (local_path={local_path or 'collected'}); "
                    f"extract endpoints/signatures/secrets; promote to suspicious_points via coverage_guard"
                ),
                priority=priority,
                timebox_minutes=30,
                heartbeat_minutes=10,
            )
        )

    # 兜底：js_files 有 url 但从未落盘（local_path 全空、非 collected/extracted）
    # 时，js_reverse 无法派发，JS 管线会静默死亡。此时生成一个 source_intel work_item，
    # 明确提示先把脚本落盘（浏览器/采集侧写回 js_files.local_path），再逐个走
    # `TOOLS/pipeline/js_recon.py --target ... --js-id <js_files.id>` 落库信号。
    pending_rows = conn.execute(
        """
        SELECT COUNT(*) FROM js_files
        WHERE COALESCE(local_path, '') = ''
          AND COALESCE(extraction_status, '') NOT IN ('collected', 'extracted')
        """
    ).fetchone()[0]
    if pending_rows and not items:
        items.append(
            _item(
                lane="source_intel",
                subject_table="js_files",
                subject_id="pending",
                subtype="js_recon",
                title=f"Run js_recon for {pending_rows} pending js_files",
                objective=(
                    f"{pending_rows} 个 js_files 尚未落盘（local_path 为空）。"
                    "先在浏览器/采集侧确认脚本已落盘并把本地路径写回 js_files.local_path，"
                    '再逐个跑 `uv run python TOOLS/pipeline/js_recon.py --target "{target_name}" --js-id <js_files.id>` '
                    "（采集+还原+落库一条命令，产物落 tmp/js_reverse/<case>/，含 summary.json）；"
                    "落库后 js_files.extraction_status 变 extracted，js_reverse 任务才会生成。"
                ),
                priority=70,
                timebox_minutes=30,
                heartbeat_minutes=10,
            )
        )
    return items


def _plan_js_clusters(conn: sqlite3.Connection, *, target_name: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    rows = conn.execute(
        """
        SELECT c.*
        FROM js_signal_clusters c
        JOIN targets t ON t.id = c.target_id
        WHERE t.target_name = ?
        ORDER BY c.best_risk_score DESC, c.id ASC
        """,
        (target_name,),
    ).fetchall()
    for row in rows:
        status = row["status"] or ""
        signal_types = _json_loads_list(row["signal_types_json"])
        best_risk = int(row["best_risk_score"] or 0)

        js_subtype = None
        if status == "needs_auth":
            js_subtype = "auth_material"
        elif status == "needs_signature" or _contains_any(signal_types, ("signature", "crypto")):
            js_subtype = "signature_chain"
        elif _contains_any(signal_types, ("business_api", "api_endpoint", "auth_material")):
            js_subtype = "business_api" if _contains_any(signal_types, ("business_api",)) else "api_extract"

        if js_subtype or best_risk >= 70:
            items.append(
                _item(
                    lane="js_reverse",
                    subject_table="js_signal_clusters",
                    subject_id=str(row["id"]),
                    subtype=js_subtype or "api_extract",
                    title=f"Reverse JS cluster {row['id']}",
                    objective=row["canonical_url"] or row["fingerprint"],
                    priority=max(60, best_risk),
                )
            )

        if best_risk >= 70 and _contains_any(signal_types, ("business_api", "signature")):
            items.append(
                _item(
                    lane="hypothesis",
                    subject_table="js_signal_clusters",
                    subject_id=str(row["id"]),
                    subtype="business_api",
                    title=f"Hypothesis for JS cluster {row['id']}",
                    objective=row["canonical_url"] or row["fingerprint"],
                    priority=max(70, best_risk),
                    model_tier="opus",
                    reasoning_tier="medium",
                )
            )
    return items


def _plan_hunt_queue(conn: sqlite3.Connection, *, target_name: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT h.id, h.url, h.business_intent, h.signal_reason, h.risk_score
        FROM hunt_queue h
        JOIN targets t ON t.id = h.target_id
        WHERE t.target_name = ?
          AND h.status = 'queued'
        ORDER BY COALESCE(h.risk_score, 0) DESC, h.id ASC
        """,
        (target_name,),
    ).fetchall()
    return [
        _item(
            lane="logic_probe",
            subject_table="hunt_queue",
            subject_id=str(row["id"]),
            title=f"Probe {row['url']}",
            objective=row["business_intent"] or row["signal_reason"] or row["url"],
            priority=max(55, int(row["risk_score"] or 0)),
            risk_class="safe_replay",
        )
        for row in rows
    ]


def _plan_suspicious_points(conn: sqlite3.Connection, *, target_name: str) -> list[dict[str, Any]]:
    url_scope = _target_url_scope(conn, target_name=target_name)
    rows = conn.execute(
        """
        SELECT sp.id, sp.page_url, sp.url, sp.param, sp.method, sp.reasoning, sp.risk,
               sp.test_type, sp.source, sp.notes, sp.auth_surface_type, sp.signal_value,
               sp.signal_reason, sp.risk_score, sp.evidence
        FROM suspicious_points sp
        WHERE sp.test_status = 'untested'
          AND COALESCE(sp.noise_reason, '') = ''
        ORDER BY sp.created_at ASC, sp.id ASC
        """
    ).fetchall()
    items: list[dict[str, Any]] = []
    for row in rows:
        if not _suspicious_point_in_scope(row, url_scope):
            continue

        # 历史负结论抑制：该攻击面已在 coverage_ledger 验证为 covered/blocked 时，
        # 不得作为新怀疑点重复升级（如 fastjson @type 已验证不可利用又当新发现）。
        coverage_hits = find_negative_coverage(
            conn,
            target_name=target_name,
            keywords=sp_keywords(
                test_type=row["test_type"],
                signal_reason=row["signal_reason"],
                reasoning=row["reasoning"],
                evidence=row["evidence"],
            ),
        )
        if coverage_hits:
            top = coverage_hits[0]
            reason = f"coverage_negative:{top['item_key']}"
            conn.execute(
                "UPDATE suspicious_points SET noise_reason=?, notes=COALESCE(notes,'')||'\n'||? WHERE id=?",
                (
                    reason,
                    f"[coverage_guard] 历史负结论 {top['status']} ({top['item_key']}): "
                    f"{(top['summary'] or top['blocker_reason'] or '')[:200]}；不重复升级",
                    row["id"],
                ),
            )
            conn.commit()
            continue

        gate = _suspicious_point_gate(row)
        if gate:
            items.append(
                _item(
                    lane="operator_task",
                    subject_table="suspicious_points",
                    subject_id=str(row["id"]),
                    subtype="vuln_review_gate",
                    title=f"Operator gate suspicious point {row['id']}",
                    objective=_sp_compact_objective(row, gate=gate),
                    priority=90,
                    auth_requirement=gate["auth_requirement"],
                    risk_class=gate["risk_class"],
                )
            )
            continue

        items.append(
            _item(
                lane="vuln_review",
                subject_table="suspicious_points",
                subject_id=str(row["id"]),
                subtype="single_sp_review",
                title=f"Review suspicious point {row['id']}",
                objective=_sp_compact_objective(row),
                priority=60 if _sp_risk_level(row) == "medium" else 55,
                model_tier="sonnet",
                reasoning_tier="low",
                auth_requirement=_sp_auth_requirement(row),
                risk_class="safe_replay",
                timebox_minutes=10,
            )
        )
    return items


def _plan_findings(conn: sqlite3.Connection, *, target_name: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT f.id, f.url, f.type, f.review_status, f.evidence, f.report_file
        FROM findings f
        JOIN targets t ON t.id = f.target_id
        WHERE t.target_name = ?
          AND COALESCE(f.review_status, 'candidate') IN ('candidate', 'confirmed', 'included')
          AND (
              COALESCE(f.evidence, '') = ''
              OR COALESCE(f.report_file, '') = ''
          )
        ORDER BY f.confirmed_at ASC, f.id ASC
        """,
        (target_name,),
    ).fetchall()
    return [
        _item(
            lane="evidence_pack",
            subject_table="findings",
            subject_id=str(row["id"]),
            title=f"Prepare evidence for {row['id']}",
            objective=row["type"] or row["url"] or row["id"],
            priority=65,
        )
        for row in rows
    ]


def _page_js_index(conn: sqlite3.Connection) -> dict[str, list[sqlite3.Row]]:
    rows = conn.execute(
        """
        SELECT page_url, url, discovered_apis_json, internal_routes_json, source_map_url, source_kind
        FROM js_files
        """
    ).fetchall()
    mapping: dict[str, list[sqlite3.Row]] = {}
    for row in rows:
        mapping.setdefault(row["page_url"], []).append(row)
    return mapping


def _target_url_scope(conn: sqlite3.Connection, *, target_name: str) -> set[str]:
    values: set[str] = set()
    for row in conn.execute(
        """
        SELECT domain
        FROM targets
        WHERE target_name = ?
          AND COALESCE(domain, '') != ''
        """,
        (target_name,),
    ).fetchall():
        values.update(_scope_values(row["domain"]))

    for row in conn.execute(
        """
        SELECT asset_type, asset_value
        FROM target_assets
        WHERE target_name = ?
          AND asset_type IN ('domain', 'subdomain', 'ip', 'url')
          AND COALESCE(status, 'new') != 'excluded'
        """,
        (target_name,),
    ).fetchall():
        values.update(_scope_values(row["asset_value"]))
    return values


def _scope_values(raw: str | None) -> set[str]:
    if not raw:
        return set()
    value = raw.strip().lower()
    if not value:
        return set()
    parsed = urlparse(value if "://" in value else f"//{value}")
    host = parsed.hostname or value
    host = host.strip().lower().lstrip("*.").rstrip(".")
    return {host} if host else set()


def _url_in_scope(raw_url: str | None, scope: set[str]) -> bool:
    if not scope:
        return True
    if not raw_url:
        return False
    value = raw_url.strip().lower()
    parsed = urlparse(value if "://" in value else f"//{value}")
    host = (parsed.hostname or value).strip().lower().rstrip(".")
    if not host:
        return False
    return any(host == item or host.endswith(f".{item}") for item in scope)


def _suspicious_point_in_scope(row: sqlite3.Row, scope: set[str]) -> bool:
    if _url_in_scope(row["url"], scope):
        return True
    return _url_in_scope(row["page_url"], scope)


def _suspicious_point_gate(row: sqlite3.Row) -> dict[str, str] | None:
    risk = _sp_risk_level(row)
    auth_requirement = _sp_auth_requirement(row)
    text = _sp_joined_text(row)

    if risk in {"high", "critical"}:
        return {
            "reason": f"{risk}_risk_requires_operator_confirmation",
            "auth_requirement": auth_requirement,
            "risk_class": "high_risk",
        }
    if auth_requirement in {"required", "multi_account_required", "role_required"}:
        return {
            "reason": f"{auth_requirement}_boundary_requires_operator_confirmation",
            "auth_requirement": auth_requirement,
            "risk_class": "sensitive_read",
        }
    if _contains_operator_required_signal(text):
        return {
            "reason": "operator_required_signal",
            "auth_requirement": auth_requirement,
            "risk_class": "sensitive_read",
        }
    return None


def _sp_compact_objective(row: sqlite3.Row, gate: dict[str, str] | None = None) -> str:
    parts = [
        f"sp={row['id']}",
        f"type={row['test_type'] or 'unknown'}",
        f"method={row['method'] or 'GET'}",
        f"url_ref={_compact_url_ref(row['url'] or row['page_url'])}",
    ]
    if row["param"]:
        parts.append(f"param={compact_public_text(row['param'], max_chars=80)}")
    if row["source"]:
        parts.append(f"source={compact_public_text(row['source'], max_chars=80)}")
    if row["signal_reason"]:
        parts.append(f"signal={compact_public_text(row['signal_reason'], max_chars=160)}")
    elif row["reasoning"]:
        parts.append(f"reason={compact_public_text(row['reasoning'], max_chars=160)}")
    if gate:
        parts.append(f"operator_gate={gate['reason']}")
    parts.append("raw_evidence_policy=use evidence_refs/fact tables only")
    return compact_public_text(" | ".join(parts), max_chars=500)


def _compact_url_ref(raw_url: str | None) -> str:
    if not raw_url:
        return "unknown"
    text = compact_public_text(raw_url, max_chars=180)
    parsed = urlparse(text if "://" in text else f"//{text}")
    host = parsed.hostname or ""
    path = parsed.path or ""
    if not host:
        return text
    if len(path) > 80:
        path = path[:79].rstrip("/") + "…"
    return f"{host}{path}"


def _sp_risk_level(row: sqlite3.Row) -> str:
    risk = str(row["risk"] or "").strip().lower()
    if risk in {"critical", "high", "medium", "low"}:
        return risk
    score = int(row["risk_score"] or 0)
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def _sp_auth_requirement(row: sqlite3.Row) -> str:
    text = _sp_joined_text(row)
    if any(token in text for token in ("secondary", "a/b", "a b", "multi_account", "idor", "越权", "双账号")):
        return "multi_account_required"
    if any(token in text for token in ("role", "admin", "vertical", "role_account", "角色", "管理员")):
        return "role_required"
    if any(
        token in text
        for token in (
            "requires_auth",
            "auth_required",
            "authenticated_api",
            "login_required",
            "needs_login",
            "session",
            "cookie",
            "authorization",
            "bearer",
            "登录",
            "认证边界",
        )
    ):
        return "required"
    return "unknown"


def _contains_operator_required_signal(text: str) -> bool:
    return any(
        token in text
        for token in (
            "operator_required",
            "operator-required",
            "manual_review",
            "needs_operator",
            "confirm_scope",
            "人工",
            "操作员",
            "授权边界",
            "高危",
        )
    )


def _sp_joined_text(row: sqlite3.Row) -> str:
    return " ".join(
        str(row[key] or "").lower()
        for key in (
            "id",
            "test_type",
            "source",
            "reasoning",
            "notes",
            "auth_surface_type",
            "signal_value",
            "signal_reason",
        )
    )


def _is_js_rich_page(page_row: sqlite3.Row, js_rows: list[sqlite3.Row]) -> bool:
    if _json_loads_list(page_row["js_files_json"]):
        return True
    if _json_loads_list(page_row["api_calls_json"]):
        return True
    for js_row in js_rows:
        if _json_loads_list(js_row["discovered_apis_json"]):
            return True
        if _json_loads_list(js_row["internal_routes_json"]):
            return True
        if js_row["source_map_url"]:
            return True
        if "chunk" in (js_row["url"] or "").lower():
            return True
    return False


def _work_item_exists(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    lane: str,
    subject_table: str,
    subject_id: str,
    subtype: str | None,
) -> bool:
    if lane == "evidence_pack" and subject_table == "findings":
        row = conn.execute(
            """
            SELECT 1
            FROM work_items
            WHERE target_name = ?
              AND lane = ?
              AND subject_table = ?
              AND subject_id = ?
            LIMIT 1
            """,
            (target_name, lane, subject_table, subject_id),
        ).fetchone()
        return row is not None
    row = conn.execute(
        """
        SELECT 1
        FROM work_items
        WHERE target_name = ?
          AND lane = ?
          AND subject_table = ?
          AND subject_id = ?
          AND COALESCE(subtype, '') = COALESCE(?, '')
        LIMIT 1
        """,
        (target_name, lane, subject_table, subject_id, subtype),
    ).fetchone()
    return row is not None


def _item(
    *,
    lane: str,
    subject_table: str,
    subject_id: str,
    subtype: str | None = None,
    title: str = "",
    objective: str = "",
    priority: int = 50,
    model_tier: str = "sonnet",
    reasoning_tier: str = "low",
    auth_requirement: str = "unknown",
    risk_class: str = "safe_passive",
    timebox_minutes: int = 10,
    heartbeat_minutes: int = 5,
    system_id: int | None = None,
) -> dict[str, Any]:
    return {
        "lane": lane,
        "subject_table": subject_table,
        "subject_id": subject_id,
        "subtype": subtype,
        "title": title,
        "objective": objective,
        "priority": priority,
        "model_tier": model_tier,
        "reasoning_tier": reasoning_tier,
        "auth_requirement": auth_requirement,
        "risk_class": risk_class,
        "timebox_minutes": timebox_minutes,
        "heartbeat_minutes": heartbeat_minutes,
        "system_id": system_id,
    }


def _json_loads_list(raw: str | None) -> list[Any]:
    if not raw:
        return []
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return []
    return value if isinstance(value, list) else []


def _contains_any(values: list[Any], needles: tuple[str, ...]) -> bool:
    joined = " ".join(str(v).lower() for v in values)
    return any(needle in joined for needle in needles)


def _resolve_db_path(args: argparse.Namespace) -> Path:
    if args.db:
        return Path(args.db)
    return find_db(args.target)


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed blackboard work items from fact tables")
    parser.add_argument("--target", required=True, help="target_name in the DB")
    parser.add_argument("--db", help="explicit DB path")
    parser.add_argument("--dry-run", action="store_true", help="plan only, do not write")
    parser.add_argument("--apply", action="store_true", help="write work_items")
    args = parser.parse_args()

    dry_run = True
    if args.apply:
        dry_run = False
    elif args.dry_run:
        dry_run = True

    db_path = _resolve_db_path(args)
    conn = connect(db_path)
    try:
        result = apply_seed(conn, target_name=args.target, dry_run=dry_run)
    finally:
        conn.close()

    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
