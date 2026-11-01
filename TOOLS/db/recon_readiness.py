"""Compute focused-system reconnaissance readiness from stable facts."""

from __future__ import annotations

import sqlite3
from typing import Any

RECON_KEYS = (
    "recon.identity",
    "recon.scope",
    "recon.asset_membership",
    "recon.network_edge",
    "recon.technology",
    "recon.entry_auth",
    "recon.api_ownership",
    "recon.business_flows",
    "recon.trust_boundaries",
    "recon.critical_unknowns",
)
TESTING_LANES = {"preauth_probe", "logic_probe", "vuln_review", "replay", "cognitive_experiment"}
MAPPING_LANES = {
    "source_intel",
    "network_profile",
    "entry_probe",
    "js_reverse",
    "semantic_profile",
    "entry_explore",
    "origin_verify",
}


def _exists(conn: sqlite3.Connection, table: str) -> bool:
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone() is not None


def _system(conn: sqlite3.Connection, target_name: str, system_id: int) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM target_systems WHERE id=? AND target_name=?", (system_id, target_name)).fetchone()
    if row is None:
        raise ValueError("focused system not found")
    return row


def evaluate_readiness(conn: sqlite3.Connection, *, target_name: str, system_id: int) -> dict[str, Any]:
    system = _system(conn, target_name, system_id)
    blockers: list[str] = []
    next_actions: list[str] = []
    links = conn.execute(
        """SELECT l.*,a.asset_value,a.scope_class,a.scope_status,a.authorization_state FROM system_asset_links l JOIN target_assets a ON a.id=l.asset_id WHERE l.system_id=? AND l.target_name=?""",
        (system_id, target_name),
    ).fetchall()
    primary = [x for x in links if x["relationship"] == "primary"]
    if not system["canonical_url"] or not system["display_name"] or not primary:
        blockers.append("system identity or primary asset is incomplete")
        next_actions.append("补齐系统名称、完整 URL 和 primary asset")
    if system["scope_class"] not in {"owned", "authorized_vendor"}:
        blockers.append("system is not actively authorized")
        next_actions.append("由操作员确认授权范围")
    if primary and any(
        x["scope_class"] not in {"owned", "authorized_vendor"} or x["scope_status"] != "in_scope" or x["authorization_state"] == "revoked"
        for x in primary
    ):
        blockers.append("primary asset is outside active scope")
        next_actions.append("修正 primary asset 的范围状态")
    counts = {key: "unknown" for key in RECON_KEYS}
    if primary:
        counts["recon.identity"] = "covered"
    if system["scope_class"] in {"owned", "authorized_vendor"} and primary:
        counts["recon.scope"] = "covered"
    if primary:
        counts["recon.asset_membership"] = "covered"
    profile_ids: list[int] = []
    if primary and _exists(conn, "attack_surface_profiles"):
        asset_ids = [int(x["asset_id"]) for x in primary]
        profile_rows = conn.execute(
            "SELECT p.id FROM attack_surface_profiles p JOIN soft_targets s ON s.id=p.soft_target_id "  # noqa: S608 -- 仅拼接 "?" 占位符，值全走参数绑定
            "WHERE p.target_name=? AND s.asset_id IN ({})".format(",".join("?" for _ in asset_ids)),
            (target_name, *asset_ids),
        ).fetchall()
        profile_ids = [int(x[0]) for x in profile_rows]
    if _exists(conn, "coverage_ledger") and profile_ids:
        rows = conn.execute(
            "SELECT item_key,status FROM coverage_ledger WHERE target_name=? AND profile_id IN ({}) AND item_key IN ({}) ORDER BY updated_at DESC,id DESC".format(  # noqa: S608 -- 仅拼接 "?" 占位符，值全走参数绑定
                ",".join("?" for _ in profile_ids), ",".join("?" for _ in RECON_KEYS)
            ),
            (target_name, *profile_ids, *RECON_KEYS),
        ).fetchall()
    elif _exists(conn, "coverage_ledger") and not _exists(conn, "attack_surface_profiles"):
        # Legacy fixtures without profile support are only safe as a
        # compatibility path; real v33 databases must provide profile scope.
        rows = conn.execute(
            "SELECT item_key,status FROM coverage_ledger WHERE target_name=? AND item_key IN ({}) ORDER BY id DESC".format(  # noqa: S608 -- 仅拼接 "?" 占位符；RECON_KEYS 为模块常量
                ",".join("?" for _ in RECON_KEYS)
            ),
            (target_name, *RECON_KEYS),
        ).fetchall()
    else:
        rows = []
    for row in rows:
        counts[row["item_key"]] = row["status"]
    if counts["recon.critical_unknowns"] in {"unknown", "uncovered"}:
        blockers.append("critical unknowns have no next action")
        next_actions.append("为 critical unknown 写安全下一步或停止理由")
    if _exists(conn, "endpoint_observations"):
        endpoint_cols = {row[1] for row in conn.execute("PRAGMA table_info(endpoint_observations)")}
        asset_ids = [int(x["asset_id"]) for x in primary]
        unresolved = (
            conn.execute(
                "SELECT COUNT(*) FROM endpoint_observations e WHERE e.target_name=? AND e.asset_id IN ({}) AND e.resolution_status IN ('unresolved','unknown') AND COALESCE(e.business_hint,'')<>''".format(  # noqa: S608 -- 仅拼接 "?" 占位符，值全走参数绑定
                    ",".join("?" for _ in asset_ids)
                ),
                (target_name, *asset_ids),
            ).fetchone()[0]
            if asset_ids and "asset_id" in endpoint_cols
            else 0
        )
    else:
        unresolved = 0
    if unresolved:
        blockers.append(f"{unresolved} high-value endpoint(s) unresolved")
        next_actions.append("先完成接口归属和认证入口画像")
    open_cards = (
        conn.execute(
            "SELECT COUNT(*) FROM operator_inbox WHERE target_name=? AND status='open' AND COALESCE(blocking,1)=1 AND system_id=?",
            (target_name, system_id),
        ).fetchone()[0]
        if _exists(conn, "operator_inbox")
        else 0
    )
    if open_cards:
        blockers.append(f"{open_cards} blocking human action card(s) open")
    progress = {status: sum(1 for value in counts.values() if value == status) for status in ("covered", "unknown", "uncovered", "blocked")}
    if system["lifecycle_state"] == "stale":
        state = "stale"
    elif not primary or system["scope_class"] in {"intel_only", "unknown"}:
        state = "unmapped"
    elif blockers:
        state = "blocked" if open_cards else "mapping"
    else:
        state = "ready"
    return {
        "system_id": system_id,
        "state": state,
        "blockers": blockers[:10],
        "next_safe_actions": next_actions[:5],
        "coverage": {"keys": counts, "counts": progress},
        "high_value_unresolved_endpoints": unresolved,
        "open_blocking_actions": open_cards,
        "allowed_lanes": sorted(MAPPING_LANES if state in {"unmapped", "mapping", "blocked", "stale"} else MAPPING_LANES | TESTING_LANES),
    }


def lane_allowed(readiness: dict[str, Any], lane: str) -> bool:
    return lane in set(readiness.get("allowed_lanes", []))
