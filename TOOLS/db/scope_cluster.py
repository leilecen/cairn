"""Preview and apply operator-approved scope clusters without inheriting scope by IP."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import sqlite3
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

_TOOLS_DIR = Path(__file__).resolve().parent.parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

from db.db_utils import connect, find_db  # noqa: E402
from db.operator_actions import create_action_card  # noqa: E402

_MULTI_LABEL_SUFFIXES = {
    "com.cn",
    "net.cn",
    "org.cn",
    "gov.cn",
    "edu.cn",
    "com.hk",
    "com.au",
    "co.uk",
    "co.jp",
}
_AUDIT_SOURCE = "scope_cluster_decision"
_CARD_SENSITIVE = re.compile(r"cookie|authorization|bearer|set-cookie|http/1\.|host:", re.I)


def _validate_target(conn: sqlite3.Connection, target_name: str) -> None:
    if conn.execute("SELECT 1 FROM targets WHERE target_name=? LIMIT 1", (target_name,)).fetchone() is None:
        raise ValueError("target_name does not exactly match the database targets")


def _host(value: str | None) -> str:
    raw = str(value or "").strip().lower()
    parsed = urlparse(raw if "://" in raw else f"//{raw}")
    return (parsed.hostname or raw).strip(".")


def _registered_domain(value: str | None) -> str | None:
    host = _host(value)
    if not host:
        return None
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass
    labels = host.split(".")
    if len(labels) < 2:
        return None
    suffix_length = 2 if ".".join(labels[-2:]) in _MULTI_LABEL_SUFFIXES else 1
    if len(labels) <= suffix_length:
        return host
    return ".".join(labels[-(suffix_length + 1) :])


def _technology(value: str | None) -> str | None:
    text = " ".join(str(value or "").lower().replace("_", "-").split())
    return text[:120] or None


def _target_roots(conn: sqlite3.Connection, target_name: str) -> set[str]:
    roots: set[str] = set()
    for row in conn.execute("SELECT domain FROM targets WHERE target_name=?", (target_name,)).fetchall():
        root = _registered_domain(row[0])
        if root:
            roots.add(root)
    return roots


def _cluster_id(kind: str, key: str, asset_ids: list[int]) -> str:
    material = f"{kind}|{key}|{','.join(str(item) for item in sorted(asset_ids))}"
    return "scope-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def _cluster_assets_unchecked(conn: sqlite3.Connection, *, target_name: str) -> dict[str, Any]:
    roots = _target_roots(conn, target_name)
    rows = conn.execute(
        """SELECT id,asset_type,asset_value,port,resolved_ip,source,last_verified_at,last_verify_status,
                  COALESCE(last_tech_stack,tech_stack) AS product
           FROM target_assets
           WHERE target_name=? AND scope_status='needs_review'
           ORDER BY id""",
        (target_name,),
    ).fetchall()
    # key 有两种形态：("resolved_ip"/"registered_domain"/"product_fingerprint", str) 与 ("asset", id)
    # 闭包后半段只用分组内成员，key 本身只进 _cluster_id(需 str)，因此在取值处统一 str()。
    grouped: dict[tuple[str, str], list[sqlite3.Row]] = {}
    for row in rows:
        registered = _registered_domain(row["asset_value"])
        if registered:
            key = ("registered_domain", registered)
        elif row["resolved_ip"]:
            key = ("resolved_ip", str(row["resolved_ip"]).strip())
        elif _technology(row["product"]):
            key = ("product_fingerprint", _technology(row["product"]) or "unknown")
        else:
            key = ("asset", str(row["id"]))
        grouped.setdefault(key, []).append(row)

    clusters: list[dict[str, Any]] = []
    for (kind, group_key), members in sorted(grouped.items(), key=lambda item: (item[0][0], item[0][1])):
        asset_ids = [int(row["id"]) for row in members]
        member_roots = {_registered_domain(row["asset_value"]) for row in members}
        same_registered_domain = bool((member_roots - {None}) & roots)
        recommendation = "confirm" if same_registered_domain else "reject"
        warnings: list[str] = []
        if any(row["resolved_ip"] for row in members) or kind == "resolved_ip":
            warnings.append("shared IP is time/source/confidence association only; never inherit scope, system, tenant, auth or vendor")
        if not same_registered_domain:
            warnings.append("external or unproven registered domain requires separate authorization")
        if kind == "product_fingerprint":
            warnings.append("same product fingerprint is a prioritization clue, not shared ownership or vulnerability")
        basis: dict[str, Any] = {"kind": kind, "value": group_key}
        if kind == "resolved_ip":
            basis["associations"] = [
                {
                    "asset_id": int(row["id"]),
                    "source": str(row["source"] or "unknown")[:80],
                    "observed_at": row["last_verified_at"],
                    "confidence": "unknown",
                }
                for row in members
            ]
        clusters.append(
            {
                "cluster_id": _cluster_id(kind, group_key, asset_ids),
                "basis": basis,
                "asset_ids": asset_ids,
                "assets": [str(row["asset_value"])[:180] for row in members],
                "recommended_decision": recommendation,
                "risk_warnings": warnings,
            }
        )
    return {"target_name": target_name, "cluster_count": len(clusters), "clusters": clusters}


def cluster_assets(conn: sqlite3.Connection, *, target_name: str) -> dict[str, Any]:
    """Return deterministic compact clusters; this function never writes."""
    _validate_target(conn, target_name)
    return _cluster_assets_unchecked(conn, target_name=target_name)


def compact_cluster_result(result: dict[str, Any], *, sample_size: int = 10, include_clusters: bool = False) -> dict[str, Any]:
    """Return a bounded summary suitable for CLI and action-card output."""
    if not 0 <= sample_size <= 10:
        raise ValueError("sample_size must be between 0 and 10")
    clusters = result["clusters"]
    by_recommendation: dict[str, int] = {}
    by_basis: dict[str, int] = {}
    for item in clusters:
        recommendation = str(item["recommended_decision"])
        basis_kind = str(item["basis"]["kind"])
        by_recommendation[recommendation] = by_recommendation.get(recommendation, 0) + 1
        by_basis[basis_kind] = by_basis.get(basis_kind, 0) + 1
    sample = [
        {
            "cluster_id": item["cluster_id"],
            "basis": {
                "kind": item["basis"]["kind"],
                "value": _safe_basis_value(item["basis"]["value"]),
            },
            "asset_count": len(item["asset_ids"]),
            "recommendation": item["recommended_decision"],
        }
        for item in clusters[:sample_size]
    ]
    compact: dict[str, Any] = {
        "target_name": result["target_name"],
        "cluster_count": len(clusters),
        "asset_count": sum(len(item["asset_ids"]) for item in clusters),
        "counts": {
            "by_recommendation": dict(sorted(by_recommendation.items())),
            "by_basis": dict(sorted(by_basis.items())),
        },
        "sample": sample,
        "omitted": max(0, len(clusters) - len(sample)),
    }
    if include_clusters:
        compact["clusters"] = clusters
    return compact


def _safe_basis_value(value: Any) -> str:
    text = str(value)[:120]
    if _CARD_SENSITIVE.search(text):
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:8]
        return f"[redacted-basis:{digest}]"
    return text


def _card_why_needed(result: dict[str, Any]) -> str:
    for sample_size in range(min(5, len(result["clusters"])), -1, -1):
        summary = compact_cluster_result(result, sample_size=sample_size)
        summary.pop("target_name", None)
        payload = {
            "reason": "Explicit operator decisions are required before needs_review assets change.",
            "summary": summary,
            "full_preview": "rerun scope_cluster.py cluster and select a cluster_id",
        }
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        if len(encoded) <= 1000:
            return encoded
    raise RuntimeError("unable to build bounded scope cluster action summary")


def write_cluster_card(conn: sqlite3.Connection, *, target_name: str) -> dict[str, Any]:
    result = cluster_assets(conn, target_name=target_name)
    digest = hashlib.sha256(json.dumps(result["clusters"], ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()[:16]
    return create_action_card(
        conn,
        target_name=target_name,
        system_id=None,
        kind="scope_cluster_confirm",
        action_key=f"scope-clusters:{digest}",
        action_label=f"Review {result['cluster_count']} scope clusters",
        why_needed=_card_why_needed(result),
        steps=["Review each compact cluster basis and warnings", "Apply confirm, reject or exclude by cluster ID"],
        expected_observation="Every selected cluster has an explicit decision and reason",
        report_back_format="cluster_id=<id>; decision=confirm|reject|exclude; reason=<compact reason>",
        blocking=True,
    )


def _decision_query(cluster_id: str, decision: str) -> str:
    return f"scope-cluster:{cluster_id}:{decision}"


def _existing_audit(conn: sqlite3.Connection, *, target_name: str, query: str, source_kind: str = _AUDIT_SOURCE) -> sqlite3.Row | None:
    return conn.execute(
        """SELECT * FROM recon_sources
           WHERE target_name=? AND source_kind=? AND query=?
           ORDER BY id LIMIT 1""",
        (target_name, source_kind, query),
    ).fetchone()


def _asset_state(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "status": row["status"],
        "scope_status": row["scope_status"],
        "scope_class": row["scope_class"],
        "authorization_state": row["authorization_state"],
        "scope_reason": row["scope_reason"],
    }


def _after_state(before: dict[str, Any], decision: str, *, target_owned: bool) -> dict[str, Any]:
    after = dict(before)
    if decision == "confirm":
        after.update(
            scope_status="in_scope",
            scope_class=(
                before["scope_class"]
                if before["scope_class"] in {"owned", "authorized_vendor"}
                else ("owned" if target_owned else "authorized_vendor")
            ),
            authorization_state="authorized",
            scope_reason="operator:confirm scope cluster",
        )
    else:
        after.update(
            scope_status="out_of_scope",
            scope_class="intel_only",
            authorization_state="revoked",
            scope_reason=f"operator:{decision} scope cluster",
        )
        if decision == "exclude":
            after["status"] = "excluded"
    return after


def apply_cluster_decision(conn: sqlite3.Connection, *, target_name: str, cluster_id: str, decision: str) -> dict[str, Any]:
    if decision not in {"confirm", "reject", "exclude"}:
        raise ValueError("decision must be confirm, reject or exclude")
    conn.execute("BEGIN IMMEDIATE")
    try:
        _validate_target(conn, target_name)
        query = _decision_query(cluster_id, decision)
        existing = _existing_audit(conn, target_name=target_name, query=query)
        if existing:
            conn.commit()
            return {"audit_id": int(existing["id"]), "changed": 0, "idempotent": True}
        clusters = {item["cluster_id"]: item for item in _cluster_assets_unchecked(conn, target_name=target_name)["clusters"]}
        cluster = clusters.get(cluster_id)
        if cluster is None:
            raise ValueError("cluster_id is not an unresolved cluster for this target")
        assets: list[dict[str, Any]] = []
        for asset_id in cluster["asset_ids"]:
            row = conn.execute(
                "SELECT * FROM target_assets WHERE target_name=? AND id=? AND scope_status='needs_review'",
                (target_name, asset_id),
            ).fetchone()
            if row is None:
                raise RuntimeError("cluster membership changed before apply")
            before = _asset_state(row)
            after = _after_state(
                before,
                decision,
                target_owned=cluster["recommended_decision"] == "confirm",
            )
            conn.execute(
                """UPDATE target_assets
                   SET status=?,scope_status=?,scope_class=?,authorization_state=?,scope_reason=?
                   WHERE target_name=? AND id=? AND scope_status='needs_review'""",
                (
                    after["status"],
                    after["scope_status"],
                    after["scope_class"],
                    after["authorization_state"],
                    after["scope_reason"],
                    target_name,
                    asset_id,
                ),
            )
            assets.append({"asset_id": asset_id, "before": before, "after": after})
        payload = {
            "schema": "scope_cluster_decision/v1",
            "cluster_id": cluster_id,
            "decision": decision,
            "basis": cluster["basis"],
            "assets": assets,
        }
        cur = conn.execute(
            """INSERT INTO recon_sources(target_name,source_kind,query,result_json,status)
               VALUES(?,?,?,?, 'observed')""",
            (target_name, _AUDIT_SOURCE, query, json.dumps(payload, ensure_ascii=False, sort_keys=True)),
        )
        conn.commit()
        return {"audit_id": int(cur.lastrowid or 0), "changed": len(assets), "idempotent": False}
    except Exception:
        conn.rollback()
        raise


def rollback_cluster_decision(conn: sqlite3.Connection, *, target_name: str, audit_id: int) -> dict[str, Any]:
    conn.execute("BEGIN IMMEDIATE")
    try:
        _validate_target(conn, target_name)
        rollback_query = f"scope-cluster-rollback:{audit_id}"
        existing = _existing_audit(conn, target_name=target_name, query=rollback_query, source_kind="scope_cluster_rollback")
        if existing:
            payload = json.loads(existing["result_json"])
            conn.commit()
            return {"audit_id": int(existing["id"]), "restored": payload["restored"], "idempotent": True}
        row = conn.execute(
            "SELECT * FROM recon_sources WHERE id=? AND target_name=? AND source_kind=?",
            (audit_id, target_name, _AUDIT_SOURCE),
        ).fetchone()
        if row is None:
            raise ValueError("scope decision audit not found for target")
        payload = json.loads(row["result_json"])
        for item in payload["assets"]:
            current = conn.execute("SELECT * FROM target_assets WHERE target_name=? AND id=?", (target_name, item["asset_id"])).fetchone()
            if current is None or _asset_state(current) != item["after"]:
                raise RuntimeError("asset changed after decision; refusing unsafe rollback")
            before = item["before"]
            conn.execute(
                """UPDATE target_assets
                   SET status=?,scope_status=?,scope_class=?,authorization_state=?,scope_reason=?
                   WHERE target_name=? AND id=?""",
                (
                    before["status"],
                    before["scope_status"],
                    before["scope_class"],
                    before["authorization_state"],
                    before["scope_reason"],
                    target_name,
                    item["asset_id"],
                ),
            )
        result = {
            "schema": "scope_cluster_rollback/v1",
            "source_audit_id": audit_id,
            "restored": len(payload["assets"]),
        }
        cur = conn.execute(
            """INSERT INTO recon_sources(target_name,source_kind,query,result_json,status)
               VALUES(?,'scope_cluster_rollback',?,?, 'observed')""",
            (target_name, rollback_query, json.dumps(result, ensure_ascii=False, sort_keys=True)),
        )
        conn.commit()
        return {"audit_id": int(cur.lastrowid or 0), "restored": result["restored"], "idempotent": False}
    except Exception:
        conn.rollback()
        raise


def _path(args: argparse.Namespace) -> Path:
    return Path(args.file) if args.file else find_db(args.target)


def main() -> int:
    parser = argparse.ArgumentParser(description="Preview and apply operator-approved scope clusters")
    parser.add_argument("--target", required=True)
    parser.add_argument("--file")
    sub = parser.add_subparsers(dest="command", required=True)
    cluster = sub.add_parser("cluster")
    cluster.add_argument("--write-card", action="store_true")
    cluster.add_argument("--include-clusters", action="store_true")
    apply = sub.add_parser("apply")
    apply.add_argument("--cluster-id", required=True)
    apply.add_argument("--decision", choices=("confirm", "reject", "exclude"), required=True)
    rollback = sub.add_parser("rollback")
    rollback.add_argument("--audit-id", type=int, required=True)
    args = parser.parse_args()
    conn = connect(_path(args))
    try:
        if args.command == "cluster":
            full_result = cluster_assets(conn, target_name=args.target)
            result = compact_cluster_result(full_result, include_clusters=args.include_clusters)
            if args.write_card:
                result["action_card"] = write_cluster_card(conn, target_name=args.target)
        elif args.command == "apply":
            result = apply_cluster_decision(conn, target_name=args.target, cluster_id=args.cluster_id, decision=args.decision)
        else:
            result = rollback_cluster_decision(conn, target_name=args.target, audit_id=args.audit_id)
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return 1
    finally:
        conn.close()
    print(json.dumps({"ok": True, **result}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
