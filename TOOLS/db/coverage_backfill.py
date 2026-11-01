"""Idempotently backfill compact coverage facts from existing target data."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

_TOOLS_DIR = Path(__file__).resolve().parent.parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

from db.db_utils import connect, find_db  # noqa: E402

M8_COVERAGE_KEYS = (
    "identity:product_discrimination",
    "identity:domain_ip_service_linkage",
    "vendor_family:public_advisory_paths",
    "generic_probe:input_error_diff",
    "auth_boundary:public_endpoints",
    "js:login_page_decode",
    "intel:passive_neighbor_index",
    "external_intel:document_reconciliation",
)

M9_COVERAGE_KEYS = (
    "entry:mobile_h5_discovery",
    "entry:recursive_js_expansion",
    "entry:lazy_chunk_coverage",
    "endpoint:param_semantic_classification",
)


def _validate_target(conn: sqlite3.Connection, target_name: str) -> None:
    if conn.execute("SELECT 1 FROM targets WHERE target_name=? LIMIT 1", (target_name,)).fetchone() is None:
        raise ValueError("target_name does not exactly match the database targets")


def category_for_key(item_key: str, *, work_lanes: Mapping[int, str] | None = None) -> str:
    if item_key in M8_COVERAGE_KEYS:
        return "m8_control"
    if item_key in M9_COVERAGE_KEYS:
        return "m9_recursive_recon"
    if item_key.startswith("asset:"):
        return "asset_liveness"
    if item_key.startswith("endpoint:"):
        return "endpoint_recon"
    if item_key.startswith("sp:"):
        return "vuln_probe"
    if item_key.startswith("profile:"):
        return "semantic_profile"
    if item_key.startswith("work:"):
        work_id = int(item_key.split(":", 1)[1])
        lane = (work_lanes or {}).get(work_id)
        if not lane:
            raise ValueError(f"work lane is required for {item_key}")
        return f"lane:{lane}"
    raise ValueError(f"unsupported coverage item_key: {item_key}")


def normalize_url(value: str) -> str:
    raw = str(value or "").strip()
    parsed = urlparse(raw)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return raw.split("#", 1)[0]
    host = parsed.hostname.lower()
    netloc = host
    if parsed.port is not None:
        netloc += f":{parsed.port}"
    query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)))
    return urlunparse((parsed.scheme.lower(), netloc, parsed.path or "/", "", query, ""))


def _compact_refs(raw: str | None, fallback: str) -> list[str]:
    try:
        values = json.loads(raw or "[]")
    except json.JSONDecodeError:
        values = []
    if not isinstance(values, list):
        values = []
    compact = [str(item)[:160] for item in values[:10] if isinstance(item, (str, int))]
    return compact or [fallback]


def _target_hosts(conn: sqlite3.Connection, target_name: str) -> set[str]:
    values = [row[0] for row in conn.execute("SELECT domain FROM targets WHERE target_name=?", (target_name,)).fetchall()]
    values.extend(
        row[0]
        for row in conn.execute(
            "SELECT asset_value FROM target_assets WHERE target_name=? AND asset_type IN ('domain','subdomain','url')",
            (target_name,),
        ).fetchall()
    )
    hosts: set[str] = set()
    for value in values:
        parsed = urlparse(str(value) if "://" in str(value or "") else f"//{value}")
        if parsed.hostname:
            hosts.add(parsed.hostname.lower().strip("."))
    return hosts


def _url_belongs(value: str | None, hosts: set[str]) -> bool:
    if not value:
        return False
    parsed = urlparse(str(value) if "://" in str(value) else f"//{value}")
    host = (parsed.hostname or "").lower().strip(".")
    return bool(host and any(host == item or host.endswith(f".{item}") for item in hosts))


def _sp_status(value: str | None) -> str:
    status = str(value or "").lower()
    if status in {"blocked", "needs_operator", "auth_blocked"}:
        return "blocked"
    if status in {"tested", "confirmed", "refuted", "done", "reviewed"}:
        return "covered"
    return "unknown"


def _items(conn: sqlite3.Connection, target_name: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    work_lanes: dict[int, str] = {}
    # B1's ID repair is database-wide.  Do not hide a broken schema-33 row
    # merely because its URL cannot be associated with this target yet.
    if conn.execute("SELECT 1 FROM suspicious_points WHERE id IS NULL OR trim(id)='' LIMIT 1").fetchone() is not None:
        raise ValueError("empty suspicious_points.id must be repaired before coverage backfill")
    for row in conn.execute(
        """SELECT id,asset_value,status,live_status,last_status_code,last_verified_at
           FROM target_assets
           WHERE target_name=? AND (status='validated' OR live_status='live')
           ORDER BY id""",
        (target_name,),
    ).fetchall():
        items.append(
            {
                "item_key": f"asset:{row['asset_value']}",
                "status": "covered",
                "confidence": "high" if row["live_status"] == "live" else "medium",
                "evidence_refs": [f"target_assets:{row['id']}"],
                "summary": f"asset liveness fact status={row['status']} live={row['live_status']}",
                "next_action": "revalidate when stale",
            }
        )
    focused = conn.execute(
        """SELECT s.id,s.display_name FROM system_soft_targets st
           JOIN target_systems s ON s.id=st.system_id AND s.target_name=st.target_name
           WHERE st.target_name=? AND st.eligibility_status='eligible' AND st.status='focused'
           ORDER BY st.id LIMIT 1""",
        (target_name,),
    ).fetchone()
    if focused is not None:
        for key in (*M8_COVERAGE_KEYS, *M9_COVERAGE_KEYS):
            items.append(
                {
                    "item_key": key,
                    "status": "unknown",
                    "confidence": "unknown",
                    "evidence_refs": [],
                    "summary": (f"offline control not yet evaluated for system {focused['id']} {focused['display_name']}"),
                    "next_action": "resolve from offline/passive evidence or record an explicit blocker",
                    "seed_only": True,
                }
            )
    for row in conn.execute(
        """SELECT id,canonical_url,evidence_refs_json,confidence,test_status,resolution_status
           FROM endpoint_observations WHERE target_name=? ORDER BY id""",
        (target_name,),
    ).fetchall():
        items.append(
            {
                "item_key": f"endpoint:{normalize_url(row['canonical_url'])}",
                "status": "covered",
                "confidence": row["confidence"] if row["confidence"] in {"low", "medium", "high"} else "unknown",
                "evidence_refs": _compact_refs(row["evidence_refs_json"], f"endpoint_observations:{row['id']}"),
                "summary": f"endpoint observed resolution={row['resolution_status']} test={row['test_status']}",
                "next_action": "retain unknown auth and scope boundaries",
            }
        )

    hosts = _target_hosts(conn, target_name)
    for row in conn.execute("SELECT id,url,page_url,test_status FROM suspicious_points ORDER BY rowid").fetchall():
        if not (_url_belongs(row["url"], hosts) or _url_belongs(row["page_url"], hosts)):
            continue
        sp_id = str(row["id"])
        items.append(
            {
                "item_key": f"sp:{sp_id}",
                "status": _sp_status(row["test_status"]),
                "confidence": "unknown",
                "evidence_refs": [f"suspicious_points:{sp_id}"],
                "summary": f"suspicious point lifecycle={row['test_status'] or 'unknown'}",
                "next_action": "operator-gated review" if _sp_status(row["test_status"]) != "covered" else "review evidence",
            }
        )
    for row in conn.execute(
        """SELECT id,lane,summary FROM work_items
           WHERE target_name=? AND status='done' ORDER BY id""",
        (target_name,),
    ).fetchall():
        work_id = int(row["id"])
        work_lanes[work_id] = str(row["lane"])
        items.append(
            {
                "item_key": f"work:{work_id}",
                "status": "covered",
                "confidence": "medium",
                "evidence_refs": [f"work_items:{work_id}"],
                "summary": str(row["summary"] or f"completed lane={row['lane']}")[:500],
                "next_action": "consume compact worker result",
            }
        )
    for row in conn.execute(
        """SELECT id,status,confidence,evidence_refs_json,summary FROM attack_surface_profiles
           WHERE target_name=? ORDER BY id""",
        (target_name,),
    ).fetchall():
        profile_id = int(row["id"])
        profile_status = "blocked" if row["status"] == "blocked" else ("covered" if row["status"] == "active" else "unknown")
        items.append(
            {
                "item_key": f"profile:{profile_id}",
                "status": profile_status,
                "confidence": row["confidence"] if row["confidence"] in {"low", "medium", "high"} else "unknown",
                "evidence_refs": _compact_refs(row["evidence_refs_json"], f"attack_surface_profiles:{profile_id}"),
                "summary": str(row["summary"] or f"semantic profile status={row['status']}")[:500],
                "next_action": "resolve profile blocker" if row["status"] == "blocked" else "preserve unknown coverage",
            }
        )
    for item in items:
        item["category"] = category_for_key(item["item_key"], work_lanes=work_lanes)
    unique: dict[str, dict[str, Any]] = {}
    for item in items:
        existing = unique.get(item["item_key"])
        if existing is None:
            unique[item["item_key"]] = item
            continue
        if existing["category"] != item["category"]:
            raise ValueError(f"category mismatch for duplicate key {item['item_key']}")
        existing["evidence_refs"] = list(dict.fromkeys([*existing["evidence_refs"], *item["evidence_refs"]]))[:10]
    return list(unique.values())


def backfill_coverage(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    apply: bool = False,
    include_items: bool = False,
    sample_size: int = 10,
) -> dict[str, Any]:
    if sample_size < 0 or sample_size > 100:
        raise ValueError("sample_size must be between 0 and 100")
    if not apply:
        _validate_target(conn, target_name)
        items = _items(conn, target_name)
        return _coverage_result(
            target_name=target_name,
            mode="preview",
            items=items,
            inserted=0,
            updated=0,
            include_items=include_items,
            sample_size=sample_size,
        )

    nested = conn.in_transaction
    conn.execute("SAVEPOINT b7_coverage_backfill" if nested else "BEGIN IMMEDIATE")
    try:
        _validate_target(conn, target_name)
        items = _items(conn, target_name)
        inserted = 0
        updated = 0
        for item in items:
            existing = conn.execute(
                """SELECT id,category,status,confidence,evidence_refs_json,summary,next_action
                   FROM coverage_ledger
                   WHERE target_name=? AND profile_id IS NULL AND item_key=?
                   ORDER BY id LIMIT 1""",
                (target_name, item["item_key"]),
            ).fetchone()
            refs_json = json.dumps(item["evidence_refs"], ensure_ascii=False, separators=(",", ":"))
            if existing is None:
                conn.execute(
                    """INSERT INTO coverage_ledger(
                           target_name,profile_id,item_key,category,status,confidence,
                           evidence_refs_json,summary,next_action
                       ) VALUES(?,NULL,?,?,?,?,?,?,?)""",
                    (
                        target_name,
                        item["item_key"],
                        item["category"],
                        item["status"],
                        item["confidence"],
                        refs_json,
                        item["summary"],
                        item["next_action"],
                    ),
                )
                inserted += 1
                continue
            if item.get("seed_only"):
                continue
            desired = (
                item["category"],
                item["status"],
                item["confidence"],
                refs_json,
                item["summary"],
                item["next_action"],
            )
            current = tuple(existing[key] for key in ("category", "status", "confidence", "evidence_refs_json", "summary", "next_action"))
            if desired != current:
                conn.execute(
                    """UPDATE coverage_ledger SET category=?,status=?,confidence=?,evidence_refs_json=?,
                           summary=?,next_action=?,updated_at=datetime('now','localtime') WHERE id=?""",
                    (*desired, existing["id"]),
                )
                updated += 1
        if nested:
            conn.execute("RELEASE SAVEPOINT b7_coverage_backfill")
        else:
            conn.commit()
    except Exception:
        if nested:
            conn.execute("ROLLBACK TO SAVEPOINT b7_coverage_backfill")
            conn.execute("RELEASE SAVEPOINT b7_coverage_backfill")
        else:
            conn.rollback()
        raise
    return _coverage_result(
        target_name=target_name,
        mode="apply",
        items=items,
        inserted=inserted,
        updated=updated,
        include_items=include_items,
        sample_size=sample_size,
    )


def _coverage_result(
    *,
    target_name: str,
    mode: str,
    items: list[dict[str, Any]],
    inserted: int,
    updated: int,
    include_items: bool,
    sample_size: int,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "target_name": target_name,
        "mode": mode,
        "planned": len(items),
        "inserted": inserted,
        "updated": updated,
        "sample": [
            {"item_key": str(item["item_key"])[:120], "category": item["category"], "status": item["status"]}
            for item in items[:sample_size]
        ],
        "omitted": max(0, len(items) - sample_size),
    }
    if include_items:
        result["items"] = items
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Backfill compact coverage facts")
    parser.add_argument("--target", required=True)
    parser.add_argument("--file")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    path = Path(args.file) if args.file else find_db(args.target)
    conn = connect(path)
    try:
        result = backfill_coverage(conn, target_name=args.target, apply=args.apply)
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return 1
    finally:
        conn.close()
    print(json.dumps({"ok": True, **result}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
