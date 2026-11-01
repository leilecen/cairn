"""Import bounded passive-neighbor provider fixtures without network access."""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
from pathlib import Path
from typing import Any, Mapping

_TOOLS_DIR = Path(__file__).resolve().parent.parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

from db.db_utils import connect, find_db  # noqa: E402
from db.identity_classification import (  # noqa: E402
    normalize_host,
    normalize_ip,
    validate_compact_text,
    validate_evidence_refs,
    validate_port,
    validate_timestamp,
)

_SECRET = re.compile(
    r"(?:GET|POST|PUT|DELETE|PATCH)\s+\S+\s+HTTP/|authorization:|cookie:|bearer\s+\S+|"
    r"[\"'](?:password|passwd|secret|token|authorization|cookie)[\"']\s*:",
    re.I,
)


def _validate_target(conn: sqlite3.Connection, target_name: str) -> None:
    if conn.execute("SELECT 1 FROM targets WHERE target_name=? LIMIT 1", (target_name,)).fetchone() is None:
        raise ValueError("target_name does not exactly match the database targets")


def _items(payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    provider = validate_compact_text(
        payload.get("provider"),
        field="provider",
        max_chars=80,
        allow_empty=False,
        pattern=re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$"),
    )
    query = validate_compact_text(payload.get("query"), field="query", max_chars=240, allow_empty=False)
    observed_at = validate_timestamp(payload.get("observed_at"), allow_none=False)
    refs = validate_evidence_refs(payload.get("evidence_refs"), allow_empty=False)
    results = payload.get("results") or []
    if not isinstance(results, list):
        raise ValueError("results must be a list")
    compact: list[dict[str, Any]] = []
    for raw in results:
        if not isinstance(raw, Mapping):
            raise ValueError("each result must be an object")
        dumped = json.dumps(raw, ensure_ascii=False)
        if _SECRET.search(dumped) or len(dumped) > 3000:
            raise ValueError("raw HTTP or credential material is not accepted")
        host = normalize_host(raw.get("host"))
        ip = normalize_ip(raw.get("ip"))
        port = validate_port(raw.get("port"), allow_none=False)
        title = validate_compact_text(raw.get("title"), field="title", max_chars=160)
        product = validate_compact_text(raw.get("product"), field="product", max_chars=120)
        compact.append(
            {
                "provider": provider,
                "query": query,
                "observed_at": observed_at,
                "host": host,
                "ip": ip,
                "port": port,
                "title": title,
                "product": product,
                "evidence_refs": refs,
                "scope_status": "needs_review",
                "network_observed": False,
            }
        )
    unique = {(item["host"], item["ip"], item["port"]): item for item in compact}
    return [unique[key] for key in sorted(unique)]


def import_passive_neighbors(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    payload: Mapping[str, Any],
    apply: bool = False,
    include_items: bool = False,
    sample_size: int = 10,
) -> dict[str, Any]:
    if not 0 <= sample_size <= 100:
        raise ValueError("sample_size must be between 0 and 100")
    if not apply:
        _validate_target(conn, target_name)
        items = _items(payload)
        return _result(target_name, "preview", items, 0, include_items, sample_size)
    nested = conn.in_transaction
    conn.execute("SAVEPOINT b7_passive_neighbor" if nested else "BEGIN IMMEDIATE")
    try:
        _validate_target(conn, target_name)
        items = _items(payload)
        inserted = 0
        all_refs: list[str] = list(validate_evidence_refs(payload.get("evidence_refs"), allow_empty=False))
        for item in items:
            query = f"{item['provider']}|{item['query']}|{item['host']}|{item['ip']}|{item['port']}"
            result_json = json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            cur = conn.execute(
                """INSERT OR IGNORE INTO recon_sources(target_name,source_kind,query,result_json,status)
                   VALUES(?,'passive_neighbor_index',?,?,'needs_review')""",
                (target_name, query, result_json),
            )
            inserted += max(cur.rowcount, 0)
            all_refs.extend(item["evidence_refs"])
        refs = list(dict.fromkeys(all_refs))[:10]
        if refs:
            existing = conn.execute(
                """SELECT id,status FROM coverage_ledger
                   WHERE target_name=? AND profile_id IS NULL AND item_key='intel:passive_neighbor_index'
                   ORDER BY id LIMIT 1""",
                (target_name,),
            ).fetchone()
            refs_json = json.dumps(refs, ensure_ascii=False, separators=(",", ":"))
            if existing is None:
                conn.execute(
                    """INSERT INTO coverage_ledger(
                           target_name,profile_id,item_key,category,status,confidence,evidence_refs_json,
                           summary,next_action
                       ) VALUES(?,NULL,'intel:passive_neighbor_index','m8_control','covered','medium',?,?,?)""",
                    (
                        target_name,
                        refs_json,
                        "passive provider fixture imported; neighbor ownership remains needs_review",
                        "operator confirms scope before any active work",
                    ),
                )
            elif existing["status"] not in {"covered", "blocked"}:
                conn.execute(
                    """UPDATE coverage_ledger SET status='covered',confidence='medium',evidence_refs_json=?,
                           summary='passive provider fixture imported; neighbor ownership remains needs_review',
                           next_action='operator confirms scope before any active work',
                           updated_at=datetime('now','localtime') WHERE id=?""",
                    (refs_json, existing["id"]),
                )
        if nested:
            conn.execute("RELEASE SAVEPOINT b7_passive_neighbor")
        else:
            conn.commit()
    except Exception:
        if nested:
            conn.execute("ROLLBACK TO SAVEPOINT b7_passive_neighbor")
            conn.execute("RELEASE SAVEPOINT b7_passive_neighbor")
        else:
            conn.rollback()
        raise
    return _result(target_name, "apply", items, inserted, include_items, sample_size)


def _result(
    target_name: str, mode: str, items: list[dict[str, Any]], inserted: int, include_items: bool, sample_size: int
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "target_name": target_name,
        "mode": mode,
        "planned": len(items),
        "inserted": inserted,
        "network_requests": 0,
        "sample": [
            {"host": item["host"], "ip": item["ip"], "port": item["port"], "product": item["product"]} for item in items[:sample_size]
        ],
        "omitted": max(0, len(items) - sample_size),
    }
    if include_items:
        result["items"] = items
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Import an offline passive-neighbor fixture")
    parser.add_argument("--target", required=True)
    parser.add_argument("--file")
    parser.add_argument("--fixture", required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    path = Path(args.file) if args.file else find_db(args.target)
    fixture = Path(args.fixture)
    if not path.exists() or not fixture.is_file():
        print(json.dumps({"ok": False, "error": "database or fixture file does not exist"}, ensure_ascii=False))
        return 1
    try:
        payload = json.loads(fixture.read_text(encoding="utf-8"))
        conn = connect(path)
        try:
            result = import_passive_neighbors(conn, target_name=args.target, payload=payload, apply=args.apply)
        finally:
            conn.close()
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return 1
    print(json.dumps({"ok": True, **result}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
