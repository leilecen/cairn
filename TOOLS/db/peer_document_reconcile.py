"""Reconcile already-parsed peer documents into asset and chain candidates."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
import sys
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import unquote, urlsplit

_TOOLS_DIR = Path(__file__).resolve().parent.parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

from db.db_utils import connect, find_db  # noqa: E402
from db.identity_classification import (  # noqa: E402
    normalize_host,
    validate_compact_text,
    validate_evidence_ref,
    validate_port,
)
from db.work_queue import create_work_item  # noqa: E402

_FORBIDDEN_KEY = re.compile(r"raw|body|headers?|cookie|authorization|password|passwd|secret|token", re.I)
_FORBIDDEN_TEXT = re.compile(r"(?:GET|POST|PUT|DELETE|PATCH)\s+\S+\s+HTTP/|authorization:|cookie:|password\s*=", re.I)
_METHODS = {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}
_PARAMETER = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\[\]-]{0,79}$")


def _validate_target(conn: sqlite3.Connection, target_name: str) -> None:
    if conn.execute("SELECT 1 FROM targets WHERE target_name=? LIMIT 1", (target_name,)).fetchone() is None:
        raise ValueError("target_name does not exactly match the database targets")


def _validate_compact(value: Any, *, depth: int = 0) -> None:
    if depth > 5:
        raise ValueError("document record is too deeply nested")
    if isinstance(value, Mapping):
        for key, item in value.items():
            if _FORBIDDEN_KEY.search(str(key)):
                raise ValueError("raw HTTP or credential material is not accepted")
            _validate_compact(item, depth=depth + 1)
    elif isinstance(value, list):
        for item in value:
            _validate_compact(item, depth=depth + 1)
    elif isinstance(value, str) and (_FORBIDDEN_TEXT.search(value) or len(value) > 1000):
        raise ValueError("raw HTTP or credential material is not accepted")


def _path(value: str) -> str:
    raw = validate_compact_text(value, field="path", max_chars=500, allow_empty=False)
    parsed = urlsplit(raw)
    decoded = unquote(raw)
    if (
        parsed.scheme
        or parsed.netloc
        or not raw.startswith("/")
        or parsed.query
        or parsed.fragment
        or "\\" in raw
        or any(segment in {".", ".."} for segment in decoded.split("/"))
    ):
        raise ValueError("path must be an absolute normalized path without traversal")
    return "/" + "/".join(segment for segment in raw.split("/") if segment)


def _method(value: Any) -> str:
    method = validate_compact_text(value or "GET", field="method", max_chars=12, allow_empty=False).upper()
    if method not in _METHODS:
        raise ValueError("method is not allowed")
    return method


def _parameters(value: Any) -> list[str]:
    if not isinstance(value, list):
        raise ValueError("params must be a list of parameter names")
    result = []
    for item in value[:10]:
        name = validate_compact_text(item, field="parameter name", max_chars=80, allow_empty=False)
        if _PARAMETER.fullmatch(name) is None:
            raise ValueError("params may contain parameter names only")
        result.append(name)
    return list(dict.fromkeys(result))


def _compact_record(record: Mapping[str, Any], document_ref: str, index: int) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    asset = record.get("asset")
    if isinstance(asset, Mapping):
        host = normalize_host(asset.get("host"))
        if host:
            output.append(
                {
                    "kind": "asset",
                    "source_document_ref": document_ref,
                    "record_index": index,
                    "host": host,
                    "port": validate_port(asset.get("port")),
                    "vendor": validate_compact_text(asset.get("vendor"), field="vendor", max_chars=120),
                    "product": validate_compact_text(asset.get("product"), field="product", max_chars=120),
                    "status": "needs_review",
                }
            )
    chain = record.get("chain")
    if isinstance(chain, Mapping) and str(chain.get("path") or "").strip():
        preconditions = chain.get("preconditions") or []
        if not isinstance(preconditions, list):
            raise ValueError("preconditions must be a compact list")
        output.append(
            {
                "kind": "chain",
                "source_document_ref": document_ref,
                "record_index": index,
                "host": normalize_host(asset.get("host")) if isinstance(asset, Mapping) else "",
                "port": validate_port(asset.get("port")) if isinstance(asset, Mapping) else None,
                "path": _path(str(chain["path"])),
                "method": _method(chain.get("method")),
                "params": _parameters(chain.get("params") or []),
                "preconditions": [
                    validate_compact_text(item, field="precondition", max_chars=120, allow_empty=False) for item in preconditions[:5]
                ],
                "reference": validate_compact_text(chain.get("reference"), field="reference", max_chars=240),
                "status": "hypothesis",
            }
        )
    return output


def _match(conn: sqlite3.Connection, target_name: str, item: dict[str, Any]) -> dict[str, Any]:
    host = item.get("host") or ""
    port = item.get("port")
    asset = conn.execute(
        """SELECT id FROM target_assets WHERE target_name=? AND lower(asset_value)=?
           AND COALESCE(port,443)=COALESCE(?,443) ORDER BY id LIMIT 1""",
        (target_name, host, port),
    ).fetchone()
    endpoint = None
    if item["kind"] == "chain":
        endpoint = conn.execute(
            """SELECT id FROM endpoint_observations WHERE target_name=? AND lower(COALESCE(host,''))=?
               AND path=? AND upper(method)=? ORDER BY id LIMIT 1""",
            (target_name, host, item["path"], item["method"]),
        ).fetchone()
    asset_id = int(asset["id"]) if asset else None
    system = None
    if asset_id is not None:
        system = conn.execute(
            """SELECT system_id FROM system_asset_links WHERE target_name=? AND asset_id=?
               ORDER BY id LIMIT 1""",
            (target_name, asset_id),
        ).fetchone()
    status = "matched" if endpoint is not None else ("partial" if asset is not None else "unmatched")
    return {
        "system_id": int(system["system_id"]) if system else None,
        "asset_id": asset_id,
        "endpoint_id": int(endpoint["id"]) if endpoint else None,
        "status": status,
    }


def _items(conn: sqlite3.Connection, target_name: str, document_ref: str, records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    compact: list[dict[str, Any]] = []
    for index, record in enumerate(records):
        _validate_compact(record)
        for item in _compact_record(record, document_ref, index):
            item["match"] = _match(conn, target_name, item)
            compact.append(item)
    return compact


def _key(item: Mapping[str, Any]) -> str:
    material = "|".join(
        str(item.get(name) or "") for name in ("source_document_ref", "kind", "host", "port", "path", "method", "reference")
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:24]


def reconcile_peer_document(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    document_ref: str,
    records: Iterable[Mapping[str, Any]],
    apply: bool = False,
    include_items: bool = False,
    sample_size: int = 10,
) -> dict[str, Any]:
    if not document_ref or not 0 <= sample_size <= 100:
        raise ValueError("document_ref is required and sample_size must be between 0 and 100")
    document_ref = validate_evidence_ref(document_ref)
    materialized = list(records)
    if not apply:
        _validate_target(conn, target_name)
        items = _items(conn, target_name, document_ref, materialized)
        return _result(target_name, "preview", items, 0, 0, include_items, sample_size)
    nested = conn.in_transaction
    conn.execute("SAVEPOINT b7_peer_document" if nested else "BEGIN IMMEDIATE")
    try:
        _validate_target(conn, target_name)
        items = _items(conn, target_name, document_ref, materialized)
        sources_inserted = 0
        work_inserted = 0
        for item in items:
            key = _key(item)
            source_kind = f"peer_document_{item['kind']}"
            result_json = json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            cur = conn.execute(
                """INSERT OR IGNORE INTO recon_sources(target_name,source_kind,query,result_json,status)
                   VALUES(?,?,?,?, 'needs_review')""",
                (target_name, source_kind, key, result_json),
            )
            sources_inserted += max(cur.rowcount, 0)
            if item["kind"] != "chain" or item["match"]["status"] != "matched" or item["match"]["system_id"] is None:
                continue
            source_id = conn.execute(
                """SELECT id FROM recon_sources
                   WHERE target_name=? AND source_kind=? AND query=? AND result_json=?""",
                (target_name, source_kind, key, result_json),
            ).fetchone()["id"]
            summary = (
                f"peer document hypothesis matched observed endpoint {item['host']}:{item.get('port') or ''}"
                f"{item['path']}; applicability and replay remain unverified"
            )[:500]
            existing_work = conn.execute(
                """SELECT id FROM work_items WHERE target_name=? AND lane='hypothesis'
                   AND subtype='peer_document_chain' AND subject_table='recon_sources' AND subject_id=?
                   ORDER BY id LIMIT 1""",
                (target_name, str(source_id)),
            ).fetchone()
            if existing_work is None:
                work_id = create_work_item(
                    conn,
                    target_name=target_name,
                    lane="hypothesis",
                    subtype="peer_document_chain",
                    subject_table="recon_sources",
                    subject_id=str(source_id),
                    title="Review peer document chain",
                    objective="Reconcile one observed endpoint with one peer-document hypothesis",
                    auth_requirement="unknown",
                    risk_class="safe_passive",
                    timebox_minutes=10,
                    heartbeat_minutes=5,
                    system_id=int(item["match"]["system_id"]),
                    commit=False,
                )
                conn.execute(
                    """UPDATE work_items SET summary=?,next_action=? WHERE id=?""",
                    (summary, "operator-approved bounded replay if applicable", work_id),
                )
                work_inserted += 1
        if nested:
            conn.execute("RELEASE SAVEPOINT b7_peer_document")
        else:
            conn.commit()
    except Exception:
        if nested:
            conn.execute("ROLLBACK TO SAVEPOINT b7_peer_document")
            conn.execute("RELEASE SAVEPOINT b7_peer_document")
        else:
            conn.rollback()
        raise
    return _result(target_name, "apply", items, sources_inserted, work_inserted, include_items, sample_size)


def _result(
    target_name: str,
    mode: str,
    items: list[dict[str, Any]],
    sources_inserted: int,
    work_items_inserted: int,
    include_items: bool,
    sample_size: int,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "target_name": target_name,
        "mode": mode,
        "planned_sources": len(items),
        "sources_inserted": sources_inserted,
        "work_items_inserted": work_items_inserted,
        "sample": [
            {
                "kind": item["kind"],
                "record_index": item["record_index"],
                "match_status": item["match"]["status"],
            }
            for item in items[:sample_size]
        ],
        "omitted": max(0, len(items) - sample_size),
    }
    if include_items:
        result["items"] = items
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline peer-document reconciliation")
    parser.add_argument("--target", required=True)
    parser.add_argument("--file")
    parser.add_argument("--fixture", required=True)
    parser.add_argument("--document-ref", required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    path = Path(args.file) if args.file else find_db(args.target)
    fixture = Path(args.fixture)
    if not path.exists() or not fixture.is_file():
        print(json.dumps({"ok": False, "error": "database or fixture file does not exist"}, ensure_ascii=False))
        return 1
    try:
        records = json.loads(fixture.read_text(encoding="utf-8"))
        conn = connect(path)
        try:
            result = reconcile_peer_document(
                conn,
                target_name=args.target,
                document_ref=args.document_ref,
                records=records,
                apply=args.apply,
            )
        finally:
            conn.close()
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return 1
    print(json.dumps({"ok": True, **result}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
