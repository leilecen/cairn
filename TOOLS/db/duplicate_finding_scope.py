"""Exact, system-scoped duplicate-finding reconciliation."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

_TOOLS = Path(__file__).resolve().parent.parent
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))

from db.db_utils import connect, find_db  # noqa: E402
from db.identity_classification import (  # noqa: E402
    normalize_host,
    validate_compact_text,
    validate_evidence_refs,
)


def finding_scope_key(url: Any, vuln_class: Any) -> str:
    raw = validate_compact_text(url, field="finding url", max_chars=1000, allow_empty=False)
    parsed = urlparse(raw)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("finding url must be an absolute HTTP(S) URL")
    host = normalize_host(parsed.hostname)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("finding url port is invalid") from exc
    default = 80 if parsed.scheme.lower() == "http" else 443
    netloc = f"[{host}]" if ":" in host else host
    if port is not None and port != default:
        netloc += f":{port}"
    endpoint = urlunparse((parsed.scheme.lower(), netloc, parsed.path or "/", "", "", ""))
    kind = validate_compact_text(vuln_class, field="vulnerability class", max_chars=100, allow_empty=False)
    return f"{endpoint}|{kind.casefold()}"


def _finding(conn: sqlite3.Connection, *, target_name: str, system_id: int, finding_id: str) -> sqlite3.Row:
    fid = validate_compact_text(finding_id, field="finding id", max_chars=120, allow_empty=False)
    if conn.execute("SELECT 1 FROM target_systems WHERE id=? AND target_name=?", (system_id, target_name)).fetchone() is None:
        raise ValueError("system does not match target")
    row = conn.execute(
        """SELECT f.* FROM findings f JOIN targets t ON t.id=f.target_id
           WHERE f.id=? AND t.target_name=?""",
        (fid, target_name),
    ).fetchone()
    if row is None:
        raise ValueError("finding does not match target")
    parsed = urlparse(str(row["url"] or ""))
    host = normalize_host(parsed.hostname) if parsed.hostname else ""
    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    scoped = conn.execute(
        """SELECT 1 FROM system_asset_links l JOIN target_assets a ON a.id=l.asset_id
           WHERE l.target_name=? AND l.system_id=?
             AND lower(a.asset_value)=? AND COALESCE(a.port,?)=?
             AND a.scope_status='in_scope' AND a.scope_class IN ('owned','authorized_vendor')
             AND a.authorization_state<>'revoked' LIMIT 1""",
        (target_name, system_id, host, port, port),
    ).fetchone()
    if scoped is None:
        raise ValueError("finding asset is not linked to the requested system")
    return row


def _evidence_identity(raw: Any) -> tuple[int | None, str | None, list[str]]:
    try:
        payload = json.loads(str(raw or "{}"))
    except json.JSONDecodeError:
        return None, None, []
    if not isinstance(payload, dict):
        return None, None, []
    containers = [payload]
    for key in ("worker_result", "finding", "scope"):
        value = payload.get(key)
        if isinstance(value, dict):
            containers.append(value)
    system_id: int | None = None
    root_cause: str | None = None
    refs: list[str] = []
    for item in containers:
        raw_system = item.get("system_id") or item.get("source_system_id")
        if isinstance(raw_system, int) and not isinstance(raw_system, bool):
            system_id = raw_system
        raw_root = item.get("root_cause") or item.get("rootCause") or item.get("cause")
        if isinstance(raw_root, str) and raw_root.strip():
            try:
                root_cause = validate_compact_text(raw_root, field="root cause", max_chars=160, allow_empty=False).casefold()
            except ValueError:
                root_cause = None
        raw_refs = item.get("evidence_refs") or item.get("evidence_ids")
        if isinstance(raw_refs, list):
            try:
                refs.extend(validate_evidence_refs(raw_refs, allow_empty=True))
            except ValueError:
                pass
    return system_id, root_cause, list(dict.fromkeys(refs))[:20]


def _asset_for_finding(conn: sqlite3.Connection, *, target_name: str, system_id: int, url: str) -> int | None:
    parsed = urlparse(url)
    if not parsed.hostname:
        return None
    host = normalize_host(parsed.hostname)
    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    row = conn.execute(
        """SELECT a.id FROM system_asset_links l JOIN target_assets a ON a.id=l.asset_id
           WHERE l.target_name=? AND l.system_id=? AND lower(a.asset_value)=?
             AND COALESCE(a.port,?)=? AND a.scope_status='in_scope'
             AND a.scope_class IN ('owned','authorized_vendor') AND a.authorization_state<>'revoked'
           ORDER BY a.id LIMIT 1""",
        (target_name, system_id, host, port, port),
    ).fetchone()
    return int(row[0]) if row else None


def _exact_key(
    conn: sqlite3.Connection, *, target_name: str, requested_system_id: int, row: sqlite3.Row
) -> tuple[int, int, str, str, str] | None:
    evidence_system, root_cause, _ = _evidence_identity(row["evidence"])
    if evidence_system is not None and evidence_system != requested_system_id:
        return None
    asset_id = _asset_for_finding(conn, target_name=target_name, system_id=requested_system_id, url=str(row["url"] or ""))
    if asset_id is None or root_cause is None:
        return None
    scope = finding_scope_key(row["url"], row["type"])
    normalized_endpoint, vuln_class = scope.rsplit("|", 1)
    normalized_path = urlparse(normalized_endpoint).path or "/"
    return requested_system_id, asset_id, normalized_path, vuln_class, root_cause


def reconcile_duplicate_finding(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    system_id: int,
    finding_id: str,
    apply: bool = False,
    sample_size: int = 10,
) -> dict[str, Any]:
    if not 0 <= sample_size <= 100:
        raise ValueError("sample_size must be between 0 and 100")
    nested = conn.in_transaction
    if apply:
        conn.execute("SAVEPOINT m9_duplicate_finding" if nested else "BEGIN IMMEDIATE")
    try:
        candidate = _finding(conn, target_name=target_name, system_id=system_id, finding_id=finding_id)
        key = _exact_key(conn, target_name=target_name, requested_system_id=system_id, row=candidate)
        rows = conn.execute(
            """SELECT f.id,f.url,f.type,f.evidence FROM findings f JOIN targets t ON t.id=f.target_id
               WHERE t.target_name=? AND f.id<>? ORDER BY f.id LIMIT 1000""",
            (target_name, finding_id),
        ).fetchall()
        matches = [
            str(row["id"])
            for row in rows
            if key is not None and _exact_key(conn, target_name=target_name, requested_system_id=system_id, row=row) == key
        ]
        duplicate_of = matches[0] if matches else None
        updated = 0
        if apply and duplicate_of is not None:
            duplicate = next(row for row in rows if str(row["id"]) == duplicate_of)
            _, _, candidate_refs = _evidence_identity(candidate["evidence"])
            _, _, duplicate_refs = _evidence_identity(duplicate["evidence"])
            refs = list(dict.fromkeys(candidate_refs + duplicate_refs))[:20]
            note = (
                f"duplicate_of:{duplicate_of}; scope=exact_asset_system_path_class_root_cause; "
                f"evidence_refs={json.dumps(refs, ensure_ascii=False, separators=(',', ':'))}"
            )
            current = (candidate["review_status"], candidate["review_notes"] or "")
            if current != ("duplicate", note):
                conn.execute(
                    "UPDATE findings SET review_status='duplicate',review_notes=? WHERE id=?",
                    (note, finding_id),
                )
                updated = 1
        if apply:
            if nested:
                conn.execute("RELEASE SAVEPOINT m9_duplicate_finding")
            else:
                conn.commit()
    except Exception:
        if apply:
            if nested:
                conn.execute("ROLLBACK TO SAVEPOINT m9_duplicate_finding")
                conn.execute("RELEASE SAVEPOINT m9_duplicate_finding")
            else:
                conn.rollback()
        raise
    return {
        "target_name": target_name,
        "system_id": system_id,
        "finding_id": finding_id,
        "mode": "apply" if apply else "preview",
        "duplicate_of": duplicate_of,
        "match_count": len(matches),
        "updated": updated,
        "network_request_count": 0,
        "sample": matches[:sample_size],
        "omitted": max(0, len(matches) - sample_size),
    }


def _path(target: str, file: str | None) -> Path:
    path = Path(file) if file else find_db(target)
    if not path.is_file():
        raise FileNotFoundError(f"database file does not exist: {path}")
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description="Exact duplicate finding scope reconciliation")
    parser.add_argument("--target", required=True)
    parser.add_argument("--file")
    parser.add_argument("--system-id", required=True, type=int)
    parser.add_argument("--finding-id", required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    try:
        conn = connect(_path(args.target, args.file))
        try:
            result = reconcile_duplicate_finding(
                conn,
                target_name=args.target,
                system_id=args.system_id,
                finding_id=args.finding_id,
                apply=args.apply,
            )
        finally:
            conn.close()
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return 1
    print(json.dumps({"ok": True, **result}, ensure_ascii=False, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
