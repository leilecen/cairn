"""Offline passive HAR/CDP observation importer; it never drives browser navigation."""

from __future__ import annotations

import json
import re
import sqlite3
from typing import Any, Mapping
from urllib.parse import parse_qsl, urlsplit, urlunsplit

_SECRET = re.compile(r"(?i)(?:authorization|cookie|token|password|secret)\s*[:=]\s*[^\s,;]+|bearer\s+\S+")
_BLOCKERS = {"login", "qr", "captcha", "download", "cross_origin"}


def _url(value: Any) -> str:
    raw = str(value or "").strip()
    if _SECRET.search(raw):
        raise ValueError("credential material is not accepted")
    parsed = urlsplit(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("observed URL must be absolute http(s)")
    query = "&".join(f"{key}=" for key, _ in parse_qsl(parsed.query, keep_blank_values=True))
    return urlunsplit((parsed.scheme, parsed.netloc.lower(), parsed.path or "/", query, ""))


def classify_auth_state(event: Mapping[str, Any]) -> str:
    if event.get("auth_state_trusted") is True and event.get("auth_state") in {"public", "authenticated", "unknown"}:
        return str(event["auth_state"])
    status = int(event.get("status", 0) or 0)
    if status in {401, 403} or event.get("login_redirect") is True:
        return "unknown"
    if status and 200 <= status < 300 and event.get("observed_with_session") is True:
        return "authenticated"
    if status and 200 <= status < 300 and event.get("observed_with_session") is False:
        return "public"
    return "unknown"


def _origin_key(parsed: Any) -> tuple[str, str, int]:
    """Normalize scheme/host/port so default ports never split one origin."""
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    try:
        port = parsed.port
    except ValueError:
        port = None
    if port is None:
        port = 443 if scheme == "https" else 80
    return (scheme, host, port)


def import_passive_observations(
    conn: sqlite3.Connection, *, target_name: str, page_url: str, events: list[Mapping[str, Any]]
) -> dict[str, Any]:
    """Import already-captured xhr/fetch/script facts. No requests, SPs, or work items.

    Two-phase import for atomicity: every event is validated and prepared before
    the first write, and the write phase runs inside a savepoint, so a malformed
    event can never leave a half-imported batch behind in the caller transaction.
    Counters reflect rows actually inserted (INSERT OR IGNORE duplicates are not
    reported as new), and cross-origin checks normalize default ports per scheme.
    """
    if not conn.execute("SELECT 1 FROM targets WHERE target_name=?", (target_name,)).fetchone():
        raise ValueError("target_name does not match database")
    page = _url(page_url)
    origin = _origin_key(urlsplit(page))
    # Phase 1: validate and prepare every row before touching the database.
    prepared: list[tuple[str, dict[str, Any]]] = []
    blocked = 0
    for event in events:
        kind = str(event.get("resource_type") or "").lower()
        if str(event.get("blocker") or "").lower() in _BLOCKERS:
            blocked += 1
            continue
        url = _url(event.get("url"))
        parsed = urlsplit(url)
        if _origin_key(parsed) != origin:
            blocked += 1
            continue
        refs = event.get("evidence_refs") or []
        if not isinstance(refs, list) or not refs:
            raise ValueError("compact evidence_refs are required")
        if any(_SECRET.search(str(ref)) for ref in refs):
            raise ValueError("credential material is not accepted")
        refs_json = json.dumps([str(ref)[:160] for ref in refs[:10]], separators=(",", ":"))
        if kind in {"xhr", "fetch"}:
            prepared.append(
                (
                    "endpoint",
                    {
                        "target_name": target_name,
                        "url": url,
                        "host": parsed.hostname,
                        "path": parsed.path or "/",
                        "method": str(event.get("method") or "GET").upper(),
                        "auth_state": classify_auth_state(event),
                        "refs_json": refs_json,
                    },
                )
            )
        elif kind == "script":
            prepared.append(("script", {"url": url, "page": page}))
        else:
            continue
        if any(token in parsed.path.lower() for token in ("/mobile/", "/h5/", "/app/")):
            prepared.append(("seed", {"url": url, "refs_json": refs_json}))
    # Phase 2: write inside a savepoint so any write failure rolls back the batch.
    nested = conn.in_transaction
    conn.execute("SAVEPOINT auth_passive_import" if nested else "BEGIN IMMEDIATE")
    endpoints = scripts = seeds = 0
    try:
        for kind, payload in prepared:
            if kind == "endpoint":
                cur = conn.execute(
                    """INSERT OR IGNORE INTO endpoint_observations(
                           target_name,canonical_url,host,path,method,source,auth_state,evidence_refs_json)
                       VALUES(?,?,?,?,?,'auth_passive',?,?)""",
                    (
                        payload["target_name"],
                        payload["url"],
                        payload["host"],
                        payload["path"],
                        payload["method"],
                        payload["auth_state"],
                        payload["refs_json"],
                    ),
                )
                endpoints += max(cur.rowcount, 0)
            elif kind == "script":
                cur = conn.execute(
                    """INSERT INTO js_files(url,page_url,source_kind,extraction_status)
                       VALUES(?,?,'browser_script','pending')
                       ON CONFLICT(url) DO UPDATE SET source_kind='browser_script'""",
                    (payload["url"], payload["page"]),
                )
                scripts += max(cur.rowcount, 0)
            else:
                cur = conn.execute(
                    """INSERT OR IGNORE INTO recon_sources(target_name,source_kind,query,result_json,status)
                       VALUES(?,'entry_recursion_observed',?,?,'needs_review')""",
                    (
                        target_name,
                        payload["url"],
                        json.dumps(
                            {"url": payload["url"], "evidence_refs": json.loads(payload["refs_json"])},
                            separators=(",", ":"),
                        ),
                    ),
                )
                seeds += max(cur.rowcount, 0)
        if nested:
            conn.execute("RELEASE SAVEPOINT auth_passive_import")
        else:
            conn.commit()
    except Exception:
        if nested:
            conn.execute("ROLLBACK TO SAVEPOINT auth_passive_import")
            conn.execute("RELEASE SAVEPOINT auth_passive_import")
        else:
            conn.rollback()
        raise
    return {
        "endpoints": endpoints,
        "scripts": scripts,
        "m9_seeds": seeds,
        "blocked": blocked,
        "network_request_count": 0,
    }
