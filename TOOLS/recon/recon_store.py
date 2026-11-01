"""Compact, idempotent storage for reconnaissance observations."""

from __future__ import annotations

import json
import re
import sqlite3
from typing import Any, Iterable


def ensure_recon_schema(conn: sqlite3.Connection) -> None:
    """Create recon tables for legacy DBs before blackboard operations."""
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS recon_sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT, target_name TEXT NOT NULL,
            source_kind TEXT NOT NULL, query TEXT, result_json TEXT NOT NULL DEFAULT '{}',
            status TEXT NOT NULL DEFAULT 'observed', error TEXT,
            observed_at TEXT DEFAULT (datetime('now','localtime')),
            UNIQUE(target_name, source_kind, query, result_json)
        );
        CREATE TABLE IF NOT EXISTS origin_candidates (
            id INTEGER PRIMARY KEY AUTOINCREMENT, target_name TEXT NOT NULL, asset_id INTEGER,
            hostname TEXT NOT NULL, candidate_ip TEXT NOT NULL, source TEXT NOT NULL,
            confidence TEXT NOT NULL DEFAULT 'unknown', score INTEGER NOT NULL DEFAULT 0,
            verification_status TEXT NOT NULL DEFAULT 'unknown',
            evidence_refs_json TEXT NOT NULL DEFAULT '[]', notes TEXT,
            observed_at TEXT DEFAULT (datetime('now','localtime')),
            UNIQUE(target_name, asset_id, hostname, candidate_ip, source)
        );
        CREATE TABLE IF NOT EXISTS cdn_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT, target_name TEXT NOT NULL, asset_id INTEGER,
            hostname TEXT NOT NULL, classification TEXT NOT NULL, provider TEXT NOT NULL DEFAULT '',
            reasons_json TEXT NOT NULL DEFAULT '[]', evidence_refs_json TEXT NOT NULL DEFAULT '[]',
            observed_at TEXT DEFAULT (datetime('now','localtime')),
            UNIQUE(target_name, asset_id, hostname, classification, provider)
        );
        CREATE TABLE IF NOT EXISTS network_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT, target_name TEXT NOT NULL, asset_id INTEGER,
            host TEXT NOT NULL, ip TEXT, port INTEGER, protocol TEXT, service TEXT,
            tls_json TEXT NOT NULL DEFAULT '{}', http_json TEXT NOT NULL DEFAULT '{}',
            waf_signal TEXT, load_balancer_signal TEXT, status TEXT NOT NULL DEFAULT 'observed',
            source TEXT NOT NULL, evidence_refs_json TEXT NOT NULL DEFAULT '[]',
            observed_at TEXT DEFAULT (datetime('now','localtime')),
            UNIQUE(target_name, host, ip, port, protocol, source)
        );
        CREATE TABLE IF NOT EXISTS technology_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT, target_name TEXT NOT NULL, asset_id INTEGER,
            host TEXT NOT NULL, technology TEXT NOT NULL, category TEXT NOT NULL DEFAULT 'framework',
            version TEXT, confidence TEXT NOT NULL DEFAULT 'unknown', source TEXT NOT NULL,
            evidence_refs_json TEXT NOT NULL DEFAULT '[]', observed_at TEXT DEFAULT (datetime('now','localtime')),
            UNIQUE(target_name, host, technology, version, source)
        );
        CREATE TABLE IF NOT EXISTS entry_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT, target_name TEXT NOT NULL, asset_id INTEGER,
            url TEXT NOT NULL, entry_type TEXT NOT NULL, source TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'unknown', status_code INTEGER,
            confidence TEXT NOT NULL DEFAULT 'unknown', response_class TEXT,
            evidence_refs_json TEXT NOT NULL DEFAULT '[]', notes TEXT,
            observed_at TEXT DEFAULT (datetime('now','localtime')),
            UNIQUE(target_name, asset_id, url, entry_type, source)
        );
        """
    )
    conn.commit()


def _json(value: Any) -> str:
    return json.dumps(_compact(value), ensure_ascii=False, sort_keys=True)


_SECRET_KEY = re.compile(r"(password|passwd|secret|token|authorization|cookie|private[_-]?key|access[_-]?key)", re.I)
_SECRET_VALUE = re.compile(
    r"(?i)(authorization\s*:\s*[^\r\n,;]+|cookie\s*:\s*[^\r\n,;]+|"
    r"(?:password|passwd|token|secret|提取码)\s*[:=]\s*[^\s,;]+|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,})"
)


def _compact(value: Any, *, depth: int = 0) -> Any:
    if depth > 4:
        return "[truncated]"
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in list(value.items())[:80]:
            key_text = str(key)
            result[key_text] = "[redacted]" if _SECRET_KEY.search(key_text) else _compact(item, depth=depth + 1)
        return result
    if isinstance(value, list):
        return [_compact(item, depth=depth + 1) for item in value[:100]]
    if isinstance(value, str):
        text = value[:1000]
        return _SECRET_VALUE.sub("[redacted]", text)
    return value


def record_source(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    source_kind: str,
    query: str = "",
    result: Any = None,
    status: str = "observed",
    error: str = "",
    ensure_schema: bool = True,
    commit: bool = True,
) -> int:
    if ensure_schema:
        ensure_recon_schema(conn)
    cur = conn.execute(
        """INSERT OR IGNORE INTO recon_sources
           (target_name, source_kind, query, result_json, status, error)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (target_name, source_kind, query, _json(result or {}), status, error),
    )
    if commit:
        conn.commit()
    return int(cur.lastrowid or 0)


def record_origin(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    hostname: str,
    candidate_ip: str,
    source: str,
    asset_id: int | None = None,
    confidence: str = "unknown",
    score: int = 0,
    verification_status: str = "unknown",
    evidence_refs: Iterable[str] = (),
    notes: str = "",
) -> int:
    ensure_recon_schema(conn)
    existing = conn.execute(
        """SELECT id FROM origin_candidates
           WHERE target_name=? AND asset_id IS ? AND hostname=? AND candidate_ip=? AND source=?""",
        (target_name, asset_id, hostname, candidate_ip, source),
    ).fetchone()
    values = (confidence, score, verification_status, _json(list(evidence_refs)), notes)
    if existing:
        conn.execute(
            """UPDATE origin_candidates SET confidence=?, score=?, verification_status=?,
               evidence_refs_json=?, notes=? WHERE id=?""",
            values + (existing[0],),
        )
        conn.commit()
        return int(existing[0])
    cur = conn.execute(
        """INSERT INTO origin_candidates
           (target_name, asset_id, hostname, candidate_ip, source, confidence, score,
            verification_status, evidence_refs_json, notes)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(target_name, asset_id, hostname, candidate_ip, source)
           DO UPDATE SET confidence=excluded.confidence, score=excluded.score,
             verification_status=excluded.verification_status,
             evidence_refs_json=excluded.evidence_refs_json, notes=excluded.notes""",
        (
            target_name,
            asset_id,
            hostname,
            candidate_ip,
            source,
            confidence,
            score,
            verification_status,
            _json(list(evidence_refs)),
            notes,
        ),
    )
    conn.commit()
    return int(cur.lastrowid or 0)


def record_cdn_observation(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    asset_id: int,
    hostname: str,
    classification: str,
    provider: str | None,
    reasons: Iterable[str] = (),
    evidence_refs: Iterable[str] = (),
) -> int:
    ensure_recon_schema(conn)
    existing = conn.execute(
        """SELECT id FROM cdn_observations WHERE target_name=? AND asset_id=? AND hostname=?
           AND classification=? AND provider=?""",
        (target_name, asset_id, hostname, classification, provider or ""),
    ).fetchone()
    values = (_json(list(reasons)), _json(list(evidence_refs)))
    if existing:
        conn.execute(
            "UPDATE cdn_observations SET reasons_json=?,evidence_refs_json=? WHERE id=?",
            values + (existing[0],),
        )
        conn.commit()
        return int(existing[0])
    cur = conn.execute(
        """INSERT INTO cdn_observations(
               target_name,asset_id,hostname,classification,provider,reasons_json,evidence_refs_json
           ) VALUES(?,?,?,?,?,?,?)""",
        (target_name, asset_id, hostname, classification, provider or "", *values),
    )
    conn.commit()
    return int(cur.lastrowid or 0)


def record_entry(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    url: str,
    entry_type: str,
    source: str,
    status: str = "unknown",
    status_code: int | None = None,
    confidence: str = "unknown",
    response_class: str = "",
    evidence_refs: Iterable[str] = (),
    asset_id: int | None = None,
    notes: str = "",
) -> int:
    ensure_recon_schema(conn)
    existing = conn.execute(
        """SELECT id FROM entry_observations
           WHERE target_name=? AND asset_id IS ? AND url=? AND entry_type=? AND source=?""",
        (target_name, asset_id, url, entry_type, source),
    ).fetchone()
    values = (status, status_code, confidence, response_class, _json(list(evidence_refs)), notes)
    if existing:
        conn.execute(
            """UPDATE entry_observations SET status=?, status_code=?, confidence=?,
               response_class=?, evidence_refs_json=?, notes=? WHERE id=?""",
            values + (existing[0],),
        )
        conn.commit()
        return int(existing[0])
    cur = conn.execute(
        """INSERT INTO entry_observations
           (target_name, asset_id, url, entry_type, source, status, status_code,
            confidence, response_class, evidence_refs_json, notes)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(target_name, asset_id, url, entry_type, source)
           DO UPDATE SET status=excluded.status, status_code=excluded.status_code,
             confidence=excluded.confidence, response_class=excluded.response_class,
             evidence_refs_json=excluded.evidence_refs_json, notes=excluded.notes""",
        (
            target_name,
            asset_id,
            url,
            entry_type,
            source,
            status,
            status_code,
            confidence,
            response_class,
            _json(list(evidence_refs)),
            notes,
        ),
    )
    conn.commit()
    return int(cur.lastrowid or 0)


def record_network(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    host: str,
    source: str,
    asset_id: int | None = None,
    ip: str = "",
    port: int | None = None,
    protocol: str = "",
    service: str = "",
    tls: Any = None,
    http: Any = None,
    waf_signal: str = "",
    load_balancer_signal: str = "",
    status: str = "observed",
    evidence_refs: Iterable[str] = (),
) -> int:
    ensure_recon_schema(conn)
    existing = conn.execute(
        """SELECT id FROM network_observations WHERE target_name=? AND host=? AND ip IS ?
           AND port IS ? AND protocol=? AND source=?""",
        (target_name, host, ip or None, port, protocol, source),
    ).fetchone()
    params = (
        service,
        _json(tls or {}),
        _json(http or {}),
        waf_signal,
        load_balancer_signal,
        status,
        _json(list(evidence_refs)),
    )
    if existing:
        conn.execute(
            """UPDATE network_observations SET service=?, tls_json=?, http_json=?, waf_signal=?,
               load_balancer_signal=?, status=?, evidence_refs_json=? WHERE id=?""",
            params + (existing[0],),
        )
        conn.commit()
        return int(existing[0])
    cur = conn.execute(
        """INSERT INTO network_observations
           (target_name, asset_id, host, ip, port, protocol, service, tls_json, http_json,
            waf_signal, load_balancer_signal, status, source, evidence_refs_json)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            target_name,
            asset_id,
            host,
            ip or None,
            port,
            protocol,
            service,
            _json(tls or {}),
            _json(http or {}),
            waf_signal,
            load_balancer_signal,
            status,
            source,
            _json(list(evidence_refs)),
        ),
    )
    conn.commit()
    return int(cur.lastrowid or 0)


def record_technology(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    host: str,
    technology: str,
    source: str,
    asset_id: int | None = None,
    category: str = "framework",
    version: str = "",
    confidence: str = "unknown",
    evidence_refs: Iterable[str] = (),
) -> int:
    ensure_recon_schema(conn)
    existing = conn.execute(
        """SELECT id FROM technology_observations WHERE target_name=? AND host=?
           AND technology=? AND version IS ? AND source=?""",
        (target_name, host, technology, version or None, source),
    ).fetchone()
    if existing:
        conn.execute(
            """UPDATE technology_observations SET category=?, confidence=?, evidence_refs_json=?
               WHERE id=?""",
            (category, confidence, _json(list(evidence_refs)), existing[0]),
        )
        conn.commit()
        return int(existing[0])
    cur = conn.execute(
        """INSERT INTO technology_observations
           (target_name, asset_id, host, technology, category, version, confidence, source, evidence_refs_json)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            target_name,
            asset_id,
            host,
            technology,
            category,
            version or None,
            confidence,
            source,
            _json(list(evidence_refs)),
        ),
    )
    conn.commit()
    return int(cur.lastrowid or 0)


def compact_recon_summary(conn: sqlite3.Connection, *, target_name: str) -> dict[str, Any]:
    ensure_recon_schema(conn)

    def count(table: str) -> int:
        allowed = {
            "recon_sources",
            "origin_candidates",
            "cdn_observations",
            "network_observations",
            "technology_observations",
            "entry_observations",
        }
        if table not in allowed:
            raise ValueError(f"unsupported recon summary table: {table}")
        query = f"SELECT COUNT(*) FROM {table} WHERE target_name=?"  # noqa: S608 - table is allowlisted above.
        return int(conn.execute(query, (target_name,)).fetchone()[0])

    return {
        "target": target_name,
        "sources": count("recon_sources"),
        "origin_candidates": count("origin_candidates"),
        "cdn_observations": count("cdn_observations"),
        "network_observations": count("network_observations"),
        "technology_observations": count("technology_observations"),
        "entry_observations": count("entry_observations"),
    }
