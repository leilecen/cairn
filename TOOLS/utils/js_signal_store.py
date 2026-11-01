"""Persistence helpers for JS intelligence signals and clusters."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from urllib.parse import urlparse


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}


def canonicalize_signal(signal: dict) -> dict:
    normalized = dict(signal)
    method = (normalized.get("method") or "GET").upper()
    url = normalized.get("url") or ""
    path = normalized.get("path") or (urlparse(url).path if url else "")
    normalized["method"] = method
    normalized["path"] = path or ""
    normalized["host"] = normalized.get("host") or (urlparse(url).netloc if url else "")
    normalized["protocol"] = normalized.get("protocol") or "http"
    normalized["params"] = list(normalized.get("params") or [])
    normalized["headers"] = list(normalized.get("headers") or [])
    normalized["value_flow"] = dict(normalized.get("value_flow") or {})
    normalized["caller_chain"] = list(normalized.get("caller_chain") or [])
    normalized["runtime_seen"] = int(normalized.get("runtime_seen") or 0)
    normalized["runtime_evidence"] = list(normalized.get("runtime_evidence") or [])
    normalized["confidence"] = int(normalized.get("confidence") or 50)
    normalized["risk_score"] = int(normalized.get("risk_score") or 0)
    return normalized


def build_cluster_fingerprint(signal: dict) -> str:
    normalized = canonicalize_signal(signal)
    key = "|".join(
        [
            normalized.get("signal_type", ""),
            normalized.get("method", ""),
            normalized.get("host", ""),
            normalized.get("path", ""),
            normalized.get("signature_hint", ""),
        ]
    )
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:24]


def insert_js_signal(
    conn: sqlite3.Connection,
    target_id: int | None,
    js_file_id: int | None,
    signal: dict,
    source_kind: str,
    *,
    commit: bool = True,
) -> str:
    normalized = canonicalize_signal(signal)
    signal_id = normalized.get("id") or f"JS-SIG-{uuid.uuid4().hex[:10]}"
    available = _table_columns(conn, "js_signals")
    payload = {
        "id": signal_id,
        "target_id": target_id,
        "js_file_id": js_file_id,
        "source_kind": source_kind,
        "signal_type": normalized.get("signal_type"),
        "protocol": normalized.get("protocol"),
        "method": normalized.get("method"),
        "url": normalized.get("url"),
        "path": normalized.get("path"),
        "host": normalized.get("host"),
        "params_json": json.dumps(normalized.get("params", []), ensure_ascii=False),
        "headers_json": json.dumps(normalized.get("headers", []), ensure_ascii=False),
        "evidence_snippet": normalized.get("evidence_snippet", ""),
        "evidence_location": normalized.get("evidence_location", ""),
        "caller_hint": normalized.get("caller_hint", ""),
        "page_route": normalized.get("page_route", ""),
        "auth_hint": normalized.get("auth_hint", ""),
        "signature_hint": normalized.get("signature_hint", ""),
        "business_hint": normalized.get("business_hint", ""),
        "value_flow_json": json.dumps(normalized.get("value_flow", {}), ensure_ascii=False),
        "caller_chain_json": json.dumps(normalized.get("caller_chain", []), ensure_ascii=False),
        "runtime_seen": normalized.get("runtime_seen", 0),
        "runtime_evidence_json": json.dumps(normalized.get("runtime_evidence", []), ensure_ascii=False),
        "confidence": normalized.get("confidence", 50),
        "risk_score": normalized.get("risk_score", 0),
        "status": normalized.get("status", "new"),
    }
    columns = [column for column in payload if column in available]
    placeholders = ", ".join("?" for _ in columns)
    insert_sql = f"INSERT INTO js_signals ({', '.join(columns)}) VALUES ({placeholders})"  # noqa: S608 -- 列名经 schema 白名单过滤，SQL 表达式来自静态 update_map
    update_map = {
        "url": "excluded.url",
        "host": "excluded.host",
        "params_json": "excluded.params_json",
        "headers_json": "excluded.headers_json",
        "evidence_snippet": "excluded.evidence_snippet",
        "caller_hint": "excluded.caller_hint",
        "auth_hint": "excluded.auth_hint",
        "signature_hint": "excluded.signature_hint",
        "business_hint": "excluded.business_hint",
        "value_flow_json": "COALESCE(excluded.value_flow_json, js_signals.value_flow_json)",
        "caller_chain_json": "COALESCE(excluded.caller_chain_json, js_signals.caller_chain_json)",
        "runtime_seen": "MAX(js_signals.runtime_seen, excluded.runtime_seen)",
        "runtime_evidence_json": "COALESCE(excluded.runtime_evidence_json, js_signals.runtime_evidence_json)",
        "confidence": "MAX(js_signals.confidence, excluded.confidence)",
        "risk_score": "MAX(js_signals.risk_score, excluded.risk_score)",
    }
    assignments = [f"{column} = {expr}" for column, expr in update_map.items() if column in available]
    if "updated_at" in available:
        assignments.append("updated_at = datetime('now','localtime')")
    insert_sql += " ON CONFLICT(js_file_id, signal_type, method, path, evidence_location) DO UPDATE SET " + ", ".join(assignments)
    conn.execute(insert_sql, tuple(payload[column] for column in columns))
    if commit:
        conn.commit()
    row = conn.execute(
        """
        SELECT id FROM js_signals
        WHERE js_file_id IS ? AND signal_type = ? AND method = ? AND path = ? AND evidence_location = ?
        """,
        (
            js_file_id,
            normalized.get("signal_type"),
            normalized.get("method"),
            normalized.get("path"),
            normalized.get("evidence_location", ""),
        ),
    ).fetchone()
    return row[0] if row else signal_id


def upsert_js_cluster(conn: sqlite3.Connection, target_id: int | None, signal_id: str, *, commit: bool = True) -> str:
    available = _table_columns(conn, "js_signal_clusters")
    row = conn.execute("SELECT * FROM js_signals WHERE id=?", (signal_id,)).fetchone()
    if row is None:
        raise ValueError(f"js_signal not found: {signal_id}")
    signal = dict(row)
    signal["params"] = json.loads(signal.get("params_json") or "[]")
    fingerprint = build_cluster_fingerprint(signal)
    cluster_id = f"JS-CLU-{fingerprint[:12]}"
    canonical_url = signal.get("url") or signal.get("path") or ""
    existing = conn.execute(
        "SELECT * FROM js_signal_clusters WHERE target_id IS ? AND fingerprint=?",
        (target_id, fingerprint),
    ).fetchone()
    if existing is None:
        payload = {
            "id": cluster_id,
            "target_id": target_id,
            "fingerprint": fingerprint,
            "canonical_method": signal.get("method") or "GET",
            "canonical_url": canonical_url,
            "signal_types_json": json.dumps([signal.get("signal_type")], ensure_ascii=False),
            "source_count": 1,
            "best_confidence": signal.get("confidence") or 50,
            "best_risk_score": signal.get("risk_score") or 0,
            "representative_signal_id": signal_id,
            "status": "new",
            "runtime_seen": signal.get("runtime_seen") or 0,
            "runtime_count": 1 if signal.get("runtime_seen") else 0,
        }
        columns = [column for column in payload if column in available]
        placeholders = ", ".join("?" for _ in columns)
        conn.execute(
            f"INSERT INTO js_signal_clusters ({', '.join(columns)}) VALUES ({placeholders})",  # noqa: S608 -- 列名经 schema 白名单过滤，值走参数绑定
            tuple(payload[column] for column in columns),
        )
    else:
        signal_types = set(json.loads(existing["signal_types_json"] or "[]"))
        signal_types.add(signal.get("signal_type"))
        best_risk_score = max(existing["best_risk_score"] or 0, signal.get("risk_score") or 0)
        representative_signal_id = (
            signal_id if (signal.get("risk_score") or 0) >= (existing["best_risk_score"] or 0) else existing["representative_signal_id"]
        )
        status = "clustered" if best_risk_score >= 70 else existing["status"]
        assignments = []
        values = []
        if "canonical_method" in available:
            assignments.append("canonical_method=?")
            values.append(signal.get("method") or existing["canonical_method"] or "GET")
        if "canonical_url" in available:
            assignments.append("canonical_url=CASE WHEN COALESCE(canonical_url, '') = '' THEN ? ELSE canonical_url END")
            values.append(canonical_url)
        if "signal_types_json" in available:
            assignments.append("signal_types_json=?")
            values.append(json.dumps(sorted(signal_types), ensure_ascii=False))
        if "source_count" in available:
            assignments.append("source_count=source_count + 1")
        if "best_confidence" in available:
            assignments.append("best_confidence=MAX(best_confidence, ?)")
            values.append(signal.get("confidence") or 50)
        if "best_risk_score" in available:
            assignments.append("best_risk_score=?")
            values.append(best_risk_score)
        if "representative_signal_id" in available:
            assignments.append("representative_signal_id=?")
            values.append(representative_signal_id)
        if "runtime_seen" in available:
            assignments.append("runtime_seen=MAX(runtime_seen, ?)")
            values.append(signal.get("runtime_seen") or 0)
        if "runtime_count" in available:
            assignments.append("runtime_count=runtime_count + ?")
            values.append(1 if signal.get("runtime_seen") else 0)
        if "status" in available:
            assignments.append("status=?")
            values.append(status)
        if "updated_at" in available:
            assignments.append("updated_at=datetime('now','localtime')")
        values.append(existing["id"])
        conn.execute(f"UPDATE js_signal_clusters SET {', '.join(assignments)} WHERE id=?", tuple(values))  # noqa: S608 -- SET 子句由固定列名字面量拼接，值走参数绑定
    if commit:
        conn.commit()
    return cluster_id


def promote_js_candidates(conn: sqlite3.Connection, min_score: int = 70, target_id: int | None = None) -> int:
    columns = _table_columns(conn, "js_signal_clusters")
    target_clause = ""
    params: list[object] = [min_score]
    if target_id is not None and "target_id" in columns:
        target_clause = " AND c.target_id = ?"
        params.append(target_id)
    rows = conn.execute(
        f"""
        SELECT c.*, s.params_json, s.signature_hint, s.auth_hint, s.evidence_snippet
        FROM js_signal_clusters c
        LEFT JOIN js_signals s ON s.id = c.representative_signal_id
        WHERE COALESCE(c.best_risk_score, 0) >= ?
          AND COALESCE(c.status, 'new') != 'promoted'{target_clause}
        """,  # noqa: S608 -- 仅拼接 "?" 占位符与固定字面量，值走参数绑定
        tuple(params),
    ).fetchall()
    created = 0
    for row in rows:
        params_text = ",".join(json.loads(row["params_json"] or "[]"))
        sp_id = f"SP-JI-{uuid.uuid4().hex[:8]}"
        evidence = row["evidence_snippet"] or row["canonical_url"] or row["fingerprint"]
        conn.execute(
            """
            INSERT OR IGNORE INTO suspicious_points (
                id, url, param, method, test_type, evidence, source, risk,
                test_status, created_at, reasoning, risk_score
            ) VALUES (?, ?, ?, ?, 'js_cluster', ?, 'js_intel', 'Medium', 'untested', datetime('now','localtime'), ?, ?)
            """,
            (
                sp_id,
                row["canonical_url"],
                params_text,
                row["canonical_method"] or "GET",
                evidence,
                f"js_cluster:{row['fingerprint']}",
                row["best_risk_score"],
            ),
        )
        inserted = conn.execute("SELECT changes()").fetchone()[0]
        if inserted:
            created += 1
            conn.execute(
                "UPDATE js_signal_clusters SET status='promoted' WHERE id=?",
                (row["id"],),
            )
            conn.execute(
                "UPDATE js_signals SET status='promoted', promoted_sp_id=? WHERE id=?",
                (sp_id, row["representative_signal_id"]),
            )
    conn.commit()
    return created
