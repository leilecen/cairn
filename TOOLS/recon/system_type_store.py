"""Persist compact, per-asset declarative system type observations."""

from __future__ import annotations

import json
import re
import sqlite3
from typing import Any

from recon.system_types import classify_system

# Response classes that actually evidence an entry point.  A transport failure
# (status_code 0) or a not-found/unknown response is absence of evidence; letting
# those rows through previously labelled unreachable hosts as login systems.
_ENTRY_RESPONSE_CLASSES = ("auth_redirect", "auth_required", "restricted")

_CLASSIFIER = "declarative_system_types"
_RULE_CONTEXT = "system_signatures:v1"
_SECRET = re.compile(
    r"(?i)(authorization\s*:\s*[^\s,;]+|cookie\s*:\s*[^\s,;]+|"
    r"(?:token|secret|password|passwd)\s*[:=]\s*[^\s,;]+)"
)


def ensure_system_type_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS system_type_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_name TEXT NOT NULL,
            asset_id INTEGER NOT NULL,
            classifier TEXT NOT NULL DEFAULT 'declarative_system_types',
            rule_context TEXT NOT NULL DEFAULT 'system_signatures:v1',
            label TEXT NOT NULL,
            rule_id TEXT,
            reasons_json TEXT NOT NULL DEFAULT '[]',
            evidence_refs_json TEXT NOT NULL DEFAULT '[]',
            observed_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
            UNIQUE(target_name, asset_id, classifier, rule_context)
        );
        CREATE INDEX IF NOT EXISTS idx_system_type_observations_target_asset
            ON system_type_observations(target_name, asset_id, observed_at DESC);
        """
    )
    conn.commit()


def _json(value: Any, default: Any) -> Any:
    if not isinstance(value, str):
        return default
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return default


def _safe(value: Any, limit: int = 240) -> str:
    return _SECRET.sub("[redacted]", str(value or ""))[:limit]


def _tech_values(asset: sqlite3.Row | tuple[Any, ...], conn: sqlite3.Connection, target_name: str, asset_id: int) -> list[str]:
    values: list[str] = []
    for raw_value in (asset[3], asset[4]):
        raw = _json(raw_value, None)
        if isinstance(raw, list):
            values.extend(_safe(item) for item in raw)
        elif raw:
            values.append(_safe(raw))
    if conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='technology_observations'").fetchone():
        rows = conn.execute(
            "SELECT technology FROM technology_observations WHERE target_name=? AND asset_id=? LIMIT 20",
            (target_name, asset_id),
        )
        values.extend(_safe(row[0]) for row in rows)
    return list(dict.fromkeys(item for item in values if item))[:30]


def _entries(conn: sqlite3.Connection, target_name: str, asset_id: int) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    if conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='entry_observations'").fetchone():
        columns = {row[1] for row in conn.execute("PRAGMA table_info(entry_observations)")}
        where = "target_name=? AND asset_id=?"
        params: list[Any] = [target_name, asset_id]
        if "status_code" in columns:
            where += " AND COALESCE(status_code,0) > 0"
        if "response_class" in columns:
            placeholders = ",".join("?" for _ in _ENTRY_RESPONSE_CLASSES)
            where += f" AND response_class IN ({placeholders})"
            params.extend(_ENTRY_RESPONSE_CLASSES)
        for row in conn.execute(
            f"SELECT url,entry_type,evidence_refs_json FROM entry_observations WHERE {where} ORDER BY id LIMIT 30",  # noqa: S608 -- WHERE 只拼固定字面量与占位符，值走参数绑定
            tuple(params),
        ):
            refs = _json(row[2], [])
            rows.append(
                {
                    "url": _safe(row[0], 500),
                    "entry_type": _safe(row[1], 80),
                    "evidence_ref": _safe(refs[0], 240) if refs and isinstance(refs[0], str) else "",
                }
            )
    if conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='asset_auth_entries'").fetchone():
        for row in conn.execute(
            "SELECT url,entry_type FROM asset_auth_entries WHERE target_name=? AND asset_id=? ORDER BY id LIMIT 20",
            (target_name, asset_id),
        ):
            rows.append(
                {
                    "url": _safe(row[0], 500),
                    "entry_type": _safe(row[1], 80),
                    "evidence_ref": f"asset_auth_entries:{asset_id}",
                }
            )
    return rows[:40]


def observe_asset_system_types(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    asset_id: int | None = None,
    classifier: str = _CLASSIFIER,
    rule_context: str = _RULE_CONTEXT,
) -> dict[str, int]:
    """Classify target assets independently and upsert only compact results."""
    ensure_system_type_schema(conn)
    if asset_id is None:
        assets = conn.execute(
            "SELECT id,target_name,last_title,tech_stack,last_tech_stack FROM target_assets WHERE target_name=? ORDER BY id",
            (target_name,),
        ).fetchall()
    else:
        assets = conn.execute(
            "SELECT id,target_name,last_title,tech_stack,last_tech_stack FROM target_assets WHERE target_name=? AND id=? ORDER BY id",
            (target_name, asset_id),
        ).fetchall()
    for asset in assets:
        observation = {
            "title": _safe(asset[2]),
            "technologies": _tech_values(asset, conn, target_name, int(asset[0])),
            "urls": _entries(conn, target_name, int(asset[0])),
        }
        result = classify_system(observation)
        matches = result.get("matches", [])
        rule_ids = [item.get("rule_id") for item in matches if isinstance(item, dict) and item.get("rule_id")]
        reasons = [_safe(item, 240) for item in result.get("reasons", []) if isinstance(item, str)][:3]
        refs = [item for item in result.get("evidence_refs", []) if isinstance(item, str)][:3]
        conn.execute(
            """INSERT INTO system_type_observations
               (target_name,asset_id,classifier,rule_context,label,rule_id,reasons_json,evidence_refs_json)
               VALUES(?,?,?,?,?,?,?,?)
               ON CONFLICT(target_name,asset_id,classifier,rule_context) DO UPDATE SET
                 label=excluded.label,rule_id=excluded.rule_id,reasons_json=excluded.reasons_json,
                 evidence_refs_json=excluded.evidence_refs_json,observed_at=datetime('now','localtime')""",
            (
                target_name,
                int(asset[0]),
                classifier,
                rule_context,
                result["label"],
                ",".join(str(item) for item in rule_ids[:5] if item is not None),
                json.dumps(reasons, ensure_ascii=False),
                json.dumps(refs, ensure_ascii=False),
            ),
        )
    conn.commit()
    return {"observed": len(assets)}
