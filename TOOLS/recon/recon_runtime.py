"""Compact, resumable run ledger for reconnaissance adapters.

This module intentionally records execution state separately from
``recon_sources``.  A source record is an observed fact; a run is only the
state needed to resume or rate-limit an adapter.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from typing import Any

_SECRET_KEY = re.compile(
    r"(password|passwd|secret|token|authorization|cookie|private[_-]?key|access[_-]?key|api[_-]?key)",
    re.I,
)
_SECRET_VALUE = re.compile(
    r"(?i)(authorization\s*:\s*[^\r\n,;]+|cookie\s*:\s*[^\r\n,;]+|"
    r"(?:password|passwd|token|secret|提取码)\s*[:=]\s*[^\s,;]+|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,})"
)
_UNSET = object()


def _compact(value: Any, *, depth: int = 0) -> Any:
    if depth > 4:
        return "[truncated]"
    if isinstance(value, dict):
        return {
            str(key): "[redacted]" if _SECRET_KEY.search(str(key)) else _compact(item, depth=depth + 1)
            for key, item in list(value.items())[:80]
        }
    if isinstance(value, list):
        return [_compact(item, depth=depth + 1) for item in value[:100]]
    if isinstance(value, str):
        return _SECRET_VALUE.sub("[redacted]", value[:1000])
    return value


def _json(value: Any) -> str:
    return json.dumps(_compact(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def input_fingerprint(input_data: Any) -> str:
    """Return a stable, secret-free identity for an adapter input."""
    return hashlib.sha256(_json(input_data).encode("utf-8")).hexdigest()


def ensure_recon_runtime_schema(conn: sqlite3.Connection) -> None:
    """Create the independent run-state ledger without creating observations."""
    conn.execute(
        """CREATE TABLE IF NOT EXISTS recon_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_name TEXT NOT NULL,
            source TEXT NOT NULL,
            input_fingerprint TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'queued',
            attempt INTEGER NOT NULL DEFAULT 0,
            cursor_json TEXT NOT NULL DEFAULT '{}',
            budget_json TEXT NOT NULL DEFAULT '{}',
            summary_json TEXT NOT NULL DEFAULT '{}',
            last_success_at TEXT,
            next_retry_at TEXT,
            updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
            UNIQUE(target_name, source, input_fingerprint)
        )"""
    )
    conn.commit()


def _require_text(name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value.strip()


def get_recon_run(conn: sqlite3.Connection, *, run_id: int) -> sqlite3.Row | None:
    """Read one compact ledger row, or ``None`` when it does not exist."""
    ensure_recon_runtime_schema(conn)
    return conn.execute("SELECT * FROM recon_runs WHERE id=?", (run_id,)).fetchone()


def begin_recon_run(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    source: str,
    input_data: Any,
    budget: Any = _UNSET,
) -> sqlite3.Row:
    """Create or resume a run, incrementing its attempt counter exactly once."""
    ensure_recon_runtime_schema(conn)
    target_name = _require_text("target_name", target_name)
    source = _require_text("source", source)
    fingerprint = input_fingerprint(input_data)
    existing = conn.execute(
        "SELECT id FROM recon_runs WHERE target_name=? AND source=? AND input_fingerprint=?",
        (target_name, source, fingerprint),
    ).fetchone()
    if existing:
        if budget is _UNSET:
            conn.execute(
                """UPDATE recon_runs SET status='running', attempt=attempt+1,
                   updated_at=datetime('now','localtime') WHERE id=?""",
                (existing[0],),
            )
        else:
            conn.execute(
                """UPDATE recon_runs SET status='running', attempt=attempt+1, budget_json=?,
                   updated_at=datetime('now','localtime') WHERE id=?""",
                (_json(budget), existing[0]),
            )
        run_id = int(existing[0])
    else:
        cur = conn.execute(
            """INSERT INTO recon_runs
               (target_name, source, input_fingerprint, status, attempt, budget_json)
               VALUES (?, ?, ?, 'running', 1, ?)""",
            (target_name, source, fingerprint, _json({} if budget is _UNSET else budget)),
        )
        run_id = int(cur.lastrowid or 0)
    conn.commit()
    row = get_recon_run(conn, run_id=run_id)
    if row is None:
        raise RuntimeError(f"recon run disappeared after create: {run_id}")
    return row


def update_recon_run(
    conn: sqlite3.Connection,
    *,
    run_id: int,
    status: str | None = None,
    cursor: Any = _UNSET,
    budget: Any = _UNSET,
    summary: Any = _UNSET,
    last_success_at: str | None | object = _UNSET,
    next_retry_at: str | None | object = _UNSET,
) -> sqlite3.Row:
    """Persist resumable state without incrementing the attempt counter."""
    ensure_recon_runtime_schema(conn)
    assignments: list[str] = []
    values: list[Any] = []
    if status is not None:
        assignments.append("status=?")
        values.append(_require_text("status", status))
    for column, value in (("cursor_json", cursor), ("budget_json", budget), ("summary_json", summary)):
        if value is not _UNSET:
            assignments.append(f"{column}=?")
            values.append(_json(value))
    for column, value in (("last_success_at", last_success_at), ("next_retry_at", next_retry_at)):
        if value is not _UNSET:
            if value is not None and not isinstance(value, str):
                raise ValueError(f"{column} must be a string or None")
            assignments.append(f"{column}=?")
            values.append(value)
    if not assignments:
        raise ValueError("at least one run field must be updated")
    values.append(run_id)
    cur = conn.execute(
        f"UPDATE recon_runs SET {', '.join(assignments)}, updated_at=datetime('now','localtime') WHERE id=?",  # noqa: S608
        values,
    )
    if cur.rowcount != 1:
        raise LookupError(f"recon run not found: {run_id}")
    conn.commit()
    row = get_recon_run(conn, run_id=run_id)
    if row is None:
        raise RuntimeError(f"recon run disappeared after update: {run_id}")
    return row
