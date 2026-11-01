from __future__ import annotations

import sqlite3
from pathlib import Path

from db.migrate import apply_migration, ensure_schema_version

ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "migrations" / "033_human_focus_control.sql"


def _base(conn: sqlite3.Connection) -> None:
    conn.executescript("""
    CREATE TABLE schema_version(version INTEGER PRIMARY KEY, description TEXT);
    CREATE TABLE target_assets(id INTEGER PRIMARY KEY, target_name TEXT, asset_value TEXT);
    CREATE TABLE work_items(id INTEGER PRIMARY KEY, target_name TEXT, lane TEXT, status TEXT, dispatch_state TEXT);
    CREATE TABLE hunt_sessions(id INTEGER PRIMARY KEY, target_name TEXT, status TEXT);
    CREATE TABLE operator_inbox(
      id INTEGER PRIMARY KEY, target_name TEXT, related_work_item_id INTEGER, kind TEXT, title TEXT,
      detail TEXT, suggested_action TEXT, url TEXT, burp_action_id INTEGER, evidence_ref_id INTEGER,
      status TEXT, created_at TEXT, resolved_at TEXT
    );
    INSERT INTO operator_inbox VALUES(7,'T',1,'manual_review','旧卡','detail','act','https://example.com',NULL,NULL,'open','now',NULL);
    """)


def test_migration_033_is_idempotent_and_preserves_operator_rows():
    conn = sqlite3.connect(":memory:")
    _base(conn)
    ensure_schema_version(conn)
    assert apply_migration(conn, 33, str(MIGRATION))
    assert apply_migration(conn, 33, str(MIGRATION))
    assert conn.execute("SELECT COUNT(*) FROM operator_inbox").fetchone()[0] == 1
    row = conn.execute("SELECT title,detail,kind,steps_json,blocking FROM operator_inbox WHERE id=7").fetchone()
    assert row == ("旧卡", "detail", "manual_review", "[]", 1)
    assert conn.execute("SELECT COUNT(*) FROM target_systems").fetchone()[0] == 0
    columns = {r[1] for r in conn.execute("PRAGMA table_info(hunt_sessions)")}
    assert {"system_id", "recon_readiness_snapshot_json", "operator_acknowledged_at"} <= columns
    assert conn.execute("SELECT COUNT(*) FROM schema_version WHERE version=33").fetchone()[0] == 1
    conn.close()


def test_migration_033_runs_against_new_schema_sql():
    conn = sqlite3.connect(":memory:")
    conn.executescript((ROOT / "TOOLS" / "db" / "schema.sql").read_text(encoding="utf-8"))
    ensure_schema_version(conn)
    conn.execute("INSERT INTO schema_version(version,description) VALUES(32,'032')")
    assert apply_migration(conn, 33, str(MIGRATION))
    assert apply_migration(conn, 33, str(MIGRATION))
    assert conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='target_systems'").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM operator_inbox").fetchone()[0] == 0
