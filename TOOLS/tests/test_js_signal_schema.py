import sqlite3
import sys
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))

from db.migrate import apply_migration, ensure_schema_version


def test_js_intelligence_migration_on_legacy_js_files(tmp_path):
    db_path = tmp_path / "legacy.db"
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE js_files (
            id INTEGER PRIMARY KEY,
            url TEXT UNIQUE,
            page_url TEXT,
            analyzed INTEGER DEFAULT 0,
            discovered_apis_json TEXT,
            hardcoded_secrets_json TEXT,
            internal_routes_json TEXT,
            debug_switches_json TEXT,
            analyzed_at TEXT
        )
        """
    )
    ensure_schema_version(conn)
    migration = Path(__file__).resolve().parents[2] / "migrations" / "020_js_intelligence.sql"
    assert apply_migration(conn, 20, str(migration)) is True
    columns = {row[1] for row in conn.execute("PRAGMA table_info(js_files)").fetchall()}
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    assert "content_hash" in columns
    assert "js_signals" in tables
    assert "js_signal_clusters" in tables


def test_js_signals_unique_constraint(tmp_path):
    db_path = tmp_path / "new.db"
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        CREATE TABLE js_signals (
            id TEXT PRIMARY KEY,
            js_file_id INTEGER,
            signal_type TEXT NOT NULL,
            method TEXT,
            path TEXT,
            evidence_location TEXT,
            UNIQUE(js_file_id, signal_type, method, path, evidence_location)
        );
        """
    )
    conn.execute(
        """
        INSERT INTO js_signals (id, js_file_id, signal_type, method, path, evidence_location)
        VALUES ('1', 1, 'api_endpoint', 'GET', '/api/user', 'line:1')
        """
    )
    conn.execute(
        """
        INSERT INTO js_signals (id, js_file_id, signal_type, method, path, evidence_location)
        VALUES ('2', 1, 'api_endpoint', 'GET', '/api/user', 'line:1')
        ON CONFLICT(js_file_id, signal_type, method, path, evidence_location) DO NOTHING
        """
    )
    count = conn.execute("SELECT COUNT(*) FROM js_signals").fetchone()[0]
    assert count == 1
