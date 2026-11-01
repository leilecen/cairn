import sqlite3
from pathlib import Path

from db.migrate import apply_migration, ensure_schema_version


def test_cognitive_migration_is_idempotent_and_preserves_rows():
    c = sqlite3.connect(":memory:")
    c.executescript("""
    CREATE TABLE soft_targets(id INTEGER PRIMARY KEY);
    CREATE TABLE work_items(id INTEGER PRIMARY KEY,target_name TEXT);
    CREATE TABLE attack_threads(id INTEGER PRIMARY KEY,target_name TEXT,hypothesis TEXT,status TEXT,created_at TEXT);
    INSERT INTO attack_threads VALUES(1,'demo','old','active','now');
    CREATE TABLE schema_version(version INTEGER PRIMARY KEY,description TEXT);
    """)
    ensure_schema_version(c)
    path = Path(__file__).parents[2] / "migrations/032_cognitive_hunt_loop.sql"
    assert apply_migration(c, 32, str(path))
    assert apply_migration(c, 32, str(path))
    assert c.execute("SELECT COUNT(*) FROM attack_threads").fetchone()[0] == 1
    assert c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='experiments'").fetchone()
    assert c.execute("SELECT COUNT(*) FROM pragma_table_info('attack_threads') WHERE name='expected_observation'").fetchone()[0] == 1
