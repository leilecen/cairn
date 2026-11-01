"""Acceptance tests for v2 model_tier rename (cheap/standard/premium → haiku/sonnet/opus)."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from db.migrate import apply_migration, ensure_schema_version
from db.work_queue import create_work_item

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = PROJECT_ROOT / "TOOLS" / "db" / "schema.sql"
MIGRATION_024 = PROJECT_ROOT / "migrations" / "024_model_tier_rename.sql"


def _schema_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    return conn


def _legacy_work_items_conn() -> sqlite3.Connection:
    """Minimal pre-v2 work_items table with old model_tier CHECK values."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    ensure_schema_version(conn)
    conn.executescript(
        """
        CREATE TABLE work_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_name TEXT NOT NULL,
            lane TEXT NOT NULL,
            subtype TEXT,
            subject_table TEXT NOT NULL,
            subject_id TEXT NOT NULL,
            attack_thread_id INTEGER,
            title TEXT,
            objective TEXT,
            priority INTEGER DEFAULT 50,
            status TEXT DEFAULT 'queued',
            claimed_by TEXT,
            claimed_at TEXT,
            lease_until TEXT,
            heartbeat_at TEXT,
            timebox_minutes INTEGER DEFAULT 10,
            heartbeat_minutes INTEGER DEFAULT 5,
            attempt_count INTEGER DEFAULT 0,
            max_attempts INTEGER DEFAULT 3,
            model_tier TEXT DEFAULT 'standard'
                CHECK(model_tier IN ('cheap','standard','premium')),
            reasoning_tier TEXT DEFAULT 'low',
            upgrade_policy TEXT DEFAULT 'ask_main',
            auth_requirement TEXT DEFAULT 'unknown',
            risk_class TEXT DEFAULT 'safe_passive',
            summary TEXT,
            next_action TEXT,
            blocker_reason TEXT,
            last_error TEXT,
            created_at TEXT DEFAULT (datetime('now','localtime')),
            updated_at TEXT DEFAULT (datetime('now','localtime'))
        );
        """
    )
    conn.execute(
        """
        INSERT INTO work_items (
            target_name, lane, subject_table, subject_id, model_tier
        ) VALUES
            ('demo', 'quick_scout', 'pages', '1', 'cheap'),
            ('demo', 'js_reverse', 'js_files', '2', 'standard'),
            ('demo', 'hypothesis', 'js_signal_clusters', '3', 'premium')
        """
    )
    conn.commit()
    return conn


def test_create_work_item_defaults_to_sonnet():
    conn = _schema_conn()
    work_item_id = create_work_item(
        conn,
        target_name="demo",
        lane="quick_scout",
        subject_table="pages",
        subject_id="1",
    )
    row = conn.execute("SELECT model_tier FROM work_items WHERE id = ?", (work_item_id,)).fetchone()
    assert row["model_tier"] == "sonnet"


def test_schema_accepts_haiku_sonnet_opus_and_rejects_legacy():
    conn = _schema_conn()
    conn.execute(
        """
        INSERT INTO work_items (
            target_name, lane, subject_table, subject_id, model_tier
        ) VALUES ('demo', 'quick_scout', 'pages', '1', 'haiku')
        """
    )
    conn.execute(
        """
        INSERT INTO work_items (
            target_name, lane, subject_table, subject_id, model_tier
        ) VALUES ('demo', 'vuln_review', 'suspicious_points', '2', 'opus')
        """
    )
    conn.commit()

    try:
        conn.execute(
            """
            INSERT INTO work_items (
                target_name, lane, subject_table, subject_id, model_tier
            ) VALUES ('demo', 'quick_scout', 'pages', '3', 'cheap')
            """
        )
        raise AssertionError("legacy model_tier 'cheap' should be rejected by CHECK")
    except sqlite3.IntegrityError:
        pass


def test_migration_024_maps_legacy_tiers():
    assert MIGRATION_024.exists(), "migrations/024_model_tier_rename.sql must exist"
    conn = _legacy_work_items_conn()
    assert apply_migration(conn, 24, str(MIGRATION_024)) is True

    rows = conn.execute("SELECT subject_id, model_tier FROM work_items ORDER BY subject_id").fetchall()
    assert [(r["subject_id"], r["model_tier"]) for r in rows] == [
        ("1", "haiku"),
        ("2", "sonnet"),
        ("3", "opus"),
    ]

    # New inserts must accept Claude model names.
    conn.execute(
        """
        INSERT INTO work_items (
            target_name, lane, subject_table, subject_id, model_tier
        ) VALUES ('demo', 'evidence_pack', 'findings', '9', 'haiku')
        """
    )
    conn.commit()


def test_blackboard_seed_helper_defaults_to_sonnet():
    from db.blackboard_seed import _item

    item = _item(
        lane="quick_scout",
        subject_table="pages",
        subject_id="1",
        title="t",
        objective="o",
    )
    assert item["model_tier"] == "sonnet"
