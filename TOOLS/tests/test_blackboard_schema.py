import sqlite3
from pathlib import Path

import pytest
from db.migrate import apply_migration, ensure_schema_version
from db.operator_actions import create_action_card

PROJECT_ROOT = Path(__file__).resolve().parents[2]
MIGRATION_PATH = PROJECT_ROOT / "migrations" / "022_blackboard_orchestration.sql"
SURFACE_MIGRATION_PATH = PROJECT_ROOT / "migrations" / "027_attack_surface_profile_coverage.sql"
SCHEMA_PATH = PROJECT_ROOT / "TOOLS" / "db" / "schema.sql"
# `TOOLS/schema.sql` 曾是陈旧副本（55 表，止于 migration 038），2026-10-17 删除。
# DDL 真源只有一个：`TOOLS/db/schema.sql` + `migrations/`。
SCHEMA_PATHS = (SCHEMA_PATH,)


def _conn():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    return conn


def _table_names(conn):
    return {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}


def _index_names(conn):
    return {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='index'").fetchall()}


def test_blackboard_migration_is_idempotent():
    conn = _conn()
    ensure_schema_version(conn)

    assert apply_migration(conn, 22, str(MIGRATION_PATH)) is True
    assert apply_migration(conn, 22, str(MIGRATION_PATH)) is True

    version_rows = conn.execute("SELECT version FROM schema_version WHERE version = 22").fetchall()
    assert len(version_rows) == 1


def test_blackboard_tables_and_indexes_exist_after_migration():
    conn = _conn()
    ensure_schema_version(conn)

    assert apply_migration(conn, 22, str(MIGRATION_PATH)) is True

    assert {
        "work_items",
        "agent_events",
        "operator_inbox",
        "burp_actions",
        "browser_actions",
        "evidence_refs",
    }.issubset(_table_names(conn))

    assert {
        "idx_work_items_pick",
        "idx_work_items_target_lane",
        "idx_agent_events_work_item",
        "idx_operator_inbox_open",
        "idx_burp_actions_status",
    }.issubset(_index_names(conn))


def test_blackboard_check_constraints_are_enforced():
    conn = _conn()
    ensure_schema_version(conn)
    assert apply_migration(conn, 22, str(MIGRATION_PATH)) is True

    conn.execute(
        """
        INSERT INTO work_items (target_name, lane, subject_table, subject_id)
        VALUES ('demo', 'quick_scout', 'pages', '1')
        """
    )

    for statement in (
        """
        INSERT INTO work_items (target_name, lane, subject_table, subject_id, status)
        VALUES ('demo', 'quick_scout', 'pages', '2', 'bogus')
        """,
        """
        INSERT INTO agent_events (work_item_id, agent_id, event_type, payload_json)
        VALUES (1, 'agent-1', 'bogus', '{}')
        """,
        """
        INSERT INTO operator_inbox (target_name, title, kind)
        VALUES ('demo', 'need login', 'bogus')
        """,
        """
        INSERT INTO burp_actions (target_name, action_type, risk_class)
        VALUES ('demo', 'send_to_repeater', 'bogus')
        """,
        """
        INSERT INTO browser_actions (target_name, action_type, status)
        VALUES ('demo', 'open_url', 'bogus')
        """,
        """
        INSERT INTO evidence_refs (target_name, source_table, source_id, evidence_type)
        VALUES ('demo', 'work_items', '1', 'bogus')
        """,
    ):
        try:
            conn.execute(statement)
        except sqlite3.IntegrityError:
            pass
        else:
            raise AssertionError(f"expected CHECK failure for statement: {statement}")

    conn.execute(
        """
        INSERT INTO agent_events (work_item_id, agent_id, event_type, payload_json)
        VALUES (1, 'agent-1', 'failed', '{"error":"boom"}')
        """
    )
    event = conn.execute("SELECT event_type FROM agent_events WHERE work_item_id = 1 ORDER BY id DESC LIMIT 1").fetchone()
    assert event[0] == "failed"


def test_schema_sql_contains_blackboard_tables_for_new_db():
    conn = _conn()
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))

    assert {
        "work_items",
        "agent_events",
        "operator_inbox",
        "burp_actions",
        "browser_actions",
        "evidence_refs",
        "attack_surface_profiles",
        "coverage_ledger",
        "schema_version",
    }.issubset(_table_names(conn))

    assert {
        "idx_work_items_pick",
        "idx_work_items_target_lane",
        "idx_agent_events_work_item",
        "idx_operator_inbox_open",
        "idx_burp_actions_status",
        "idx_attack_surface_profiles_target",
        "idx_coverage_ledger_target_status",
    }.issubset(_index_names(conn))


def test_attack_surface_profile_coverage_migration_and_contract():
    conn = _conn()
    ensure_schema_version(conn)
    assert apply_migration(conn, 22, str(MIGRATION_PATH)) is True
    assert apply_migration(conn, 27, str(SURFACE_MIGRATION_PATH)) is True

    assert {"attack_surface_profiles", "coverage_ledger"}.issubset(_table_names(conn))
    conn.execute(
        """
        INSERT INTO attack_surface_profiles (
            target_name, subject_table, subject_id, system_tags_json, roles_json,
            trust_boundaries_json, tech_stack_json, confidence, evidence_refs_json, summary
        ) VALUES (
            'demo', 'soft_targets', '9', '["account-system"]', '["user"]',
            '["browser-to-api"]', '["nginx evidence_refs:1"]', 'medium',
            '["evidence_refs:1"]', 'compact profile'
        )
        """
    )
    profile_id = conn.execute("SELECT id FROM attack_surface_profiles").fetchone()[0]
    conn.execute(
        """
        INSERT INTO coverage_ledger (
            target_name, profile_id, item_key, category, status, confidence,
            evidence_refs_json, summary, blocker_reason
        ) VALUES (
            'demo', ?, 'admin-flow', 'role_flow', 'blocked', 'unknown',
            '[]', 'admin flow still blocked', 'role account needed'
        )
        """,
        (profile_id,),
    )
    conn.execute(
        """
        INSERT INTO evidence_refs (target_name, source_table, source_id, evidence_type)
        VALUES ('demo', 'attack_surface_profiles', ?, 'semantic_profile')
        """,
        (str(profile_id),),
    )
    conn.execute(
        """
        INSERT INTO evidence_refs (target_name, source_table, source_id, evidence_type)
        VALUES ('demo', 'coverage_ledger', '1', 'coverage_ledger')
        """
    )

    row = conn.execute("SELECT status, blocker_reason FROM coverage_ledger").fetchone()
    assert row["status"] == "blocked"
    assert row["blocker_reason"] == "role account needed"


def test_blackboard_migration_keeps_legacy_tables_intact():
    conn = _conn()
    conn.executescript(
        """
        CREATE TABLE targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_name TEXT NOT NULL,
            domain TEXT
        );
        CREATE TABLE pages (
            id INTEGER PRIMARY KEY,
            url TEXT UNIQUE,
            status TEXT DEFAULT 'queued'
        );
        """
    )
    ensure_schema_version(conn)

    assert apply_migration(conn, 22, str(MIGRATION_PATH)) is True

    conn.execute("INSERT INTO targets (target_name, domain) VALUES ('legacy', 'example.com')")
    conn.execute("INSERT INTO pages (id, url, status) VALUES (1, 'https://example.com', 'queued')")

    assert conn.execute("SELECT COUNT(*) FROM targets").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM pages").fetchone()[0] == 1
    assert "work_items" in _table_names(conn)


@pytest.mark.parametrize("schema_path", SCHEMA_PATHS, ids=("db-schema",))
def test_fresh_schema_mirrors_034_chain_fix_contract(schema_path):
    conn = _conn()
    conn.executescript(schema_path.read_text(encoding="utf-8"))

    assert conn.execute("SELECT max(version) FROM schema_version").fetchone()[0] == 38
    assert {"pattern_guesses", "system_soft_targets"}.issubset(_table_names(conn))
    work_columns = {row[1] for row in conn.execute("PRAGMA table_info(work_items)")}
    inbox_columns = {row[1] for row in conn.execute("PRAGMA table_info(operator_inbox)")}
    sp_columns = {row[1]: row for row in conn.execute("PRAGMA table_info(suspicious_points)")}
    assert "blocker_class" in work_columns
    assert "expires_at" in inbox_columns
    assert sp_columns["id"][3] == 1

    conn.execute(
        """INSERT INTO work_items(target_name,lane,subject_table,subject_id,blocker_class)
           VALUES('fresh','logic_probe','fixture','1','scope')"""
    )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            """INSERT INTO work_items(target_name,lane,subject_table,subject_id,blocker_class)
               VALUES('fresh','logic_probe','fixture','2','invalid')"""
        )

    for kind in ("scope_cluster_confirm", "blocked_decision"):
        card = create_action_card(
            conn,
            target_name="fresh",
            system_id=None,
            kind=kind,
            action_key=f"fresh:{kind}",
            action_label="Operator decision",
            why_needed="A bounded decision is required",
            steps=["Review compact facts"],
            expected_observation="A recorded decision",
            report_back_format="decision and reason",
            url="https://example.test/",
        )
        assert card["kind"] == kind
