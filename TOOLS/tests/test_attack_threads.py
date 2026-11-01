import sqlite3
from pathlib import Path

from db.attack_threads import (
    create_attack_thread,
    list_attack_threads,
    record_attack_thread_event,
    update_attack_thread,
)
from db.migrate import apply_migration, ensure_schema_version
from db.work_queue import claim_by_id, complete_work_item, create_work_item

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = PROJECT_ROOT / "TOOLS" / "db" / "schema.sql"
MIGRATION_PATH = PROJECT_ROOT / "migrations" / "023_attack_threads.sql"


def _conn_from_schema():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    return conn


def _tuple_conn_from_schema():
    conn = sqlite3.connect(":memory:")
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    return conn


def test_attack_thread_tables_exist_in_full_schema():
    conn = _conn_from_schema()
    tables = {row["name"] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    work_columns = {row["name"] for row in conn.execute("PRAGMA table_info(work_items)").fetchall()}

    assert "attack_threads" in tables
    assert "attack_thread_events" in tables
    assert "attack_thread_id" in work_columns


def test_attack_thread_migration_is_idempotent_on_legacy_db():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    ensure_schema_version(conn)
    conn.execute(
        """
        CREATE TABLE work_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_name TEXT NOT NULL,
            lane TEXT NOT NULL,
            subject_table TEXT NOT NULL,
            subject_id TEXT NOT NULL,
            status TEXT DEFAULT 'queued'
        )
        """
    )
    conn.commit()

    assert apply_migration(conn, 23, str(MIGRATION_PATH)) is True
    assert apply_migration(conn, 23, str(MIGRATION_PATH)) is True

    columns = {row["name"] for row in conn.execute("PRAGMA table_info(work_items)").fetchall()}
    assert "attack_thread_id" in columns
    assert conn.execute("SELECT COUNT(*) FROM schema_version WHERE version = 23").fetchone()[0] == 1


def test_attack_thread_helper_creates_updates_and_lists():
    conn = _conn_from_schema()

    thread_id = create_attack_thread(
        conn,
        target_name="demo",
        asset_url="https://example.com/app",
        hypothesis="order export has object-level auth gap",
        why_promising="JS exposes export endpoint and id parameter",
        priority=80,
        owner="main",
        sprint_id="demo-20260716-01",
    )
    updated = update_attack_thread(
        conn,
        attack_thread_id=thread_id,
        current_evidence="request and response diff exist",
        next_probe="test at most three object ids",
        confidence="medium",
        status="candidate",
    )
    event_id = record_attack_thread_event(
        conn,
        attack_thread_id=thread_id,
        actor="main",
        event_type="candidate",
        payload={"reason": "B gate looks reachable"},
        severity="notice",
    )
    rows = list_attack_threads(conn, target_name="demo", statuses=["candidate"])

    assert updated["status"] == "candidate"
    assert updated["confidence"] == "medium"
    assert event_id > 0
    assert [row["id"] for row in rows] == [thread_id]
    assert rows[0]["hypothesis"] == "order export has object-level auth gap"


def test_attack_thread_helper_returns_dicts_without_row_factory():
    conn = _tuple_conn_from_schema()

    thread_id = create_attack_thread(
        conn,
        target_name="demo",
        asset_url=None,
        hypothesis="profile endpoint may expose personal info",
        commit=False,
    )
    updated = update_attack_thread(
        conn,
        attack_thread_id=thread_id,
        status="candidate",
        confidence="medium",
        commit=False,
    )
    rows = list_attack_threads(conn, target_name="demo")

    assert updated["id"] == thread_id
    assert updated["status"] == "candidate"
    assert rows[0]["id"] == thread_id


def test_hypothesis_worker_result_promotes_to_attack_thread():
    conn = _conn_from_schema()
    work_item_id = create_work_item(
        conn,
        target_name="demo",
        lane="hypothesis",
        subject_table="js_signal_clusters",
        subject_id="cluster-1",
        subtype="business_api",
        title="draft hypothesis",
    )
    claimed = claim_by_id(conn, work_item_id=work_item_id, agent_id="hypothesis-1", target_name="demo")
    assert claimed is not None
    complete_work_item(
        conn,
        work_item_id=work_item_id,
        agent_id="hypothesis-1",
        summary="candidate drafted",
        result_payload={
            "hypothesis": "object id may lack authorization",
            "why_promising": "business API exposes object identifier",
            "next_probe": "compare two authorized object ids",
            "confidence": "medium",
        },
    )
    thread = conn.execute("SELECT * FROM attack_threads WHERE target_name='demo'").fetchone()
    linked = conn.execute("SELECT attack_thread_id FROM work_items WHERE id=?", (work_item_id,)).fetchone()
    assert thread["hypothesis"] == "object id may lack authorization"
    assert linked["attack_thread_id"] == thread["id"]
