from __future__ import annotations

# ruff: noqa: E501
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from db.focus_control import activate_focus, expire_focus, pause_focus, propose_switch, reconcile_focus, renew_focus
from db.system_cluster import apply_cluster_plan
from db.system_registry import link_asset, register_system
from db.system_scorer import score_systems
from db.work_queue import create_work_item


def _db():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    c.executescript("""
    CREATE TABLE schema_version(version INTEGER PRIMARY KEY,description TEXT); INSERT INTO schema_version VALUES(33,'033');
    CREATE TABLE target_assets(id INTEGER PRIMARY KEY,target_name TEXT,asset_value TEXT,scope_class TEXT,scope_status TEXT,authorization_state TEXT);
    CREATE TABLE target_systems(id INTEGER PRIMARY KEY AUTOINCREMENT,target_name TEXT,system_key TEXT,display_name TEXT,canonical_url TEXT,description TEXT,scope_class TEXT,lifecycle_state TEXT,created_by TEXT,created_at TEXT,updated_at TEXT,UNIQUE(target_name,system_key));
    CREATE TABLE system_asset_links(id INTEGER PRIMARY KEY AUTOINCREMENT,target_name TEXT,system_id INTEGER,asset_id INTEGER,relationship TEXT,confidence TEXT,evidence_refs_json TEXT,created_at TEXT,updated_at TEXT,UNIQUE(system_id,asset_id,relationship));
    CREATE TABLE hunt_sessions(id INTEGER PRIMARY KEY AUTOINCREMENT,target_name TEXT,focus_subject_table TEXT,focus_subject_id TEXT,goal TEXT,success_criteria_json TEXT,stop_conditions_json TEXT,status TEXT,selected_by TEXT,started_at TEXT,ended_at TEXT,system_id INTEGER,recon_readiness_snapshot_json TEXT,operator_acknowledged_at TEXT);
    CREATE TABLE work_items(id INTEGER PRIMARY KEY AUTOINCREMENT,target_name TEXT,lane TEXT,subtype TEXT,subject_table TEXT,subject_id TEXT,attack_thread_id INTEGER,title TEXT,objective TEXT,priority INTEGER,model_tier TEXT,reasoning_tier TEXT,auth_requirement TEXT,risk_class TEXT,timebox_minutes INTEGER,heartbeat_minutes INTEGER,status TEXT DEFAULT 'queued',dispatch_state TEXT DEFAULT 'active',system_id INTEGER,park_reason TEXT,created_at TEXT,updated_at TEXT);
    CREATE TABLE soft_targets(id INTEGER PRIMARY KEY,target_name TEXT,asset_id INTEGER,status TEXT,updated_at TEXT);
    CREATE TABLE decision_events(id INTEGER PRIMARY KEY AUTOINCREMENT,target_name TEXT,hunt_session_id INTEGER,actor TEXT,decision_type TEXT,compact_snapshot_json TEXT,candidate_actions_json TEXT DEFAULT '[]',chosen_action TEXT,rationale TEXT,expected_change TEXT,actual_change TEXT DEFAULT '',created_at TEXT);
    CREATE TABLE operator_inbox(id INTEGER PRIMARY KEY,target_name TEXT,status TEXT,blocking INTEGER,system_id INTEGER);
    INSERT INTO target_assets VALUES(1,'T','blog.example','owned','in_scope','active');
    """)
    return c


def test_focus_activation_requires_ack_and_parks_unmapped_queue_atomically():
    c = _db()
    system = register_system(
        c,
        target_name="T",
        system_key="blog",
        display_name="官方博客",
        canonical_url="https://blog.example",
        scope_class="owned",
    )
    link_asset(c, target_name="T", system_id=system["id"], asset_id=1, relationship="primary", confidence="high")
    old = create_work_item(c, target_name="T", lane="quick_scout", subject_table="pages", subject_id="1")
    with pytest.raises(PermissionError):
        activate_focus(c, target_name="T", system_id=system["id"], goal="map", operator_acknowledged=False)
    result = activate_focus(c, target_name="T", system_id=system["id"], goal="map", operator_acknowledged=True)
    assert result["session_id"]
    assert c.execute("SELECT dispatch_state FROM work_items WHERE id=?", (old,)).fetchone()[0] == "parked"
    assert reconcile_focus(c, target_name="T")["consistent"]


def test_switch_is_only_a_proposal_until_operator_transaction():
    c = _db()
    a = register_system(
        c,
        target_name="T",
        system_key="a",
        display_name="系统 A",
        canonical_url="https://a.example",
        scope_class="owned",
    )
    b = register_system(
        c,
        target_name="T",
        system_key="b",
        display_name="系统 B",
        canonical_url="https://b.example",
        scope_class="owned",
    )
    proposal = propose_switch(c, target_name="T", from_system_id=a["id"], to_system_id=b["id"], reason="信息增益更高")
    assert proposal["requires_operator_confirmation"] and c.execute("SELECT COUNT(*) FROM hunt_sessions").fetchone()[0] == 0


def _modern_db():
    root = Path(__file__).resolve().parents[2]
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    c.executescript((root / "TOOLS" / "db" / "schema.sql").read_text(encoding="utf-8"))
    c.execute("INSERT INTO targets(id,target_name,domain) VALUES(1,'T','example.com')")
    c.execute(
        """INSERT INTO target_assets(id,target_name,asset_value,scope_status,scope_class,authorization_state)
           VALUES(1,'T','app.example.com','in_scope','owned','authorized')"""
    )
    c.commit()
    apply_cluster_plan(c, "T")
    score_systems(c, "T", apply=True)
    return c


def test_focus_is_operator_only_and_has_explicit_120_minute_lifecycle():
    c = _modern_db()
    system_id = c.execute("SELECT id FROM target_systems WHERE target_name='T'").fetchone()[0]
    with pytest.raises(PermissionError):
        activate_focus(c, target_name="T", system_id=system_id, goal="map", actor="main", operator_acknowledged=True)
    statements = []
    c.set_trace_callback(statements.append)
    result = activate_focus(c, target_name="T", system_id=system_id, goal="map", operator_acknowledged=True)
    normalized = [item.strip().upper() for item in statements]
    assert next(i for i, item in enumerate(normalized) if item.startswith("BEGIN IMMEDIATE")) < next(
        i for i, item in enumerate(normalized) if item.startswith("SELECT")
    )
    soft = c.execute("SELECT * FROM system_soft_targets WHERE system_id=?", (system_id,)).fetchone()
    assert soft["status"] == "focused" and soft["timebox_minutes"] == 120 and soft["timebox_until"]
    renew_focus(c, target_name="T", session_id=result["session_id"], minutes=60)
    assert c.execute("SELECT timebox_minutes FROM system_soft_targets WHERE system_id=?", (system_id,)).fetchone()[0] == 60
    old = datetime.now() - timedelta(minutes=1)
    c.execute(
        "UPDATE system_soft_targets SET timebox_until=? WHERE system_id=?",
        (old.strftime("%Y-%m-%d %H:%M:%S"), system_id),
    )
    c.commit()
    assert expire_focus(c, target_name="T")["expired"] == 1
    assert expire_focus(c, target_name="T")["expired"] == 0
    assert c.execute("SELECT status FROM hunt_sessions WHERE id=?", (result["session_id"],)).fetchone()[0] == "paused"
    assert {row[0] for row in c.execute("SELECT decision_type FROM decision_events")} >= {"focus", "continue", "park"}


def test_focus_rejects_cross_target_system_and_scope_blocked_score():
    c = _modern_db()
    system_id = c.execute("SELECT id FROM target_systems WHERE target_name='T'").fetchone()[0]
    c.execute("UPDATE system_soft_targets SET eligibility_status='scope_blocked' WHERE system_id=?", (system_id,))
    c.commit()
    with pytest.raises(PermissionError):
        activate_focus(c, target_name="T", system_id=system_id, goal="map", operator_acknowledged=True)
    with pytest.raises(ValueError):
        activate_focus(c, target_name="OTHER", system_id=system_id, goal="map", operator_acknowledged=True)


def test_pause_locks_before_read_records_one_decision_and_rolls_back_on_failure():
    c = _modern_db()
    system_id = c.execute("SELECT id FROM target_systems").fetchone()[0]
    session = activate_focus(c, target_name="T", system_id=system_id, goal="map", operator_acknowledged=True)
    statements = []
    c.set_trace_callback(statements.append)
    pause_focus(c, target_name="T", session_id=session["session_id"])
    normalized = [item.strip().upper() for item in statements]
    assert next(i for i, item in enumerate(normalized) if item.startswith("BEGIN IMMEDIATE")) < next(
        i for i, item in enumerate(normalized) if item.startswith("SELECT")
    )
    assert c.execute("SELECT COUNT(*) FROM decision_events WHERE decision_type='park'").fetchone()[0] == 1
    with pytest.raises(ValueError):
        pause_focus(c, target_name="T", session_id=session["session_id"])
    assert c.execute("SELECT COUNT(*) FROM decision_events WHERE decision_type='park'").fetchone()[0] == 1


def test_nested_pause_uses_savepoint_and_failure_preserves_callers_prior_write():
    c = _modern_db()
    system_id = c.execute("SELECT id FROM target_systems").fetchone()[0]
    session = activate_focus(c, target_name="T", system_id=system_id, goal="map", operator_acknowledged=True)
    c.execute("UPDATE target_assets SET notes='caller-write' WHERE id=1")
    assert c.in_transaction
    statements = []
    c.set_trace_callback(statements.append)
    pause_focus(c, target_name="T", session_id=session["session_id"])
    assert c.in_transaction
    assert any(item.strip().upper().startswith("SAVEPOINT PAUSE_FOCUS") for item in statements)
    assert c.execute("SELECT notes FROM target_assets WHERE id=1").fetchone()[0] == "caller-write"
    c.rollback()
    assert c.execute("SELECT status FROM hunt_sessions WHERE id=?", (session["session_id"],)).fetchone()[0] == "active"

    c.execute("UPDATE target_assets SET notes='preserve-on-failure' WHERE id=1")
    with pytest.raises(ValueError):
        pause_focus(c, target_name="T", session_id=999999)
    assert c.in_transaction
    assert c.execute("SELECT notes FROM target_assets WHERE id=1").fetchone()[0] == "preserve-on-failure"
    c.commit()
