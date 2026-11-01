from __future__ import annotations

import sqlite3

from db.dispatcher import build_dispatch_plan


def _db():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    c.executescript("""
    CREATE TABLE schema_version(version INTEGER PRIMARY KEY); INSERT INTO schema_version VALUES(33);
    CREATE TABLE target_systems(id INTEGER PRIMARY KEY,target_name TEXT); CREATE TABLE target_assets(id INTEGER PRIMARY KEY,target_name TEXT,scope_class TEXT,scope_status TEXT,authorization_state TEXT); CREATE TABLE hunt_sessions(id INTEGER PRIMARY KEY,target_name TEXT,status TEXT,system_id INTEGER);
    CREATE TABLE operator_inbox(id INTEGER PRIMARY KEY,target_name TEXT,status TEXT,blocking INTEGER,system_id INTEGER);
    CREATE TABLE work_items(id INTEGER PRIMARY KEY,target_name TEXT,lane TEXT,subtype TEXT,subject_table TEXT,subject_id TEXT,title TEXT,objective TEXT,priority INTEGER,status TEXT,dispatch_state TEXT,claimed_by TEXT,attempt_count INTEGER,max_attempts INTEGER,timebox_minutes INTEGER,heartbeat_minutes INTEGER,summary TEXT,system_id INTEGER,created_at TEXT);
    INSERT INTO target_systems VALUES(1,'T'); INSERT INTO hunt_sessions VALUES(1,'T','active',1);
    """)
    return c


def test_dispatcher_rejects_cross_system_and_unmapped_legacy_tasks():
    c = _db()
    c.execute(
        "INSERT INTO work_items VALUES(1,'T','entry_probe','x','target_assets','1','legacy','map',90,'queued','active',NULL,0,3,10,5,'',NULL,'now')"
    )
    c.execute(
        "INSERT INTO work_items VALUES(2,'T','entry_probe','x','target_assets','1','other','map',89,'queued','active',NULL,0,3,10,5,'',2,'now')"
    )
    c.commit()
    plan = build_dispatch_plan(c, target_name="T")
    assert plan["tasks"] == [] and len(plan["skipped_decision_lanes"]) >= 2
