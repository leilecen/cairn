from __future__ import annotations

import sqlite3

from db.human_brief import build_human_brief


def test_human_brief_marks_overdue_and_long_worker_without_waiting():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    c.executescript("""
    CREATE TABLE target_systems(id INTEGER PRIMARY KEY,target_name TEXT,display_name TEXT,canonical_url TEXT,scope_class TEXT,lifecycle_state TEXT);
    CREATE TABLE hunt_sessions(id INTEGER PRIMARY KEY,target_name TEXT,status TEXT,system_id INTEGER,goal TEXT,started_at TEXT,operator_acknowledged_at TEXT);
    CREATE TABLE target_assets(id INTEGER PRIMARY KEY,target_name TEXT,asset_value TEXT,scope_class TEXT,scope_status TEXT,authorization_state TEXT);
    CREATE TABLE system_asset_links(id INTEGER PRIMARY KEY,target_name TEXT,system_id INTEGER,asset_id INTEGER,relationship TEXT,confidence TEXT,evidence_refs_json TEXT);
    CREATE TABLE coverage_ledger(id INTEGER PRIMARY KEY,target_name TEXT,item_key TEXT,status TEXT);
    CREATE TABLE operator_inbox(id INTEGER PRIMARY KEY,target_name TEXT,status TEXT,blocking INTEGER,system_id INTEGER);
    CREATE TABLE work_items(id INTEGER PRIMARY KEY,target_name TEXT,system_id INTEGER,lane TEXT,subtype TEXT,status TEXT,claimed_by TEXT,timebox_minutes INTEGER,heartbeat_minutes INTEGER,heartbeat_at TEXT,lease_until TEXT,updated_at TEXT);
    INSERT INTO target_systems VALUES(1,'T','博客','https://blog.example','owned','mapping'); INSERT INTO target_assets VALUES(1,'T','blog.example','owned','in_scope','active'); INSERT INTO system_asset_links VALUES(1,'T',1,1,'primary','high','[]'); INSERT INTO hunt_sessions VALUES(1,'T','active',1,'map','now','now'); INSERT INTO work_items VALUES(1,'T',1,'entry_probe','x','claimed','agent',20,5,'2000-01-01 00:00:00','2000-01-01 00:20:00','now');
    """)
    brief = build_human_brief(c, target_name="T")
    assert brief["ai_activity"][0]["overdue"] and brief["ai_activity"][0]["split_recommended"]
