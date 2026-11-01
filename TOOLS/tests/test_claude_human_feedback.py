from __future__ import annotations

import sqlite3

from db.claude_monitor import build_handoff, normalize_session_note


def test_db_first_handoff_exposes_current_system_and_db_wins(tmp_path):
    db = tmp_path / "h.db"
    c = sqlite3.connect(db)
    c.executescript("""
    CREATE TABLE target_systems(id INTEGER PRIMARY KEY,target_name TEXT,display_name TEXT,canonical_url TEXT,scope_class TEXT,lifecycle_state TEXT);
    CREATE TABLE hunt_sessions(id INTEGER PRIMARY KEY,target_name TEXT,status TEXT,system_id INTEGER,goal TEXT,started_at TEXT,operator_acknowledged_at TEXT);
    CREATE TABLE target_assets(id INTEGER PRIMARY KEY,target_name TEXT,asset_value TEXT,scope_class TEXT,scope_status TEXT,authorization_state TEXT);
    CREATE TABLE system_asset_links(id INTEGER PRIMARY KEY,target_name TEXT,system_id INTEGER,asset_id INTEGER,relationship TEXT,confidence TEXT,evidence_refs_json TEXT);
    CREATE TABLE coverage_ledger(id INTEGER PRIMARY KEY,target_name TEXT,item_key TEXT,status TEXT);
    CREATE TABLE operator_inbox(id INTEGER PRIMARY KEY,target_name TEXT,status TEXT,blocking INTEGER,system_id INTEGER);
    CREATE TABLE work_items(id INTEGER PRIMARY KEY,target_name TEXT,system_id INTEGER,lane TEXT,subtype TEXT,status TEXT,claimed_by TEXT,timebox_minutes INTEGER,heartbeat_minutes INTEGER,heartbeat_at TEXT,lease_until TEXT,updated_at TEXT);
    INSERT INTO target_systems VALUES(2,'T','真实系统','https://real.example','owned','mapping'); INSERT INTO target_assets VALUES(1,'T','real.example','owned','in_scope','active'); INSERT INTO system_asset_links VALUES(1,'T',2,1,'primary','high','[]'); INSERT INTO hunt_sessions VALUES(1,'T','active',2,'map','now','now');
    """)
    c.commit()
    c.close()
    note = normalize_session_note(
        {
            "session_id": "s",
            "target": "T",
            "current_system": {"id": 1, "display_name": "过期", "canonical_url": "https://stale.example"},
        }
    )
    handoff = build_handoff([note], "s", db_path=db)
    assert handoff["current_system"]["id"] == 2 and handoff["focus_consistency"] == "db_wins"
