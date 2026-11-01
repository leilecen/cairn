from __future__ import annotations

import sqlite3

from db.recon_readiness import evaluate_readiness, lane_allowed


def test_readiness_is_unmapped_without_primary_and_mapping_with_active_primary():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    c.executescript("""
    CREATE TABLE target_systems(id INTEGER PRIMARY KEY,target_name TEXT,display_name TEXT,canonical_url TEXT,scope_class TEXT,lifecycle_state TEXT);
    CREATE TABLE target_assets(id INTEGER PRIMARY KEY,target_name TEXT,asset_value TEXT,scope_class TEXT,scope_status TEXT,authorization_state TEXT);
    CREATE TABLE system_asset_links(id INTEGER PRIMARY KEY,target_name TEXT,system_id INTEGER,asset_id INTEGER,relationship TEXT,confidence TEXT,evidence_refs_json TEXT);
    CREATE TABLE coverage_ledger(id INTEGER PRIMARY KEY,target_name TEXT,item_key TEXT,status TEXT);
    CREATE TABLE operator_inbox(id INTEGER PRIMARY KEY,target_name TEXT,status TEXT,blocking INTEGER,system_id INTEGER);
    INSERT INTO target_systems VALUES(1,'T','博客','https://blog.example','owned','mapping');
    """)
    first = evaluate_readiness(c, target_name="T", system_id=1)
    assert first["state"] == "unmapped"
    c.execute("INSERT INTO target_assets VALUES(1,'T','blog.example','owned','in_scope','active')")
    c.execute("INSERT INTO system_asset_links VALUES(1,'T',1,1,'primary','high','[]')")
    second = evaluate_readiness(c, target_name="T", system_id=1)
    assert second["state"] in {"mapping", "blocked"}
    assert lane_allowed(second, "entry_probe")
    assert not lane_allowed(second, "logic_probe")
