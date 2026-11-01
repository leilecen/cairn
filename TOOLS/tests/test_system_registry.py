from __future__ import annotations

import sqlite3

import pytest
from db.system_registry import link_asset, register_system, system_compact


def _db():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    c.executescript("""
    CREATE TABLE target_assets(id INTEGER PRIMARY KEY,target_name TEXT,asset_value TEXT,scope_class TEXT,scope_status TEXT,authorization_state TEXT);
    CREATE TABLE target_systems(id INTEGER PRIMARY KEY AUTOINCREMENT,target_name TEXT,system_key TEXT,display_name TEXT,canonical_url TEXT,description TEXT,scope_class TEXT,lifecycle_state TEXT,created_by TEXT,created_at TEXT,updated_at TEXT,UNIQUE(target_name,system_key));
    CREATE TABLE system_asset_links(id INTEGER PRIMARY KEY AUTOINCREMENT,target_name TEXT,system_id INTEGER,asset_id INTEGER,relationship TEXT,confidence TEXT,evidence_refs_json TEXT,created_at TEXT,updated_at TEXT,UNIQUE(system_id,asset_id,relationship));
    INSERT INTO target_assets VALUES(1,'T','blog.example','owned','in_scope','active');
    INSERT INTO target_assets VALUES(2,'OTHER','other.example','owned','in_scope','active');
    """)
    return c


def test_system_registry_is_idempotent_and_links_only_same_target_asset():
    c = _db()
    first = register_system(
        c,
        target_name="T",
        system_key="blog",
        display_name="官方博客",
        canonical_url="https://blog.example",
        scope_class="owned",
    )
    second = register_system(
        c,
        target_name="T",
        system_key="blog",
        display_name="官方博客",
        canonical_url="https://blog.example/",
        scope_class="owned",
    )
    assert first["id"] == second["id"]
    link_asset(c, target_name="T", system_id=first["id"], asset_id=1, relationship="primary", confidence="high")
    with pytest.raises(ValueError):
        link_asset(c, target_name="T", system_id=first["id"], asset_id=2, relationship="api")
    assert system_compact(c, target_name="T", system_id=first["id"])["assets"][0]["asset_value"] == "blog.example"
