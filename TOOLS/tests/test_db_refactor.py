from __future__ import annotations

import sqlite3

from db.rebuild_target_db import rebuild


def test_rebuild_creates_asset_links_and_normalized_endpoint_map():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        CREATE TABLE targets(id INTEGER PRIMARY KEY, target_name TEXT, domain TEXT);
        INSERT INTO targets VALUES(1, 'demo', 'example.test');
        CREATE TABLE target_assets(id INTEGER PRIMARY KEY, target_name TEXT, asset_value TEXT, scope_status TEXT, scope_reason TEXT);
        INSERT INTO target_assets VALUES(1, 'demo', 'app.example.test', 'needs_review', NULL);
        INSERT INTO target_assets VALUES(2, 'demo', 'vendor.other.test', 'needs_review', NULL);
        CREATE TABLE pages(id INTEGER PRIMARY KEY, url TEXT, status TEXT, title TEXT, signal_reason TEXT, source TEXT);
        INSERT INTO pages VALUES(1, 'https://app.example.test/login', 'visited', 'Login', '', 'crawl');
        CREATE TABLE js_files(id INTEGER PRIMARY KEY, url TEXT, page_url TEXT);
        INSERT INTO js_files VALUES(1, 'https://app.example.test/app.js', 'https://app.example.test/login');
        CREATE TABLE js_signals(
            id TEXT PRIMARY KEY, url TEXT, path TEXT, host TEXT, method TEXT, js_file_id INTEGER,
            source_kind TEXT, business_hint TEXT, caller_hint TEXT, params_json TEXT,
            evidence_location TEXT, confidence INTEGER, runtime_seen INTEGER
        );
        INSERT INTO js_signals VALUES('sig-1','https://app.example.test/api/me','/api/me','app.example.test','GET',1,'js','profile','', '[]','line:1',80,0);
        CREATE TABLE hunt_queue(
            id INTEGER PRIMARY KEY, url TEXT, method TEXT, source TEXT, endpoint_type TEXT,
            business_intent TEXT, signal_reason TEXT, query_string TEXT, status TEXT
        );
        INSERT INTO hunt_queue VALUES(1,'https://app.example.test/api/orders','GET','auto','api','orders','', '', 'queued');
        CREATE TABLE page_asset_links(page_id INTEGER, asset_id INTEGER, relation TEXT, confidence TEXT, PRIMARY KEY(page_id,asset_id));
        CREATE TABLE js_asset_links(js_file_id INTEGER, asset_id INTEGER, relation TEXT, confidence TEXT, PRIMARY KEY(js_file_id,asset_id));
        CREATE TABLE endpoint_observations(
            id INTEGER PRIMARY KEY AUTOINCREMENT, target_name TEXT, asset_id INTEGER, page_id INTEGER,
            js_file_id INTEGER, js_signal_id TEXT, source_table TEXT, source_id TEXT, canonical_url TEXT,
            host TEXT, path TEXT, method TEXT, source TEXT, auth_state TEXT, response_class TEXT,
            status_code INTEGER, content_type TEXT, waf_state TEXT, business_hint TEXT,
            parameter_names_json TEXT, evidence_refs_json TEXT, confidence TEXT, test_status TEXT,
            first_seen_at TEXT, last_seen_at TEXT, observed_count INTEGER,
            UNIQUE(target_name,canonical_url,method,source,source_id)
        );
        """
    )
    result = rebuild(conn, "demo")
    assert result["in_scope_assets"] == 1
    assert result["needs_review_assets"] == 1
    assert conn.execute("SELECT COUNT(*) FROM page_asset_links").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM js_asset_links").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM endpoint_observations").fetchone()[0] == 3
    assert conn.execute("SELECT COUNT(*) FROM endpoint_observations WHERE asset_id=1").fetchone()[0] == 3
    conn.close()
