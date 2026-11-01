-- Endpoint map and explicit asset scope metadata.
-- The legacy pages/js_files/hunt_queue tables remain readable for compatibility;
-- new writes should prefer the normalized observation tables below.

ALTER TABLE target_assets ADD COLUMN scope_status TEXT DEFAULT 'needs_review';
ALTER TABLE target_assets ADD COLUMN scope_reason TEXT;
ALTER TABLE target_assets ADD COLUMN source_query TEXT;
ALTER TABLE target_assets ADD COLUMN source_snapshot TEXT;

CREATE TABLE IF NOT EXISTS page_asset_links (
    page_id INTEGER NOT NULL REFERENCES pages(id),
    asset_id INTEGER NOT NULL REFERENCES target_assets(id),
    relation TEXT NOT NULL DEFAULT 'same_host',
    confidence TEXT NOT NULL DEFAULT 'medium',
    evidence_ref TEXT,
    created_at TEXT DEFAULT (datetime('now','localtime')),
    PRIMARY KEY(page_id, asset_id)
);
CREATE INDEX IF NOT EXISTS idx_page_asset_links_asset
    ON page_asset_links(asset_id, confidence);

CREATE TABLE IF NOT EXISTS js_asset_links (
    js_file_id INTEGER NOT NULL REFERENCES js_files(id),
    asset_id INTEGER NOT NULL REFERENCES target_assets(id),
    relation TEXT NOT NULL DEFAULT 'same_host',
    confidence TEXT NOT NULL DEFAULT 'medium',
    evidence_ref TEXT,
    created_at TEXT DEFAULT (datetime('now','localtime')),
    PRIMARY KEY(js_file_id, asset_id)
);
CREATE INDEX IF NOT EXISTS idx_js_asset_links_asset
    ON js_asset_links(asset_id, confidence);

CREATE TABLE IF NOT EXISTS endpoint_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_name TEXT NOT NULL,
    asset_id INTEGER REFERENCES target_assets(id),
    page_id INTEGER REFERENCES pages(id),
    js_file_id INTEGER REFERENCES js_files(id),
    js_signal_id TEXT,
    source_table TEXT,
    source_id TEXT,
    canonical_url TEXT NOT NULL,
    host TEXT,
    path TEXT,
    method TEXT NOT NULL DEFAULT 'GET',
    source TEXT NOT NULL,
    auth_state TEXT NOT NULL DEFAULT 'unknown'
        CHECK(auth_state IN ('public','login_redirect','auth_required','token_required','role_required','unknown','blocked_by_waf','not_tested')),
    response_class TEXT,
    status_code INTEGER,
    content_type TEXT,
    waf_state TEXT,
    business_hint TEXT,
    parameter_names_json TEXT NOT NULL DEFAULT '[]',
    evidence_refs_json TEXT NOT NULL DEFAULT '[]',
    confidence TEXT NOT NULL DEFAULT 'unknown'
        CHECK(confidence IN ('low','medium','high','unknown')),
    test_status TEXT NOT NULL DEFAULT 'not_tested'
        CHECK(test_status IN ('not_tested','queued','observed','tested','blocked','parked')),
    first_seen_at TEXT DEFAULT (datetime('now','localtime')),
    last_seen_at TEXT DEFAULT (datetime('now','localtime')),
    observed_count INTEGER NOT NULL DEFAULT 1,
    UNIQUE(target_name, canonical_url, method, source, source_id)
);
CREATE INDEX IF NOT EXISTS idx_endpoint_observations_asset
    ON endpoint_observations(target_name, asset_id, auth_state, test_status);
CREATE INDEX IF NOT EXISTS idx_endpoint_observations_host_path
    ON endpoint_observations(host, path, method);

CREATE TABLE IF NOT EXISTS endpoint_evidence_links (
    endpoint_id INTEGER NOT NULL REFERENCES endpoint_observations(id),
    evidence_ref_id INTEGER NOT NULL REFERENCES evidence_refs(id),
    relation TEXT NOT NULL DEFAULT 'observed',
    created_at TEXT DEFAULT (datetime('now','localtime')),
    PRIMARY KEY(endpoint_id, evidence_ref_id)
);

CREATE INDEX IF NOT EXISTS idx_target_assets_scope
    ON target_assets(target_name, scope_status, live_status);
