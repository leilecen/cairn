-- Strict asset classification, endpoint provenance, and bounded pre-auth runs.
ALTER TABLE target_assets ADD COLUMN scope_class TEXT DEFAULT 'unknown';
ALTER TABLE target_assets ADD COLUMN authorization_state TEXT DEFAULT 'unknown';
ALTER TABLE target_assets ADD COLUMN relation_to_target TEXT;

ALTER TABLE endpoint_observations ADD COLUMN raw_endpoint TEXT;
ALTER TABLE endpoint_observations ADD COLUMN resolved_url TEXT;
ALTER TABLE endpoint_observations ADD COLUMN base_url TEXT;
ALTER TABLE endpoint_observations ADD COLUMN source_page_url TEXT;
ALTER TABLE endpoint_observations ADD COLUMN source_js_url TEXT;
ALTER TABLE endpoint_observations ADD COLUMN origin_host TEXT;
ALTER TABLE endpoint_observations ADD COLUMN route_kind TEXT;
ALTER TABLE endpoint_observations ADD COLUMN service_hint TEXT;
ALTER TABLE endpoint_observations ADD COLUMN resolution_status TEXT DEFAULT 'unresolved';
ALTER TABLE endpoint_observations ADD COLUMN scope_class TEXT DEFAULT 'unknown';
ALTER TABLE endpoint_observations ADD COLUMN redirect_location TEXT;
ALTER TABLE endpoint_observations ADD COLUMN response_fingerprint TEXT;

CREATE TABLE IF NOT EXISTS asset_relationships (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_name TEXT NOT NULL,
    asset_id INTEGER NOT NULL REFERENCES target_assets(id),
    related_host TEXT NOT NULL,
    relation_type TEXT NOT NULL,
    scope_class TEXT NOT NULL DEFAULT 'unknown',
    authorization_state TEXT NOT NULL DEFAULT 'unknown',
    evidence_refs_json TEXT NOT NULL DEFAULT '[]',
    notes TEXT,
    observed_at TEXT DEFAULT (datetime('now','localtime')),
    UNIQUE(target_name, asset_id, related_host, relation_type)
);

CREATE TABLE IF NOT EXISTS preauth_probe_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_name TEXT NOT NULL,
    asset_id INTEGER REFERENCES target_assets(id),
    endpoint_group TEXT,
    max_requests INTEGER NOT NULL DEFAULT 30,
    request_count INTEGER NOT NULL DEFAULT 0,
    min_interval_seconds REAL NOT NULL DEFAULT 2,
    status TEXT NOT NULL DEFAULT 'running',
    stop_reason TEXT,
    evidence_refs_json TEXT NOT NULL DEFAULT '[]',
    started_at TEXT DEFAULT (datetime('now','localtime')),
    finished_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_assets_scope_class
    ON target_assets(target_name, scope_class, authorization_state, scope_status);
CREATE INDEX IF NOT EXISTS idx_endpoint_resolution
    ON endpoint_observations(target_name, resolution_status, scope_class, auth_state);
CREATE INDEX IF NOT EXISTS idx_preauth_runs_target
    ON preauth_probe_runs(target_name, asset_id, status, started_at DESC);
