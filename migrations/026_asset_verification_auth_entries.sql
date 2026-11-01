ALTER TABLE target_assets ADD COLUMN live_status TEXT DEFAULT 'unknown';
ALTER TABLE target_assets ADD COLUMN last_status_code INTEGER;
ALTER TABLE target_assets ADD COLUMN last_title TEXT;
ALTER TABLE target_assets ADD COLUMN resolved_ip TEXT;
ALTER TABLE target_assets ADD COLUMN last_tech_stack TEXT;
ALTER TABLE target_assets ADD COLUMN last_verified_at TEXT;
ALTER TABLE target_assets ADD COLUMN last_verify_status TEXT;
ALTER TABLE target_assets ADD COLUMN auth_required INTEGER DEFAULT 0;
ALTER TABLE target_assets ADD COLUMN auth_entry_found INTEGER DEFAULT 0;
ALTER TABLE target_assets ADD COLUMN login_urls TEXT DEFAULT '[]';
ALTER TABLE target_assets ADD COLUMN register_urls TEXT DEFAULT '[]';
ALTER TABLE target_assets ADD COLUMN auth_blocker TEXT DEFAULT 'unknown';

CREATE TABLE IF NOT EXISTS asset_auth_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_name TEXT NOT NULL,
    asset_id INTEGER,
    url TEXT NOT NULL,
    entry_type TEXT NOT NULL CHECK(entry_type IN ('login','register')),
    source TEXT NOT NULL,
    confidence TEXT DEFAULT 'medium',
    status TEXT DEFAULT 'observed',
    notes TEXT,
    discovered_at TEXT DEFAULT (datetime('now','localtime')),
    UNIQUE(target_name, asset_id, url, entry_type, source)
);

CREATE INDEX IF NOT EXISTS idx_asset_auth_entries_target
ON asset_auth_entries(target_name, entry_type, confidence);
