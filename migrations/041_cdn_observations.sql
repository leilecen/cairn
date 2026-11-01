-- 041: passive CDN classifications are facts, separate from source candidates.
CREATE TABLE IF NOT EXISTS cdn_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_name TEXT NOT NULL,
    asset_id INTEGER,
    hostname TEXT NOT NULL,
    classification TEXT NOT NULL,
    provider TEXT NOT NULL DEFAULT '',
    reasons_json TEXT NOT NULL DEFAULT '[]',
    evidence_refs_json TEXT NOT NULL DEFAULT '[]',
    observed_at TEXT DEFAULT (datetime('now','localtime')),
    UNIQUE(target_name, asset_id, hostname, classification, provider)
);
CREATE INDEX IF NOT EXISTS idx_cdn_observations_target ON cdn_observations(target_name, classification);
