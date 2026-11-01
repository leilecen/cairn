-- 040: per-asset type observations; deliberately independent from system clustering.
CREATE TABLE IF NOT EXISTS system_type_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_name TEXT NOT NULL,
    asset_id INTEGER NOT NULL,
    classifier TEXT NOT NULL DEFAULT 'declarative_system_types',
    rule_context TEXT NOT NULL DEFAULT 'system_signatures:v1',
    label TEXT NOT NULL,
    rule_id TEXT,
    reasons_json TEXT NOT NULL DEFAULT '[]',
    evidence_refs_json TEXT NOT NULL DEFAULT '[]',
    observed_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    UNIQUE(target_name, asset_id, classifier, rule_context)
);
CREATE INDEX IF NOT EXISTS idx_system_type_observations_target_asset
    ON system_type_observations(target_name, asset_id, observed_at DESC);
