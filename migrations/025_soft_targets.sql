CREATE TABLE IF NOT EXISTS soft_targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_name TEXT NOT NULL,
    asset_id INTEGER,
    asset_type TEXT DEFAULT 'domain',
    asset_value TEXT NOT NULL,
    port INTEGER,
    protocol TEXT DEFAULT 'https',
    total_score INTEGER NOT NULL DEFAULT 0,
    raw_score INTEGER NOT NULL DEFAULT 0,
    penalty INTEGER NOT NULL DEFAULT 0,
    tier TEXT NOT NULL,
    rank INTEGER,
    status TEXT NOT NULL DEFAULT 'ranked'
        CHECK(status IN ('ranked','available','focused','failed','parked','completed','excluded')),
    dimension_scores_json TEXT NOT NULL DEFAULT '{}',
    evidence_json TEXT NOT NULL DEFAULT '[]',
    failure_reason TEXT,
    failure_evidence_json TEXT,
    focused_at TEXT,
    completed_at TEXT,
    created_at TEXT DEFAULT (datetime('now','localtime')),
    updated_at TEXT DEFAULT (datetime('now','localtime')),
    UNIQUE(target_name, asset_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_soft_targets_identity
ON soft_targets(target_name, asset_value, COALESCE(port, 443));

CREATE INDEX IF NOT EXISTS idx_soft_targets_rank
ON soft_targets(target_name, status, total_score DESC, rank ASC);

CREATE TABLE IF NOT EXISTS soft_target_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    soft_target_id INTEGER REFERENCES soft_targets(id),
    target_name TEXT NOT NULL,
    asset_value TEXT NOT NULL,
    from_status TEXT,
    to_status TEXT NOT NULL
        CHECK(to_status IN ('ranked','available','focused','failed','parked','completed','excluded')),
    reason TEXT,
    evidence_json TEXT,
    actor TEXT DEFAULT 'soft_target_scorer',
    created_at TEXT DEFAULT (datetime('now','localtime'))
);

CREATE INDEX IF NOT EXISTS idx_soft_target_events_target
ON soft_target_events(target_name, created_at);
