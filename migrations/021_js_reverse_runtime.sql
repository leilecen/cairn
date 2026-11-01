ALTER TABLE js_signals ADD COLUMN value_flow_json TEXT;
ALTER TABLE js_signals ADD COLUMN caller_chain_json TEXT;
ALTER TABLE js_signals ADD COLUMN runtime_seen INTEGER DEFAULT 0;
ALTER TABLE js_signals ADD COLUMN runtime_evidence_json TEXT;

ALTER TABLE js_signal_clusters ADD COLUMN runtime_seen INTEGER DEFAULT 0;
ALTER TABLE js_signal_clusters ADD COLUMN runtime_count INTEGER DEFAULT 0;
ALTER TABLE js_signal_clusters ADD COLUMN attack_surface_json TEXT;

CREATE TABLE IF NOT EXISTS runtime_requests (
    id TEXT PRIMARY KEY,
    target_id INTEGER,
    source TEXT NOT NULL,
    method TEXT,
    url TEXT NOT NULL,
    host TEXT,
    path TEXT,
    headers_json TEXT,
    body_keys_json TEXT,
    page_route TEXT,
    request_time TEXT,
    matched_signal_id TEXT,
    matched_cluster_id TEXT,
    redaction_applied INTEGER DEFAULT 1,
    raw_reference TEXT,
    created_at TEXT DEFAULT (datetime('now','localtime'))
);

CREATE INDEX IF NOT EXISTS idx_runtime_requests_target_id ON runtime_requests(target_id);
CREATE INDEX IF NOT EXISTS idx_runtime_requests_match ON runtime_requests(matched_cluster_id, matched_signal_id);
