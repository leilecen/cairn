ALTER TABLE pages ADD COLUMN canonical_url TEXT;
ALTER TABLE pages ADD COLUMN endpoint_fingerprint TEXT;
ALTER TABLE pages ADD COLUMN signal_value TEXT;
ALTER TABLE pages ADD COLUMN signal_reason TEXT;

ALTER TABLE hunt_queue ADD COLUMN endpoint_fingerprint TEXT;
ALTER TABLE hunt_queue ADD COLUMN canonical_url TEXT;
ALTER TABLE hunt_queue ADD COLUMN signal_value TEXT;
ALTER TABLE hunt_queue ADD COLUMN signal_reason TEXT;
ALTER TABLE hunt_queue ADD COLUMN risk_score INTEGER DEFAULT 0;
ALTER TABLE hunt_queue ADD COLUMN noise_reason TEXT;

ALTER TABLE suspicious_points ADD COLUMN canonical_url TEXT;
ALTER TABLE suspicious_points ADD COLUMN auth_surface_type TEXT;
ALTER TABLE suspicious_points ADD COLUMN signal_value TEXT;
ALTER TABLE suspicious_points ADD COLUMN signal_reason TEXT;
ALTER TABLE suspicious_points ADD COLUMN noise_reason TEXT;

CREATE INDEX IF NOT EXISTS idx_pages_endpoint_fingerprint ON pages(endpoint_fingerprint);
CREATE INDEX IF NOT EXISTS idx_hunt_queue_signal ON hunt_queue(status, risk_score, signal_value);
CREATE INDEX IF NOT EXISTS idx_sp_auth_surface ON suspicious_points(test_status, auth_surface_type, risk_score);

CREATE TABLE IF NOT EXISTS etl_cache (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task TEXT NOT NULL,
    instruction_hash TEXT NOT NULL,
    data_hash TEXT NOT NULL,
    result TEXT NOT NULL,
    model TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now', 'localtime')),
    hit_count INTEGER DEFAULT 0,
    UNIQUE(task, instruction_hash, data_hash)
);

CREATE VIEW IF NOT EXISTS review_candidates AS
SELECT
    'hunt_queue' AS source_table,
    CAST(id AS TEXT) AS source_id,
    method,
    url,
    canonical_url,
    endpoint_fingerprint,
    endpoint_type,
    business_intent,
    risk_hint,
    risk_score,
    status,
    signal_value,
    signal_reason,
    noise_reason,
    created_at
FROM hunt_queue
WHERE status='queued' AND COALESCE(noise_reason, '') = ''
UNION ALL
SELECT
    'suspicious_points' AS source_table,
    id AS source_id,
    method,
    url,
    canonical_url,
    endpoint_fingerprint,
    test_type AS endpoint_type,
    reasoning AS business_intent,
    risk AS risk_hint,
    risk_score,
    test_status AS status,
    signal_value,
    signal_reason,
    noise_reason,
    created_at
FROM suspicious_points
WHERE test_status='untested' AND COALESCE(noise_reason, '') = '';
