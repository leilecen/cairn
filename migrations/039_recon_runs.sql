-- 039: resumable adapter execution ledger; observations remain in recon_sources.
CREATE TABLE IF NOT EXISTS recon_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_name TEXT NOT NULL,
    source TEXT NOT NULL,
    input_fingerprint TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    attempt INTEGER NOT NULL DEFAULT 0,
    cursor_json TEXT NOT NULL DEFAULT '{}',
    budget_json TEXT NOT NULL DEFAULT '{}',
    summary_json TEXT NOT NULL DEFAULT '{}',
    last_success_at TEXT,
    next_retry_at TEXT,
    updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    UNIQUE(target_name, source, input_fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_recon_runs_ready
    ON recon_runs(target_name, status, next_retry_at);
