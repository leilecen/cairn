CREATE TABLE IF NOT EXISTS attack_threads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_name TEXT NOT NULL,
    asset_url TEXT,
    hypothesis TEXT NOT NULL,
    why_promising TEXT,
    current_evidence TEXT,
    next_probe TEXT,
    confidence TEXT DEFAULT 'low'
        CHECK(confidence IN ('low','medium','high')),
    priority INTEGER DEFAULT 50,
    status TEXT DEFAULT 'active'
        CHECK(status IN ('proposed','active','candidate','parked','killed')),
    kill_condition TEXT,
    owner TEXT,
    sprint_id TEXT,
    created_at TEXT DEFAULT (datetime('now','localtime')),
    updated_at TEXT DEFAULT (datetime('now','localtime')),
    last_partial_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_attack_threads_target_status
    ON attack_threads(target_name, status, priority DESC, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_attack_threads_sprint
    ON attack_threads(target_name, sprint_id, status);

CREATE TABLE IF NOT EXISTS attack_thread_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    attack_thread_id INTEGER REFERENCES attack_threads(id),
    actor TEXT NOT NULL,
    event_type TEXT NOT NULL
        CHECK(event_type IN (
            'created',
            'partial',
            'pivot',
            'parked',
            'killed',
            'candidate',
            'operator_decision'
        )),
    severity TEXT DEFAULT 'info'
        CHECK(severity IN ('debug','info','notice','warning','critical')),
    payload_json TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now','localtime'))
);

CREATE INDEX IF NOT EXISTS idx_attack_thread_events_thread
    ON attack_thread_events(attack_thread_id, created_at);

ALTER TABLE work_items ADD COLUMN attack_thread_id INTEGER REFERENCES attack_threads(id);
