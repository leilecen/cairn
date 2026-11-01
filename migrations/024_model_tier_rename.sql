-- 024_model_tier_rename.sql
-- Rename work_items.model_tier CHECK values:
--   cheap → haiku, standard → sonnet, premium → opus

CREATE TABLE work_items_v2 (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_name TEXT NOT NULL,
    lane TEXT NOT NULL,
    subtype TEXT,
    subject_table TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    attack_thread_id INTEGER REFERENCES attack_threads(id),
    title TEXT,
    objective TEXT,
    priority INTEGER DEFAULT 50,
    status TEXT DEFAULT 'queued'
        CHECK(status IN ('queued','claimed','partial','blocked','done','failed','cancelled')),
    claimed_by TEXT,
    claimed_at TEXT,
    lease_until TEXT,
    heartbeat_at TEXT,
    timebox_minutes INTEGER DEFAULT 10,
    heartbeat_minutes INTEGER DEFAULT 5,
    attempt_count INTEGER DEFAULT 0,
    max_attempts INTEGER DEFAULT 3,
    model_tier TEXT DEFAULT 'sonnet'
        CHECK(model_tier IN ('haiku','sonnet','opus')),
    reasoning_tier TEXT DEFAULT 'low'
        CHECK(reasoning_tier IN ('low','medium','high')),
    upgrade_policy TEXT DEFAULT 'ask_main'
        CHECK(upgrade_policy IN ('never','ask_main','auto_if_high_risk_signal')),
    auth_requirement TEXT DEFAULT 'unknown'
        CHECK(auth_requirement IN ('none','optional','required','multi_account_required','role_required','unknown')),
    risk_class TEXT DEFAULT 'safe_passive'
        CHECK(risk_class IN ('safe_passive','safe_replay','sensitive_read','state_changing','high_risk')),
    summary TEXT,
    next_action TEXT,
    blocker_reason TEXT,
    last_error TEXT,
    created_at TEXT DEFAULT (datetime('now','localtime')),
    updated_at TEXT DEFAULT (datetime('now','localtime'))
);

INSERT INTO work_items_v2 (
    id, target_name, lane, subtype, subject_table, subject_id, attack_thread_id,
    title, objective, priority, status, claimed_by, claimed_at, lease_until, heartbeat_at,
    timebox_minutes, heartbeat_minutes, attempt_count, max_attempts, model_tier,
    reasoning_tier, upgrade_policy, auth_requirement, risk_class, summary, next_action,
    blocker_reason, last_error, created_at, updated_at
)
SELECT
    id, target_name, lane, subtype, subject_table, subject_id, attack_thread_id,
    title, objective, priority, status, claimed_by, claimed_at, lease_until, heartbeat_at,
    timebox_minutes, heartbeat_minutes, attempt_count, max_attempts,
    CASE model_tier
        WHEN 'cheap' THEN 'haiku'
        WHEN 'standard' THEN 'sonnet'
        WHEN 'premium' THEN 'opus'
        WHEN 'haiku' THEN 'haiku'
        WHEN 'sonnet' THEN 'sonnet'
        WHEN 'opus' THEN 'opus'
        ELSE 'sonnet'
    END,
    reasoning_tier, upgrade_policy, auth_requirement, risk_class, summary, next_action,
    blocker_reason, last_error, created_at, updated_at
FROM work_items;

DROP TABLE work_items;

ALTER TABLE work_items_v2 RENAME TO work_items;

CREATE INDEX IF NOT EXISTS idx_work_items_pick
ON work_items(status, priority DESC, created_at ASC);

CREATE INDEX IF NOT EXISTS idx_work_items_target_lane
ON work_items(target_name, lane, status);
