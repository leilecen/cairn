CREATE TABLE IF NOT EXISTS work_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_name TEXT NOT NULL,
    lane TEXT NOT NULL,
    subtype TEXT,
    subject_table TEXT NOT NULL,
    subject_id TEXT NOT NULL,
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
    model_tier TEXT DEFAULT 'standard'
        CHECK(model_tier IN ('cheap','standard','premium')),
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

CREATE INDEX IF NOT EXISTS idx_work_items_pick
ON work_items(status, priority DESC, created_at ASC);

CREATE INDEX IF NOT EXISTS idx_work_items_target_lane
ON work_items(target_name, lane, status);

CREATE TABLE IF NOT EXISTS agent_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    work_item_id INTEGER REFERENCES work_items(id),
    agent_id TEXT NOT NULL,
    event_type TEXT NOT NULL
        CHECK(event_type IN (
            'heartbeat',
            'partial_result',
            'hypothesis',
            'replay_result',
            'evidence',
            'blocker',
            'needs_operator',
            'upgrade_request',
            'done',
            'failed'
        )),
    severity TEXT DEFAULT 'info'
        CHECK(severity IN ('debug','info','notice','warning','critical')),
    payload_json TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now','localtime'))
);

CREATE INDEX IF NOT EXISTS idx_agent_events_work_item
ON agent_events(work_item_id, created_at);

CREATE TABLE IF NOT EXISTS operator_inbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_name TEXT NOT NULL,
    related_work_item_id INTEGER REFERENCES work_items(id),
    kind TEXT NOT NULL
        CHECK(kind IN (
            'choose_asset',
            'login_required',
            'secondary_account_required',
            'role_account_required',
            'screenshot_needed',
            'confirm_scope',
            'confirm_high_risk',
            'manual_review',
            'report_decision'
        )),
    title TEXT NOT NULL,
    detail TEXT,
    suggested_action TEXT,
    url TEXT,
    burp_action_id INTEGER,
    evidence_ref_id INTEGER,
    status TEXT DEFAULT 'open'
        CHECK(status IN ('open','accepted','skipped','done','cancelled')),
    created_at TEXT DEFAULT (datetime('now','localtime')),
    resolved_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_operator_inbox_open
ON operator_inbox(target_name, status, created_at);

CREATE TABLE IF NOT EXISTS burp_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_name TEXT NOT NULL,
    work_item_id INTEGER REFERENCES work_items(id),
    action_type TEXT NOT NULL
        CHECK(action_type IN (
            'send_to_repeater',
            'replay_compare',
            'active_scan',
            'collaborator_check'
        )),
    method TEXT,
    url TEXT,
    headers_json TEXT,
    body TEXT,
    note TEXT,
    risk_class TEXT DEFAULT 'safe_replay'
        CHECK(risk_class IN ('safe_passive','safe_replay','sensitive_read','state_changing','high_risk')),
    repeater_tab_name TEXT,
    burp_request_ref TEXT,
    status TEXT DEFAULT 'queued'
        CHECK(status IN ('queued','sent','failed','skipped')),
    error TEXT,
    created_at TEXT DEFAULT (datetime('now','localtime')),
    sent_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_burp_actions_status
ON burp_actions(target_name, status, created_at);

CREATE TABLE IF NOT EXISTS browser_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_name TEXT NOT NULL,
    work_item_id INTEGER REFERENCES work_items(id),
    action_type TEXT NOT NULL
        CHECK(action_type IN ('open_url','capture_screenshot','manual_login','inspect_page')),
    url TEXT,
    selector TEXT,
    note TEXT,
    status TEXT DEFAULT 'queued'
        CHECK(status IN ('queued','done','failed','skipped')),
    created_at TEXT DEFAULT (datetime('now','localtime')),
    completed_at TEXT
);

CREATE TABLE IF NOT EXISTS evidence_refs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_name TEXT NOT NULL,
    source_table TEXT NOT NULL,
    source_id TEXT NOT NULL,
    evidence_type TEXT NOT NULL
        CHECK(evidence_type IN (
            'request',
            'response',
            'diff',
            'screenshot',
            'js_signal',
            'hypothesis',
            'repeater_tab',
            'operator_note'
        )),
    title TEXT,
    summary TEXT,
    ref_json TEXT,
    created_at TEXT DEFAULT (datetime('now','localtime'))
);
