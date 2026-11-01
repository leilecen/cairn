-- Full schema — includes all migrations through 039.
-- New DBs created via init_db() use this file directly.
-- init_db() marks all migrations as already applied.

CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_name TEXT NOT NULL,
    domain TEXT,
    ip TEXT,
    tech_stack TEXT,
    requires_auth INTEGER DEFAULT 0,
    auth_status TEXT DEFAULT 'not_logged_in',
    discovered_at TEXT DEFAULT (datetime('now', 'localtime')),
    notes TEXT
);

CREATE TABLE IF NOT EXISTS scan_state (
    id INTEGER PRIMARY KEY,
    target_id INTEGER REFERENCES targets(id),
    seed_url TEXT,
    phase TEXT DEFAULT 'init',
    started_at TEXT,
    spider_ended_at TEXT,
    reviewed_at TEXT,
    max_depth INTEGER DEFAULT 3,
    max_pages INTEGER DEFAULT 200,
    total_pages INTEGER DEFAULT 0,
    total_js INTEGER DEFAULT 0,
    total_apis INTEGER DEFAULT 0,
    total_forms INTEGER DEFAULT 0,
    total_suspicious INTEGER DEFAULT 0,
    total_findings INTEGER DEFAULT 0,
    call_count INTEGER DEFAULT 0,
    cdp_url TEXT DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS pages (
    id INTEGER PRIMARY KEY,
    url TEXT UNIQUE,
    depth INTEGER DEFAULT 0,
    status TEXT DEFAULT 'queued',
    title TEXT,
    links_found INTEGER DEFAULT 0,
    forms_json TEXT,
    js_files_json TEXT,
    api_calls_json TEXT,
    suspicious_params_json TEXT,
    crawled_at TEXT,
    source TEXT DEFAULT NULL,
    canonical_url TEXT,
    endpoint_fingerprint TEXT,
    signal_value TEXT,
    signal_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_pages_endpoint_fingerprint ON pages(endpoint_fingerprint);

CREATE TABLE IF NOT EXISTS js_files (
    id INTEGER PRIMARY KEY,
    url TEXT UNIQUE,
    page_url TEXT,
    analyzed INTEGER DEFAULT 0,
    discovered_apis_json TEXT,
    hardcoded_secrets_json TEXT,
    internal_routes_json TEXT,
    debug_switches_json TEXT,
    analyzed_at TEXT,
    content_hash TEXT,
    local_path TEXT,
    size_bytes INTEGER,
    source_kind TEXT DEFAULT 'web_script',
    source_map_url TEXT,
    source_map_status TEXT,
    extraction_status TEXT DEFAULT 'pending',
    extraction_version TEXT,
    signal_count INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_js_files_source_kind ON js_files(source_kind);
CREATE INDEX IF NOT EXISTS idx_js_files_extraction_status ON js_files(extraction_status);

CREATE TABLE IF NOT EXISTS js_signals (
    id TEXT PRIMARY KEY,
    target_id INTEGER,
    js_file_id INTEGER,
    source_kind TEXT NOT NULL,
    signal_type TEXT NOT NULL,
    protocol TEXT DEFAULT 'http',
    method TEXT,
    url TEXT,
    path TEXT,
    host TEXT,
    params_json TEXT,
    headers_json TEXT,
    evidence_snippet TEXT,
    evidence_location TEXT,
    caller_hint TEXT,
    page_route TEXT,
    auth_hint TEXT,
    signature_hint TEXT,
    business_hint TEXT,
    value_flow_json TEXT,
    caller_chain_json TEXT,
    runtime_seen INTEGER DEFAULT 0,
    runtime_evidence_json TEXT,
    confidence INTEGER DEFAULT 50,
    risk_score INTEGER DEFAULT 0,
    status TEXT DEFAULT 'new',
    promoted_sp_id TEXT,
    created_at TEXT DEFAULT (datetime('now','localtime')),
    updated_at TEXT DEFAULT (datetime('now','localtime')),
    UNIQUE(js_file_id, signal_type, method, path, evidence_location)
);
CREATE INDEX IF NOT EXISTS idx_js_signals_target_id ON js_signals(target_id);
CREATE INDEX IF NOT EXISTS idx_js_signals_js_file_id ON js_signals(js_file_id);
CREATE INDEX IF NOT EXISTS idx_js_signals_risk_status ON js_signals(risk_score, status);

CREATE TABLE IF NOT EXISTS js_signal_clusters (
    id TEXT PRIMARY KEY,
    target_id INTEGER,
    fingerprint TEXT NOT NULL,
    canonical_method TEXT,
    canonical_url TEXT,
    signal_types_json TEXT,
    source_count INTEGER DEFAULT 1,
    best_confidence INTEGER DEFAULT 0,
    best_risk_score INTEGER DEFAULT 0,
    representative_signal_id TEXT,
    status TEXT DEFAULT 'new',
    runtime_seen INTEGER DEFAULT 0,
    runtime_count INTEGER DEFAULT 0,
    attack_surface_json TEXT,
    ai_summary_json TEXT,
    ai_char_count INTEGER DEFAULT 0,
    ai_cache_key TEXT,
    created_at TEXT DEFAULT (datetime('now','localtime')),
    updated_at TEXT DEFAULT (datetime('now','localtime')),
    UNIQUE(target_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_js_clusters_target_id ON js_signal_clusters(target_id);
CREATE INDEX IF NOT EXISTS idx_js_clusters_risk_status ON js_signal_clusters(best_risk_score, status);

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

CREATE TABLE IF NOT EXISTS suspicious_points (
    id TEXT PRIMARY KEY NOT NULL,
    page_url TEXT,
    url TEXT,
    param TEXT,
    method TEXT DEFAULT 'GET',
    test_type TEXT,
    evidence TEXT,
    source TEXT,
    reasoning TEXT,
    risk TEXT DEFAULT 'Medium',
    test_status TEXT DEFAULT 'untested',
    burp_request_id INTEGER,
    created_at TEXT DEFAULT (datetime('now', 'localtime')),
    notes TEXT,
    endpoint_fingerprint TEXT,
    response_summary TEXT,
    risk_score INTEGER DEFAULT 0,
    canonical_url TEXT,
    auth_surface_type TEXT,
    signal_value TEXT,
    signal_reason TEXT,
    noise_reason TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_suspicious_points_auth_fingerprint
    ON suspicious_points(source, endpoint_fingerprint, test_type)
    WHERE endpoint_fingerprint IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_sp_auth_surface ON suspicious_points(test_status, auth_surface_type, risk_score);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    sp_id TEXT,
    target_id INTEGER REFERENCES targets(id),
    type TEXT,
    url TEXT,
    param TEXT,
    method TEXT,
    payload TEXT,
    evidence TEXT,
    risk TEXT,
    cvss TEXT,
    remediation TEXT,
    confirmed_at TEXT,
    burp_request_id INTEGER,
    review_status TEXT DEFAULT NULL,
    review_notes TEXT,
    reported_platforms TEXT DEFAULT '',
    report_file TEXT,
    audit_status TEXT DEFAULT 'pending',
    audit_notes TEXT DEFAULT NULL,
    -- 报告编写字段（043_report_fields.sql 同步）：吸收自 CyberStrike triage 规则
    -- 与 Strix 反脆弱字段。全部可空，旧数据不迁移也能出报告（显示占位符）。
    title TEXT,
    preconditions TEXT,
    counterevidence TEXT,
    confidence_rationale TEXT,
    severity_change_conditions TEXT,
    impact TEXT,
    poc_description TEXT,
    fix_verification TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_risk ON findings(risk);

CREATE TABLE IF NOT EXISTS auth_credentials (
    id INTEGER PRIMARY KEY,
    account_label TEXT,
    username TEXT,
    password TEXT,
    login_url TEXT,
    created_at TEXT DEFAULT (datetime('now', 'localtime'))
);

CREATE TABLE IF NOT EXISTS auth_flow_steps (
    id INTEGER PRIMARY KEY,
    step_index INTEGER,
    action_type TEXT,
    url TEXT,
    selector_uid TEXT,
    value TEXT,
    wait_ms INTEGER,
    description TEXT
);

CREATE TABLE IF NOT EXISTS auth_sessions (
    id INTEGER PRIMARY KEY,
    token_type TEXT,
    token_name TEXT,
    token_value TEXT,
    domain TEXT,
    path TEXT DEFAULT '/',
    is_active INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now', 'localtime')),
    role TEXT DEFAULT 'primary',
    expires_at TEXT,
    last_checked_at TEXT,
    cookie_source TEXT DEFAULT 'manual',
    username TEXT DEFAULT NULL,
    password TEXT DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS hunt_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER REFERENCES targets(id),
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    query_string TEXT,
    body TEXT,
    content_type TEXT,
    burp_history_id INTEGER,
    endpoint_type TEXT,
    business_intent TEXT,
    risk_hint TEXT DEFAULT 'Medium',
    status TEXT DEFAULT 'queued' CHECK(status IN ('queued','in_progress','tested','confirmed','error')),
    tested_types_json TEXT DEFAULT '[]',
    finding_ids TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now','localtime')),
    tested_at TEXT,
    notes TEXT,
    source TEXT DEFAULT 'auto' CHECK(source IN ('auto','manual_replay','auth_explore')),
    flow_id TEXT,
    endpoint_fingerprint TEXT,
    canonical_url TEXT,
    signal_value TEXT,
    signal_reason TEXT,
    risk_score INTEGER DEFAULT 0,
    noise_reason TEXT,
    UNIQUE(method, url, query_string)
);
CREATE INDEX IF NOT EXISTS idx_hunt_queue_status ON hunt_queue(status);
CREATE INDEX IF NOT EXISTS idx_hunt_queue_target ON hunt_queue(target_id);
CREATE INDEX IF NOT EXISTS idx_hunt_queue_source ON hunt_queue(source);
CREATE INDEX IF NOT EXISTS idx_hunt_queue_signal ON hunt_queue(status, risk_score, signal_value);

CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_sessions_role_name_domain
    ON auth_sessions(role, token_name, domain);

CREATE TABLE IF NOT EXISTS auth_storage_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    role TEXT DEFAULT 'primary',
    storage_type TEXT NOT NULL,
    origin TEXT NOT NULL,
    token_name TEXT NOT NULL,
    token_value TEXT NOT NULL,
    token_kind TEXT DEFAULT 'storage',
    is_active INTEGER DEFAULT 1,
    first_seen_at TEXT DEFAULT (datetime('now','localtime')),
    last_seen_at TEXT DEFAULT (datetime('now','localtime')),
    expires_at TEXT,
    source TEXT DEFAULT 'cdp_capture',
    UNIQUE(role, storage_type, origin, token_name)
);

CREATE TABLE IF NOT EXISTS plugins (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    name              TEXT NOT NULL UNIQUE,
    type              TEXT NOT NULL CHECK(type IN (
                          'nuclei_template','python_script','tool_binary','config'
                      )),
    trigger_stack     TEXT,
    covers_vuln_types TEXT,
    file_path         TEXT,
    install_cmd       TEXT,
    source            TEXT DEFAULT 'mapping'
                          CHECK(source IN ('mapping','ai_generated')),
    active            INTEGER DEFAULT 1,
    created_at        TEXT DEFAULT (datetime('now','localtime')),
    last_used_at      TEXT
);

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

DROP VIEW IF EXISTS review_candidates;
CREATE VIEW review_candidates AS
SELECT
    'hunt_queue' AS source_table,
    CAST(id AS TEXT) AS source_id,
    COALESCE(source, 'auto') AS source,
    COALESCE(canonical_url, url) AS url,
    COALESCE(method, 'GET') AS method,
    COALESCE(endpoint_fingerprint, canonical_url, url) AS fingerprint,
    COALESCE(NULLIF(signal_reason, ''), NULLIF(business_intent, ''), NULLIF(endpoint_type, ''), NULLIF(risk_hint, ''), 'hunt_queue_candidate') AS reason,
    CASE
        WHEN COALESCE(risk_score, 0) > 0 THEN risk_score
        WHEN risk_hint = 'Critical' THEN 90
        WHEN risk_hint = 'High' THEN 75
        WHEN risk_hint = 'Medium' THEN 55
        WHEN risk_hint = 'Low' THEN 25
        ELSE 40
    END AS risk_score,
    'review_hunt_queue' AS next_action,
    status,
    created_at,
    burp_history_id
FROM hunt_queue
WHERE status = 'queued' AND COALESCE(noise_reason, '') = ''
UNION ALL
SELECT
    'suspicious_points' AS source_table,
    id AS source_id,
    COALESCE(source, 'suspicious_point') AS source,
    COALESCE(canonical_url, url) AS url,
    COALESCE(method, 'GET') AS method,
    COALESCE(endpoint_fingerprint, canonical_url, url) AS fingerprint,
    COALESCE(NULLIF(signal_reason, ''), NULLIF(reasoning, ''), NULLIF(test_type, ''), 'suspicious_point_candidate') AS reason,
    CASE
        WHEN COALESCE(risk_score, 0) > 0 THEN risk_score
        WHEN risk = 'Critical' THEN 90
        WHEN risk = 'High' THEN 75
        WHEN risk = 'Medium' THEN 55
        WHEN risk = 'Low' THEN 25
        ELSE 45
    END AS risk_score,
    'review_suspicious_point' AS next_action,
    test_status AS status,
    created_at,
    burp_request_id AS burp_history_id
FROM suspicious_points
WHERE test_status = 'untested' AND COALESCE(noise_reason, '') = ''
UNION ALL
SELECT
    'pages' AS source_table,
    CAST(p.id AS TEXT) AS source_id,
    COALESCE(p.source, 'crawl') AS source,
    COALESCE(p.canonical_url, p.url) AS url,
    'GET' AS method,
    COALESCE(p.endpoint_fingerprint, p.canonical_url, p.url) AS fingerprint,
    COALESCE(NULLIF(p.signal_reason, ''), NULLIF(p.signal_value, ''), NULLIF(p.title, ''), 'page_signal') AS reason,
    CASE
        WHEN p.signal_value = 'high_value' THEN 52
        WHEN p.signal_value = 'medium_value' THEN 40
        WHEN COALESCE(p.signal_reason, '') != '' THEN 35
        ELSE 0
    END AS risk_score,
    'crawl_or_probe_page' AS next_action,
    p.status AS status,
    p.crawled_at AS created_at,
    NULL AS burp_history_id
FROM pages p
WHERE COALESCE(p.signal_value, '') IN ('high_value', 'medium_value')
  AND COALESCE(p.signal_reason, '') != 'public_or_configuration_signal'
  AND NOT EXISTS (
      SELECT 1
      FROM hunt_queue h
      WHERE COALESCE(h.noise_reason, '') = ''
        AND (
            (p.endpoint_fingerprint IS NOT NULL AND p.endpoint_fingerprint != '' AND h.endpoint_fingerprint = p.endpoint_fingerprint)
            OR COALESCE(h.canonical_url, h.url) = COALESCE(p.canonical_url, p.url)
        )
  )
  AND NOT EXISTS (
      SELECT 1
      FROM suspicious_points sp
      WHERE COALESCE(sp.noise_reason, '') = ''
        AND (
            (p.endpoint_fingerprint IS NOT NULL AND p.endpoint_fingerprint != '' AND sp.endpoint_fingerprint = p.endpoint_fingerprint)
            OR COALESCE(sp.canonical_url, sp.url) = COALESCE(p.canonical_url, p.url)
        )
  )
UNION ALL
SELECT
    'js_files' AS source_table,
    CAST(j.id AS TEXT) AS source_id,
    'js_analysis' AS source,
    j.url AS url,
    'GET' AS method,
    j.url AS fingerprint,
    CASE
        WHEN COALESCE(j.hardcoded_secrets_json, '[]') NOT IN ('', '[]', '{}', 'null') THEN 'hardcoded_secrets'
        WHEN COALESCE(j.debug_switches_json, '[]') NOT IN ('', '[]', '{}', 'null') THEN 'debug_switches'
        WHEN COALESCE(j.internal_routes_json, '[]') NOT IN ('', '[]', '{}', 'null') THEN 'internal_routes'
        ELSE 'discovered_apis'
    END AS reason,
    CASE
        WHEN COALESCE(j.hardcoded_secrets_json, '[]') NOT IN ('', '[]', '{}', 'null') THEN 58
        WHEN COALESCE(j.debug_switches_json, '[]') NOT IN ('', '[]', '{}', 'null') THEN 48
        WHEN COALESCE(j.internal_routes_json, '[]') NOT IN ('', '[]', '{}', 'null') THEN 45
        ELSE 32
    END AS risk_score,
    'analyze_js_signal' AS next_action,
    CASE WHEN COALESCE(j.analyzed, 0) = 1 THEN 'analyzed' ELSE 'queued' END AS status,
    j.analyzed_at AS created_at,
    NULL AS burp_history_id
FROM js_files j
WHERE COALESCE(j.analyzed, 0) = 1
  AND (
      COALESCE(j.discovered_apis_json, '[]') NOT IN ('', '[]', '{}', 'null')
      OR COALESCE(j.hardcoded_secrets_json, '[]') NOT IN ('', '[]', '{}', 'null')
      OR COALESCE(j.internal_routes_json, '[]') NOT IN ('', '[]', '{}', 'null')
      OR COALESCE(j.debug_switches_json, '[]') NOT IN ('', '[]', '{}', 'null')
  )
UNION ALL
SELECT
    'js_signal_clusters' AS source_table,
    c.id AS source_id,
    'js_intel' AS source,
    COALESCE(c.canonical_url, '') AS url,
    COALESCE(c.canonical_method, 'GET') AS method,
    c.fingerprint AS fingerprint,
    COALESCE(c.signal_types_json, 'js_cluster') AS reason,
    COALESCE(c.best_risk_score, 0) AS risk_score,
    CASE
        WHEN COALESCE(c.best_risk_score, 0) >= 70 THEN 'review_promoted_js_cluster'
        ELSE 'review_js_cluster'
    END AS next_action,
    COALESCE(c.status, 'new') AS status,
    c.created_at,
    NULL AS burp_history_id
FROM js_signal_clusters c
WHERE COALESCE(c.status, 'new') IN ('new', 'clustered', 'needs_auth', 'needs_signature', 'needs_operator')
  AND COALESCE(c.best_risk_score, 0) >= 40;

CREATE TABLE IF NOT EXISTS target_assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_name TEXT NOT NULL,
    asset_type TEXT DEFAULT 'domain' CHECK(asset_type IN ('domain','subdomain','ip','url','cidr','other')),
    asset_value TEXT NOT NULL,
    port INTEGER,
    protocol TEXT DEFAULT 'https',
    source TEXT DEFAULT 'manual' CHECK(source IN ('manual','fofa','zoomeye','other')),
    tech_stack TEXT,
    requires_auth INTEGER DEFAULT 0,
    status TEXT DEFAULT 'new' CHECK(status IN ('new','validated','queued','scanned','excluded')),
    priority INTEGER DEFAULT 0,
    notes TEXT,
    created_at TEXT DEFAULT (datetime('now','localtime')),
    validated_at TEXT,
    live_status TEXT DEFAULT 'unknown',
    last_status_code INTEGER,
    last_title TEXT,
    resolved_ip TEXT,
    last_tech_stack TEXT,
    last_verified_at TEXT,
    last_verify_status TEXT,
    auth_required INTEGER DEFAULT 0,
    auth_entry_found INTEGER DEFAULT 0,
    login_urls TEXT DEFAULT '[]',
    register_urls TEXT DEFAULT '[]',
    auth_blocker TEXT DEFAULT 'unknown',
    scope_status TEXT DEFAULT 'needs_review',
    scope_reason TEXT,
    source_query TEXT,
    source_snapshot TEXT,
    scope_class TEXT DEFAULT 'unknown',
    authorization_state TEXT DEFAULT 'unknown',
    relation_to_target TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_target_assets_identity
    ON target_assets(target_name, asset_value, COALESCE(port, 443));

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

CREATE TABLE IF NOT EXISTS attack_surface_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_name TEXT NOT NULL,
    soft_target_id INTEGER REFERENCES soft_targets(id),
    subject_table TEXT NOT NULL DEFAULT 'soft_targets',
    subject_id TEXT NOT NULL,
    system_tags_json TEXT NOT NULL DEFAULT '[]',
    business_tags_json TEXT NOT NULL DEFAULT '[]',
    roles_json TEXT NOT NULL DEFAULT '[]',
    flows_json TEXT NOT NULL DEFAULT '[]',
    trust_boundaries_json TEXT NOT NULL DEFAULT '[]',
    tech_stack_json TEXT NOT NULL DEFAULT '[]',
    confidence TEXT DEFAULT 'unknown'
        CHECK(confidence IN ('low','medium','high','unknown')),
    evidence_refs_json TEXT NOT NULL DEFAULT '[]',
    summary TEXT,
    status TEXT NOT NULL DEFAULT 'draft'
        CHECK(status IN ('draft','active','stale','blocked')),
    created_at TEXT DEFAULT (datetime('now','localtime')),
    updated_at TEXT DEFAULT (datetime('now','localtime')),
    UNIQUE(target_name, subject_table, subject_id)
);
CREATE INDEX IF NOT EXISTS idx_attack_surface_profiles_target
    ON attack_surface_profiles(target_name, status, updated_at DESC);

CREATE TABLE IF NOT EXISTS coverage_ledger (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_name TEXT NOT NULL,
    profile_id INTEGER REFERENCES attack_surface_profiles(id),
    work_item_id INTEGER REFERENCES work_items(id),
    item_key TEXT NOT NULL,
    category TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'unknown'
        CHECK(status IN ('covered','unknown','uncovered','blocked')),
    confidence TEXT DEFAULT 'unknown'
        CHECK(confidence IN ('low','medium','high','unknown')),
    evidence_refs_json TEXT NOT NULL DEFAULT '[]',
    summary TEXT,
    blocker_reason TEXT,
    next_action TEXT,
    created_at TEXT DEFAULT (datetime('now','localtime')),
    updated_at TEXT DEFAULT (datetime('now','localtime')),
    UNIQUE(target_name, profile_id, item_key)
);
CREATE INDEX IF NOT EXISTS idx_coverage_ledger_target_status
    ON coverage_ledger(target_name, status, category);

CREATE TABLE IF NOT EXISTS work_items (
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
    ,dispatch_state TEXT DEFAULT 'active',
    system_id INTEGER REFERENCES target_systems(id),
    park_reason TEXT,
    blocker_class TEXT
        CHECK(blocker_class IS NULL OR blocker_class IN (
            'auth_barrier','network','scope','evidence','critical_found','refuted','parked','other'
        ))
);
CREATE INDEX IF NOT EXISTS idx_work_items_pick ON work_items(status, priority DESC, created_at ASC);
CREATE INDEX IF NOT EXISTS idx_work_items_target_lane ON work_items(target_name, lane, status);

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
CREATE INDEX IF NOT EXISTS idx_agent_events_work_item ON agent_events(work_item_id, created_at);

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
            'report_decision',
            'evidence_capture',
            'focus_switch',
            'registration_required',
            'burp_action_required',
            'scope_cluster_confirm',
            'blocked_decision'
        )),
    title TEXT NOT NULL,
    detail TEXT,
    suggested_action TEXT,
    url TEXT,
    burp_action_id INTEGER,
    evidence_ref_id INTEGER,
    system_id INTEGER REFERENCES target_systems(id),
    action_key TEXT,
    action_label TEXT,
    why_needed TEXT,
    steps_json TEXT NOT NULL DEFAULT '[]',
    expected_observation TEXT,
    report_back_format TEXT,
    blocking INTEGER NOT NULL DEFAULT 1,
    status TEXT DEFAULT 'open'
        CHECK(status IN ('open','accepted','skipped','done','cancelled')),
    created_at TEXT DEFAULT (datetime('now','localtime')),
    resolved_at TEXT,
    expires_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_operator_inbox_open ON operator_inbox(target_name, status, created_at);

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
CREATE INDEX IF NOT EXISTS idx_burp_actions_status ON burp_actions(target_name, status, created_at);

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
            'semantic_profile',
            'coverage_ledger',
            'repeater_tab',
            'operator_note'
        )),
    title TEXT,
    summary TEXT,
    ref_json TEXT,
    created_at TEXT DEFAULT (datetime('now','localtime'))
);

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
    hunt_session_id INTEGER REFERENCES hunt_sessions(id),
    hypothesis_kind TEXT DEFAULT 'falsifiable',
    expected_observation TEXT DEFAULT '',
    refuting_observation TEXT DEFAULT '',
    alternative_explanations_json TEXT NOT NULL DEFAULT '[]',
    information_gain INTEGER NOT NULL DEFAULT 0 CHECK(information_gain BETWEEN 0 AND 3),
    stop_conditions_json TEXT NOT NULL DEFAULT '[]',
    pivot_options_json TEXT NOT NULL DEFAULT '[]',
    evaluation_status TEXT NOT NULL DEFAULT 'untested' CHECK(evaluation_status IN ('untested','supported','refuted','inconclusive','blocked')),
    last_evaluated_at TEXT,
    created_at TEXT DEFAULT (datetime('now','localtime')),
    updated_at TEXT DEFAULT (datetime('now','localtime')),
    last_partial_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_attack_threads_target_status
    ON attack_threads(target_name, status, priority DESC, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_attack_threads_sprint
    ON attack_threads(target_name, sprint_id, status);

CREATE TABLE IF NOT EXISTS hunt_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_name TEXT NOT NULL,
    soft_target_id INTEGER REFERENCES soft_targets(id),
    focus_subject_table TEXT NOT NULL,
    focus_subject_id TEXT NOT NULL,
    goal TEXT NOT NULL,
    success_criteria_json TEXT NOT NULL DEFAULT '[]',
    stop_conditions_json TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'proposed' CHECK(status IN ('proposed','active','paused','completed','abandoned')),
    selected_by TEXT NOT NULL,
    system_id INTEGER REFERENCES target_systems(id),
    recon_readiness_snapshot_json TEXT NOT NULL DEFAULT '{}',
    operator_acknowledged_at TEXT,
    started_at TEXT, ended_at TEXT, summary TEXT,
    created_at TEXT DEFAULT (datetime('now','localtime')),
    updated_at TEXT DEFAULT (datetime('now','localtime'))
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_hunt_sessions_one_active ON hunt_sessions(target_name) WHERE status='active';
CREATE INDEX IF NOT EXISTS idx_hunt_sessions_target_status ON hunt_sessions(target_name,status,updated_at DESC);

CREATE TABLE IF NOT EXISTS experiments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_session_id INTEGER NOT NULL REFERENCES hunt_sessions(id), attack_thread_id INTEGER NOT NULL REFERENCES attack_threads(id),
    work_item_id INTEGER UNIQUE REFERENCES work_items(id), experiment_key TEXT NOT NULL,
    question TEXT NOT NULL, method_class TEXT NOT NULL CHECK(method_class IN ('offline','passive','active_low','operator_gated')),
    expected_observation TEXT NOT NULL, control_description TEXT NOT NULL,
    budget_json TEXT NOT NULL DEFAULT '{}', stop_conditions_json TEXT NOT NULL DEFAULT '[]', risk_class TEXT NOT NULL DEFAULT 'safe_passive',
    status TEXT NOT NULL DEFAULT 'proposed' CHECK(status IN ('proposed','approved','queued','running','observed','blocked','cancelled')),
    outcome TEXT NOT NULL DEFAULT 'not_run' CHECK(outcome IN ('supports','refutes','inconclusive','blocked','not_run')),
    observation_summary TEXT DEFAULT '', alternative_explanation TEXT DEFAULT '', evidence_refs_json TEXT NOT NULL DEFAULT '[]',
    confidence_before TEXT DEFAULT 'unknown', confidence_after TEXT DEFAULT 'unknown', unknown_items_before_json TEXT NOT NULL DEFAULT '[]', unknown_items_after_json TEXT NOT NULL DEFAULT '[]',
    surprise_score INTEGER NOT NULL DEFAULT 0 CHECK(surprise_score BETWEEN 0 AND 3),
    created_at TEXT DEFAULT (datetime('now','localtime')), updated_at TEXT DEFAULT (datetime('now','localtime')), finished_at TEXT,
    UNIQUE(hunt_session_id,experiment_key)
);
CREATE INDEX IF NOT EXISTS idx_experiments_thread_status ON experiments(attack_thread_id,status,outcome);

CREATE TABLE IF NOT EXISTS decision_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, target_name TEXT NOT NULL, hunt_session_id INTEGER REFERENCES hunt_sessions(id), attack_thread_id INTEGER REFERENCES attack_threads(id), experiment_id INTEGER REFERENCES experiments(id), actor TEXT NOT NULL,
    decision_type TEXT NOT NULL CHECK(decision_type IN ('focus','dispatch','continue','park','pivot','escalate','stop')), compact_snapshot_json TEXT NOT NULL DEFAULT '{}', candidate_actions_json TEXT NOT NULL DEFAULT '[]', chosen_action TEXT NOT NULL, rationale TEXT NOT NULL, expected_change TEXT NOT NULL DEFAULT '', actual_change TEXT NOT NULL DEFAULT '', created_at TEXT DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_decision_events_target_time ON decision_events(target_name,created_at DESC);

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

CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TEXT DEFAULT (datetime('now', 'localtime')),
    description TEXT
);
INSERT OR IGNORE INTO schema_version(version, description)
VALUES(34, '034_chain_fix_fresh_baseline');
INSERT OR IGNORE INTO schema_version(version, description)
VALUES(35, '035_business_state_machine');
INSERT OR IGNORE INTO schema_version(version, description)
VALUES(36, '036_inspiration_base');

CREATE TABLE IF NOT EXISTS inspirations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_name TEXT NOT NULL,
    stage TEXT NOT NULL DEFAULT 'gleam'
        CHECK(stage IN ('gleam','clue')),
    content TEXT NOT NULL,
    trigger TEXT,
    source TEXT NOT NULL DEFAULT 'human'
        CHECK(source IN ('agent','human','harvest')),
    agent_id TEXT,
    session_id TEXT,
    confidence TEXT NOT NULL DEFAULT 'low'
        CHECK(confidence IN ('low','medium','high')),
    status TEXT NOT NULL DEFAULT 'open'
        CHECK(status IN ('open','queued','verified','refuted','harvested','discarded')),
    refined_from_id INTEGER REFERENCES inspirations(id),
    blocked_on_kind TEXT,
    blocked_on_id INTEGER,
    promoted_sp_id INTEGER,
    promoted_wi_id INTEGER,
    harvest_id TEXT,
    harvest_note TEXT,
    notes TEXT,
    asset_id INTEGER REFERENCES target_assets(id),
    created_at TEXT DEFAULT (datetime('now','localtime')),
    updated_at TEXT DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_inspirations_target_stage ON inspirations(target_name, stage, status);
CREATE INDEX IF NOT EXISTS idx_inspirations_refined ON inspirations(refined_from_id);
CREATE INDEX IF NOT EXISTS idx_inspirations_blocked_on ON inspirations(blocked_on_kind, blocked_on_id);
CREATE INDEX IF NOT EXISTS idx_inspirations_asset ON inspirations(asset_id);

-- 037 experience entries: 经验库表(harvest 灵感沉淀的结构化知识,可跨 session/目标复用)
CREATE TABLE IF NOT EXISTS experience_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_name TEXT,                       -- 可空:经验可能跨目标通用
    category TEXT NOT NULL,                 -- 经验所属攻击面类型,如 sql_injection / ssrf / logic_flaw
    title TEXT NOT NULL,
    body TEXT NOT NULL,                     -- 经验正文(触发场景 + 破解思路 + 验证)
    trigger_signal TEXT,                    -- 什么信号触发这个经验(如 "TableName 参数")
    source_inspiration_id INTEGER,          -- 来源灵感 harvest 时引用
    effectiveness TEXT NOT NULL DEFAULT 'untested'
        CHECK(effectiveness IN ('untested','validated','mixed','invalid')),
    reuse_count INTEGER NOT NULL DEFAULT 0,
    notes TEXT,
    created_at TEXT DEFAULT (datetime('now','localtime')),
    updated_at TEXT DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_experience_category ON experience_entries(category);
CREATE INDEX IF NOT EXISTS idx_experience_signal ON experience_entries(trigger_signal);
INSERT OR IGNORE INTO schema_version(version, description)
VALUES(37, '037_experience_entries');
INSERT OR IGNORE INTO schema_version(version, description)
VALUES(38, '038_inspiration_asset');

CREATE TABLE IF NOT EXISTS recon_sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT, target_name TEXT NOT NULL, source_kind TEXT NOT NULL,
    query TEXT, result_json TEXT NOT NULL DEFAULT '{}', status TEXT NOT NULL DEFAULT 'observed',
    error TEXT, observed_at TEXT DEFAULT (datetime('now','localtime')),
    UNIQUE(target_name, source_kind, query, result_json)
);
CREATE TABLE IF NOT EXISTS origin_candidates (
    id INTEGER PRIMARY KEY AUTOINCREMENT, target_name TEXT NOT NULL, asset_id INTEGER,
    hostname TEXT NOT NULL, candidate_ip TEXT NOT NULL, source TEXT NOT NULL,
    confidence TEXT NOT NULL DEFAULT 'unknown', score INTEGER NOT NULL DEFAULT 0,
    verification_status TEXT NOT NULL DEFAULT 'unknown', evidence_refs_json TEXT NOT NULL DEFAULT '[]',
    notes TEXT, observed_at TEXT DEFAULT (datetime('now','localtime')),
    UNIQUE(target_name, asset_id, hostname, candidate_ip, source)
);
CREATE TABLE IF NOT EXISTS network_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT, target_name TEXT NOT NULL, asset_id INTEGER,
    host TEXT NOT NULL, ip TEXT, port INTEGER, protocol TEXT, service TEXT,
    tls_json TEXT NOT NULL DEFAULT '{}', http_json TEXT NOT NULL DEFAULT '{}', waf_signal TEXT,
    load_balancer_signal TEXT, status TEXT NOT NULL DEFAULT 'observed', source TEXT NOT NULL,
    evidence_refs_json TEXT NOT NULL DEFAULT '[]', observed_at TEXT DEFAULT (datetime('now','localtime')),
    UNIQUE(target_name, host, ip, port, protocol, source)
);
CREATE TABLE IF NOT EXISTS technology_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT, target_name TEXT NOT NULL, asset_id INTEGER,
    host TEXT NOT NULL, technology TEXT NOT NULL, category TEXT NOT NULL DEFAULT 'framework',
    version TEXT, confidence TEXT NOT NULL DEFAULT 'unknown', source TEXT NOT NULL,
    evidence_refs_json TEXT NOT NULL DEFAULT '[]', observed_at TEXT DEFAULT (datetime('now','localtime')),
    UNIQUE(target_name, host, technology, version, source)
);
CREATE TABLE IF NOT EXISTS entry_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT, target_name TEXT NOT NULL, asset_id INTEGER,
    url TEXT NOT NULL, entry_type TEXT NOT NULL, source TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'unknown',
    status_code INTEGER, confidence TEXT NOT NULL DEFAULT 'unknown', response_class TEXT,
    evidence_refs_json TEXT NOT NULL DEFAULT '[]', notes TEXT,
    observed_at TEXT DEFAULT (datetime('now','localtime')),
    UNIQUE(target_name, asset_id, url, entry_type, source)
);

CREATE TABLE IF NOT EXISTS page_asset_links (
    page_id INTEGER NOT NULL REFERENCES pages(id),
    asset_id INTEGER NOT NULL REFERENCES target_assets(id),
    relation TEXT NOT NULL DEFAULT 'same_host',
    confidence TEXT NOT NULL DEFAULT 'medium',
    evidence_ref TEXT,
    created_at TEXT DEFAULT (datetime('now','localtime')),
    PRIMARY KEY(page_id, asset_id)
);
CREATE INDEX IF NOT EXISTS idx_page_asset_links_asset ON page_asset_links(asset_id, confidence);

CREATE TABLE IF NOT EXISTS js_asset_links (
    js_file_id INTEGER NOT NULL REFERENCES js_files(id),
    asset_id INTEGER NOT NULL REFERENCES target_assets(id),
    relation TEXT NOT NULL DEFAULT 'same_host',
    confidence TEXT NOT NULL DEFAULT 'medium',
    evidence_ref TEXT,
    created_at TEXT DEFAULT (datetime('now','localtime')),
    PRIMARY KEY(js_file_id, asset_id)
);
CREATE INDEX IF NOT EXISTS idx_js_asset_links_asset ON js_asset_links(asset_id, confidence);

CREATE TABLE IF NOT EXISTS endpoint_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_name TEXT NOT NULL,
    asset_id INTEGER REFERENCES target_assets(id),
    page_id INTEGER REFERENCES pages(id),
    js_file_id INTEGER REFERENCES js_files(id),
    js_signal_id TEXT,
    source_table TEXT,
    source_id TEXT,
    canonical_url TEXT NOT NULL,
    host TEXT,
    path TEXT,
    method TEXT NOT NULL DEFAULT 'GET',
    source TEXT NOT NULL,
    auth_state TEXT NOT NULL DEFAULT 'unknown',
    response_class TEXT,
    status_code INTEGER,
    content_type TEXT,
    waf_state TEXT,
    business_hint TEXT,
    parameter_names_json TEXT NOT NULL DEFAULT '[]',
    evidence_refs_json TEXT NOT NULL DEFAULT '[]',
    confidence TEXT NOT NULL DEFAULT 'unknown',
    test_status TEXT NOT NULL DEFAULT 'not_tested',
    first_seen_at TEXT DEFAULT (datetime('now','localtime')),
    last_seen_at TEXT DEFAULT (datetime('now','localtime')),
    observed_count INTEGER NOT NULL DEFAULT 1,
    raw_endpoint TEXT,
    resolved_url TEXT,
    base_url TEXT,
    source_page_url TEXT,
    source_js_url TEXT,
    origin_host TEXT,
    route_kind TEXT,
    service_hint TEXT,
    resolution_status TEXT DEFAULT 'unresolved',
    scope_class TEXT DEFAULT 'unknown',
    redirect_location TEXT,
    response_fingerprint TEXT,
    UNIQUE(target_name, canonical_url, method, source, source_id)
);
CREATE INDEX IF NOT EXISTS idx_endpoint_observations_asset ON endpoint_observations(target_name, asset_id, auth_state, test_status);
CREATE INDEX IF NOT EXISTS idx_endpoint_observations_host_path ON endpoint_observations(host, path, method);

CREATE TABLE IF NOT EXISTS endpoint_evidence_links (
    endpoint_id INTEGER NOT NULL REFERENCES endpoint_observations(id),
    evidence_ref_id INTEGER NOT NULL REFERENCES evidence_refs(id),
    relation TEXT NOT NULL DEFAULT 'observed',
    created_at TEXT DEFAULT (datetime('now','localtime')),
    PRIMARY KEY(endpoint_id, evidence_ref_id)
);
CREATE INDEX IF NOT EXISTS idx_target_assets_scope ON target_assets(target_name, scope_status, live_status);
CREATE INDEX IF NOT EXISTS idx_assets_scope_class ON target_assets(target_name, scope_class, authorization_state, scope_status);
CREATE INDEX IF NOT EXISTS idx_endpoint_resolution ON endpoint_observations(target_name, resolution_status, scope_class, auth_state);

CREATE TABLE IF NOT EXISTS asset_relationships (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_name TEXT NOT NULL,
    asset_id INTEGER NOT NULL REFERENCES target_assets(id),
    related_host TEXT NOT NULL,
    relation_type TEXT NOT NULL,
    scope_class TEXT NOT NULL DEFAULT 'unknown',
    authorization_state TEXT NOT NULL DEFAULT 'unknown',
    evidence_refs_json TEXT NOT NULL DEFAULT '[]',
    notes TEXT,
    observed_at TEXT DEFAULT (datetime('now','localtime')),
    UNIQUE(target_name, asset_id, related_host, relation_type)
);

CREATE TABLE IF NOT EXISTS preauth_probe_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_name TEXT NOT NULL,
    asset_id INTEGER REFERENCES target_assets(id),
    endpoint_group TEXT,
    max_requests INTEGER NOT NULL DEFAULT 30,
    request_count INTEGER NOT NULL DEFAULT 0,
    min_interval_seconds REAL NOT NULL DEFAULT 2,
    status TEXT NOT NULL DEFAULT 'running',
    stop_reason TEXT,
    evidence_refs_json TEXT NOT NULL DEFAULT '[]',
    started_at TEXT DEFAULT (datetime('now','localtime')),
    finished_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_preauth_runs_target ON preauth_probe_runs(target_name, asset_id, status, started_at DESC);

-- Human-in-the-loop focus control (migration 033 mirror for new databases).
CREATE TABLE IF NOT EXISTS target_systems (
    id INTEGER PRIMARY KEY AUTOINCREMENT, target_name TEXT NOT NULL, system_key TEXT NOT NULL,
    display_name TEXT NOT NULL, canonical_url TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
    scope_class TEXT NOT NULL DEFAULT 'unknown' CHECK(scope_class IN ('owned','authorized_vendor','intel_only','unknown')),
    lifecycle_state TEXT NOT NULL DEFAULT 'discovered' CHECK(lifecycle_state IN ('discovered','mapping','ready','testing','human_blocked','parked','completed','excluded')),
    created_by TEXT NOT NULL DEFAULT 'operator', created_at TEXT DEFAULT (datetime('now','localtime')),
    updated_at TEXT DEFAULT (datetime('now','localtime')), UNIQUE(target_name, system_key)
);
CREATE TABLE IF NOT EXISTS system_asset_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT, target_name TEXT NOT NULL, system_id INTEGER NOT NULL REFERENCES target_systems(id),
    asset_id INTEGER NOT NULL REFERENCES target_assets(id), relationship TEXT NOT NULL,
    confidence TEXT NOT NULL DEFAULT 'unknown', evidence_refs_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT DEFAULT (datetime('now','localtime')), updated_at TEXT DEFAULT (datetime('now','localtime')),
    UNIQUE(system_id,asset_id,relationship)
);
CREATE INDEX IF NOT EXISTS idx_target_systems_target_state ON target_systems(target_name,lifecycle_state,updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_system_asset_links_system ON system_asset_links(system_id,relationship,confidence);

-- V3 chain-fix storage (migration 034 mirror for fresh databases).
CREATE TABLE IF NOT EXISTS pattern_guesses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_name TEXT NOT NULL,
    seed_evidence_json TEXT NOT NULL,
    pattern TEXT NOT NULL,
    pattern_type TEXT NOT NULL CHECK(pattern_type IN ('url_replace','route_guess','prefix','subdomain_guess','bucket_guess')),
    derived_candidates_json TEXT NOT NULL,
    verify_action TEXT,
    verify_bound INTEGER DEFAULT 100,
    gate_required INTEGER DEFAULT 0 CHECK(gate_required IN (0,1)),
    gate_status TEXT DEFAULT 'none' CHECK(gate_status IN ('none','auto_allowed','gated','approved','rejected')),
    status TEXT DEFAULT 'generated' CHECK(status IN ('generated','verified','confirmed','refuted','parked')),
    result_summary TEXT,
    attack_thread_id INTEGER,
    work_item_ids_json TEXT,
    created_at TEXT DEFAULT (datetime('now','localtime')),
    updated_at TEXT DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_pattern_guesses_target ON pattern_guesses(target_name,status);

CREATE TABLE IF NOT EXISTS system_soft_targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_name TEXT NOT NULL,
    system_id INTEGER NOT NULL REFERENCES target_systems(id),
    eligibility_status TEXT NOT NULL DEFAULT 'needs_review'
        CHECK(eligibility_status IN ('eligible','scope_blocked','authz_blocked','needs_review')),
    eligibility_reason TEXT,
    login_access TEXT NOT NULL DEFAULT 'none'
        CHECK(login_access IN ('can_register','default_creds','test_account','operator_required','none')),
    business_richness_score INTEGER NOT NULL DEFAULT 0,
    focus_value_score INTEGER NOT NULL DEFAULT 0,
    total_score INTEGER NOT NULL DEFAULT 0,
    tier TEXT NOT NULL DEFAULT 'unranked',
    rank INTEGER,
    status TEXT NOT NULL DEFAULT 'ranked'
        CHECK(status IN ('ranked','focused','parked','completed','excluded')),
    focused_at TEXT,
    timebox_minutes INTEGER NOT NULL DEFAULT 120,
    timebox_until TEXT,
    dimension_scores_json TEXT NOT NULL DEFAULT '{}',
    evidence_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT DEFAULT (datetime('now','localtime')),
    updated_at TEXT DEFAULT (datetime('now','localtime')),
    UNIQUE(target_name,system_id)
);
CREATE INDEX IF NOT EXISTS idx_system_soft_targets_rank
    ON system_soft_targets(target_name,eligibility_status,status,total_score DESC,rank);

-- ===== Business state machine (migration 035) =====
CREATE TABLE IF NOT EXISTS business_flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_name TEXT NOT NULL,
    asset_id INTEGER REFERENCES target_assets(id),
    system_id INTEGER REFERENCES target_systems(id),
    flow_key TEXT NOT NULL,
    name TEXT NOT NULL,
    category TEXT,
    entry_url TEXT,
    derivation TEXT DEFAULT 'manual',
    completeness TEXT DEFAULT 'skeleton',
    prerequisites_json TEXT NOT NULL DEFAULT '[]',
    description TEXT,
    status TEXT NOT NULL DEFAULT 'draft',
    confidence TEXT NOT NULL DEFAULT 'unknown',
    evidence_refs_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT DEFAULT (datetime('now','localtime')),
    updated_at TEXT DEFAULT (datetime('now','localtime')),
    UNIQUE(target_name, asset_id, flow_key)
);
CREATE INDEX IF NOT EXISTS idx_business_flows_target
    ON business_flows(target_name, status, updated_at DESC);

CREATE TABLE IF NOT EXISTS business_flow_steps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id INTEGER NOT NULL REFERENCES business_flows(id),
    step_order INTEGER NOT NULL,
    step_key TEXT NOT NULL,
    name TEXT NOT NULL,
    endpoint_id INTEGER REFERENCES endpoint_observations(id),
    url TEXT,
    method TEXT,
    action_hint TEXT,
    business_state TEXT,
    preconditions_json TEXT NOT NULL DEFAULT '[]',
    test_plan_json TEXT NOT NULL DEFAULT '[]',
    mapping_status TEXT NOT NULL DEFAULT 'logical',
    evidence_refs_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT DEFAULT (datetime('now','localtime')),
    updated_at TEXT DEFAULT (datetime('now','localtime')),
    UNIQUE(flow_id, step_order),
    UNIQUE(flow_id, step_key)
);
CREATE INDEX IF NOT EXISTS idx_business_flow_steps_flow
    ON business_flow_steps(flow_id, step_order);

CREATE TABLE IF NOT EXISTS business_flow_progress (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id INTEGER NOT NULL REFERENCES business_flows(id),
    step_id INTEGER NOT NULL REFERENCES business_flow_steps(id),
    current_state TEXT,
    step_status TEXT NOT NULL DEFAULT 'not_reached',
    blocked_reason TEXT,
    coverage_ledger_id INTEGER REFERENCES coverage_ledger(id),
    suspicious_point_id TEXT,
    finding_id TEXT,
    evidence_refs_json TEXT NOT NULL DEFAULT '[]',
    updated_at TEXT DEFAULT (datetime('now','localtime')),
    UNIQUE(flow_id, step_id)
);
CREATE INDEX IF NOT EXISTS idx_business_flow_progress_status
    ON business_flow_progress(step_status, updated_at DESC);

CREATE TABLE IF NOT EXISTS business_flow_templates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT NOT NULL UNIQUE,
    attack_surface_hints_json TEXT NOT NULL DEFAULT '[]',
    test_notes TEXT
);
CREATE TABLE IF NOT EXISTS cdn_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT, target_name TEXT NOT NULL, asset_id INTEGER,
    hostname TEXT NOT NULL, classification TEXT NOT NULL, provider TEXT NOT NULL DEFAULT '',
    reasons_json TEXT NOT NULL DEFAULT '[]', evidence_refs_json TEXT NOT NULL DEFAULT '[]',
    observed_at TEXT DEFAULT (datetime('now','localtime')),
    UNIQUE(target_name, asset_id, hostname, classification, provider)
);

-- Resumable reconnaissance adapter execution ledger (migration 039).
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

-- Per-asset type observations (migration 040); does not create systems or links.
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

-- Target-side egress governance ledger (migration 042); see
-- docs/modules/egress-traffic-shaping.md. Deliberately stores no query/body/cookie.
CREATE TABLE IF NOT EXISTS egress_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_name TEXT NOT NULL,
    run_id TEXT NOT NULL DEFAULT '',
    ts TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    epoch REAL NOT NULL DEFAULT 0,
    identity TEXT NOT NULL DEFAULT '',
    mode TEXT NOT NULL DEFAULT 'burp',
    host TEXT NOT NULL DEFAULT '',
    method TEXT NOT NULL DEFAULT 'GET',
    url_path TEXT NOT NULL DEFAULT '',
    status_code INTEGER NOT NULL DEFAULT 0,
    elapsed_ms INTEGER NOT NULL DEFAULT 0,
    planned_gap_ms INTEGER NOT NULL DEFAULT 0,
    decision TEXT NOT NULL DEFAULT 'sent'
        CHECK(decision IN ('sent','blocked','skipped','error')),
    stop_reason TEXT NOT NULL DEFAULT '',
    note TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_egress_log_target_ts
    ON egress_log(target_name, ts DESC);
CREATE INDEX IF NOT EXISTS idx_egress_log_host_ts
    ON egress_log(host, ts DESC);

