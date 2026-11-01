-- V3 chain-fix prerequisites: S1-S4 plus M0/M5 storage.
PRAGMA foreign_keys=OFF;
PRAGMA legacy_alter_table=ON;

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

DROP TABLE IF EXISTS operator_inbox_new_034;
CREATE TABLE operator_inbox_new_034 (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_name TEXT NOT NULL,
    related_work_item_id INTEGER REFERENCES work_items(id),
    kind TEXT NOT NULL CHECK(kind IN (
        'choose_asset','login_required','secondary_account_required','role_account_required',
        'screenshot_needed','confirm_scope','confirm_high_risk','manual_review','report_decision',
        'evidence_capture','focus_switch','registration_required','burp_action_required',
        'scope_cluster_confirm','blocked_decision'
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
    blocking INTEGER NOT NULL DEFAULT 1 CHECK(blocking IN (0,1)),
    status TEXT DEFAULT 'open' CHECK(status IN ('open','accepted','skipped','done','cancelled')),
    created_at TEXT DEFAULT (datetime('now','localtime')),
    resolved_at TEXT,
    expires_at TEXT
);
INSERT INTO operator_inbox_new_034(
    id,target_name,related_work_item_id,kind,title,detail,suggested_action,url,
    burp_action_id,evidence_ref_id,system_id,action_key,action_label,why_needed,
    steps_json,expected_observation,report_back_format,blocking,status,created_at,resolved_at,expires_at
)
SELECT
    id,target_name,related_work_item_id,kind,title,detail,suggested_action,url,
    burp_action_id,evidence_ref_id,system_id,action_key,action_label,why_needed,
    steps_json,expected_observation,report_back_format,blocking,status,created_at,resolved_at,expires_at
FROM operator_inbox;
DROP TABLE operator_inbox;
ALTER TABLE operator_inbox_new_034 RENAME TO operator_inbox;
CREATE INDEX IF NOT EXISTS idx_operator_inbox_open ON operator_inbox(target_name,status,created_at);
CREATE INDEX IF NOT EXISTS idx_operator_inbox_system_open
    ON operator_inbox(target_name,system_id,status,blocking,created_at);

DROP TABLE IF EXISTS suspicious_points_new_034;
CREATE TABLE suspicious_points_new_034 (
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
    created_at TEXT DEFAULT (datetime('now','localtime')),
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
INSERT INTO suspicious_points_new_034(
    id,page_url,url,param,method,test_type,evidence,source,reasoning,risk,test_status,
    burp_request_id,created_at,notes,endpoint_fingerprint,response_summary,risk_score,
    canonical_url,auth_surface_type,signal_value,signal_reason,noise_reason
)
SELECT
    id,page_url,url,param,method,test_type,evidence,source,reasoning,risk,test_status,
    burp_request_id,created_at,notes,endpoint_fingerprint,response_summary,risk_score,
    canonical_url,auth_surface_type,signal_value,signal_reason,noise_reason
FROM suspicious_points;
DROP TABLE suspicious_points;
ALTER TABLE suspicious_points_new_034 RENAME TO suspicious_points;
CREATE UNIQUE INDEX IF NOT EXISTS idx_suspicious_points_auth_fingerprint
    ON suspicious_points(source,endpoint_fingerprint,test_type)
    WHERE endpoint_fingerprint IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_sp_auth_surface
    ON suspicious_points(test_status,auth_surface_type,risk_score);

ALTER TABLE work_items ADD COLUMN blocker_class TEXT
    CHECK(blocker_class IS NULL OR blocker_class IN (
        'auth_barrier','network','scope','evidence','critical_found','refuted','parked','other'
    ));

PRAGMA legacy_alter_table=OFF;
PRAGMA foreign_keys=ON;
