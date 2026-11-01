-- Human-in-the-loop system focus, readiness and action cards.
PRAGMA foreign_keys=OFF;

CREATE TABLE IF NOT EXISTS target_systems (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_name TEXT NOT NULL,
    system_key TEXT NOT NULL,
    display_name TEXT NOT NULL,
    canonical_url TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    scope_class TEXT NOT NULL DEFAULT 'unknown' CHECK(scope_class IN ('owned','authorized_vendor','intel_only','unknown')),
    lifecycle_state TEXT NOT NULL DEFAULT 'discovered' CHECK(lifecycle_state IN ('discovered','mapping','ready','testing','human_blocked','parked','completed','excluded')),
    created_by TEXT NOT NULL DEFAULT 'operator',
    created_at TEXT DEFAULT (datetime('now','localtime')),
    updated_at TEXT DEFAULT (datetime('now','localtime')),
    UNIQUE(target_name, system_key)
);
CREATE INDEX IF NOT EXISTS idx_target_systems_target_state ON target_systems(target_name,lifecycle_state,updated_at DESC);

CREATE TABLE IF NOT EXISTS system_asset_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_name TEXT NOT NULL,
    system_id INTEGER NOT NULL REFERENCES target_systems(id),
    asset_id INTEGER NOT NULL REFERENCES target_assets(id),
    relationship TEXT NOT NULL CHECK(relationship IN ('primary','api','auth','admin','static','callback','dependency','related')),
    confidence TEXT NOT NULL DEFAULT 'unknown' CHECK(confidence IN ('low','medium','high','unknown')),
    evidence_refs_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT DEFAULT (datetime('now','localtime')),
    updated_at TEXT DEFAULT (datetime('now','localtime')),
    UNIQUE(system_id,asset_id,relationship)
);
CREATE INDEX IF NOT EXISTS idx_system_asset_links_system ON system_asset_links(system_id,relationship,confidence);

ALTER TABLE hunt_sessions ADD COLUMN system_id INTEGER REFERENCES target_systems(id);
ALTER TABLE hunt_sessions ADD COLUMN recon_readiness_snapshot_json TEXT NOT NULL DEFAULT '{}';
ALTER TABLE hunt_sessions ADD COLUMN operator_acknowledged_at TEXT;
ALTER TABLE work_items ADD COLUMN system_id INTEGER REFERENCES target_systems(id);
ALTER TABLE work_items ADD COLUMN park_reason TEXT;

ALTER TABLE operator_inbox RENAME TO operator_inbox_legacy_033;
CREATE TABLE operator_inbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_name TEXT NOT NULL,
    related_work_item_id INTEGER REFERENCES work_items(id),
    kind TEXT NOT NULL CHECK(kind IN ('choose_asset','login_required','secondary_account_required','role_account_required','screenshot_needed','confirm_scope','confirm_high_risk','manual_review','report_decision','focus_switch','registration_required','burp_action_required','evidence_capture')),
    title TEXT NOT NULL,
    detail TEXT,
    suggested_action TEXT,
    url TEXT,
    burp_action_id INTEGER,
    evidence_ref_id INTEGER,
    status TEXT DEFAULT 'open' CHECK(status IN ('open','accepted','skipped','done','cancelled')),
    created_at TEXT DEFAULT (datetime('now','localtime')),
    resolved_at TEXT,
    system_id INTEGER REFERENCES target_systems(id),
    action_key TEXT,
    action_label TEXT,
    why_needed TEXT,
    steps_json TEXT NOT NULL DEFAULT '[]',
    expected_observation TEXT,
    report_back_format TEXT,
    blocking INTEGER NOT NULL DEFAULT 1 CHECK(blocking IN (0,1)),
    expires_at TEXT
);
INSERT INTO operator_inbox(id,target_name,related_work_item_id,kind,title,detail,suggested_action,url,burp_action_id,evidence_ref_id,status,created_at,resolved_at)
SELECT id,target_name,related_work_item_id,kind,title,detail,suggested_action,url,burp_action_id,evidence_ref_id,status,created_at,resolved_at FROM operator_inbox_legacy_033;
DROP TABLE operator_inbox_legacy_033;
CREATE INDEX IF NOT EXISTS idx_operator_inbox_open ON operator_inbox(target_name,status,created_at);
CREATE INDEX IF NOT EXISTS idx_operator_inbox_system_open ON operator_inbox(target_name,system_id,status,blocking,created_at);

PRAGMA foreign_keys=ON;
