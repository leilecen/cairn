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

ALTER TABLE evidence_refs RENAME TO evidence_refs_027_old;
CREATE TABLE evidence_refs (
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
INSERT INTO evidence_refs (
    id, target_name, source_table, source_id, evidence_type, title, summary, ref_json, created_at
)
SELECT id, target_name, source_table, source_id, evidence_type, title, summary, ref_json, created_at
FROM evidence_refs_027_old;
DROP TABLE evidence_refs_027_old;
