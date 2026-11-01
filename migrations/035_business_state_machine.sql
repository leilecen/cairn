-- 035: business state machine (逻辑漏洞按图索骥)。
-- 4 张表：business_flows(链) / business_flow_steps(节点+前置) /
--         business_flow_progress(有序进度+中间态回写) / business_flow_templates(启发式提醒)。
-- 详见 local/archive/specs/2026-08-16-business-state-machine-design.md

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
