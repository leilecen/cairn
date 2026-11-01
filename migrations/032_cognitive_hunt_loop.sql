-- Cognitive hunt loop: focused sessions, falsifiable hypotheses and bounded experiments.
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
    started_at TEXT,
    ended_at TEXT,
    summary TEXT,
    created_at TEXT DEFAULT (datetime('now','localtime')),
    updated_at TEXT DEFAULT (datetime('now','localtime'))
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_hunt_sessions_one_active
    ON hunt_sessions(target_name) WHERE status='active';
CREATE INDEX IF NOT EXISTS idx_hunt_sessions_target_status ON hunt_sessions(target_name,status,updated_at DESC);

ALTER TABLE attack_threads ADD COLUMN hunt_session_id INTEGER REFERENCES hunt_sessions(id);
ALTER TABLE attack_threads ADD COLUMN hypothesis_kind TEXT DEFAULT 'falsifiable';
ALTER TABLE attack_threads ADD COLUMN expected_observation TEXT DEFAULT '';
ALTER TABLE attack_threads ADD COLUMN refuting_observation TEXT DEFAULT '';
ALTER TABLE attack_threads ADD COLUMN alternative_explanations_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE attack_threads ADD COLUMN information_gain INTEGER NOT NULL DEFAULT 0 CHECK(information_gain BETWEEN 0 AND 3);
ALTER TABLE attack_threads ADD COLUMN stop_conditions_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE attack_threads ADD COLUMN pivot_options_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE attack_threads ADD COLUMN evaluation_status TEXT NOT NULL DEFAULT 'untested' CHECK(evaluation_status IN ('untested','supported','refuted','inconclusive','blocked'));
ALTER TABLE attack_threads ADD COLUMN last_evaluated_at TEXT;
CREATE INDEX IF NOT EXISTS idx_attack_threads_hunt_session ON attack_threads(hunt_session_id,evaluation_status,status);

CREATE TABLE IF NOT EXISTS experiments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_session_id INTEGER NOT NULL REFERENCES hunt_sessions(id),
    attack_thread_id INTEGER NOT NULL REFERENCES attack_threads(id),
    work_item_id INTEGER UNIQUE REFERENCES work_items(id),
    experiment_key TEXT NOT NULL,
    question TEXT NOT NULL,
    method_class TEXT NOT NULL CHECK(method_class IN ('offline','passive','active_low','operator_gated')),
    expected_observation TEXT NOT NULL,
    control_description TEXT NOT NULL,
    budget_json TEXT NOT NULL DEFAULT '{}',
    stop_conditions_json TEXT NOT NULL DEFAULT '[]',
    risk_class TEXT NOT NULL DEFAULT 'safe_passive',
    status TEXT NOT NULL DEFAULT 'proposed' CHECK(status IN ('proposed','approved','queued','running','observed','blocked','cancelled')),
    outcome TEXT NOT NULL DEFAULT 'not_run' CHECK(outcome IN ('supports','refutes','inconclusive','blocked','not_run')),
    observation_summary TEXT DEFAULT '',
    alternative_explanation TEXT DEFAULT '',
    evidence_refs_json TEXT NOT NULL DEFAULT '[]',
    confidence_before TEXT DEFAULT 'unknown',
    confidence_after TEXT DEFAULT 'unknown',
    unknown_items_before_json TEXT NOT NULL DEFAULT '[]',
    unknown_items_after_json TEXT NOT NULL DEFAULT '[]',
    surprise_score INTEGER NOT NULL DEFAULT 0 CHECK(surprise_score BETWEEN 0 AND 3),
    created_at TEXT DEFAULT (datetime('now','localtime')),
    updated_at TEXT DEFAULT (datetime('now','localtime')),
    finished_at TEXT,
    UNIQUE(hunt_session_id, experiment_key)
);
CREATE INDEX IF NOT EXISTS idx_experiments_thread_status ON experiments(attack_thread_id,status,outcome);

CREATE TABLE IF NOT EXISTS decision_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_name TEXT NOT NULL,
    hunt_session_id INTEGER REFERENCES hunt_sessions(id),
    attack_thread_id INTEGER REFERENCES attack_threads(id),
    experiment_id INTEGER REFERENCES experiments(id),
    actor TEXT NOT NULL,
    decision_type TEXT NOT NULL CHECK(decision_type IN ('focus','dispatch','continue','park','pivot','escalate','stop')),
    compact_snapshot_json TEXT NOT NULL DEFAULT '{}',
    candidate_actions_json TEXT NOT NULL DEFAULT '[]',
    chosen_action TEXT NOT NULL,
    rationale TEXT NOT NULL,
    expected_change TEXT NOT NULL DEFAULT '',
    actual_change TEXT NOT NULL DEFAULT '',
    created_at TEXT DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_decision_events_target_time ON decision_events(target_name,created_at DESC);
