-- 036 inspiration base: inspirations 表(灵感两层 gleam/clue + 堵点精确挂载 + 6 状态生命周期)
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
    created_at TEXT DEFAULT (datetime('now','localtime')),
    updated_at TEXT DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_inspirations_target_stage ON inspirations(target_name, stage, status);
CREATE INDEX IF NOT EXISTS idx_inspirations_refined ON inspirations(refined_from_id);
CREATE INDEX IF NOT EXISTS idx_inspirations_blocked_on ON inspirations(blocked_on_kind, blocked_on_id);
