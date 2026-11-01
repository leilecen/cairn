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
