-- 042_egress_log: 目标侧出口治理台账（docs/modules/egress-traffic-shaping.md）
--
-- 用途：记录每一次经 Egress 发出的目标侧请求的形态要素（身份、模式、host、path、
-- 计划间隔、实际耗时、熔断结论），用于（1）证明符合委托 intensity、（2）复盘
-- 目标侧观测形态。刻意不记录 query/body/cookie，避免把 payload 与凭证写进库。
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
