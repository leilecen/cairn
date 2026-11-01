CREATE TABLE IF NOT EXISTS recon_sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_name TEXT NOT NULL,
    source_kind TEXT NOT NULL,
    query TEXT,
    result_json TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'observed',
    error TEXT,
    observed_at TEXT DEFAULT (datetime('now','localtime')),
    UNIQUE(target_name, source_kind, query, result_json)
);

CREATE TABLE IF NOT EXISTS origin_candidates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_name TEXT NOT NULL,
    asset_id INTEGER,
    hostname TEXT NOT NULL,
    candidate_ip TEXT NOT NULL,
    source TEXT NOT NULL,
    confidence TEXT NOT NULL DEFAULT 'unknown',
    score INTEGER NOT NULL DEFAULT 0,
    verification_status TEXT NOT NULL DEFAULT 'unknown',
    evidence_refs_json TEXT NOT NULL DEFAULT '[]',
    notes TEXT,
    observed_at TEXT DEFAULT (datetime('now','localtime')),
    UNIQUE(target_name, asset_id, hostname, candidate_ip, source)
);

CREATE TABLE IF NOT EXISTS network_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_name TEXT NOT NULL,
    asset_id INTEGER,
    host TEXT NOT NULL,
    ip TEXT,
    port INTEGER,
    protocol TEXT,
    service TEXT,
    tls_json TEXT NOT NULL DEFAULT '{}',
    http_json TEXT NOT NULL DEFAULT '{}',
    waf_signal TEXT,
    load_balancer_signal TEXT,
    status TEXT NOT NULL DEFAULT 'observed',
    source TEXT NOT NULL,
    evidence_refs_json TEXT NOT NULL DEFAULT '[]',
    observed_at TEXT DEFAULT (datetime('now','localtime')),
    UNIQUE(target_name, host, ip, port, protocol, source)
);

CREATE TABLE IF NOT EXISTS technology_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_name TEXT NOT NULL,
    asset_id INTEGER,
    host TEXT NOT NULL,
    technology TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT 'framework',
    version TEXT,
    confidence TEXT NOT NULL DEFAULT 'unknown',
    source TEXT NOT NULL,
    evidence_refs_json TEXT NOT NULL DEFAULT '[]',
    observed_at TEXT DEFAULT (datetime('now','localtime')),
    UNIQUE(target_name, host, technology, version, source)
);

CREATE TABLE IF NOT EXISTS entry_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_name TEXT NOT NULL,
    asset_id INTEGER,
    url TEXT NOT NULL,
    entry_type TEXT NOT NULL,
    source TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'unknown',
    status_code INTEGER,
    confidence TEXT NOT NULL DEFAULT 'unknown',
    response_class TEXT,
    evidence_refs_json TEXT NOT NULL DEFAULT '[]',
    notes TEXT,
    observed_at TEXT DEFAULT (datetime('now','localtime')),
    UNIQUE(target_name, asset_id, url, entry_type, source)
);

CREATE INDEX IF NOT EXISTS idx_recon_sources_target ON recon_sources(target_name, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_origin_candidates_target ON origin_candidates(target_name, hostname, score DESC);
CREATE INDEX IF NOT EXISTS idx_network_observations_target ON network_observations(target_name, host, port);
CREATE INDEX IF NOT EXISTS idx_entry_observations_target ON entry_observations(target_name, entry_type, confidence);
