import sqlite3
import sys
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))

from utils.js_signal_store import build_cluster_fingerprint, insert_js_signal, promote_js_candidates, upsert_js_cluster


def _conn():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        CREATE TABLE js_signals (
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
        CREATE TABLE js_signal_clusters (
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
        CREATE TABLE suspicious_points (
            id TEXT PRIMARY KEY,
            url TEXT,
            param TEXT,
            method TEXT,
            test_type TEXT,
            evidence TEXT,
            source TEXT,
            risk TEXT,
            test_status TEXT,
            created_at TEXT,
            reasoning TEXT,
            risk_score INTEGER DEFAULT 0
        );
        """
    )
    return conn


def test_insert_cluster_and_promote():
    conn = _conn()
    signal = {
        "signal_type": "api_endpoint",
        "method": "POST",
        "url": "https://example.com/api/admin/users",
        "path": "/api/admin/users",
        "params": ["userId", "tenantId", "sign"],
        "evidence_snippet": "axios.post('/api/admin/users', { userId, tenantId, sign })",
        "evidence_location": "line:12",
        "caller_hint": "axios",
        "caller_chain": ["onLoad", "getUsers"],
        "value_flow": {"url": "https://example.com/api/admin/users"},
        "risk_score": 85,
        "confidence": 90,
    }
    signal_id = insert_js_signal(conn, 1, 10, signal, "web_script")
    cluster_id = upsert_js_cluster(conn, 1, signal_id)
    promoted = promote_js_candidates(conn, min_score=70)

    cluster = conn.execute("SELECT * FROM js_signal_clusters WHERE id=?", (cluster_id,)).fetchone()
    sp = conn.execute("SELECT * FROM suspicious_points").fetchone()

    assert build_cluster_fingerprint(signal)
    assert promoted == 1
    assert cluster["status"] == "promoted"
    assert sp["source"] == "js_intel"
    assert sp["risk_score"] == 85
    assert "userId" in sp["param"]
    assert conn.execute("SELECT caller_chain_json FROM js_signals WHERE id=?", (signal_id,)).fetchone()[0]


def test_duplicate_signal_upsert_is_stable():
    conn = _conn()
    signal = {
        "signal_type": "api_endpoint",
        "method": "GET",
        "url": "https://example.com/api/user",
        "path": "/api/user",
        "params": [],
        "evidence_snippet": "fetch('/api/user')",
        "evidence_location": "line:1",
        "risk_score": 30,
    }
    first = insert_js_signal(conn, 1, 1, signal, "web_script")
    second = insert_js_signal(conn, 1, 1, signal, "web_script")
    rows = conn.execute("SELECT COUNT(*) FROM js_signals").fetchone()[0]
    assert first == second
    assert rows == 1
