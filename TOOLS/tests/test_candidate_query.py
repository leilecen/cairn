import sqlite3
import sys
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))

from db.candidate_query import query_candidates
from db.session_dash import dash_target


def _build_db(db_path: Path) -> None:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        CREATE TABLE scan_state (
            id INTEGER PRIMARY KEY,
            phase TEXT DEFAULT 'probe',
            started_at TEXT DEFAULT '2026-06-19 10:00:00',
            call_count INTEGER DEFAULT 3
        );
        INSERT INTO scan_state (id, phase, started_at, call_count)
        VALUES (1, 'probe', '2026-06-19 10:00:00', 3);

        CREATE TABLE pages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT UNIQUE,
            status TEXT DEFAULT 'queued',
            title TEXT,
            crawled_at TEXT,
            source TEXT,
            canonical_url TEXT,
            endpoint_fingerprint TEXT,
            signal_value TEXT,
            signal_reason TEXT
        );
        INSERT INTO pages (
            url, status, title, crawled_at, source, canonical_url, endpoint_fingerprint, signal_value, signal_reason
        ) VALUES
          (
            'https://example.edu/profile',
            'queued', '个人中心', '2026-06-19 10:07:00', 'crawl',
            'https://example.edu/profile', 'fp-page-1', 'high_value', 'auth_surface'
          ),
          (
            'https://example.edu/api/user?id=1',
            'queued', '重复页面', '2026-06-19 10:08:00', 'crawl',
            'https://example.edu/api/user?id=1', 'fp-1', 'high_value', 'identity_or_object_signal'
          ),
          (
            'https://example.edu/assets/config',
            'queued', '配置页', '2026-06-19 10:09:00', 'crawl',
            'https://example.edu/assets/config', 'fp-page-2', 'medium_value', 'public_or_configuration_signal'
          );
        CREATE TABLE js_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT UNIQUE,
            page_url TEXT,
            analyzed INTEGER DEFAULT 0,
            discovered_apis_json TEXT,
            hardcoded_secrets_json TEXT,
            internal_routes_json TEXT,
            debug_switches_json TEXT,
            analyzed_at TEXT,
            content_hash TEXT,
            local_path TEXT,
            size_bytes INTEGER,
            source_kind TEXT DEFAULT 'web_script',
            source_map_url TEXT,
            source_map_status TEXT,
            extraction_status TEXT DEFAULT 'pending',
            extraction_version TEXT,
            signal_count INTEGER DEFAULT 0
        );
        INSERT INTO js_files (
            url, page_url, analyzed, discovered_apis_json, hardcoded_secrets_json,
            internal_routes_json, debug_switches_json, analyzed_at
        ) VALUES
          (
            'https://example.edu/static/app.js',
            'https://example.edu/profile', 1, '["/api/admin/users"]', '[]',
            '["/internal/ops"]', '[]', '2026-06-19 10:10:00'
          ),
          (
            'https://example.edu/static/empty.js',
            'https://example.edu/', 1, '[]', '[]',
            '[]', '[]', '2026-06-19 10:11:00'
          );
        CREATE TABLE findings (
            id TEXT PRIMARY KEY,
            risk TEXT
        );
        CREATE TABLE etl_cache (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task TEXT NOT NULL,
            instruction_hash TEXT NOT NULL,
            data_hash TEXT NOT NULL,
            result TEXT NOT NULL,
            model TEXT NOT NULL,
            hit_count INTEGER DEFAULT 0
        );
        INSERT INTO etl_cache (task, instruction_hash, data_hash, result, model, hit_count)
        VALUES ('filter_burp', 'a', 'b', '{}', 'deepseek-chat', 4);

        CREATE TABLE hunt_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            method TEXT NOT NULL,
            url TEXT NOT NULL,
            canonical_url TEXT,
            endpoint_fingerprint TEXT,
            endpoint_type TEXT,
            business_intent TEXT,
            risk_hint TEXT,
            risk_score INTEGER DEFAULT 0,
            status TEXT DEFAULT 'queued',
            source TEXT DEFAULT 'auto',
            signal_value TEXT,
            signal_reason TEXT,
            noise_reason TEXT,
            burp_history_id INTEGER,
            created_at TEXT DEFAULT (datetime('now','localtime'))
        );
        INSERT INTO hunt_queue (
            method, url, canonical_url, endpoint_fingerprint, endpoint_type,
            business_intent, risk_hint, risk_score, status, source, signal_value,
            signal_reason, noise_reason, burp_history_id, created_at
        ) VALUES
          (
            'GET', 'https://example.edu/api/user?id=1',
            'https://example.edu/api/user?id=1', 'fp-1',
            'business_api', '用户详情', 'High', 70, 'queued', 'auto',
            'high_value', 'identity_or_object_signal', '', 101, '2026-06-19 10:00:00'
          ),
          (
            'GET', 'https://example.edu/api/theme/list',
            'https://example.edu/api/theme/list', 'fp-2',
            'public_api', '主题配置', 'Low', 0, 'queued', 'auto', 'low_value',
            'public_or_configuration_signal', 'public_or_configuration_signal', NULL,
            '2026-06-19 10:01:00'
          );

        CREATE TABLE suspicious_points (
            id TEXT PRIMARY KEY,
            source TEXT,
            method TEXT DEFAULT 'GET',
            url TEXT,
            canonical_url TEXT,
            endpoint_fingerprint TEXT,
            test_type TEXT,
            reasoning TEXT,
            risk TEXT DEFAULT 'Medium',
            risk_score INTEGER DEFAULT 0,
            test_status TEXT DEFAULT 'untested',
            signal_value TEXT,
            signal_reason TEXT,
            noise_reason TEXT,
            created_at TEXT DEFAULT (datetime('now','localtime'))
        );
        INSERT INTO suspicious_points (
            id, method, url, canonical_url, endpoint_fingerprint, test_type,
            source, reasoning, risk, risk_score, test_status, signal_value, signal_reason,
            noise_reason, created_at
        ) VALUES
          (
            'SP-1', 'POST', 'https://example.edu/api/order/save',
            'https://example.edu/api/order/save', 'fp-3', 'parameter_fuzz',
            'auth_explore', '订单保存', 'High', 65, 'untested', 'medium_value',
            'state_changing_method', '', '2026-06-19 10:05:00'
          ),
          (
            'SP-2', 'GET', 'https://example.edu/api/theme/info',
            'https://example.edu/api/theme/info', 'fp-4', 'parameter_fuzz',
            'crawl', '低价值', 'Low', 0, 'untested', 'low_value',
            'public_or_configuration_signal', 'public_or_configuration_signal',
            '2026-06-19 10:06:00'
          );

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
            created_at TEXT DEFAULT (datetime('now','localtime')),
            updated_at TEXT DEFAULT (datetime('now','localtime')),
            UNIQUE(target_id, fingerprint)
        );
        INSERT INTO js_signal_clusters (
            id, target_id, fingerprint, canonical_method, canonical_url, signal_types_json, source_count,
            best_confidence, best_risk_score, representative_signal_id, status, created_at
        ) VALUES (
            'JS-CLU-1', 1, 'fp-js-1', 'POST',
            'https://example.edu/api/admin/users',
            '["api_endpoint","signature_function"]',
            2, 90, 88, 'JS-SIG-1', 'clustered', '2026-06-19 10:04:00'
        );

        CREATE VIEW review_candidates AS
        SELECT
            'hunt_queue' AS source_table,
            CAST(id AS TEXT) AS source_id,
            COALESCE(source, 'auto') AS source,
            COALESCE(canonical_url, url) AS url,
            COALESCE(method, 'GET') AS method,
            COALESCE(endpoint_fingerprint, canonical_url, url) AS fingerprint,
            COALESCE(
                NULLIF(signal_reason, ''),
                NULLIF(business_intent, ''),
                NULLIF(endpoint_type, ''),
                NULLIF(risk_hint, ''),
                'hunt_queue_candidate'
            ) AS reason,
            CASE
                WHEN COALESCE(risk_score, 0) > 0 THEN risk_score
                WHEN risk_hint = 'Critical' THEN 90
                WHEN risk_hint = 'High' THEN 75
                WHEN risk_hint = 'Medium' THEN 55
                WHEN risk_hint = 'Low' THEN 25
                ELSE 40
            END AS risk_score,
            'review_hunt_queue' AS next_action,
            status,
            created_at,
            burp_history_id
        FROM hunt_queue
        WHERE status='queued' AND COALESCE(noise_reason, '') = ''
        UNION ALL
        SELECT
            'suspicious_points' AS source_table,
            id AS source_id,
            COALESCE(source, 'suspicious_point') AS source,
            COALESCE(canonical_url, url) AS url,
            COALESCE(method, 'GET') AS method,
            COALESCE(endpoint_fingerprint, canonical_url, url) AS fingerprint,
            COALESCE(
                NULLIF(signal_reason, ''),
                NULLIF(reasoning, ''),
                NULLIF(test_type, ''),
                'suspicious_point_candidate'
            ) AS reason,
            CASE
                WHEN COALESCE(risk_score, 0) > 0 THEN risk_score
                WHEN risk = 'Critical' THEN 90
                WHEN risk = 'High' THEN 75
                WHEN risk = 'Medium' THEN 55
                WHEN risk = 'Low' THEN 25
                ELSE 45
            END AS risk_score,
            'review_suspicious_point' AS next_action,
            test_status AS status,
            created_at,
            NULL AS burp_history_id
        FROM suspicious_points
        WHERE test_status='untested' AND COALESCE(noise_reason, '') = ''
        UNION ALL
        SELECT
            'pages' AS source_table,
            CAST(p.id AS TEXT) AS source_id,
            COALESCE(p.source, 'crawl') AS source,
            COALESCE(p.canonical_url, p.url) AS url,
            'GET' AS method,
            COALESCE(p.endpoint_fingerprint, p.canonical_url, p.url) AS fingerprint,
            COALESCE(
                NULLIF(p.signal_reason, ''),
                NULLIF(p.signal_value, ''),
                NULLIF(p.title, ''),
                'page_signal'
            ) AS reason,
            CASE
                WHEN p.signal_value = 'high_value' THEN 52
                WHEN p.signal_value = 'medium_value' THEN 40
                WHEN COALESCE(p.signal_reason, '') != '' THEN 35
                ELSE 0
            END AS risk_score,
            'crawl_or_probe_page' AS next_action,
            p.status AS status,
            p.crawled_at AS created_at,
            NULL AS burp_history_id
        FROM pages p
        WHERE COALESCE(p.signal_value, '') IN ('high_value', 'medium_value')
          AND COALESCE(p.signal_reason, '') != 'public_or_configuration_signal'
          AND NOT EXISTS (
              SELECT 1
              FROM hunt_queue h
              WHERE COALESCE(h.noise_reason, '') = ''
                AND (
                    (
                        p.endpoint_fingerprint IS NOT NULL
                        AND p.endpoint_fingerprint != ''
                        AND h.endpoint_fingerprint = p.endpoint_fingerprint
                    )
                    OR COALESCE(h.canonical_url, h.url) = COALESCE(p.canonical_url, p.url)
                )
          )
          AND NOT EXISTS (
              SELECT 1
              FROM suspicious_points sp
              WHERE COALESCE(sp.noise_reason, '') = ''
                AND (
                    (
                        p.endpoint_fingerprint IS NOT NULL
                        AND p.endpoint_fingerprint != ''
                        AND sp.endpoint_fingerprint = p.endpoint_fingerprint
                    )
                    OR COALESCE(sp.canonical_url, sp.url) = COALESCE(p.canonical_url, p.url)
                )
          )
        UNION ALL
        SELECT
            'js_files' AS source_table,
            CAST(j.id AS TEXT) AS source_id,
            'js_analysis' AS source,
            j.url AS url,
            'GET' AS method,
            j.url AS fingerprint,
            CASE
                WHEN COALESCE(j.hardcoded_secrets_json, '[]') NOT IN ('', '[]', '{}', 'null') THEN 'hardcoded_secrets'
                WHEN COALESCE(j.debug_switches_json, '[]') NOT IN ('', '[]', '{}', 'null') THEN 'debug_switches'
                WHEN COALESCE(j.internal_routes_json, '[]') NOT IN ('', '[]', '{}', 'null') THEN 'internal_routes'
                ELSE 'discovered_apis'
            END AS reason,
            CASE
                WHEN COALESCE(j.hardcoded_secrets_json, '[]') NOT IN ('', '[]', '{}', 'null') THEN 58
                WHEN COALESCE(j.debug_switches_json, '[]') NOT IN ('', '[]', '{}', 'null') THEN 48
                WHEN COALESCE(j.internal_routes_json, '[]') NOT IN ('', '[]', '{}', 'null') THEN 45
                ELSE 32
            END AS risk_score,
            'analyze_js_signal' AS next_action,
            CASE WHEN COALESCE(j.analyzed, 0) = 1 THEN 'analyzed' ELSE 'queued' END AS status,
            j.analyzed_at AS created_at,
            NULL AS burp_history_id
        FROM js_files j
        WHERE COALESCE(j.analyzed, 0) = 1
          AND (
              COALESCE(j.discovered_apis_json, '[]') NOT IN ('', '[]', '{}', 'null')
              OR COALESCE(j.hardcoded_secrets_json, '[]') NOT IN ('', '[]', '{}', 'null')
              OR COALESCE(j.internal_routes_json, '[]') NOT IN ('', '[]', '{}', 'null')
              OR COALESCE(j.debug_switches_json, '[]') NOT IN ('', '[]', '{}', 'null')
          )
        UNION ALL
        SELECT
            'js_signal_clusters' AS source_table,
            c.id AS source_id,
            'js_intel' AS source,
            COALESCE(c.canonical_url, '') AS url,
            COALESCE(c.canonical_method, 'GET') AS method,
            c.fingerprint AS fingerprint,
            COALESCE(c.signal_types_json, 'js_cluster') AS reason,
            COALESCE(c.best_risk_score, 0) AS risk_score,
            CASE
                WHEN COALESCE(c.best_risk_score, 0) >= 70 THEN 'review_promoted_js_cluster'
                ELSE 'review_js_cluster'
            END AS next_action,
            COALESCE(c.status, 'new') AS status,
            c.created_at,
            NULL AS burp_history_id
        FROM js_signal_clusters c
        WHERE COALESCE(c.status, 'new') IN ('new', 'clustered', 'needs_auth', 'needs_signature', 'needs_operator')
          AND COALESCE(c.best_risk_score, 0) >= 40;
        """
    )
    conn.commit()
    conn.close()


def test_query_candidates_orders_by_risk_and_excludes_noise(tmp_path):
    db_path = tmp_path / "demo_2026-06-19.db"
    _build_db(db_path)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    rows = query_candidates(conn, limit=10, offset=0)

    conn.close()
    assert [row["source_id"] for row in rows] == ["JS-CLU-1", "1", "SP-1", "1", "1"]
    assert rows[0]["source_table"] == "js_signal_clusters"
    assert rows[0]["next_action"] == "review_promoted_js_cluster"
    assert rows[1]["source_table"] == "hunt_queue"
    assert rows[1]["burp_history_id"] == 101
    assert rows[3]["source_table"] == "pages"
    assert rows[3]["next_action"] == "crawl_or_probe_page"
    assert rows[4]["source_table"] == "js_files"
    assert rows[4]["reason"] == "internal_routes"


def test_query_candidates_supports_limit_and_offset(tmp_path):
    db_path = tmp_path / "demo_2026-06-19.db"
    _build_db(db_path)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    rows = query_candidates(conn, limit=1, offset=1)

    conn.close()
    assert len(rows) == 1
    assert rows[0]["source_id"] == "1"
    assert rows[0]["next_action"] == "review_hunt_queue"


def test_query_candidates_exposes_normalized_contract(tmp_path):
    db_path = tmp_path / "demo_2026-06-19.db"
    _build_db(db_path)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    row = query_candidates(conn, limit=1, offset=0)[0]

    conn.close()
    assert set(row) == {
        "source_table",
        "source_id",
        "source",
        "url",
        "method",
        "fingerprint",
        "reason",
        "risk_score",
        "next_action",
        "status",
        "created_at",
        "burp_history_id",
    }


def test_dash_target_reports_candidate_and_cache_metrics(tmp_path):
    db_path = tmp_path / "demo_2026-06-19.db"
    _build_db(db_path)

    dash = dash_target(db_path)

    assert dash["review_candidates"]["total"] == 5
    assert dash["review_candidates"]["high_score"] == 3
    assert dash["queue_noise_marked"] == 1
    assert dash["etl_cache"]["entries"] == 1
    assert dash["etl_cache"]["hit_count"] == 4
    assert dash["js_signals"]["clusters"] == 1
    assert dash["js_signals"]["promoted"] == 0
