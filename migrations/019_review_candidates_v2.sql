DROP VIEW IF EXISTS review_candidates;

CREATE VIEW review_candidates AS
SELECT
    'hunt_queue' AS source_table,
    CAST(id AS TEXT) AS source_id,
    COALESCE(source, 'auto') AS source,
    COALESCE(canonical_url, url) AS url,
    COALESCE(method, 'GET') AS method,
    COALESCE(endpoint_fingerprint, canonical_url, url) AS fingerprint,
    COALESCE(NULLIF(signal_reason, ''), NULLIF(business_intent, ''), NULLIF(endpoint_type, ''), NULLIF(risk_hint, ''), 'hunt_queue_candidate') AS reason,
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
WHERE status = 'queued' AND COALESCE(noise_reason, '') = ''
UNION ALL
SELECT
    'suspicious_points' AS source_table,
    id AS source_id,
    COALESCE(source, 'suspicious_point') AS source,
    COALESCE(canonical_url, url) AS url,
    COALESCE(method, 'GET') AS method,
    COALESCE(endpoint_fingerprint, canonical_url, url) AS fingerprint,
    COALESCE(NULLIF(signal_reason, ''), NULLIF(reasoning, ''), NULLIF(test_type, ''), 'suspicious_point_candidate') AS reason,
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
    burp_request_id AS burp_history_id
FROM suspicious_points
WHERE test_status = 'untested' AND COALESCE(noise_reason, '') = ''
UNION ALL
SELECT
    'pages' AS source_table,
    CAST(p.id AS TEXT) AS source_id,
    COALESCE(p.source, 'crawl') AS source,
    COALESCE(p.canonical_url, p.url) AS url,
    'GET' AS method,
    COALESCE(p.endpoint_fingerprint, p.canonical_url, p.url) AS fingerprint,
    COALESCE(NULLIF(p.signal_reason, ''), NULLIF(p.signal_value, ''), NULLIF(p.title, ''), 'page_signal') AS reason,
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
            (p.endpoint_fingerprint IS NOT NULL AND p.endpoint_fingerprint != '' AND h.endpoint_fingerprint = p.endpoint_fingerprint)
            OR COALESCE(h.canonical_url, h.url) = COALESCE(p.canonical_url, p.url)
        )
  )
  AND NOT EXISTS (
      SELECT 1
      FROM suspicious_points sp
      WHERE COALESCE(sp.noise_reason, '') = ''
        AND (
            (p.endpoint_fingerprint IS NOT NULL AND p.endpoint_fingerprint != '' AND sp.endpoint_fingerprint = p.endpoint_fingerprint)
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
  );
