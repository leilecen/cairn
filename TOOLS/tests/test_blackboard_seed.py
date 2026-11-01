import json
import sqlite3
import subprocess
import sys
from pathlib import Path

from db.blackboard_seed import apply_seed, plan_seed_work_items
from db.sprint_tick import run_sprint_tick

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = PROJECT_ROOT / "TOOLS" / "db" / "schema.sql"
SEED_SCRIPT = PROJECT_ROOT / "TOOLS" / "db" / "blackboard_seed.py"


def _conn():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    return conn


def _build_seed_fixture(conn: sqlite3.Connection, target_name: str = "demo") -> None:
    conn.execute(
        """
        INSERT INTO targets (id, target_name, domain, notes)
        VALUES (1, ?, 'example.com', 'has target row')
        """,
        (target_name,),
    )
    conn.execute(
        """
        INSERT INTO target_assets (target_name, asset_type, asset_value, status, priority, notes)
        VALUES (?, 'domain', 'app.example.com', 'new', 30, 'new asset')
        """,
        (target_name,),
    )
    conn.execute(
        """
        INSERT INTO pages (
            id, url, depth, status, title, js_files_json, api_calls_json, crawled_at, source,
            canonical_url, endpoint_fingerprint, signal_value, signal_reason
        ) VALUES
          (
            1, 'https://example.com/dashboard', 0, 'queued', 'Dashboard',
            '[]', '[]', '2026-07-14 09:00:00', 'crawl',
            'https://example.com/dashboard', 'page-1', 'high_value', 'auth_surface'
          ),
          (
            2, 'https://example.com/entry', 0, 'done', 'Entry',
            '[]', '[]', '2026-07-14 09:01:00', 'crawl',
            'https://example.com/entry', 'page-2', 'medium_value', 'entry_surface'
          ),
          (
            3, 'https://example.com/blank', 0, 'done', '',
            '["/static/app.chunk.js"]', '["/api/user"]', '2026-07-14 09:02:00', 'crawl',
            'https://example.com/blank', 'page-3', 'medium_value', 'blank_but_js_rich'
          ),
          (
            4, 'https://example.com/static', 0, 'done', '',
            '[]', '[]', '2026-07-14 09:03:00', 'crawl',
            'https://example.com/static', 'page-4', 'low_value', 'public_or_configuration_signal'
          )
        """
    )
    conn.execute(
        """
        INSERT INTO js_files (
            id, url, page_url, analyzed, discovered_apis_json, hardcoded_secrets_json,
            internal_routes_json, debug_switches_json, analyzed_at, source_kind,
            source_map_url, source_map_status, extraction_status, signal_count
        ) VALUES
          (
            1, 'https://example.com/static/app.chunk.js', 'https://example.com/blank', 1,
            '["/api/user","/api/order"]', '[]', '["/admin"]', '[]', '2026-07-14 09:04:00',
            'web_script', 'https://example.com/static/app.chunk.js.map', 'fetched', 'done', 4
          )
        """
    )
    conn.execute(
        """
        INSERT INTO js_signal_clusters (
            id, target_id, fingerprint, canonical_method, canonical_url, signal_types_json,
            source_count, best_confidence, best_risk_score, representative_signal_id, status,
            attack_surface_json, ai_summary_json, created_at
        ) VALUES
          (
            'clu-auth', 1, 'fp-auth', 'GET', 'https://example.com/api/account',
            '["auth_material"]', 1, 80, 72, 'sig-1', 'needs_auth',
            '{"auth":"required"}', '{"summary":"needs auth"}', '2026-07-14 09:05:00'
          ),
          (
            'clu-sign', 1, 'fp-sign', 'POST', 'https://example.com/api/sign',
            '["signature_function","business_api"]', 2, 90, 88, 'sig-2', 'clustered',
            '{"signature":"yes"}', '{"summary":"signature chain"}', '2026-07-14 09:06:00'
          )
        """
    )
    conn.execute(
        """
        INSERT INTO hunt_queue (
            id, target_id, method, url, canonical_url, endpoint_fingerprint, endpoint_type,
            business_intent, risk_hint, status, source, signal_value, signal_reason, created_at
        ) VALUES
          (
            1, 1, 'GET', 'https://example.com/api/user?id=1', 'https://example.com/api/user?id=1',
            'hq-1', 'business_api', 'user detail', 'High', 'queued', 'auto',
            'high_value', 'identity_or_object_signal', '2026-07-14 09:07:00'
          )
        """
    )
    conn.execute(
        """
        INSERT INTO suspicious_points (
            id, page_url, url, param, method, test_type, evidence, source, reasoning, risk,
            test_status, created_at
        ) VALUES
          (
            'SP-1', 'https://example.com/order', 'https://example.com/api/order/save', 'id',
            'POST', 'parameter_fuzz', 'diff', 'auth_explore', 'needs review', 'High',
            'untested', '2026-07-14 09:08:00'
          ),
          (
            'SP-2', 'https://example.com/profile', 'https://example.com/api/profile', 'name',
            'GET', 'parameter_fuzz', 'diff', 'auth_explore', 'compact low risk review', 'Medium',
            'untested', '2026-07-14 09:08:30'
          )
        """
    )
    conn.execute(
        """
        INSERT INTO findings (
            id, sp_id, target_id, type, url, param, method, payload, evidence, risk, cvss,
            remediation, confirmed_at, review_status, report_file, audit_status
        ) VALUES
          (
            'F-1', 'SP-1', 1, 'idor', 'https://example.com/api/order/save', 'id', 'POST',
            '', '', 'High', '8.0', 'fix authz', '2026-07-14 09:09:00', 'confirmed', '', 'pending'
          )
        """
    )
    conn.commit()


def test_plan_seed_work_items_includes_blank_page_js_reverse_and_core_sources():
    conn = _conn()
    _build_seed_fixture(conn)

    plan = plan_seed_work_items(conn, target_name="demo")

    lanes = {(item["lane"], item["subject_table"], item["subject_id"], item["subtype"]) for item in plan}
    assert ("asset_triage", "target_assets", "1", None) in lanes
    assert ("asset_triage", "targets", "1", None) in lanes
    assert ("quick_scout", "pages", "1", None) in lanes
    assert ("entry_explore", "pages", "2", None) in lanes
    assert ("js_reverse", "pages", "3", "api_extract") in lanes
    assert ("logic_probe", "hunt_queue", "1", None) in lanes
    assert ("operator_task", "suspicious_points", "SP-1", "vuln_review_gate") in lanes
    assert ("vuln_review", "suspicious_points", "SP-2", "single_sp_review") in lanes
    assert ("evidence_pack", "findings", "F-1", None) in lanes


def test_plan_seed_work_items_uses_clusters_for_js_reverse_and_hypothesis():
    conn = _conn()
    _build_seed_fixture(conn)

    plan = plan_seed_work_items(conn, target_name="demo")
    cluster_items = {(item["lane"], item["subject_id"], item["subtype"]) for item in plan if item["subject_table"] == "js_signal_clusters"}

    assert ("js_reverse", "clu-auth", "auth_material") in cluster_items
    assert ("js_reverse", "clu-sign", "signature_chain") in cluster_items
    assert ("hypothesis", "clu-sign", "business_api") in cluster_items


def test_plan_seed_work_items_creates_semantic_profile_for_focused_target_only():
    conn = _conn()
    _build_seed_fixture(conn)
    conn.execute(
        """
        INSERT INTO soft_targets (
            id, target_name, asset_id, asset_value, total_score, tier, rank, status, focused_at
        ) VALUES
          (9, 'demo', 1, 'app.example.com', 82, 'tier1', 1, 'focused', '2026-07-14 09:10:00'),
          (10, 'demo', 2, 'api.example.com', 70, 'tier2', 2, 'ranked', NULL)
        """
    )
    conn.commit()

    plan = plan_seed_work_items(conn, target_name="demo")
    semantic_items = [item for item in plan if item["lane"] == "semantic_profile"]

    assert len(semantic_items) == 1
    assert semantic_items[0]["subject_table"] == "soft_targets"
    assert semantic_items[0]["subject_id"] == "9"
    assert semantic_items[0]["subtype"] == "focused_target_profile"
    assert "unknown, uncovered and blocked" in semantic_items[0]["objective"]

    conn.execute(
        """
        INSERT INTO attack_surface_profiles (
            target_name, soft_target_id, subject_table, subject_id, status
        ) VALUES ('demo', 9, 'soft_targets', '9', 'active')
        """
    )
    conn.commit()

    plan_after_profile = plan_seed_work_items(conn, target_name="demo")
    assert not [item for item in plan_after_profile if item["lane"] == "semantic_profile"]


def test_plan_seed_work_items_does_not_promote_static_page_to_js_reverse():
    conn = _conn()
    _build_seed_fixture(conn)

    plan = plan_seed_work_items(conn, target_name="demo")

    assert ("js_reverse", "pages", "4") not in {(item["lane"], item["subject_table"], item["subject_id"]) for item in plan}


def test_plan_seed_work_items_filters_page_and_sp_by_target_scope():
    conn = _conn()
    _build_seed_fixture(conn)
    conn.execute("INSERT INTO targets (id, target_name, domain) VALUES (2, 'other', 'other.edu')")
    conn.execute(
        """
        INSERT INTO pages (
            id, url, depth, status, title, js_files_json, api_calls_json, crawled_at, source,
            canonical_url, endpoint_fingerprint, signal_value, signal_reason
        ) VALUES (
            20, 'https://other.edu/admin', 0, 'queued', 'Admin',
            '[]', '[]', '2026-07-14 10:00:00', 'crawl',
            'https://other.edu/admin', 'page-other', 'high_value', 'foreign_target'
        )
        """
    )
    conn.execute(
        """
        INSERT INTO suspicious_points (
            id, page_url, url, param, method, test_type, evidence, source, reasoning, risk,
            test_status, created_at
        ) VALUES
          (
            'SP-OTHER', 'https://other.edu/admin', 'https://other.edu/api/admin', 'id',
            'GET', 'parameter_fuzz', 'diff', 'auth_explore', 'foreign sp', 'High',
            'untested', '2026-07-14 10:01:00'
          ),
          (
            'SP-REL', 'https://example.com/rel', '/api/relative', 'id',
            'GET', 'parameter_fuzz', 'diff', 'auth_explore', 'relative same target', 'Medium',
            'untested', '2026-07-14 10:02:00'
          )
        """
    )
    conn.commit()

    plan = plan_seed_work_items(conn, target_name="demo")
    planned = {(item["lane"], item["subject_table"], item["subject_id"]) for item in plan}

    assert ("quick_scout", "pages", "20") not in planned
    assert ("vuln_review", "suspicious_points", "SP-OTHER") not in planned
    assert ("vuln_review", "suspicious_points", "SP-REL") in planned


def test_suspicious_points_seed_gates_high_risk_and_auth_boundary_without_raw_evidence():
    conn = _conn()
    _build_seed_fixture(conn)
    conn.execute(
        """
        INSERT INTO suspicious_points (
            id, page_url, url, param, method, test_type, evidence, source, reasoning, risk,
            test_status, notes, auth_surface_type, signal_reason, risk_score, created_at
        ) VALUES
          (
            'SP-AUTH', 'https://example.com/account', 'https://example.com/api/account', 'accountId',
            'GET', 'idor', 'Cookie: sid=secret\r\nAuthorization: Bearer abcdefghijklmnopqrstuvwxyz',
            'generic_logic_probe', 'requires A/B account before review', 'Medium',
            'untested', 'operator_required secondary account', 'authenticated_api',
            '<html><script>raw js</script></html>', 50, '2026-07-14 09:10:00'
          )
        """
    )
    conn.commit()

    plan = plan_seed_work_items(conn, target_name="demo")
    gated = [item for item in plan if item["subject_id"] in {"SP-1", "SP-AUTH"}]
    auto = [item for item in plan if item["subject_id"] == "SP-2"]

    assert {(item["lane"], item["subtype"]) for item in gated} == {("operator_task", "vuln_review_gate")}
    assert auto[0]["lane"] == "vuln_review"
    assert auto[0]["risk_class"] == "safe_replay"

    gated_text = " ".join(item["objective"] for item in gated)
    assert "Cookie:" not in gated_text
    assert "Authorization:" not in gated_text
    assert "<script>" not in gated_text
    assert "operator_gate=" in gated_text


def test_suspicious_point_seed_suppresses_coverage_negative_attack_surface():
    """已验证为负结论（coverage_ledger covered）的攻击面不得当新发现重复升级。"""
    conn = _conn()
    conn.execute(
        """INSERT INTO targets (id, target_name, domain, notes)
           VALUES (1, 'demo', 'baolei.example', 'fastjson target')"""
    )
    conn.execute(
        """INSERT INTO suspicious_points (
               id, url, param, method, test_type, evidence, reasoning, signal_reason, test_status
           ) VALUES (
               'SP-FJ', 'https://baolei.example/api', 'body', 'POST', 'fastjson:rce',
               '{"a":{"@type":"com.sun.rowset.JdbcRowSetImpl"}}',
               'pre-auth plaintext body -> fastjson @type surface',
               'preauth_plaintext_body', 'untested'
           )"""
    )
    conn.execute(
        """INSERT INTO coverage_ledger(target_name, item_key, category, status, summary, evidence_refs_json)
           VALUES ('demo', 'generic_probe:fastjson_deserialization', 'generic_probe', 'covered',
                   'FastJSON @type 全局递归过滤 HTTP 400，四类 gadget 全拦，不可利用', '[]')"""
    )
    conn.commit()

    plan = plan_seed_work_items(conn, target_name="demo")
    sp_items = [item for item in plan if item.get("subject_table") == "suspicious_points"]
    assert all(item["subject_id"] != "SP-FJ" for item in sp_items), "covered 攻击面不得生成新 work_item"

    row = conn.execute("SELECT noise_reason, notes FROM suspicious_points WHERE id='SP-FJ'").fetchone()
    assert row["noise_reason"].startswith("coverage_negative:")
    assert "fastjson_deserialization" in row["noise_reason"]
    assert "不重复升级" in (row["notes"] or "")


def test_suspicious_point_seed_suppresses_only_negative_coverage_statuses():
    """uncovered/unknown 的 coverage 不抑制（uncovered 是未防护正信号）。"""
    conn = _conn()
    conn.execute("""INSERT INTO targets (id, target_name, domain, notes) VALUES (1, 'demo', 'baolei.example', 't')""")
    conn.execute(
        """INSERT INTO suspicious_points (
               id, url, param, method, test_type, reasoning, signal_reason, test_status
           ) VALUES (
               'SP-SQLI', 'https://baolei.example/api?id=1', 'id', 'GET', 'sqli:boolean',
               'id 参数布尔盲注疑似', 'identity_or_object_signal', 'untested'
           )"""
    )
    conn.execute(
        """INSERT INTO coverage_ledger(target_name, item_key, category, status, summary, evidence_refs_json)
           VALUES ('demo', 'generic_probe:sqli_boolean', 'generic_probe', 'uncovered',
                   'id 参数观察到未防护边界（uncovered 是正信号，不抑制）', '[]')"""
    )
    conn.commit()

    plan = plan_seed_work_items(conn, target_name="demo")
    sp_items = [item for item in plan if item.get("subject_table") == "suspicious_points"]
    assert any(item["subject_id"] == "SP-SQLI" for item in sp_items), "uncovered 不抑制，应照常派发"


def test_suspicious_point_seed_is_idempotent_for_active_and_terminal_work_items():
    conn = _conn()
    _build_seed_fixture(conn)

    first = apply_seed(conn, target_name="demo", dry_run=False)
    second = apply_seed(conn, target_name="demo", dry_run=False)

    sp_rows = conn.execute(
        """
        SELECT lane, subtype, subject_id, COUNT(*) AS n
        FROM work_items
        WHERE subject_table = 'suspicious_points'
        GROUP BY lane, subtype, subject_id
        """
    ).fetchall()

    assert first["created"] > 0
    assert second["created"] == 0
    assert all(row["n"] == 1 for row in sp_rows)


def test_apply_seed_creates_items_and_repeat_run_skips_existing():
    conn = _conn()
    _build_seed_fixture(conn)

    first = apply_seed(conn, target_name="demo", dry_run=False)
    second = apply_seed(conn, target_name="demo", dry_run=False)
    count = conn.execute("SELECT COUNT(*) FROM work_items WHERE target_name = 'demo'").fetchone()[0]

    assert first["created"] > 0
    assert second["created"] == 0
    assert second["skipped_existing"] == first["created"]
    assert count == first["created"]


def test_apply_seed_dry_run_does_not_write_work_items():
    conn = _conn()
    _build_seed_fixture(conn)

    result = apply_seed(conn, target_name="demo", dry_run=True)
    count = conn.execute("SELECT COUNT(*) FROM work_items").fetchone()[0]

    assert result["created"] > 0
    assert count == 0


def _minimal_recon_fixture(conn: sqlite3.Connection, target_name: str = "demo") -> None:
    """Minimal fixture: only targets + target_assets + target_systems (no pages/js_files),
    so plan_seed_work_items stays within collection lanes."""
    conn.execute("INSERT INTO targets (id, target_name, domain, notes) VALUES (1, ?, 'example.com', 'x')", (target_name,))
    conn.execute(
        """INSERT INTO target_assets (target_name, asset_type, asset_value, status, priority, notes)
           VALUES (?, 'domain', 'app.example.com', 'new', 30, 'x')""",
        (target_name,),
    )
    conn.execute(
        """INSERT INTO target_systems(target_name,system_key,display_name,canonical_url,scope_class,lifecycle_state)
           VALUES(?,'portal','Portal','https://example.com','owned','mapping')""",
        (target_name,),
    )


def test_modern_unfocused_system_seeds_no_asset_wide_ai_collection_lanes():
    """没有深测 focus 时，L3 asset-wide AI collection 不得被 seed。"""
    conn = _conn()
    _minimal_recon_fixture(conn)
    conn.commit()
    result = apply_seed(conn, target_name="demo", dry_run=False)
    assert result.get("blocked_reason") != "active_system_required"
    lanes = {row["lane"] for row in conn.execute("SELECT DISTINCT lane FROM work_items")}
    assert not lanes.intersection({"source_intel", "network_profile", "entry_probe", "origin_verify"})


def test_recon_collection_does_not_cover_multiple_assets_without_focus():
    """多个资产无 focus 时，不得生成 asset-wide L3 收集任务。"""
    conn = _conn()
    _minimal_recon_fixture(conn)
    conn.execute(
        "UPDATE target_assets SET scope_status='in_scope', scope_class='owned',"
        " authorization_state='authorized', live_status='live', resolved_ip='1.2.3.4'"
    )
    conn.execute(
        """INSERT INTO target_assets(target_name, asset_type, asset_value, scope_status, scope_class,
           authorization_state, live_status, resolved_ip)
           VALUES('demo','domain','app2.example.com','in_scope','owned','authorized','live','5.6.7.8')"""
    )
    conn.commit()
    result = apply_seed(conn, target_name="demo", dry_run=False)
    assert result.get("blocked_reason") != "active_system_required"
    lanes = {row["lane"] for row in conn.execute("SELECT DISTINCT lane FROM work_items")}
    assert not lanes.intersection({"source_intel", "network_profile", "entry_probe", "origin_verify"})
    assert "preauth_probe" not in lanes


def test_sprint_tick_unfocused_modern_system_seeds_no_l3_collection():
    conn = _conn()
    _minimal_recon_fixture(conn)
    conn.commit()
    tick = run_sprint_tick(conn, target_name="demo", seed=True, reclaim=False)
    assert tick["blackboard"]["seed"].get("blocked_reason") != "active_system_required"
    lanes = {row["lane"] for row in conn.execute("SELECT DISTINCT lane FROM work_items")}
    assert not lanes.intersection({"source_intel", "network_profile", "entry_probe", "origin_verify"})


def test_active_system_seeds_only_linked_assets_with_derived_system_id():
    conn = _conn()
    _minimal_recon_fixture(conn)
    linked_asset = conn.execute("SELECT id FROM target_assets WHERE target_name='demo' LIMIT 1").fetchone()[0]
    conn.execute(
        """UPDATE target_assets SET scope_status='in_scope', scope_class='owned',
           authorization_state='authorized', live_status='live', resolved_ip='1.1.1.1'
           WHERE id=?""",
        (linked_asset,),
    )
    unlinked_asset = conn.execute(
        """INSERT INTO target_assets(
            target_name, asset_type, asset_value, scope_status, scope_class,
            authorization_state, live_status, resolved_ip
        ) VALUES('demo','domain','other.example.com','in_scope','owned','authorized','live','2.2.2.2')"""
    ).lastrowid
    system = conn.execute("SELECT id FROM target_systems WHERE target_name='demo' LIMIT 1").fetchone()[0]
    conn.execute(
        """INSERT INTO hunt_sessions(
            target_name,focus_subject_table,focus_subject_id,goal,status,selected_by,system_id
        ) VALUES('demo','target_systems',?,'test','active','operator',?)""",
        (str(system), system),
    )
    conn.execute(
        """INSERT INTO system_asset_links(
            target_name,system_id,asset_id,relationship,confidence
        ) VALUES('demo',?,?, 'primary','high')""",
        (system, linked_asset),
    )
    conn.commit()
    apply_seed(conn, target_name="demo", dry_run=False)
    rows = conn.execute(
        """SELECT lane, subject_id, system_id FROM work_items
           WHERE lane IN ('network_profile','entry_probe','origin_verify')"""
    ).fetchall()
    assert rows
    assert {int(row[2]) for row in rows} == {system}
    assert {int(row[1]) for row in rows} == {linked_asset}
    assert unlinked_asset not in {int(row[1]) for row in rows}


def test_blackboard_seed_cli_supports_db_and_dry_run(tmp_path):
    db_path = tmp_path / "seed_demo.db"
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    _build_seed_fixture(conn)
    conn.close()

    cmd = [
        sys.executable,
        str(SEED_SCRIPT),
        "--db",
        str(db_path),
        "--target",
        "demo",
        "--dry-run",
    ]
    completed = subprocess.run(cmd, capture_output=True, text=True, check=True, cwd=PROJECT_ROOT)  # noqa: S603
    payload = json.loads(completed.stdout)

    verify = sqlite3.connect(db_path)
    count = verify.execute("SELECT COUNT(*) FROM work_items").fetchone()[0]
    verify.close()

    assert payload["created"] > 0
    assert payload["skipped_existing"] == 0
    assert payload["by_lane"]["js_reverse"] >= 2
    assert count == 0


def test_coverage_seed_budget_is_five_and_repeat_tick_is_idempotent():
    conn = _conn()
    conn.execute("INSERT INTO targets(target_name,domain) VALUES('coverage-demo','coverage.test')")
    for index in range(7):
        asset = f"a{index}.coverage.test"
        conn.execute(
            """INSERT INTO target_assets(target_name,asset_value,status,scope_status)
               VALUES('coverage-demo',?,'scanned','needs_review')""",
            (asset,),
        )
        conn.execute(
            """INSERT INTO coverage_ledger(target_name,item_key,category,status)
               VALUES('coverage-demo',?,'asset_liveness','unknown')""",
            (f"asset:{asset}",),
        )
    conn.commit()

    first = apply_seed(conn, target_name="coverage-demo", dry_run=False)
    second = apply_seed(conn, target_name="coverage-demo", dry_run=False)
    derived = conn.execute(
        """SELECT count(*) FROM work_items
           WHERE target_name='coverage-demo' AND subject_table='coverage_ledger'"""
    ).fetchone()[0]

    assert first["created"] == 6  # five coverage items plus the ordinary target triage item
    assert derived == 7
    assert second["created"] == 2
    assert apply_seed(conn, target_name="coverage-demo", dry_run=False)["created"] == 0


def test_coverage_active_probe_creates_action_card_not_queued_work():
    conn = _conn()
    conn.execute("INSERT INTO targets(target_name,domain) VALUES('coverage-demo','coverage.test')")
    conn.execute(
        """INSERT INTO coverage_ledger(target_name,item_key,category,status)
           VALUES('coverage-demo','sp:SP-COV','vuln_probe','unknown')"""
    )
    conn.commit()

    first = apply_seed(conn, target_name="coverage-demo", dry_run=False)
    second = apply_seed(conn, target_name="coverage-demo", dry_run=False)

    assert first["action_cards_created"] == 1
    assert second["action_cards_created"] == 0
    assert (
        conn.execute("SELECT count(*) FROM work_items WHERE target_name='coverage-demo' AND subject_table='coverage_ledger'").fetchone()[0]
        == 0
    )
    card = conn.execute("SELECT kind,action_key FROM operator_inbox WHERE target_name='coverage-demo'").fetchone()
    assert (card["kind"], card["action_key"]) == ("manual_review", "coverage:1")


def test_coverage_endpoint_scope_gate_prevents_active_lane():
    conn = _conn()
    conn.execute("INSERT INTO targets(target_name,domain) VALUES('coverage-demo','coverage.test')")
    asset_id = conn.execute(
        """INSERT INTO target_assets(
               target_name,asset_value,status,scope_status,scope_class,authorization_state
           ) VALUES('coverage-demo','api.coverage.test','scanned','needs_review','unknown','unknown')"""
    ).lastrowid
    conn.execute(
        """INSERT INTO endpoint_observations(
               target_name,asset_id,canonical_url,method,source,source_id
           ) VALUES('coverage-demo',?,'https://api.coverage.test/v1','GET','fixture','1')""",
        (asset_id,),
    )
    conn.execute(
        """INSERT INTO coverage_ledger(target_name,item_key,category,status)
           VALUES('coverage-demo','endpoint:https://api.coverage.test/v1','endpoint_recon','uncovered')"""
    )
    conn.commit()

    apply_seed(conn, target_name="coverage-demo", dry_run=False)

    assert (
        conn.execute("SELECT count(*) FROM work_items WHERE target_name='coverage-demo' AND subtype='coverage:endpoint_recon'").fetchone()[
            0
        ]
        == 0
    )
    assert (
        conn.execute("SELECT kind FROM operator_inbox WHERE target_name='coverage-demo' AND action_key='coverage:1'").fetchone()[0]
        == "confirm_scope"
    )


def test_coverage_endpoint_passive_collection_requires_explicit_authorized_scope():
    conn = _conn()
    conn.execute("INSERT INTO targets(target_name,domain) VALUES('coverage-demo','coverage.test')")
    asset_id = conn.execute(
        """INSERT INTO target_assets(
               target_name,asset_value,status,scope_status,scope_class,authorization_state
           ) VALUES('coverage-demo','api.coverage.test','scanned','in_scope','owned','authorized')"""
    ).lastrowid
    conn.execute(
        """INSERT INTO endpoint_observations(
               target_name,asset_id,canonical_url,method,source,source_id
           ) VALUES('coverage-demo',?,'HTTPS://API.COVERAGE.TEST:443/v1?b=2&a=1','GET','fixture','1')""",
        (asset_id,),
    )
    conn.execute(
        """INSERT INTO coverage_ledger(target_name,item_key,category,status)
           VALUES(
             'coverage-demo',
             'endpoint:https://api.coverage.test:443/v1?a=1&b=2',
             'endpoint_recon',
             'unknown'
           )"""
    )
    conn.commit()

    apply_seed(conn, target_name="coverage-demo", dry_run=False)

    row = conn.execute(
        """SELECT lane,risk_class FROM work_items
           WHERE target_name='coverage-demo' AND subtype='coverage:endpoint_recon'"""
    ).fetchone()
    assert (row["lane"], row["risk_class"]) == ("quick_scout", "safe_passive")
    assert (
        conn.execute("SELECT count(*) FROM operator_inbox WHERE target_name='coverage-demo' AND action_key='coverage:1'").fetchone()[0] == 0
    )


def test_coverage_endpoint_unknown_authorization_creates_scope_gate_not_passive_work():
    conn = _conn()
    conn.execute("INSERT INTO targets(target_name,domain) VALUES('coverage-demo','coverage.test')")
    asset_id = conn.execute(
        """INSERT INTO target_assets(
               target_name,asset_value,status,scope_status,scope_class,authorization_state
           ) VALUES('coverage-demo','api.coverage.test','scanned','in_scope','owned','unknown')"""
    ).lastrowid
    conn.execute(
        """INSERT INTO endpoint_observations(
               target_name,asset_id,canonical_url,method,source,source_id
           ) VALUES('coverage-demo',?,'https://api.coverage.test/v1','GET','fixture','1')""",
        (asset_id,),
    )
    conn.execute(
        """INSERT INTO coverage_ledger(target_name,item_key,category,status)
           VALUES('coverage-demo','endpoint:https://api.coverage.test/v1','endpoint_recon','unknown')"""
    )
    conn.commit()

    apply_seed(conn, target_name="coverage-demo", dry_run=False)

    assert (
        conn.execute("SELECT count(*) FROM work_items WHERE target_name='coverage-demo' AND subtype='coverage:endpoint_recon'").fetchone()[
            0
        ]
        == 0
    )
    assert (
        conn.execute("SELECT kind FROM operator_inbox WHERE target_name='coverage-demo' AND action_key='coverage:1'").fetchone()[0]
        == "confirm_scope"
    )


def test_plan_seed_work_items_creates_js_reverse_from_js_files_subject():
    """New-pipeline contract: js_reverse work_item subject MUST be js_files (has local_path),
    so the js-reversing-helper lane can resolve the on-disk file and run the toolchain.
    Legacy pages/clusters-only planning broke this and the subagent fell back to
    reading JS by hand instead of running scripts."""
    conn = _conn()
    _build_seed_fixture(conn)
    conn.execute(
        """
        INSERT INTO js_files (
            id, url, page_url, analyzed, discovered_apis_json, hardcoded_secrets_json,
            internal_routes_json, debug_switches_json, analyzed_at, source_kind,
            source_map_url, source_map_status, extraction_status, signal_count, local_path
        ) VALUES
          (
            10, 'https://example.com/static/app2.js', 'https://example.com/blank2', 0,
            '["/api/v2"]', '[]', '[]', '[]', '2026-07-14 10:10:00',
            'web_script', '', 'none', 'collected', 6, 'tmp/js_cache/demo/abc.js'
          ),
          (
            11, 'https://example.com/static/vendor.js', 'https://example.com/blank2', 0,
            '[]', '[]', '[]', '[]', NULL,
            'web_script', '', 'none', 'pending', 0, NULL
          )
        """
    )
    conn.commit()

    plan = plan_seed_work_items(conn, target_name="demo")
    js_file_items = {
        (item["lane"], item["subject_table"], item["subject_id"], item["subtype"]) for item in plan if item["subject_table"] == "js_files"
    }

    # id=10: collected with local_path -> js_reverse subject=js_files
    assert ("js_reverse", "js_files", "10", "api_extract") in js_file_items
    # id=11: pending, no local content yet -> not dispatchable
    assert ("js_reverse", "js_files", "11", "api_extract") not in js_file_items

    # apply_seed dedups and creates the work_item
    apply_seed(conn, target_name="demo", dry_run=False)
    row = conn.execute(
        "SELECT lane, subject_table, subject_id FROM work_items WHERE subject_table='js_files' AND subject_id='10'"
    ).fetchone()
    assert row is not None and row["lane"] == "js_reverse"
