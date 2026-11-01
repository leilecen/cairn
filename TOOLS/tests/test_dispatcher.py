import json
import sqlite3
import subprocess
import sys
from pathlib import Path

from db.dispatcher import build_dispatch_plan, to_claude_agent_args, to_codex_spawn_args
from db.experiment_planner import materialize_approved_experiments
from db.experiments import approve_experiment, propose_experiment
from db.hunt_sessions import create_session, set_status
from db.work_queue import create_work_item

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = PROJECT_ROOT / "TOOLS" / "db" / "schema.sql"
DISPATCHER_SCRIPT = PROJECT_ROOT / "TOOLS" / "db" / "dispatcher.py"


def _conn():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    # These lane-mapping unit tests intentionally exercise the pre-focus
    # compatibility path. Modern focus/readiness gates have dedicated tests.
    conn.execute("DELETE FROM schema_version")
    conn.execute("INSERT INTO schema_version(version,description) VALUES(32,'legacy-dispatch-fixture')")
    return conn


def test_dispatch_plan_maps_lanes_to_workers_and_model_tiers():
    conn = _conn()
    create_work_item(
        conn,
        target_name="demo",
        lane="quick_scout",
        subtype="explicit_single_page",
        subject_table="pages",
        subject_id="1",
    )
    create_work_item(conn, target_name="demo", lane="js_reverse", subject_table="js_files", subject_id="2")
    create_work_item(conn, target_name="demo", lane="hypothesis", subject_table="attack_threads", subject_id="3")

    plan = build_dispatch_plan(conn, target_name="demo", limit=3)
    by_lane = {item["lane"]: item for item in plan["tasks"]}

    assert by_lane["quick_scout"]["worker"] == "surface-scout"
    assert by_lane["quick_scout"]["model_tier"] == "cheap"
    assert by_lane["quick_scout"]["reasoning_effort"] == "low"
    assert by_lane["js_reverse"]["worker"] == "js-reversing-helper"
    assert by_lane["js_reverse"]["agent_type"] == "explorer"
    assert by_lane["js_reverse"]["model_tier"] == "standard"
    assert by_lane["js_reverse"]["reasoning_effort"] == "medium"
    assert by_lane["hypothesis"]["worker"] == "hypothesis-drafter"
    assert by_lane["hypothesis"]["requires_main_approval"] is True


def test_cognitive_dispatch_includes_full_experiment_contract():
    conn = _conn()
    sid = create_session(
        conn,
        target_name="demo",
        focus_subject_table="soft_targets",
        focus_subject_id="1",
        goal="offline",
        selected_by="operator",
    )
    set_status(conn, sid, "active", actor="operator")
    conn.execute(
        """INSERT INTO attack_threads(
               target_name,hypothesis,status,hunt_session_id,expected_observation,
               refuting_observation,alternative_explanations_json,stop_conditions_json
           ) VALUES('demo','h','active',?,'expected','refuting','["alt"]','["stop"]')""",
        (sid,),
    )
    tid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    eid = propose_experiment(
        conn,
        hunt_session_id=sid,
        attack_thread_id=tid,
        experiment_key="contract",
        question="one question",
        expected_observation="expected",
        control_description="control",
        stop_conditions=["stop"],
        budget={"requests": 0},
    )
    approve_experiment(conn, eid, actor="main")
    materialize_approved_experiments(conn, target_name="demo", hunt_session_id=sid)
    task = build_dispatch_plan(conn, target_name="demo", limit=2)["tasks"][0]
    assert task["experiment_contract"]["expected_observation"] == "expected"
    assert "control_description" in task["adapters"]["codex"]["message"]


def test_dispatcher_final_gate_blocks_legacy_active_low_experiment():
    conn = _conn()
    sid = create_session(
        conn,
        target_name="demo",
        focus_subject_table="soft_targets",
        focus_subject_id="1",
        goal="offline",
        selected_by="operator",
    )
    set_status(conn, sid, "active", actor="operator")
    conn.execute(
        """INSERT INTO attack_threads(
               target_name,hypothesis,status,hunt_session_id,expected_observation,
               refuting_observation,alternative_explanations_json,stop_conditions_json
           ) VALUES('demo','h','active',?,'expected','refuting','["alt"]','["stop"]')""",
        (sid,),
    )
    tid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    eid = propose_experiment(
        conn,
        hunt_session_id=sid,
        attack_thread_id=tid,
        experiment_key="legacy-active",
        question="active?",
        method_class="active_low",
        expected_observation="expected",
        control_description="control",
        stop_conditions=["stop"],
    )
    approve_experiment(conn, eid, actor="main")
    work_id = create_work_item(
        conn,
        target_name="demo",
        lane="cognitive_experiment",
        subtype=f"experiment:{eid}",
        subject_table="experiments",
        subject_id=str(eid),
        priority=99,
    )
    plan = build_dispatch_plan(conn, target_name="demo", limit=2)
    assert not any(item["work_item_id"] == work_id for item in plan["tasks"])
    skipped = next(item for item in plan["skipped_decision_lanes"] if item["work_item_id"] == work_id)
    assert skipped["decision_owner"] == "operator"
    assert "active/operator-gated" in skipped["reason"]


def test_preauth_probe_requires_active_authorized_asset_scope():
    conn = _conn()
    conn.execute(
        """INSERT INTO target_assets(target_name,asset_value,live_status,scope_status,scope_class,authorization_state)
           VALUES('demo','vendor.example.net','live','in_scope','intel_only','unknown')"""
    )
    asset_id = conn.execute("SELECT id FROM target_assets WHERE target_name='demo'").fetchone()[0]
    work_id = create_work_item(
        conn,
        target_name="demo",
        lane="preauth_probe",
        subject_table="target_assets",
        subject_id=str(asset_id),
        title="preauth",
        objective="boundary",
        priority=99,
    )
    plan = build_dispatch_plan(conn, target_name="demo", limit=2)
    assert not plan["tasks"]
    assert any(item["work_item_id"] == work_id and "scope_gate" in item["reason"] for item in plan["skipped_decision_lanes"])


def test_semantic_profile_lane_builds_claude_and_codex_compatible_plan():
    conn = _conn()
    work_item_id = create_work_item(
        conn,
        target_name="demo",
        lane="semantic_profile",
        subtype="focused_target_profile",
        subject_table="soft_targets",
        subject_id="9",
        title="Profile focused target admin.example.com",
        objective="semantic profile with unknown/uncovered/blocked coverage ledger",
        priority=88,
    )

    item = build_dispatch_plan(conn, target_name="demo", limit=1)["tasks"][0]
    codex = to_codex_spawn_args(item)
    claude = to_claude_agent_args(item)

    assert item["work_item_id"] == work_item_id
    assert item["worker"] == "attack-surface-profiler"
    assert item["model_tier"] == "standard"
    assert codex["model"] == "gpt-5.4"
    assert codex["reasoning_effort"] == "low"
    assert "unknown/uncovered/blocked" in codex["message"]
    assert claude["subagent_type"] == "attack-surface-profiler"
    assert claude["model"] == "sonnet"
    assert "coverage ledger" in claude["prompt"]


def test_dispatch_plan_honors_priority_status_order_and_default_limit_two():
    conn = _conn()
    create_work_item(
        conn,
        target_name="demo",
        lane="quick_scout",
        subtype="explicit_single_page",
        subject_table="pages",
        subject_id="low",
        priority=10,
    )
    high = create_work_item(conn, target_name="demo", lane="vuln_review", subject_table="suspicious_points", subject_id="high", priority=90)
    partial = create_work_item(
        conn, target_name="demo", lane="logic_probe", subject_table="attack_threads", subject_id="partial", priority=100
    )
    conn.execute("UPDATE work_items SET status='partial' WHERE id = ?", (partial,))
    conn.commit()

    plan = build_dispatch_plan(conn, target_name="demo")

    # v4.5 keeps the AI worker queue bounded at two total L3 tasks.
    assert [item["work_item_id"] for item in plan["tasks"]] == [partial, high]
    assert len(plan["tasks"]) == 2


def test_dispatch_plan_caps_all_l3_lanes_at_two():
    conn = _conn()
    test_lanes = ["preauth_probe", "logic_probe", "vuln_review", "replay"]
    collection_lanes = ["quick_scout", "source_intel", "entry_probe"]
    for i, lane in enumerate(test_lanes + collection_lanes):
        subtype = "explicit_single_page" if lane == "quick_scout" else ("review" if lane == "vuln_review" else "single")
        create_work_item(
            conn,
            target_name="demo",
            lane=lane,
            subtype=subtype,
            subject_table="pages",
            subject_id=str(i),
            priority=100 - i,
        )
    plan = build_dispatch_plan(conn, target_name="demo")

    task_lanes = [item["lane"] for item in plan["tasks"]]
    dispatched_test = [lane for lane in task_lanes if lane in test_lanes]
    dispatched_collection = [lane for lane in task_lanes if lane in collection_lanes]
    assert len(plan["tasks"]) <= 2
    assert len(dispatched_test) <= 2
    assert len(dispatched_collection) <= 2
    assert len(plan["tasks"]) <= 8


def test_dispatch_plan_is_read_only_and_skips_main_or_operator_lanes():
    conn = _conn()
    triage = create_work_item(conn, target_name="demo", lane="asset_triage", subject_table="targets", subject_id="1", priority=100)
    operator = create_work_item(conn, target_name="demo", lane="operator_task", subject_table="operator_inbox", subject_id="2", priority=90)
    dispatchable = create_work_item(conn, target_name="demo", lane="entry_explore", subject_table="pages", subject_id="3", priority=80)

    before = [dict(row) for row in conn.execute("SELECT * FROM work_items ORDER BY id").fetchall()]
    plan = build_dispatch_plan(conn, target_name="demo", limit=2)
    after = [dict(row) for row in conn.execute("SELECT * FROM work_items ORDER BY id").fetchall()]

    assert before == after
    assert [item["work_item_id"] for item in plan["tasks"]] == [dispatchable]
    skipped = {item["work_item_id"]: item for item in plan["skipped_decision_lanes"]}
    assert skipped[triage]["decision_owner"] == "main_model"
    assert skipped[operator]["decision_owner"] == "operator"


def test_dispatch_plan_does_not_output_large_raw_context():
    conn = _conn()
    raw_html = "<html>" + ("A" * 5000) + "</html>"
    create_work_item(
        conn,
        target_name="demo",
        lane="quick_scout",
        subtype="explicit_single_page",
        subject_table="pages",
        subject_id="1",
        title=raw_html,
        objective="inspect compact only",
    )

    item = build_dispatch_plan(conn, target_name="demo", limit=1)["tasks"][0]
    encoded = json.dumps(item, ensure_ascii=False)

    assert len(item["prompt_context"]) <= 360
    assert "A" * 1000 not in encoded
    assert "raw HTML/JS/Burp" in item["adapters"]["codex"]["message"]


def test_dispatch_plan_redacts_http_secrets_and_js_bundles_from_context():
    conn = _conn()
    create_work_item(
        conn,
        target_name="demo",
        lane="logic_probe",
        subject_table="hunt_queue",
        subject_id="1",
        title="POST /api/pay HTTP/1.1\r\nHost: example.com\r\nCookie: sid=secret",
        objective="webpackJsonp=[];function huge(){return 'bundle'}",
        priority=80,
    )

    item = build_dispatch_plan(conn, target_name="demo", limit=1)["tasks"][0]
    encoded = json.dumps(item, ensure_ascii=False)

    assert item["summary"] == "[redacted-raw-data]"
    assert "[redacted-raw-data]" in item["prompt_context"]
    assert "sid=secret" not in encoded
    assert "webpackJsonp" not in encoded


def test_claude_and_codex_adapter_helpers_return_minimal_explicit_params():
    conn = _conn()
    create_work_item(conn, target_name="demo", lane="evidence_pack", subject_table="findings", subject_id="7")
    item = build_dispatch_plan(conn, target_name="demo", limit=1)["tasks"][0]

    codex = to_codex_spawn_args(item)
    claude = to_claude_agent_args(item)

    assert codex["fork_context"] is False
    assert codex["model"] == "gpt-5.4-mini"
    assert codex["reasoning_effort"] == "low"
    assert "work_item_id" in codex["message"]
    assert claude["subagent_type"] == "src-reporter"
    assert claude["model"] == "haiku"
    assert "work_item_id" in claude["prompt"]


def test_dispatcher_cli_outputs_machine_readable_json(tmp_path):
    db_path = tmp_path / "dispatcher.db"
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    conn.execute("DELETE FROM schema_version")
    conn.execute("INSERT INTO schema_version(version,description) VALUES(32,'legacy-dispatch-fixture')")
    create_work_item(conn, target_name="demo", lane="replay", subject_table="hunt_queue", subject_id="5")
    conn.close()

    result = subprocess.run(  # noqa: S603 - fixed argv executes this repo's dispatcher with a temp DB path.
        [
            sys.executable,
            str(DISPATCHER_SCRIPT),
            "--db",
            str(db_path),
            "--target",
            "demo",
        ],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",  # Windows GBK console: child prints UTF-8, must decode as UTF-8
    )
    payload = json.loads(result.stdout)

    assert payload["target_name"] == "demo"
    assert payload["contract"]["read_only"] is True
    assert payload["tasks"][0]["lane"] == "replay"


def _modern_ready_system(conn):
    asset = conn.execute(
        """
        INSERT INTO target_assets(
            target_name,asset_value,asset_type,scope_status,scope_class,authorization_state,live_status
        ) VALUES('demo','https://example.com/','url','in_scope','owned','authorized','live')
        """
    ).lastrowid
    system = conn.execute(
        """
        INSERT INTO target_systems(
            target_name,system_key,display_name,canonical_url,scope_class,lifecycle_state
        ) VALUES('demo','demo','Demo','https://example.com/','owned','testing')
        """
    ).lastrowid
    conn.execute(
        """INSERT INTO system_asset_links(target_name,system_id,asset_id,relationship,confidence)
        VALUES('demo',?,?,'primary','high')""",
        (system, asset),
    )
    session = conn.execute(
        """
        INSERT INTO hunt_sessions(
            target_name,focus_subject_table,focus_subject_id,goal,status,selected_by,system_id
        ) VALUES('demo','target_systems',?,'test','active','operator',?)
        """,
        (str(system), system),
    ).lastrowid
    conn.commit()
    return system, session


def test_modern_dispatcher_rejects_missing_template_fields_but_legacy_remains_compatible():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    system, _ = _modern_ready_system(conn)
    _insert_focus_score(conn, system)
    work_id = create_work_item(
        conn,
        target_name="demo",
        lane="entry_probe",
        subtype="pattern_guess:1",
        subject_table="pattern_guesses",
        subject_id="1",
        objective="",
        system_id=system,
    )
    plan = build_dispatch_plan(conn, target_name="demo")
    assert not plan["tasks"]
    skipped = next(item for item in plan["skipped_decision_lanes"] if item["work_item_id"] == work_id)
    assert "template_contract" in skipped["reason"]
    assert "objective" in skipped["reason"]


def test_modern_template_keeps_active_system_gate_and_expresses_m7_m9_with_existing_lanes():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    system, _ = _modern_ready_system(conn)
    _insert_focus_score(conn, system)
    for lane, subtype, subject_id in (
        ("source_intel", "public_exposure:public_docs_search", "7"),
        ("entry_explore", "entry_recursion:mobile_h5", "8"),
        ("logic_probe", "param_semantics:db_structure", "9"),
    ):
        create_work_item(
            conn,
            target_name="demo",
            lane=lane,
            subtype=subtype,
            subject_table="evidence_refs",
            subject_id=subject_id,
            objective="Analyze one compact evidence reference.",
            system_id=system,
        )
    plan = build_dispatch_plan(conn, target_name="demo", limit=3)
    assert {(item["lane"], item["subtype"]) for item in plan["tasks"]} == {
        ("source_intel", "public_exposure:public_docs_search"),
        ("entry_explore", "entry_recursion:mobile_h5"),
    }
    assert all("授权边界" in item["adapters"]["codex"]["message"] for item in plan["tasks"])
    assert any(item["lane"] == "logic_probe" and "readiness_gate" in item["reason"] for item in plan["skipped_decision_lanes"])

    other_system = conn.execute(
        """
        INSERT INTO target_systems(target_name,system_key,display_name,canonical_url,scope_class,lifecycle_state)
        VALUES('demo','other','Other','https://other.example.com/','owned','testing')
        """
    ).lastrowid
    blocked = create_work_item(
        conn,
        target_name="demo",
        lane="logic_probe",
        subtype="param_semantics:query_filter",
        subject_table="evidence_refs",
        subject_id="10",
        objective="One compact reference.",
        system_id=other_system,
        priority=999,
    )
    plan = build_dispatch_plan(conn, target_name="demo", limit=10)
    assert not any(item["work_item_id"] == blocked for item in plan["tasks"])


def test_modern_mapping_lane_allows_empty_evidence_list_without_weakening_test_lanes():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    system, _ = _modern_ready_system(conn)
    _insert_focus_score(conn, system)
    mapping = create_work_item(
        conn,
        target_name="demo",
        lane="asset_ingest",
        subtype="asset_intel",
        subject_table="target_assets",
        subject_id="1",
        objective="Map this one explicit asset.",
        system_id=system,
    )
    testing = create_work_item(
        conn,
        target_name="demo",
        lane="entry_probe",
        subtype="pattern_guess:99",
        subject_table="pattern_guesses",
        subject_id="99",
        objective="Test one route.",
        system_id=system,
    )
    plan = build_dispatch_plan(conn, target_name="demo", limit=10)
    assert any(item["work_item_id"] == mapping for item in plan["tasks"])
    skipped = next(item for item in plan["skipped_decision_lanes"] if item["work_item_id"] == testing)
    assert "template_contract" in skipped["reason"] and "evidence_refs" in skipped["reason"]


def _focused_mapping_item(conn, system, lane="asset_ingest", subtype="asset_intel"):
    asset_id = conn.execute(
        "SELECT asset_id FROM system_asset_links WHERE target_name='demo' AND system_id=? LIMIT 1", (system,)
    ).fetchone()[0]
    return create_work_item(
        conn,
        target_name="demo",
        lane=lane,
        subtype=subtype,
        subject_table="target_assets",
        subject_id=str(asset_id),
        objective="Map this one explicit asset.",
        system_id=system,
    )


def _insert_focus_score(conn, system, *, status="focused", timebox_sql="NULL", target_name="demo"):
    conn.execute(
        f"""INSERT INTO system_soft_targets(
               target_name,system_id,eligibility_status,status,timebox_until
            ) VALUES(?,?,'eligible',?,{timebox_sql})""",  # noqa: S608 - fixed test-only SQL expressions.
        (target_name, system, status),
    )
    conn.commit()


def test_schema34_dispatcher_blocks_elapsed_focus_timebox_including_exact_now():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    system, _ = _modern_ready_system(conn)
    # preauth_probe is a test lane: it must stay blocked by focus gates.
    work_id = _focused_mapping_item(conn, system, lane="preauth_probe", subtype="asset_boundary")
    _insert_focus_score(conn, system, timebox_sql="datetime('now','localtime')")

    plan = build_dispatch_plan(conn, target_name="demo", limit=10)

    assert not plan["tasks"]
    skipped = next(item for item in plan["skipped_decision_lanes"] if item["work_item_id"] == work_id)
    assert skipped["decision_owner"] == "operator" and "timebox expired" in skipped["reason"]


def test_schema34_null_timebox_and_unfocused_or_other_target_expiry_do_not_block():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    system, _ = _modern_ready_system(conn)
    work_id = _focused_mapping_item(conn, system)
    _insert_focus_score(conn, system, timebox_sql="NULL")
    other_system = conn.execute(
        """INSERT INTO target_systems(target_name,system_key,display_name,canonical_url,scope_class,lifecycle_state)
           VALUES('other','other','Other','https://other.example/','owned','testing')"""
    ).lastrowid
    _insert_focus_score(conn, other_system, status="focused", timebox_sql="datetime('now','localtime','-1 minute')", target_name="other")
    candidate = conn.execute(
        """INSERT INTO target_systems(target_name,system_key,display_name,canonical_url,scope_class,lifecycle_state)
           VALUES('demo','candidate','Candidate','https://candidate.example/','owned','testing')"""
    ).lastrowid
    _insert_focus_score(conn, candidate, status="ranked", timebox_sql="datetime('now','localtime','-1 minute')")

    assert any(item["work_item_id"] == work_id for item in build_dispatch_plan(conn, target_name="demo")["tasks"])


def test_schema33_dispatcher_ignores_schema34_focus_timebox_contract():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    conn.execute("DELETE FROM schema_version")
    conn.execute("INSERT INTO schema_version(version,description) VALUES(33,'legacy-focus-contract')")
    system, _ = _modern_ready_system(conn)
    work_id = _focused_mapping_item(conn, system)
    _insert_focus_score(conn, system, timebox_sql="datetime('now','localtime','-1 minute')")

    assert any(item["work_item_id"] == work_id for item in build_dispatch_plan(conn, target_name="demo")["tasks"])


def test_schema34_dispatcher_rechecks_eligibility_before_final_dispatch():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    system, _ = _modern_ready_system(conn)
    # preauth_probe is a test lane; asset_ingest is a collection lane.
    preauth = _focused_mapping_item(conn, system, lane="preauth_probe", subtype="asset_boundary")
    collect = _focused_mapping_item(conn, system, lane="asset_ingest", subtype="asset_intel")
    _insert_focus_score(conn, system)

    # A linked mapping lane dispatches while the selected system is eligible.
    assert any(item["work_item_id"] == collect for item in build_dispatch_plan(conn, target_name="demo")["tasks"])
    # Test lane stays gated (readiness is mapping in this fixture, so readiness_gate fires).
    plan = build_dispatch_plan(conn, target_name="demo", limit=10)
    assert not any(item["work_item_id"] == preauth for item in plan["tasks"])

    # Downgrade: eligibility check runs before readiness, so the test lane is
    # now blocked by eligibility_gate; legacy collection records are gated too.
    conn.execute("UPDATE system_soft_targets SET eligibility_status='authz_blocked' WHERE system_id=?", (system,))
    conn.commit()
    plan = build_dispatch_plan(conn, target_name="demo", limit=10)
    assert not any(item["work_item_id"] == collect for item in plan["tasks"])
    assert not any(item["work_item_id"] == preauth for item in plan["tasks"])
    skipped = next(item for item in plan["skipped_decision_lanes"] if item["work_item_id"] == preauth)
    assert skipped["decision_owner"] == "operator"
    assert "eligibility_gate" in skipped["reason"]
    skipped_collect = next(item for item in plan["skipped_decision_lanes"] if item["work_item_id"] == collect)
    assert "eligibility_gate" in skipped_collect["reason"]


def test_collection_lanes_dispatch_without_focus_but_test_lanes_blocked():
    """已有历史收集 item 也必须在无 focus 时被 park/skip。"""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    system = conn.execute(
        """INSERT INTO target_systems(target_name,system_key,display_name,canonical_url,scope_class,lifecycle_state)
           VALUES('demo','s1','S1','https://s1.example/','owned','mapping')"""
    ).lastrowid
    asset_id = conn.execute(
        """INSERT INTO target_assets(target_name,asset_type,asset_value,scope_status,scope_class,authorization_state)
           VALUES('demo','domain','s1.example','in_scope','owned','authorized')"""
    ).lastrowid
    conn.execute(
        "INSERT INTO system_asset_links(target_name, system_id, asset_id, relationship, confidence) VALUES('demo',?,?,'primary','high')",
        (system, asset_id),
    )
    conn.commit()
    collection = create_work_item(
        conn,
        target_name="demo",
        lane="asset_ingest",
        subtype="asset_intel",
        subject_table="target_assets",
        subject_id=str(asset_id),
        objective="Collect intel across systems.",
        system_id=system,
    )
    test_lane = create_work_item(
        conn,
        target_name="demo",
        lane="preauth_probe",
        subtype="asset_boundary",
        subject_table="target_assets",
        subject_id=str(asset_id),
        objective="Measure pre-auth boundary.",
        system_id=system,
    )
    conn.commit()
    plan = build_dispatch_plan(conn, target_name="demo", limit=10)
    assert not any(item["work_item_id"] == collection for item in plan["tasks"])
    assert not any(item["work_item_id"] == test_lane for item in plan["tasks"])
    skipped_collection = next(item for item in plan["skipped_decision_lanes"] if item["work_item_id"] == collection)
    assert skipped_collection["decision_owner"] == "operator"
    assert "focus_gate" in skipped_collection["reason"]
    skipped = next(item for item in plan["skipped_decision_lanes"] if item["work_item_id"] == test_lane)
    assert "focus_gate" in skipped["reason"]


def test_dispatcher_caps_linked_l3_workers_at_two_and_keeps_active_system():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    system, _ = _modern_ready_system(conn)
    _insert_focus_score(conn, system)
    for index in range(3):
        create_work_item(
            conn,
            target_name="demo",
            lane="network_profile",
            subtype=f"network_profile:{index}",
            subject_table="target_assets",
            subject_id="1",
            objective="Profile one linked asset.",
            system_id=system,
            priority=100 - index,
        )
    plan = build_dispatch_plan(conn, target_name="demo")
    assert len(plan["tasks"]) <= 2
    assert {item["system_id"] for item in plan["tasks"]} == {system}
