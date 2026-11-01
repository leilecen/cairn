import json
import sqlite3
import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock

from db.attack_threads import create_attack_thread, update_attack_thread
from db.sprint_tick import run_sprint_tick
from db.work_queue import create_work_item

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = PROJECT_ROOT / "TOOLS" / "db" / "schema.sql"
SCRIPT_PATH = PROJECT_ROOT / "TOOLS" / "db" / "sprint_tick.py"
# 用当前解释器的绝对路径起子进程：本机没有全局 `uv`（AGENTS.md 硬约束 4），
# 早期版本写死 `assert shutil.which("uv") is not None` 会让整个测试文件在收集阶段就崩。
CLI_PREFIX = [sys.executable]


def _conn():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    # General sprint orchestration tests intentionally isolate the legacy
    # dispatch contract; modern focused-system behavior is tested separately.
    conn.execute("DELETE FROM schema_version")
    conn.execute("INSERT INTO schema_version(version,description) VALUES(32,'legacy-sprint-fixture')")
    conn.execute("INSERT INTO targets (id, target_name, domain) VALUES (1, 'demo', 'example.com')")
    conn.commit()
    return conn


def _candidate_thread(conn, priority):
    thread_id = create_attack_thread(
        conn,
        target_name="demo",
        asset_url="https://example.com/app",
        hypothesis=f"candidate {priority}",
        why_promising="seeded candidate",
        priority=priority,
        owner="test",
        sprint_id="sprint-1",
    )
    update_attack_thread(
        conn,
        attack_thread_id=thread_id,
        current_evidence=json.dumps(
            {
                "type": "generic_logic",
                "hypothesis": f"candidate {priority}",
                "request_refs": [f"evidence_refs:{priority}"],
                "response_refs": [f"evidence_refs:{priority + 100}"],
                "missing_proof": "operator screenshot",
            }
        ),
    )
    return thread_id


def test_run_sprint_tick_returns_top_three_candidates_and_blackboard():
    conn = _conn()
    for priority in [10, 90, 60, 80]:
        _candidate_thread(conn, priority)

    payload = run_sprint_tick(conn, target_name="demo", sprint_id="sprint-1")

    assert payload["target"] == "demo"
    assert payload["status"] == "candidate_ready"
    assert payload["b_class_count"] == 3
    assert [item["priority"] for item in payload["candidates"]] == [90, 80, 60]
    assert "blackboard" in payload


def test_sprint_tick_cli_outputs_json(tmp_path):
    db_path = tmp_path / "sprint.db"
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    conn.execute("INSERT INTO targets (id, target_name, domain) VALUES (1, 'demo', 'example.com')")
    conn.commit()
    conn.close()

    cmd = [
        sys.executable,
        str(SCRIPT_PATH),
        "--db",
        str(db_path),
        "--target",
        "demo",
        "--json",
    ]
    completed = subprocess.run(cmd, capture_output=True, check=True, cwd=PROJECT_ROOT)  # noqa: S603
    payload = json.loads(completed.stdout.decode("utf-8", errors="strict"))

    assert payload["target"] == "demo"
    assert payload["status"] == "insufficient_evidence"
    assert "dispatch_plan" in payload
    assert "soft_targets" in payload


def test_sprint_tick_cli_emits_utf8_json_with_chinese_system_name(tmp_path):
    """The standard CLI pipe must not inherit Windows' legacy code page."""
    db_path = tmp_path / "sprint_utf8.db"
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    conn.execute("INSERT INTO targets (id, target_name, domain) VALUES (1, 'demo', 'example.com')")
    conn.execute(
        """
        INSERT INTO target_systems (
            target_name, system_key, display_name, canonical_url, description,
            scope_class, lifecycle_state, created_by
        ) VALUES ('demo', 'demo-core', '演示系统 / core', 'https://core.example.com', '',
                  'owned', 'mapping', 'test')
        """
    )
    conn.commit()
    conn.close()

    completed = subprocess.run(  # noqa: S603 -- resolved uv executable and repository script
        [
            *CLI_PREFIX,
            str(SCRIPT_PATH),
            "--db",
            str(db_path),
            "--target",
            "demo",
            "--no-seed",
            "--no-reclaim",
            "--json",
        ],
        capture_output=True,
        check=True,
        cwd=PROJECT_ROOT,
    )  # noqa: S603

    stdout = completed.stdout.decode("utf-8", errors="strict")
    payload = json.loads(stdout)

    assert payload["blackboard"]["view"]["human_brief"]["candidate_systems"][0]["display_name"] == "演示系统 / core"


def test_sprint_tick_cli_text_output_is_utf8_safe_for_unicode_candidates(tmp_path):
    db_path = tmp_path / "sprint_text_utf8.db"
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    conn.execute("INSERT INTO targets (id, target_name, domain) VALUES (1, 'demo', 'example.com')")
    _candidate_thread(conn, 90)
    conn.execute("UPDATE attack_threads SET hypothesis='演示系统 / core 🚀' WHERE target_name='demo'")
    conn.commit()
    conn.close()

    completed = subprocess.run(  # noqa: S603 -- resolved uv executable and repository script
        [
            *CLI_PREFIX,
            str(SCRIPT_PATH),
            "--db",
            str(db_path),
            "--target",
            "demo",
            "--no-seed",
            "--no-reclaim",
        ],
        capture_output=True,
        check=True,
        cwd=PROJECT_ROOT,
    )  # noqa: S603

    assert "演示系统 / core 🚀" in completed.stdout.decode("utf-8", errors="strict")


def test_run_sprint_tick_includes_dispatch_plan_with_lane_mapping_and_default_limit_two():
    conn = _conn()
    create_work_item(
        conn,
        target_name="demo",
        lane="quick_scout",
        subtype="explicit_single_page",
        subject_table="pages",
        subject_id="1",
        priority=10,
    )
    high = create_work_item(conn, target_name="demo", lane="vuln_review", subject_table="suspicious_points", subject_id="2", priority=90)
    mid = create_work_item(conn, target_name="demo", lane="js_reverse", subject_table="js_files", subject_id="3", priority=80)

    payload = run_sprint_tick(conn, target_name="demo", seed=False, reclaim=False)
    tasks = payload["dispatch_plan"]["tasks"]

    assert payload["dispatch_plan"]["max_dispatch"] == 2
    assert [item["work_item_id"] for item in tasks] == [high, mid]
    assert [item["worker"] for item in tasks] == ["vuln-reviewer", "js-reversing-helper"]
    assert len(tasks) == 2


def test_run_sprint_tick_dispatch_plan_skips_main_and_operator_lanes():
    conn = _conn()
    triage = create_work_item(conn, target_name="demo", lane="asset_triage", subject_table="targets", subject_id="1", priority=100)
    operator = create_work_item(conn, target_name="demo", lane="operator_task", subject_table="operator_inbox", subject_id="2", priority=90)

    payload = run_sprint_tick(conn, target_name="demo", seed=False, reclaim=False)

    assert payload["dispatch_plan"]["tasks"] == []
    skipped = {item["work_item_id"]: item for item in payload["dispatch_plan"]["skipped_decision_lanes"]}
    assert skipped[triage]["decision_owner"] == "main_model"
    assert skipped[operator]["decision_owner"] == "operator"


def test_run_sprint_tick_surfaces_soft_target_selection_without_dispatching_raw_assets():
    conn = _conn()
    conn.execute(
        """
        INSERT INTO soft_targets (
            target_name, asset_id, asset_value, total_score, tier, rank,
            dimension_scores_json, evidence_json
        ) VALUES (
            'demo', 1, 'test-admin.example.com', 76, 'tier2_高优先级', 1,
            '{"attack_surface":{"score":8,"clues":["有登录功能"]}}',
            '[{"dimension":"attack_surface","reason":"有登录功能"}]'
        )
        """
    )
    conn.commit()

    payload = run_sprint_tick(conn, target_name="demo", seed=False, reclaim=False)

    assert payload["status"] == "soft_target_selection_required"
    assert payload["operator_decision_required"] is True
    assert payload["soft_targets"]["results"][0]["asset"] == "test-admin.example.com"
    assert payload["soft_targets"]["results"][0]["reason_summary"] == ["有登录功能"]
    assert payload["dispatch_plan"]["tasks"] == []


def test_run_sprint_tick_dispatch_plan_is_read_only():
    conn = _conn()
    create_work_item(conn, target_name="demo", lane="quick_scout", subject_table="pages", subject_id="1")
    before = [dict(row) for row in conn.execute("SELECT * FROM work_items ORDER BY id").fetchall()]

    run_sprint_tick(conn, target_name="demo", seed=False, reclaim=False)

    after = [dict(row) for row in conn.execute("SELECT * FROM work_items ORDER BY id").fetchall()]
    assert after == before


def test_run_sprint_tick_keeps_existing_payload_when_dispatcher_errors(monkeypatch):
    conn = _conn()
    error = sqlite3.OperationalError("no such column: claimed_by")
    monkeypatch.setattr("db.sprint_tick.build_dispatch_plan", Mock(side_effect=error))

    payload = run_sprint_tick(conn, target_name="demo", seed=False, reclaim=False)

    assert payload["target"] == "demo"
    assert payload["status"] == "insufficient_evidence"
    assert payload["blackboard"]["target"] == "demo"
    assert payload["dispatch_plan"]["tasks"] == []
    assert payload["dispatch_plan"]["error"]["type"] == "OperationalError"
    assert "claimed_by" in payload["dispatch_plan"]["error"]["message"]


def test_sprint_tick_cli_default_text_output_stays_compatible(tmp_path):
    db_path = tmp_path / "sprint_text.db"
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    conn.execute("INSERT INTO targets (id, target_name, domain) VALUES (1, 'demo', 'example.com')")
    conn.commit()
    conn.close()

    cmd = [
        sys.executable,
        str(SCRIPT_PATH),
        "--db",
        str(db_path),
        "--target",
        "demo",
    ]
    completed = subprocess.run(cmd, capture_output=True, text=True, check=True, cwd=PROJECT_ROOT)  # noqa: S603

    assert completed.stdout.strip() == "[SPRINT] target=demo status=insufficient_evidence candidates=0"


def test_sprint_tick_recommends_pivot_when_old_threads_have_no_b_candidate():
    conn = _conn()
    thread_id = create_attack_thread(
        conn,
        target_name="demo",
        asset_url="https://example.com/blank",
        hypothesis="blank page may hide APIs",
        why_promising="same-origin JS exists",
        priority=70,
        owner="test",
        sprint_id="sprint-1",
    )
    update_attack_thread(
        conn,
        attack_thread_id=thread_id,
        current_evidence=json.dumps({"type": "personal_info_idor", "objects_tested": []}),
    )
    conn.execute(
        """
        UPDATE attack_threads
        SET created_at='2026-07-16 09:00:00',
            updated_at='2026-07-16 09:00:00'
        WHERE id=?
        """,
        (thread_id,),
    )
    conn.commit()

    payload = run_sprint_tick(conn, target_name="demo", sprint_id="sprint-1")

    assert payload["pivot_recommended"] is True
    assert "no B-class candidate" in payload["pivot_reason"]
    assert "ask the operator to choose" in payload["pivot_reason"]


def test_sprint_tick_does_not_recommend_pivot_for_fresh_threads():
    conn = _conn()
    thread_id = create_attack_thread(
        conn,
        target_name="demo",
        asset_url="https://example.com/blank",
        hypothesis="blank page may hide APIs",
        why_promising="same-origin JS exists",
        priority=70,
        owner="test",
        sprint_id="sprint-1",
    )
    update_attack_thread(
        conn,
        attack_thread_id=thread_id,
        current_evidence=json.dumps({"type": "personal_info_idor", "objects_tested": []}),
    )

    payload = run_sprint_tick(conn, target_name="demo", sprint_id="sprint-1")

    assert payload["pivot_recommended"] is False
    assert payload["pivot_reason"] == ""


def test_sprint_tick_candidates_do_not_leak_raw_current_evidence():
    conn = _conn()
    thread_id = create_attack_thread(
        conn,
        target_name="demo",
        asset_url="https://example.com/app",
        hypothesis="candidate with refs",
        why_promising="request/response refs exist",
        priority=90,
        owner="test",
        sprint_id="sprint-1",
    )
    update_attack_thread(
        conn,
        attack_thread_id=thread_id,
        current_evidence=json.dumps(
            {
                "type": "generic_logic",
                "hypothesis": "candidate with refs",
                "request_refs": ["evidence_refs:1"],
                "response_refs": ["evidence_refs:2"],
                "raw": "HTTP/1.1 200 OK\r\nCookie: sid=secret\r\n\r\n<html>private</html>",
            }
        ),
    )

    payload = run_sprint_tick(conn, target_name="demo", sprint_id="sprint-1")
    encoded = json.dumps(payload, ensure_ascii=False)

    assert payload["candidates"][0]["current_evidence"] == "[redacted-raw-data]"
    assert "sid=secret" not in encoded
    assert "<html>private" not in encoded
