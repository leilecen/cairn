import json
import sqlite3
from pathlib import Path

from db.dispatcher import build_dispatch_plan, to_claude_agent_args, to_codex_spawn_args
from db.generic_probe import (
    build_generic_probe_plan,
    build_operator_gate_for_probe,
    create_generic_probe_work_items,
    normalize_probe_worker_result,
    upsert_probe_coverage,
)
from db.work_queue import block_work_item, claim_next, complete_work_item, partial_result

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = PROJECT_ROOT / "TOOLS" / "db" / "schema.sql"


def _conn():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    return conn


def test_generic_probes_are_generated_without_business_checklist():
    plan = build_generic_probe_plan(target_name="demo")

    keys = set(plan["auto_probe_keys"])
    assert "input_error_diff" in keys
    assert "method_content_type_auth_headers" in keys
    assert "cors_origin_host" in keys
    assert "api_graphql_swagger_sourcemap" in keys
    assert plan["coverage_contract"]["rule"].startswith("untested signals remain")


def test_high_risk_and_sensitive_probe_families_are_operator_gated():
    plan = build_generic_probe_plan(target_name="demo")
    gated_keys = {gate["probe_key"] for gate in plan["operator_gates"]}

    assert "weak_password_or_auth_boundary" in gated_keys
    assert "state_changing_or_high_load" in gated_keys
    assert "weak_password_or_auth_boundary" not in plan["auto_probe_keys"]

    gate = build_operator_gate_for_probe(target_name="demo", probe_key="weak_password_or_auth_boundary")
    assert gate["kind"] == "confirm_high_risk"
    assert "Confirm authorization" in gate["suggested_action"]


def test_each_auto_probe_creates_one_logic_probe_work_item():
    conn = _conn()
    result = create_generic_probe_work_items(conn, target_name="demo")

    rows = conn.execute("SELECT * FROM work_items ORDER BY id").fetchall()
    assert len(rows) == len(result["plan"]["auto_probe_keys"])
    assert {row["lane"] for row in rows} == {"logic_probe"}
    assert {row["subtype"] for row in rows} == {f"generic_probe:{key}" for key in result["plan"]["auto_probe_keys"]}


def test_dispatcher_passes_compact_generic_probe_contract_to_claude_and_codex():
    conn = _conn()
    # This assertion covers the legacy provider contract, not the v33+ human-focus gate.
    conn.execute("DELETE FROM schema_version")
    conn.execute("INSERT INTO schema_version(version,description) VALUES(32,'legacy dispatcher fixture')")
    create_generic_probe_work_items(conn, target_name="demo")

    plan = build_dispatch_plan(conn, target_name="demo", limit=2)
    assert plan["max_dispatch"] == 2
    assert len(plan["tasks"]) == 2

    item = plan["tasks"][0]
    codex = to_codex_spawn_args(item)
    claude = to_claude_agent_args(item)

    assert item["worker"] == "param-fuzzer"
    assert "rules/generic_probe_families.json" in codex["message"]
    assert "rules/generic_probe_families.json" in claude["prompt"]
    assert "operator gate" in codex["message"]
    assert "operator gate" in claude["prompt"]
    assert "raw HTML/JS/Burp" in codex["message"]


def test_probe_worker_result_is_compact_redacted_and_keeps_anomaly_hypothesis():
    result = normalize_probe_worker_result(
        {
            "status": "partial",
            "summary": "GET /api/user HTTP/1.1\r\nHost: example.test\r\nAuthorization: Bearer secretsecretsecretsecret",
            "evidence_refs": ["evidence_refs:1"],
            "confidence": "low",
            "anomaly": {"kind": "status_diff", "detail": "403 versus 200"},
            "hypothesis": "auth boundary may vary by header shape",
        }
    )
    encoded = json.dumps(result, ensure_ascii=False)

    assert result["summary"] == "[redacted-raw-data]"
    assert result["evidence_refs"] == ["evidence_refs:1"]
    assert result["anomaly"]["kind"] == "status_diff"
    assert "secretsecret" not in encoded


def test_probe_coverage_preserves_unknown_uncovered_blocked_states():
    conn = _conn()
    created = create_generic_probe_work_items(conn, target_name="demo")["created_work_items"][0]

    upsert_probe_coverage(
        conn,
        target_name="demo",
        work_item_id=created["work_item_id"],
        probe_key=created["probe_key"],
        status="blocked",
        confidence="low",
        evidence_refs=["evidence_refs:2"],
        summary="blocked before sensitive read",
        blocker_reason="operator approval required",
        next_action="ask operator",
    )

    row = conn.execute(
        "SELECT * FROM coverage_ledger WHERE item_key = ?",
        (f"generic_probe:{created['probe_key']}",),
    ).fetchone()
    assert row["status"] == "blocked"
    assert row["confidence"] == "low"
    assert json.loads(row["evidence_refs_json"]) == ["evidence_refs:2"]


def test_logic_probe_queue_lifecycle_syncs_coverage_and_suspicious_points_idempotently():
    conn = _conn()
    created = create_generic_probe_work_items(conn, target_name="demo")["created_work_items"][0]
    work_item_id = created["work_item_id"]
    probe_key = created["probe_key"]
    claim_next(conn, target_name="demo", agent_id="agent-a")

    partial_result(
        conn,
        work_item_id=work_item_id,
        agent_id="agent-a",
        payload={
            "status": "partial",
            "summary": "status shape differs; no boundary conclusion yet",
            "evidence_refs": ["evidence_refs:1"],
            "confidence": "low",
            "anomaly": {"kind": "status_diff", "summary": "403 versus 404"},
            "hypothesis": "auth boundary may depend on header shape",
        },
    )
    partial_result(
        conn,
        work_item_id=work_item_id,
        agent_id="agent-a",
        payload={
            "status": "partial",
            "summary": "GET /api/user HTTP/1.1\r\nHost: example.test\r\nCookie: sid=secret",
            "evidence_refs": ["evidence_refs:2"],
            "confidence": "low",
            "anomaly": {"kind": "status_diff", "summary": "still compact"},
        },
    )

    coverage = conn.execute(
        "SELECT status, evidence_refs_json, summary FROM coverage_ledger WHERE item_key = ?",
        (f"generic_probe:{probe_key}",),
    ).fetchone()
    points = conn.execute("SELECT * FROM suspicious_points WHERE source = 'generic_logic_probe'").fetchall()
    event_payload = json.loads(
        conn.execute(
            "SELECT payload_json FROM agent_events WHERE work_item_id = ? ORDER BY id DESC LIMIT 1",
            (work_item_id,),
        ).fetchone()["payload_json"]
    )

    assert coverage["status"] == "unknown"
    assert json.loads(coverage["evidence_refs_json"]) == ["evidence_refs:2"]
    assert coverage["summary"] == "[redacted-raw-data]"
    assert event_payload["worker_result"]["anomaly"] == {"kind": "status_diff", "summary": "still compact"}
    assert len(points) == 1
    assert json.loads(points[0]["evidence"]) == ["evidence_refs:1", "evidence_refs:2"]
    assert "secret" not in points[0]["reasoning"]
    assert points[0]["endpoint_fingerprint"] == f"demo:generic_probe:{work_item_id}:{probe_key}"

    complete_work_item(
        conn,
        work_item_id=work_item_id,
        agent_id="agent-a",
        summary="benign replay evidence collected",
        result_payload={
            "evidence_refs": ["evidence_refs:3"],
            "confidence": "medium",
            "coverage_status": "uncovered",
            "anomaly": {"kind": "missing_boundary", "summary": "missing origin guard observed"},
            "hypothesis": "missing origin guard on metadata endpoint",
            "risk_level": "medium",
        },
    )
    coverage = conn.execute(
        "SELECT status, confidence, evidence_refs_json FROM coverage_ledger WHERE item_key = ?",
        (f"generic_probe:{probe_key}",),
    ).fetchone()
    points = conn.execute("SELECT * FROM suspicious_points WHERE source = 'generic_logic_probe'").fetchall()

    assert coverage["status"] == "uncovered"
    assert coverage["confidence"] == "medium"
    assert json.loads(coverage["evidence_refs_json"]) == ["evidence_refs:3"]
    assert len(points) == 1
    assert json.loads(points[0]["evidence"]) == ["evidence_refs:1", "evidence_refs:2", "evidence_refs:3"]


def test_logic_probe_complete_without_evidence_stays_unknown_and_block_maps_blocked():
    conn = _conn()
    created = create_generic_probe_work_items(conn, target_name="demo")["created_work_items"]
    no_evidence_id = created[0]["work_item_id"]
    blocked_id = created[1]["work_item_id"]
    claim_next(conn, target_name="demo", agent_id="agent-a", limit=2)

    complete_work_item(
        conn,
        work_item_id=no_evidence_id,
        agent_id="agent-a",
        summary="looked but no evidence ref was produced",
    )
    block_work_item(
        conn,
        work_item_id=blocked_id,
        agent_id="agent-a",
        reason="auth gate required",
        blocker_class="auth_barrier",
        result_payload={"evidence_refs": ["evidence_refs:9"], "confidence": "low"},
    )

    rows = conn.execute("SELECT item_key, status, blocker_reason FROM coverage_ledger ORDER BY item_key").fetchall()
    statuses = {row["item_key"]: row["status"] for row in rows}
    blockers = {row["item_key"]: row["blocker_reason"] for row in rows}

    assert statuses[f"generic_probe:{created[0]['probe_key']}"] == "unknown"
    assert statuses[f"generic_probe:{created[1]['probe_key']}"] == "blocked"
    assert blockers[f"generic_probe:{created[1]['probe_key']}"] == "auth gate required"
    assert conn.execute("SELECT COUNT(*) FROM suspicious_points").fetchone()[0] == 0
