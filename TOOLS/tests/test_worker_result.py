import json
import sqlite3
from pathlib import Path

import pytest
from db.blackboard_view import build_blackboard_view
from db.work_queue import (
    block_work_item,
    claim_next,
    complete_work_item,
    create_work_item,
    partial_result,
)
from db.worker_result import normalize_worker_result

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = PROJECT_ROOT / "TOOLS" / "db" / "schema.sql"


def _conn():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    return conn


def test_done_result_normalizes_aliases_and_optional_fields():
    result = normalize_worker_result(
        {
            "status": "DONE",
            "summary": "verified candidate from evidence refs",
            "evidence_ids": [1, "E-2", {"id": "shot-3"}],
            "confidence": "med",
            "risk": "high",
            "upgrade_request": {"tier": "standard", "reason": "needs semantic diff"},
            "next_action": "main review",
        }
    )

    assert result["status"] == "done"
    assert result["conclusion"] == "verified candidate from evidence refs"
    assert result["evidence_refs"] == ["1", "E-2", "shot-3"]
    assert result["confidence"] == "medium"
    assert result["risk_level"] == "high"
    assert result["upgrade_request"]["requested_tier"] == "standard"


def test_worker_result_compacts_bounded_insight_proposals():
    result = normalize_worker_result(
        {
            "status": "partial",
            "summary": "bounded observation",
            "insight_proposals": [
                {
                    "summary": "login endpoint hints at a separate admin path",
                    "trigger": "admin title",
                    "asset_id": 7,
                    "evidence_refs": ["ev:1"],
                    "next_action": "operator accepts a bounded validation",
                }
            ],
        }
    )

    assert result["insight_proposals"] == [
        {
            "summary": "login endpoint hints at a separate admin path",
            "trigger": "admin title",
            "asset_id": 7,
            "evidence_refs": ["ev:1"],
            "next_action": "operator accepts a bounded validation",
        }
    ]


def test_partial_and_blocked_results_keep_fixed_shape():
    partial = normalize_worker_result({"status": "partial", "summary": "found login API"})
    blocked = normalize_worker_result(
        {
            "status": "blocked",
            "reason": "need second account",
            "blocker": "auth_barrier",
            "confidence": "low",
        }
    )

    assert set(
        [
            "status",
            "conclusion",
            "summary",
            "evidence_refs",
            "confidence",
            "blocker",
            "block_reason",
            "next_action",
        ]
    ).issubset(partial)
    assert partial["status"] == "partial"
    assert blocked["status"] == "blocked"
    assert blocked["block_reason"] == "need second account"


def test_missing_or_illegal_status_is_rejected():
    with pytest.raises(ValueError, match="status is required"):
        normalize_worker_result({})

    with pytest.raises(ValueError, match="must be one of"):
        normalize_worker_result({"status": "claimed", "summary": "not terminal or partial"})

    with pytest.raises(ValueError, match="must be 'done'"):
        normalize_worker_result({"status": "partial", "summary": "wrong transition"}, expected_status="done")


def test_sufficient_evidence_is_preserved_only_as_a_boolean():
    assert normalize_worker_result({"status": "done", "summary": "reviewed", "sufficient_evidence": False})["sufficient_evidence"] is False

    with pytest.raises(ValueError, match="sufficient_evidence must be a boolean"):
        normalize_worker_result({"status": "done", "summary": "reviewed", "sufficient_evidence": "false"})


def test_raw_or_overlong_data_is_redacted_and_truncated():
    raw = "HTTP/1.1 200 OK\r\nSet-Cookie: sid=secret\r\n\r\n" + ("A" * 5000)
    result = normalize_worker_result(
        {
            "status": "done",
            "summary": raw,
            "next_action": "x" * 5000,
            "confidence": "high",
        }
    )
    encoded = json.dumps(result, ensure_ascii=False)

    assert result["summary"] == "[redacted-raw-data]"
    assert len(result["next_action"]) <= 800
    assert "sid=secret" not in encoded
    assert result["redactions"] == ["raw_or_long_data_removed"]


def test_raw_html_js_and_http_secrets_are_removed_but_evidence_refs_survive():
    raw = {
        "status": "partial",
        "summary": "<!doctype html><html><script>webpackJsonp=[];function x(){}</script>",
        "conclusion": "GET /api/user HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer secretsecretsecretsecret",
        "evidence_refs": ["evidence_refs:12", {"id": "burp:99"}],
        "next_action": "Cookie: sid=abc123",
    }

    result = normalize_worker_result(raw)
    encoded = json.dumps(result, ensure_ascii=False)

    assert result["summary"] == "[redacted-raw-data]"
    assert result["conclusion"] == "[redacted-raw-data]"
    assert result["next_action"] == "[redacted-raw-data]"
    assert result["evidence_refs"] == ["evidence_refs:12", "burp:99"]
    assert "secretsecret" not in encoded
    assert "webpackJsonp" not in encoded


def test_work_queue_events_store_worker_result_contract_and_view_exposes_it():
    conn = _conn()
    partial_id = create_work_item(conn, target_name="demo", lane="quick_scout", subject_table="pages", subject_id="1")
    done_id = create_work_item(conn, target_name="demo", lane="js_reverse", subject_table="js_files", subject_id="2")
    blocked_id = create_work_item(
        conn,
        target_name="demo",
        lane="logic_probe",
        subject_table="hunt_queue",
        subject_id="3",
    )
    claim_next(conn, target_name="demo", agent_id="agent-a", limit=3)

    partial_result(
        conn,
        work_item_id=partial_id,
        agent_id="agent-a",
        payload={"status": "partial", "summary": "mapped 3 endpoints", "evidence_refs": ["api-1"]},
    )
    complete_work_item(
        conn,
        work_item_id=done_id,
        agent_id="agent-a",
        summary="signature chain summarized",
        next_action="queue replay",
        result_payload={"confidence": "high", "evidence_ids": [7]},
    )
    block_work_item(
        conn,
        work_item_id=blocked_id,
        agent_id="agent-a",
        reason="need role account",
        blocker_class="auth_barrier",
        result_payload={"blocker": "role_account_required", "confidence": "medium"},
    )

    events = conn.execute(
        "SELECT event_type, payload_json FROM agent_events ORDER BY id",
    ).fetchall()
    payloads = [json.loads(row["payload_json"]) for row in events]
    view = build_blackboard_view(conn, target_name="demo")

    assert all("worker_result" in payload for payload in payloads)
    assert [item["status"] for item in view["recent_worker_results"]] == ["blocked", "done", "partial"]
    assert view["recent_worker_results"][1]["evidence_refs"] == ["7"]
