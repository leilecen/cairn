import json
import sqlite3
from pathlib import Path

from db.attack_threads import create_attack_thread, update_attack_thread
from db.sprint_candidate_gate import evaluate_attack_thread_candidate

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = PROJECT_ROOT / "TOOLS" / "db" / "schema.sql"


def _conn():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    return conn


def _thread_with_evidence(conn, evidence):
    thread_id = create_attack_thread(
        conn,
        target_name="demo",
        asset_url=evidence.get("asset", "https://example.com"),
        hypothesis=evidence.get("hypothesis", "test hypothesis"),
        why_promising="seeded test evidence",
        priority=80,
        owner="test",
        sprint_id="demo-sprint",
    )
    update_attack_thread(
        conn,
        attack_thread_id=thread_id,
        current_evidence=json.dumps(evidence, ensure_ascii=False),
    )
    return thread_id


def test_personal_info_requires_three_classes_and_two_successes():
    conn = _conn()
    thread_id = _thread_with_evidence(
        conn,
        {
            "type": "personal_info_idor",
            "endpoint": "https://example.com/api/order/export",
            "hypothesis": "id parameter reads another user's order",
            "objects_tested": [
                {
                    "object_id": "1001",
                    "same_business_object": True,
                    "unauthorized_success": True,
                    "pii_classes": ["name", "phone", "address"],
                    "request_ref": "evidence_refs:1",
                    "response_ref": "evidence_refs:2",
                },
                {
                    "object_id": "1002",
                    "same_business_object": True,
                    "unauthorized_success": True,
                    "pii_classes": ["name", "phone", "address"],
                    "request_ref": "evidence_refs:3",
                    "response_ref": "evidence_refs:4",
                },
            ],
            "missing_proof": "operator screenshot",
        },
    )

    result = evaluate_attack_thread_candidate(conn, attack_thread_id=thread_id)

    assert result["classification"] == "B"
    assert result["success_count"] == 2
    assert result["tested_count"] == 2
    assert result["should_stop"] is True
    assert result["missing_proof"] == "operator screenshot"


def test_single_field_personal_info_stays_a_class():
    conn = _conn()
    thread_id = _thread_with_evidence(
        conn,
        {
            "type": "personal_info_idor",
            "objects_tested": [
                {
                    "object_id": "1001",
                    "same_business_object": True,
                    "unauthorized_success": True,
                    "pii_classes": ["phone"],
                },
                {
                    "object_id": "1002",
                    "same_business_object": True,
                    "unauthorized_success": True,
                    "pii_classes": ["phone"],
                },
            ],
        },
    )

    result = evaluate_attack_thread_candidate(conn, attack_thread_id=thread_id)

    assert result["classification"] == "A"
    assert "three personal-info classes" in result["reason"]


def test_cross_interface_without_same_object_is_killed():
    conn = _conn()
    thread_id = _thread_with_evidence(
        conn,
        {
            "type": "personal_info_idor",
            "objects_tested": [
                {
                    "object_id": "1001",
                    "same_business_object": False,
                    "unauthorized_success": True,
                    "pii_classes": ["name", "phone", "address"],
                },
                {
                    "object_id": "1002",
                    "same_business_object": False,
                    "unauthorized_success": True,
                    "pii_classes": ["name", "phone", "address"],
                },
            ],
        },
    )

    result = evaluate_attack_thread_candidate(conn, attack_thread_id=thread_id)

    assert result["classification"] == "kill"
    assert "same business object" in result["reason"]


def test_personal_info_shape_without_type_cannot_fall_back_to_generic_b():
    conn = _conn()
    thread_id = _thread_with_evidence(
        conn,
        {
            "hypothesis": "id parameter reads another user's profile",
            "request_refs": ["evidence_refs:10"],
            "response_refs": ["evidence_refs:11"],
            "objects_tested": [
                {
                    "object_id": "1001",
                    "same_business_object": True,
                    "unauthorized_success": True,
                    "pii_classes": ["phone"],
                }
            ],
        },
    )

    result = evaluate_attack_thread_candidate(conn, attack_thread_id=thread_id)

    assert result["classification"] == "A"
    assert "personal-info gate" in result["reason"]


def test_high_value_signal_escalates_without_becoming_b_candidate():
    conn = _conn()
    thread_id = _thread_with_evidence(
        conn,
        {
            "type": "rce",
            "hypothesis": "template preview may execute code",
            "request_refs": ["evidence_refs:20"],
            "response_refs": ["evidence_refs:21"],
        },
    )

    result = evaluate_attack_thread_candidate(conn, attack_thread_id=thread_id)

    assert result["classification"] == "high_value_escalation"
    assert result["classification"] != "B"
    assert result["should_stop"] is True


def test_personal_info_gate_caps_tested_objects_at_three():
    conn = _conn()
    thread_id = _thread_with_evidence(
        conn,
        {
            "type": "personal_info_idor",
            "objects_tested": [
                {
                    "object_id": "1001",
                    "same_business_object": True,
                    "unauthorized_success": False,
                    "pii_classes": ["name", "phone", "address"],
                },
                {
                    "object_id": "1002",
                    "same_business_object": True,
                    "unauthorized_success": False,
                    "pii_classes": ["name", "phone", "address"],
                },
                {
                    "object_id": "1003",
                    "same_business_object": True,
                    "unauthorized_success": False,
                    "pii_classes": ["name", "phone", "address"],
                },
                {
                    "object_id": "1004",
                    "same_business_object": True,
                    "unauthorized_success": True,
                    "pii_classes": ["name", "phone", "address"],
                },
            ],
        },
    )

    result = evaluate_attack_thread_candidate(conn, attack_thread_id=thread_id)

    assert result["classification"] == "kill"
    assert result["tested_count"] == 3
    assert result["success_count"] == 0
    assert result["should_stop"] is True
