import json
import sqlite3
from pathlib import Path

from db.burp_action_queue import (
    build_repeater_tab_name,
    create_burp_action,
    get_queued_burp_actions,
    mark_burp_action_failed,
    mark_burp_action_sent,
    mark_burp_action_skipped,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = PROJECT_ROOT / "TOOLS" / "db" / "schema.sql"


def _conn():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    conn.execute("INSERT INTO targets (id, target_name, domain) VALUES (1, 'demo', 'example.com')")
    conn.execute(
        """
        INSERT INTO work_items (
            id, target_name, lane, subject_table, subject_id, title, status, created_at, updated_at
        ) VALUES
          (101, 'demo', 'vuln_review', 'suspicious_points', 'SP-1', 'review 1', 'queued', '2026-07-14 10:00:00', '2026-07-14 10:00:00'),
          (102, 'demo', 'replay', 'hunt_queue', 'HQ-1', 'review 2', 'queued', '2026-07-14 10:01:00', '2026-07-14 10:01:00')
        """
    )
    conn.commit()
    return conn


def test_create_burp_action_persists_request_fields():
    conn = _conn()

    action_id = create_burp_action(
        conn,
        target_name="demo",
        work_item_id=101,
        method="POST",
        url="https://example.com/api/user/1",
        headers_json={"X-Test": "1"},
        body='{"id":1}',
        note="orig request",
        risk_class="safe_replay",
        repeater_tab_name=build_repeater_tab_name(target_name="demo", work_item_id=101, variant="orig"),
        burp_request_ref="history:55",
    )

    row = conn.execute("SELECT * FROM burp_actions WHERE id = ?", (action_id,)).fetchone()
    assert row["target_name"] == "demo"
    assert row["work_item_id"] == 101
    assert row["method"] == "POST"
    assert row["status"] == "queued"
    assert json.loads(row["headers_json"]) == {"X-Test": "1"}


def test_get_queued_burp_actions_returns_only_auto_allowed_risks_by_default():
    conn = _conn()
    safe_id = create_burp_action(
        conn,
        target_name="demo",
        work_item_id=101,
        method="GET",
        url="https://example.com/api/profile",
        risk_class="safe_replay",
        repeater_tab_name=build_repeater_tab_name(target_name="demo", work_item_id=101, variant="orig"),
    )
    sensitive_id = create_burp_action(
        conn,
        target_name="demo",
        work_item_id=101,
        method="GET",
        url="https://example.com/api/admin/user",
        risk_class="sensitive_read",
        repeater_tab_name=build_repeater_tab_name(target_name="demo", work_item_id=101, variant="ab"),
    )
    create_burp_action(
        conn,
        target_name="demo",
        work_item_id=102,
        method="POST",
        url="https://example.com/api/order/save",
        risk_class="state_changing",
        repeater_tab_name=build_repeater_tab_name(target_name="demo", work_item_id=102, variant="state"),
    )

    queued = get_queued_burp_actions(conn, target_name="demo")

    assert [row["id"] for row in queued] == [safe_id, sensitive_id]


def test_get_queued_burp_actions_allows_state_changing_only_when_explicitly_enabled():
    conn = _conn()
    safe_id = create_burp_action(
        conn,
        target_name="demo",
        work_item_id=101,
        method="GET",
        url="https://example.com/api/profile",
        risk_class="safe_replay",
    )
    state_id = create_burp_action(
        conn,
        target_name="demo",
        work_item_id=102,
        method="POST",
        url="https://example.com/api/order/save",
        risk_class="state_changing",
    )

    queued = get_queued_burp_actions(conn, target_name="demo", allow_state_changing=True)

    assert [row["id"] for row in queued] == [safe_id, state_id]


def test_high_risk_actions_are_never_returned_by_auto_queue():
    conn = _conn()
    create_burp_action(
        conn,
        target_name="demo",
        work_item_id=101,
        method="POST",
        url="https://example.com/api/rce",
        risk_class="high_risk",
    )

    queued = get_queued_burp_actions(conn, target_name="demo", allow_state_changing=True)

    assert queued == []


def test_mark_burp_action_sent_writes_repeater_evidence_ref():
    conn = _conn()
    action_id = create_burp_action(
        conn,
        target_name="demo",
        work_item_id=101,
        method="GET",
        url="https://example.com/api/user/1",
        note="send original",
        risk_class="safe_replay",
        repeater_tab_name=build_repeater_tab_name(target_name="demo", work_item_id=101, variant="orig"),
        burp_request_ref="history:55",
    )

    evidence_ref_id = mark_burp_action_sent(conn, action_id=action_id)

    action = conn.execute("SELECT status, sent_at FROM burp_actions WHERE id = ?", (action_id,)).fetchone()
    evidence = conn.execute("SELECT * FROM evidence_refs WHERE id = ?", (evidence_ref_id,)).fetchone()
    payload = json.loads(evidence["ref_json"])

    assert action["status"] == "sent"
    assert action["sent_at"] is not None
    assert evidence["source_table"] == "burp_actions"
    assert evidence["source_id"] == str(action_id)
    assert evidence["evidence_type"] == "repeater_tab"
    assert payload["repeater_tab_name"] == "demo-101-orig"
    assert payload["burp_request_ref"] == "history:55"


def test_mark_burp_action_failed_and_skipped_update_status():
    conn = _conn()
    failed_id = create_burp_action(conn, target_name="demo", work_item_id=101, method="GET", url="https://example.com/a")
    skipped_id = create_burp_action(conn, target_name="demo", work_item_id=101, method="GET", url="https://example.com/b")

    mark_burp_action_failed(conn, action_id=failed_id, error="burp offline")
    mark_burp_action_skipped(conn, action_id=skipped_id, error="operator deferred")

    failed = conn.execute("SELECT status, error FROM burp_actions WHERE id = ?", (failed_id,)).fetchone()
    skipped = conn.execute("SELECT status, error FROM burp_actions WHERE id = ?", (skipped_id,)).fetchone()
    assert failed["status"] == "failed"
    assert failed["error"] == "burp offline"
    assert skipped["status"] == "skipped"
    assert skipped["error"] == "operator deferred"


def test_build_repeater_tab_name_is_stable_across_supported_variants():
    assert build_repeater_tab_name(target_name="acme", work_item_id=12, variant="orig") == "acme-12-orig"
    assert build_repeater_tab_name(target_name="acme", work_item_id=12, variant="ab_swap") == "acme-12-ab"
    assert build_repeater_tab_name(target_name="acme", work_item_id=12, variant="unauthorized") == "acme-12-unauth"
    assert build_repeater_tab_name(target_name="acme", work_item_id=12, variant="state_change") == "acme-12-state"
