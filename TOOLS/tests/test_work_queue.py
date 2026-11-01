import json
import sqlite3
from datetime import datetime
from pathlib import Path

import db.vuln_review_sync as vuln_review_sync
import pytest
from db.attack_threads import create_attack_thread
from db.work_queue import (
    block_work_item,
    claim_next,
    complete_work_item,
    create_work_item,
    fail_work_item,
    get_active_work_items,
    get_open_operator_inbox,
    get_recent_agent_events,
    heartbeat,
    partial_result,
    reclaim_expired,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = PROJECT_ROOT / "TOOLS" / "db" / "schema.sql"


def _conn():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    return conn


def test_create_work_item_returns_new_id_and_defaults():
    conn = _conn()

    work_item_id = create_work_item(
        conn,
        target_name="demo",
        lane="quick_scout",
        subject_table="pages",
        subject_id="1",
        priority=70,
    )

    row = conn.execute("SELECT * FROM work_items WHERE id = ?", (work_item_id,)).fetchone()
    assert row["target_name"] == "demo"
    assert row["status"] == "queued"
    assert row["priority"] == 70
    assert row["attack_thread_id"] is None


def test_create_work_item_can_link_attack_thread():
    conn = _conn()
    thread_id = create_attack_thread(
        conn,
        target_name="demo",
        asset_url="https://example.com/app",
        hypothesis="export endpoint may expose sibling objects",
    )

    work_item_id = create_work_item(
        conn,
        target_name="demo",
        lane="logic_probe",
        subject_table="attack_threads",
        subject_id=str(thread_id),
        attack_thread_id=thread_id,
        priority=90,
    )

    row = conn.execute("SELECT * FROM work_items WHERE id = ?", (work_item_id,)).fetchone()
    assert row["attack_thread_id"] == thread_id


def test_claim_next_only_claims_each_task_once_and_honors_priority():
    conn = _conn()
    low = create_work_item(
        conn,
        target_name="demo",
        lane="quick_scout",
        subject_table="pages",
        subject_id="1",
        priority=10,
    )
    high = create_work_item(
        conn,
        target_name="demo",
        lane="quick_scout",
        subject_table="pages",
        subject_id="2",
        priority=90,
    )

    claimed = claim_next(conn, target_name="demo", agent_id="agent-a")
    claimed_again = claim_next(conn, target_name="demo", agent_id="agent-b")

    assert [row["id"] for row in claimed] == [high]
    assert [row["id"] for row in claimed_again] == [low]
    assert conn.execute("SELECT claimed_by FROM work_items WHERE id = ?", (high,)).fetchone()[0] == "agent-a"


def test_claim_next_prefers_queued_before_partial_and_skips_exhausted_items():
    conn = _conn()
    partial_id = create_work_item(
        conn,
        target_name="demo",
        lane="logic_probe",
        subject_table="hunt_queue",
        subject_id="1",
        priority=100,
    )
    queued_id = create_work_item(
        conn,
        target_name="demo",
        lane="logic_probe",
        subject_table="hunt_queue",
        subject_id="2",
        priority=20,
    )
    exhausted_id = create_work_item(
        conn,
        target_name="demo",
        lane="logic_probe",
        subject_table="hunt_queue",
        subject_id="3",
        priority=999,
    )
    owned_partial_id = create_work_item(
        conn,
        target_name="demo",
        lane="logic_probe",
        subject_table="hunt_queue",
        subject_id="4",
        priority=1000,
    )
    conn.execute(
        "UPDATE work_items SET status='partial', attempt_count=1 WHERE id = ?",
        (partial_id,),
    )
    conn.execute(
        """
        UPDATE work_items
        SET status='partial',
            claimed_by='agent-owner',
            claimed_at='2026-07-14 09:00:00',
            lease_until='2026-07-14 09:05:00',
            attempt_count=1
        WHERE id = ?
        """,
        (owned_partial_id,),
    )
    conn.execute(
        "UPDATE work_items SET attempt_count=max_attempts WHERE id = ?",
        (exhausted_id,),
    )
    conn.commit()

    claimed = claim_next(conn, target_name="demo", agent_id="agent-a", limit=2)

    assert [row["id"] for row in claimed] == [queued_id, partial_id]


def test_heartbeat_updates_work_item_and_writes_event():
    conn = _conn()
    work_item_id = create_work_item(conn, target_name="demo", lane="quick_scout", subject_table="pages", subject_id="1")
    claim_next(conn, target_name="demo", agent_id="agent-a")
    conn.execute(
        "UPDATE work_items SET lease_until='2026-07-14 09:05:00' WHERE id = ?",
        (work_item_id,),
    )
    conn.commit()

    heartbeat(conn, work_item_id=work_item_id, agent_id="agent-a", payload={"step": "ping"})

    item = conn.execute(
        "SELECT heartbeat_at, lease_until, updated_at FROM work_items WHERE id = ?",
        (work_item_id,),
    ).fetchone()
    event = conn.execute(
        "SELECT event_type, payload_json FROM agent_events WHERE work_item_id = ? ORDER BY id DESC LIMIT 1",
        (work_item_id,),
    ).fetchone()
    assert item["heartbeat_at"] is not None
    assert datetime.fromisoformat(item["lease_until"]) > datetime.fromisoformat(item["heartbeat_at"])
    assert item["updated_at"] is not None
    assert event["event_type"] == "heartbeat"
    assert '"step": "ping"' in event["payload_json"]


def test_partial_and_complete_write_events_and_update_state():
    conn = _conn()
    work_item_id = create_work_item(
        conn,
        target_name="demo",
        lane="js_reverse",
        subject_table="js_files",
        subject_id="5",
    )
    claim_next(conn, target_name="demo", agent_id="agent-a")

    partial_result(conn, work_item_id=work_item_id, agent_id="agent-a", payload={"summary": "found apis"})
    partial_row = conn.execute(
        "SELECT status, summary, claimed_by, lease_until FROM work_items WHERE id = ?",
        (work_item_id,),
    ).fetchone()
    assert partial_row["status"] == "partial"
    assert partial_row["summary"] == "found apis"
    assert partial_row["claimed_by"] == "agent-a"
    assert partial_row["lease_until"] is not None

    assert claim_next(conn, target_name="demo", agent_id="agent-b") == []
    with pytest.raises(ValueError, match="owned by agent-a"):
        complete_work_item(conn, work_item_id=work_item_id, agent_id="agent-b", summary="stolen")

    complete_work_item(conn, work_item_id=work_item_id, agent_id="agent-a", summary="done", next_action="review")
    final_row = conn.execute(
        "SELECT status, summary, next_action FROM work_items WHERE id = ?",
        (work_item_id,),
    ).fetchone()
    event_types = [
        row[0]
        for row in conn.execute(
            "SELECT event_type FROM agent_events WHERE work_item_id = ? ORDER BY id",
            (work_item_id,),
        ).fetchall()
    ]
    assert final_row["status"] == "done"
    assert final_row["summary"] == "done"
    assert final_row["next_action"] == "review"
    assert event_types[-2:] == ["partial_result", "done"]


def test_block_work_item_creates_operator_inbox_when_payload_present():
    conn = _conn()
    work_item_id = create_work_item(
        conn,
        target_name="demo",
        lane="logic_probe",
        subject_table="hunt_queue",
        subject_id="7",
    )
    claim_next(conn, target_name="demo", agent_id="agent-a")

    block_work_item(
        conn,
        work_item_id=work_item_id,
        agent_id="agent-a",
        reason="need second account",
        blocker_class="auth_barrier",
        operator_payload={
            "kind": "secondary_account_required",
            "title": "Need A/B account",
            "detail": "please prepare second account",
            "suggested_action": "login as user-b",
            "url": "https://example.com/login",
        },
    )

    item = conn.execute("SELECT status, blocker_reason FROM work_items WHERE id = ?", (work_item_id,)).fetchone()
    inbox = conn.execute(
        "SELECT kind, title, detail, suggested_action, url FROM operator_inbox WHERE related_work_item_id = ?",
        (work_item_id,),
    ).fetchone()
    event = conn.execute(
        "SELECT event_type, severity FROM agent_events WHERE work_item_id = ? ORDER BY id DESC LIMIT 1",
        (work_item_id,),
    ).fetchone()
    assert item["status"] == "blocked"
    assert item["blocker_reason"] == "need second account"
    assert inbox["kind"] == "secondary_account_required"
    assert event["event_type"] == "blocker"
    assert event["severity"] == "warning"


def test_fail_work_item_writes_failed_event_against_real_schema():
    conn = _conn()
    work_item_id = create_work_item(
        conn,
        target_name="demo",
        lane="logic_probe",
        subject_table="hunt_queue",
        subject_id="9",
    )
    claim_next(conn, target_name="demo", agent_id="agent-a")

    fail_work_item(conn, work_item_id=work_item_id, agent_id="agent-a", error="request timeout")

    item = conn.execute("SELECT status, last_error FROM work_items WHERE id = ?", (work_item_id,)).fetchone()
    event = conn.execute(
        "SELECT event_type, payload_json FROM agent_events WHERE work_item_id = ? ORDER BY id DESC LIMIT 1",
        (work_item_id,),
    ).fetchone()
    assert item["status"] == "failed"
    assert item["last_error"] == "request timeout"
    assert event["event_type"] == "failed"
    assert '"request timeout"' in event["payload_json"]


def test_reclaim_expired_requeues_empty_claims_and_preserves_partial_work():
    conn = _conn()
    empty_id = create_work_item(
        conn,
        target_name="demo",
        lane="quick_scout",
        subject_table="pages",
        subject_id="1",
        heartbeat_minutes=5,
        timebox_minutes=10,
    )
    partial_id = create_work_item(
        conn,
        target_name="demo",
        lane="js_reverse",
        subject_table="js_files",
        subject_id="2",
        heartbeat_minutes=5,
        timebox_minutes=10,
    )
    claim_next(conn, target_name="demo", agent_id="agent-a", limit=2)
    partial_result(conn, work_item_id=partial_id, agent_id="agent-a", payload={"summary": "got something"})

    conn.execute(
        """
        UPDATE work_items
        SET claimed_at='2026-07-14 09:00:00',
            lease_until='2026-07-14 09:05:00',
            heartbeat_at='2026-07-14 09:00:00'
        WHERE id IN (?, ?)
        """,
        (empty_id, partial_id),
    )
    conn.commit()

    summary = reclaim_expired(conn, now=datetime.fromisoformat("2026-07-14 09:20:00"))

    empty_row = conn.execute(
        "SELECT status, claimed_by, lease_until FROM work_items WHERE id = ?",
        (empty_id,),
    ).fetchone()
    partial_row = conn.execute(
        "SELECT status, claimed_by, lease_until FROM work_items WHERE id = ?",
        (partial_id,),
    ).fetchone()
    assert summary == {"requeued": 1, "partial_released": 1, "total": 2}
    assert empty_row["status"] == "queued"
    assert empty_row["claimed_by"] is None
    assert partial_row["status"] == "partial"
    assert partial_row["claimed_by"] is None

    reclaimed_partial = claim_next(conn, target_name="demo", agent_id="agent-b", lanes=["js_reverse"])
    assert [row["id"] for row in reclaimed_partial] == [partial_id]


def test_query_helpers_return_active_tasks_open_inbox_and_recent_events():
    conn = _conn()
    scout_id = create_work_item(conn, target_name="demo", lane="quick_scout", subject_table="pages", subject_id="1")
    reverse_id = create_work_item(conn, target_name="demo", lane="js_reverse", subject_table="js_files", subject_id="2")
    claim_next(conn, target_name="demo", agent_id="agent-a", limit=2)
    heartbeat(conn, work_item_id=scout_id, agent_id="agent-a", payload={"step": "a"})
    partial_result(conn, work_item_id=reverse_id, agent_id="agent-a", payload={"summary": "partial"})
    block_work_item(
        conn,
        work_item_id=scout_id,
        agent_id="agent-a",
        reason="need screenshot",
        blocker_class="evidence",
        operator_payload={"kind": "screenshot_needed", "title": "Take screenshot"},
    )

    active = get_active_work_items(conn, target_name="demo")
    inbox = get_open_operator_inbox(conn, target_name="demo")
    events = get_recent_agent_events(conn, target_name="demo", limit=3)

    assert [row["id"] for row in active] == [reverse_id]
    assert inbox[0]["kind"] == "screenshot_needed"
    assert len(events) == 3
    assert events[0]["event_type"] == "blocker"


def test_block_requires_valid_class_and_rolls_back_without_partial_state():
    conn = _conn()
    work_item_id = create_work_item(conn, target_name="demo", lane="logic_probe", subject_table="hunt_queue", subject_id="11")
    claim_next(conn, target_name="demo", agent_id="agent-a")

    with pytest.raises(ValueError, match="blocker_class is required"):
        block_work_item(conn, work_item_id=work_item_id, agent_id="agent-a", reason="unknown")
    with pytest.raises(ValueError, match="invalid blocker_class"):
        block_work_item(
            conn,
            work_item_id=work_item_id,
            agent_id="agent-a",
            reason="unknown",
            blocker_class="guessed",
        )

    row = conn.execute("SELECT status, blocker_class, claimed_by FROM work_items WHERE id=?", (work_item_id,)).fetchone()
    assert dict(row) == {"status": "claimed", "blocker_class": None, "claimed_by": "agent-a"}
    assert conn.execute("SELECT COUNT(*) FROM attack_threads").fetchone()[0] == 0


def test_block_settles_thread_event_and_one_decision_card_idempotently():
    conn = _conn()
    work_item_id = create_work_item(conn, target_name="demo", lane="logic_probe", subject_table="hunt_queue", subject_id="12")
    claim_next(conn, target_name="demo", agent_id="agent-a")

    block_work_item(
        conn,
        work_item_id=work_item_id,
        agent_id="agent-a",
        reason="need a second role",
        blocker_class="auth_barrier",
    )
    first = conn.execute("SELECT attack_thread_id FROM work_items WHERE id=?", (work_item_id,)).fetchone()[0]

    # A replayed settlement must not create another ledger row or card.
    conn.execute("UPDATE work_items SET status='claimed', claimed_by='agent-a' WHERE id=?", (work_item_id,))
    conn.commit()
    block_work_item(
        conn,
        work_item_id=work_item_id,
        agent_id="agent-a",
        reason="need a second role",
        blocker_class="auth_barrier",
    )

    item = conn.execute("SELECT status, blocker_class, attack_thread_id FROM work_items WHERE id=?", (work_item_id,)).fetchone()
    thread = conn.execute("SELECT target_name,status,evaluation_status FROM attack_threads WHERE id=?", (first,)).fetchone()
    event = conn.execute(
        "SELECT event_type,payload_json FROM attack_thread_events WHERE attack_thread_id=? AND event_type='parked'",
        (first,),
    ).fetchall()
    cards = conn.execute(
        "SELECT kind,action_key,blocking FROM operator_inbox WHERE related_work_item_id=? AND kind='blocked_decision'",
        (work_item_id,),
    ).fetchall()
    assert dict(item) == {"status": "blocked", "blocker_class": "auth_barrier", "attack_thread_id": first}
    assert dict(thread) == {"target_name": "demo", "status": "parked", "evaluation_status": "blocked"}
    assert len(event) == 1
    assert json.loads(event[0]["payload_json"])["blocker_class"] == "auth_barrier"
    assert len(cards) == 1
    assert cards[0]["action_key"] == f"blocked-work-{work_item_id}"
    assert cards[0]["blocking"] == 1


def test_complete_rolls_back_queue_state_when_lifecycle_sync_fails(monkeypatch):
    conn = _conn()
    conn.execute("INSERT INTO targets(id,target_name,domain) VALUES(1,'demo','example.com')")
    conn.execute(
        """
        INSERT INTO suspicious_points(id,url,test_type,risk,test_status)
        VALUES('SP-ROLLBACK','https://example.com/a','idor','Medium','untested')
        """
    )
    conn.commit()
    work_item_id = create_work_item(
        conn,
        target_name="demo",
        lane="vuln_review",
        subtype="single_sp_review",
        subject_table="suspicious_points",
        subject_id="SP-ROLLBACK",
    )
    claim_next(conn, target_name="demo", agent_id="reviewer")

    def fail_sync(*args, **kwargs):
        raise sqlite3.IntegrityError("forced sync failure")

    monkeypatch.setattr(vuln_review_sync, "sync_vuln_review_result", fail_sync)
    with pytest.raises(sqlite3.IntegrityError, match="forced sync failure"):
        complete_work_item(
            conn,
            work_item_id=work_item_id,
            agent_id="reviewer",
            summary="must roll back",
            result_payload={"confidence": "medium", "evidence_refs": ["evidence_refs:1"]},
        )

    item = conn.execute("SELECT status,claimed_by FROM work_items WHERE id=?", (work_item_id,)).fetchone()
    assert dict(item) == {"status": "claimed", "claimed_by": "reviewer"}
    assert conn.execute("SELECT COUNT(*) FROM agent_events WHERE work_item_id=? AND event_type='done'", (work_item_id,)).fetchone()[0] == 0
