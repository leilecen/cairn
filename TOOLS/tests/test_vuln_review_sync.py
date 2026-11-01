import json
import sqlite3
from pathlib import Path

from db.blackboard_seed import apply_seed
from db.work_queue import block_work_item, claim_next, complete_work_item, create_work_item, partial_result

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = PROJECT_ROOT / "TOOLS" / "db" / "schema.sql"


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    conn.execute("INSERT INTO targets (id, target_name, domain) VALUES (1, 'demo', 'example.com')")
    conn.execute(
        """
        INSERT INTO suspicious_points (
            id, page_url, url, param, method, test_type, evidence, source, reasoning, risk,
            test_status, created_at
        ) VALUES (
            'SP-VR-1', 'https://example.com/profile', 'https://example.com/api/profile',
            'id', 'GET', 'idor', '[7,8]', 'generic_logic_probe', 'compact candidate',
            'Medium', 'untested', '2026-07-27 10:00:00'
        )
        """
    )
    conn.commit()
    return conn


def _review_item(conn: sqlite3.Connection, sp_id: str = "SP-VR-1") -> int:
    item_id = create_work_item(
        conn,
        target_name="demo",
        lane="vuln_review",
        subtype="single_sp_review",
        subject_table="suspicious_points",
        subject_id=sp_id,
    )
    claim_next(conn, target_name="demo", agent_id="reviewer")
    return item_id


def test_vuln_review_done_creates_candidate_finding_and_one_evidence_pack():
    conn = _conn()
    item_id = _review_item(conn)

    complete_work_item(
        conn,
        work_item_id=item_id,
        agent_id="reviewer",
        summary="A/B semantic diff supports IDOR candidate",
        result_payload={
            "confidence": "medium",
            "risk_level": "medium",
            "evidence_refs": [7, "8"],
            "next_action": "prepare evidence pack",
        },
    )

    findings = conn.execute("SELECT * FROM findings").fetchall()
    packs = conn.execute("SELECT * FROM work_items WHERE lane = 'evidence_pack'").fetchall()
    sp = conn.execute("SELECT test_status FROM suspicious_points WHERE id = 'SP-VR-1'").fetchone()

    assert len(findings) == 1
    assert findings[0]["review_status"] == "candidate"
    assert findings[0]["sp_id"] == "SP-VR-1"
    assert findings[0]["audit_status"] == "pending"
    assert json.loads(findings[0]["evidence"])["evidence_refs"] == ["7", "8"]
    assert len(packs) == 1
    assert packs[0]["subject_table"] == "findings"
    assert packs[0]["subject_id"] == findings[0]["id"]
    assert packs[0]["subtype"] == "vuln_review_candidate"
    assert sp["test_status"] == "candidate"


def test_vuln_review_partial_blocked_and_insufficient_evidence_do_not_create_reports():
    conn = _conn()
    partial_id = _review_item(conn)
    partial_result(
        conn,
        work_item_id=partial_id,
        agent_id="reviewer",
        payload={"summary": "still comparing", "confidence": "low"},
    )

    conn.execute(
        """
        INSERT INTO suspicious_points (
            id, page_url, url, method, test_type, risk, test_status
        ) VALUES ('SP-BLOCK', 'https://example.com/a', 'https://example.com/api/a', 'GET', 'idor', 'Medium', 'untested')
        """
    )
    conn.commit()
    blocked_id = _review_item(conn, "SP-BLOCK")
    block_work_item(
        conn,
        work_item_id=blocked_id,
        agent_id="reviewer",
        reason="need second account",
        blocker_class="auth_barrier",
        result_payload={"confidence": "unknown", "next_action": "secondary_account_required"},
    )

    conn.execute(
        """
        INSERT INTO suspicious_points (
            id, page_url, url, method, test_type, risk, test_status
        ) VALUES (
            'SP-NOEVID', 'https://example.com/b', 'https://example.com/api/b',
            'GET', 'idor', 'Medium', 'untested'
        )
        """
    )
    conn.commit()
    no_evidence_id = _review_item(conn, "SP-NOEVID")
    complete_work_item(
        conn,
        work_item_id=no_evidence_id,
        agent_id="reviewer",
        summary="interesting but no evidence refs",
        result_payload={"confidence": "medium"},
    )

    assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM work_items WHERE lane = 'evidence_pack'").fetchone()[0] == 0
    statuses = {row["id"]: row["test_status"] for row in conn.execute("SELECT id, test_status FROM suspicious_points").fetchall()}
    assert statuses["SP-VR-1"] == "review_partial"
    assert statuses["SP-BLOCK"] == "blocked"
    assert statuses["SP-NOEVID"] == "review_insufficient_evidence"


def test_vuln_review_operator_gate_for_high_risk_or_auth_boundary_is_idempotent():
    conn = _conn()
    conn.execute(
        """
        UPDATE suspicious_points
        SET risk = 'High',
            reasoning = 'authorization boundary requires operator_required check'
        WHERE id = 'SP-VR-1'
        """
    )
    conn.commit()
    item_id = _review_item(conn)

    complete_work_item(
        conn,
        work_item_id=item_id,
        agent_id="reviewer",
        summary="Potential high impact, stop for confirmation",
        result_payload={"confidence": "high", "risk_level": "high", "evidence_refs": [9]},
    )

    assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM work_items WHERE lane = 'evidence_pack'").fetchone()[0] == 0
    inbox = conn.execute("SELECT kind, title FROM operator_inbox").fetchall()
    assert len(inbox) == 1
    assert inbox[0]["kind"] == "confirm_high_risk"


def test_explicit_false_and_high_confidence_does_not_promote():
    conn = _conn()
    item_id = _review_item(conn)

    complete_work_item(
        conn,
        work_item_id=item_id,
        agent_id="reviewer",
        summary="high confidence but evidence flag is explicitly false",
        result_payload={
            "confidence": "high",
            "risk_level": "medium",
            "evidence_refs": [7],
            "sufficient_evidence": False,
        },
    )

    assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 0
    assert conn.execute("SELECT test_status FROM suspicious_points WHERE id='SP-VR-1'").fetchone()[0] == "review_insufficient_evidence"


def test_explicit_true_without_evidence_refs_does_not_promote():
    conn = _conn()
    item_id = _review_item(conn)

    complete_work_item(
        conn,
        work_item_id=item_id,
        agent_id="reviewer",
        summary="flag without traceable evidence",
        result_payload={"confidence": "low", "sufficient_evidence": True},
    )

    assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 0
    assert conn.execute("SELECT test_status FROM suspicious_points WHERE id='SP-VR-1'").fetchone()[0] == "review_insufficient_evidence"


def test_existing_manually_confirmed_finding_is_never_downgraded_or_repacked():
    conn = _conn()
    conn.execute(
        """
        INSERT INTO findings(
            id,sp_id,target_id,type,url,method,evidence,risk,review_status,audit_status
        ) VALUES(
            'F-MANUAL','SP-VR-1',1,'idor','https://example.com/api/profile','GET',
            '{"source":"operator"}','High','confirmed','verified'
        )
        """
    )
    conn.commit()
    item_id = _review_item(conn)

    complete_work_item(
        conn,
        work_item_id=item_id,
        agent_id="reviewer",
        summary="automated review must not overwrite operator state",
        result_payload={
            "confidence": "medium",
            "risk_level": "medium",
            "evidence_refs": [7],
            "sufficient_evidence": True,
        },
    )

    finding = conn.execute("SELECT review_status,audit_status,evidence,risk FROM findings WHERE id='F-MANUAL'").fetchone()
    assert dict(finding) == {
        "review_status": "confirmed",
        "audit_status": "verified",
        "evidence": '{"source":"operator"}',
        "risk": "High",
    }
    assert conn.execute("SELECT COUNT(*) FROM findings WHERE sp_id='SP-VR-1'").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM work_items WHERE lane='evidence_pack'").fetchone()[0] == 0
    assert conn.execute("SELECT test_status FROM suspicious_points WHERE id='SP-VR-1'").fetchone()[0] == "review_existing_finding"


def test_vuln_review_sync_payloads_stay_compact_and_seed_does_not_duplicate_pack():
    conn = _conn()
    item_id = _review_item(conn)
    raw = "GET /secret HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer abcdefghijklmnopqrstuvwxyz"

    complete_work_item(
        conn,
        work_item_id=item_id,
        agent_id="reviewer",
        summary=raw,
        result_payload={
            "confidence": "medium",
            "risk_level": "medium",
            "evidence_refs": [7],
            "next_action": raw,
            "sufficient_evidence": True,
        },
    )
    seed = apply_seed(conn, target_name="demo", dry_run=False)

    finding = conn.execute("SELECT evidence, review_notes FROM findings").fetchone()
    pack = conn.execute("SELECT objective FROM work_items WHERE lane = 'evidence_pack'").fetchone()
    combined = f"{finding['evidence']} {finding['review_notes']} {pack['objective']}"

    assert "Authorization:" not in combined
    assert "Bearer" not in combined
    assert "[redacted-raw-data]" in combined
    assert conn.execute("SELECT COUNT(*) FROM work_items WHERE lane = 'evidence_pack'").fetchone()[0] == 1
    assert seed["by_lane"].get("evidence_pack") is None
