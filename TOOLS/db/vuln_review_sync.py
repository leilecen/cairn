"""Sync compact vuln_review worker results into findings/report work_items."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from db.worker_result import compact_public_payload, compact_public_text, normalize_worker_result

MIN_REPORTABLE_CONFIDENCE = {"medium", "high"}
OPERATOR_KINDS = {
    "auth_barrier": "login_required",
    "auth_required": "login_required",
    "login_required": "login_required",
    "secondary_account_required": "secondary_account_required",
    "multi_account_required": "secondary_account_required",
    "ab_required": "secondary_account_required",
    "a_b_required": "secondary_account_required",
    "role_required": "role_account_required",
    "role_account_required": "role_account_required",
    "confirm_scope": "confirm_scope",
    "critical_found": "confirm_high_risk",
    "high_risk": "confirm_high_risk",
    "manual_review": "manual_review",
    "sensitive_read": "manual_review",
}


def sync_vuln_review_result(
    conn: sqlite3.Connection,
    *,
    work_item: sqlite3.Row,
    worker_result: dict[str, Any],
) -> None:
    """Safely and idempotently promote one single_sp_review result.

    This hook consumes only the normalized compact worker_result. It never reads
    raw HTTP/HTML/JS/Burp bodies and never marks a finding confirmed.
    """

    if work_item["lane"] != "vuln_review" or work_item["subtype"] != "single_sp_review":
        return
    if work_item["subject_table"] != "suspicious_points":
        return

    result = normalize_vuln_review_worker_result(worker_result)
    sp = conn.execute("SELECT * FROM suspicious_points WHERE id = ?", (work_item["subject_id"],)).fetchone()
    if sp is None:
        return

    gate = _operator_gate_from_result_or_sp(result, sp)
    if result["status"] == "blocked":
        _update_sp_review_state(conn, sp_id=sp["id"], status="blocked", result=result)
        _ensure_operator_inbox(conn, work_item=work_item, result=result, sp=sp, kind=gate or "manual_review")
        return

    if result["status"] == "partial":
        _update_sp_review_state(conn, sp_id=sp["id"], status="review_partial", result=result)
        if gate:
            _ensure_operator_inbox(conn, work_item=work_item, result=result, sp=sp, kind=gate)
        return

    if gate:
        _update_sp_review_state(conn, sp_id=sp["id"], status="operator_required", result=result)
        _ensure_operator_inbox(conn, work_item=work_item, result=result, sp=sp, kind=gate)
        return

    if not _has_sufficient_evidence(result):
        _update_sp_review_state(conn, sp_id=sp["id"], status="review_insufficient_evidence", result=result)
        return

    if _has_non_candidate_finding(conn, sp_id=sp["id"]):
        _update_sp_review_state(conn, sp_id=sp["id"], status="review_existing_finding", result=result)
        return

    finding_id = _upsert_finding_candidate(conn, work_item=work_item, sp=sp, result=result)
    _update_sp_review_state(conn, sp_id=sp["id"], status="candidate", result=result)
    _ensure_evidence_pack_work_item(conn, work_item=work_item, finding_id=finding_id, result=result)


def normalize_vuln_review_worker_result(
    payload: dict[str, Any],
    *,
    expected_status: str | None = None,
) -> dict[str, Any]:
    """Normalize vuln_review output and preserve compact lifecycle flags."""

    result = normalize_worker_result(payload, expected_status=expected_status)
    if "operator_gate" in payload:
        result["operator_gate"] = compact_public_text(payload["operator_gate"], max_chars=120)
    return result


def _has_sufficient_evidence(result: dict[str, Any]) -> bool:
    if not result.get("evidence_refs"):
        return False
    explicit = result.get("sufficient_evidence")
    if explicit is not None:
        return bool(explicit)
    return result.get("confidence") in MIN_REPORTABLE_CONFIDENCE


def _operator_gate_from_result_or_sp(result: dict[str, Any], sp: sqlite3.Row) -> str | None:
    risk = str(result.get("risk_level") or sp["risk"] or "").strip().lower()
    if risk in {"high", "critical"}:
        return "confirm_high_risk"

    text = " ".join(
        str(value or "").lower()
        for value in (
            result.get("blocker"),
            result.get("block_reason"),
            result.get("next_action"),
            result.get("summary"),
            sp["reasoning"],
            sp["notes"],
            sp["auth_surface_type"],
            sp["signal_reason"],
        )
    )
    for token, kind in OPERATOR_KINDS.items():
        if token in text:
            return kind
    if any(token in text for token in ("authorization", "cookie", "bearer", "登录", "双账号", "授权边界", "高危")):
        return "manual_review"
    return None


def _upsert_finding_candidate(
    conn: sqlite3.Connection,
    *,
    work_item: sqlite3.Row,
    sp: sqlite3.Row,
    result: dict[str, Any],
) -> str:
    existing = conn.execute(
        """
        SELECT id
        FROM findings
        WHERE sp_id = ?
          AND COALESCE(review_status, 'candidate') = 'candidate'
        ORDER BY confirmed_at ASC, id ASC
        LIMIT 1
        """,
        (sp["id"],),
    ).fetchone()
    finding_id = existing["id"] if existing is not None else f"F-VR-{work_item['id']}"
    evidence = _finding_evidence_json(work_item=work_item, result=result)
    review_notes = _review_notes(result)
    target_id = _target_id(conn, work_item["target_name"])
    conn.execute(
        """
        INSERT INTO findings (
            id, sp_id, target_id, type, url, param, method, payload, evidence, risk,
            remediation, confirmed_at, review_status, review_notes, audit_status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, '', ?, ?, '', datetime('now','localtime'),
                  'candidate', ?, 'pending')
        ON CONFLICT(id) DO UPDATE SET
            evidence = excluded.evidence,
            risk = excluded.risk,
            review_status = 'candidate',
            review_notes = excluded.review_notes,
            audit_status = COALESCE(findings.audit_status, 'pending')
        """,
        (
            finding_id,
            sp["id"],
            target_id,
            sp["test_type"] or "vuln_review_candidate",
            sp["url"] or sp["page_url"] or "",
            sp["param"] or "",
            sp["method"] or "GET",
            evidence,
            _risk_title(result.get("risk_level") or sp["risk"] or "Medium"),
            review_notes,
        ),
    )
    return str(finding_id)


def _has_non_candidate_finding(conn: sqlite3.Connection, *, sp_id: str) -> bool:
    return (
        conn.execute(
            """
            SELECT 1 FROM findings
            WHERE sp_id=? AND COALESCE(review_status, 'candidate') <> 'candidate'
            LIMIT 1
            """,
            (sp_id,),
        ).fetchone()
        is not None
    )


def _ensure_evidence_pack_work_item(
    conn: sqlite3.Connection,
    *,
    work_item: sqlite3.Row,
    finding_id: str,
    result: dict[str, Any],
) -> None:
    existing = conn.execute(
        """
        SELECT 1
        FROM work_items
        WHERE target_name = ?
          AND lane = 'evidence_pack'
          AND subject_table = 'findings'
          AND subject_id = ?
          AND COALESCE(subtype, '') = 'vuln_review_candidate'
        LIMIT 1
        """,
        (work_item["target_name"], finding_id),
    ).fetchone()
    if existing is not None:
        return
    from db.work_queue import create_work_item  # noqa: PLC0415

    create_work_item(
        conn,
        target_name=work_item["target_name"],
        lane="evidence_pack",
        subtype="vuln_review_candidate",
        subject_table="findings",
        subject_id=finding_id,
        title=f"Prepare evidence pack for {finding_id}",
        objective=compact_public_text(
            f"finding={finding_id} | source_work_item={work_item['id']} | "
            f"summary={result.get('summary') or result.get('conclusion')} | "
            "raw_evidence_policy=use evidence_refs/fact tables only",
            max_chars=500,
        ),
        priority=65,
        model_tier="haiku",
        reasoning_tier="low",
        auth_requirement="unknown",
        risk_class="safe_passive",
        timebox_minutes=10,
        heartbeat_minutes=5,
        commit=False,
    )


def _ensure_operator_inbox(
    conn: sqlite3.Connection,
    *,
    work_item: sqlite3.Row,
    result: dict[str, Any],
    sp: sqlite3.Row,
    kind: str,
) -> None:
    inbox_kind = kind if kind in set(OPERATOR_KINDS.values()) else OPERATOR_KINDS.get(kind, "manual_review")
    existing = conn.execute(
        """
        SELECT 1
        FROM operator_inbox
        WHERE target_name = ?
          AND related_work_item_id = ?
          AND kind = ?
          AND status = 'open'
        LIMIT 1
        """,
        (work_item["target_name"], work_item["id"], inbox_kind),
    ).fetchone()
    if existing is not None:
        return
    conn.execute(
        """
        INSERT INTO operator_inbox (
            target_name, related_work_item_id, kind, title, detail, suggested_action,
            url, status, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 'open', datetime('now','localtime'))
        """,
        (
            work_item["target_name"],
            work_item["id"],
            inbox_kind,
            f"Review gate for suspicious point {sp['id']}",
            _review_notes(result),
            result.get("next_action") or "Confirm authorization/scope before further validation.",
            sp["url"] or sp["page_url"],
        ),
    )


def _update_sp_review_state(conn: sqlite3.Connection, *, sp_id: str, status: str, result: dict[str, Any]) -> None:
    conn.execute(
        """
        UPDATE suspicious_points
        SET test_status = ?,
            response_summary = ?,
            notes = ?
        WHERE id = ?
        """,
        (status, result.get("summary") or result.get("conclusion") or "", _review_notes(result), sp_id),
    )


def _finding_evidence_json(*, work_item: sqlite3.Row, result: dict[str, Any]) -> str:
    payload = {
        "schema": "vuln_review_candidate.v1",
        "source_work_item_id": int(work_item["id"]),
        "source_sp_id": work_item["subject_id"],
        "evidence_refs": result.get("evidence_refs", []),
        "summary": result.get("summary") or result.get("conclusion") or "",
        "confidence": result.get("confidence", "unknown"),
        "next_action": result.get("next_action", ""),
        "raw_evidence_policy": "evidence_refs/fact_tables_only",
    }
    return json.dumps(compact_public_payload(payload, max_chars=360), ensure_ascii=False, sort_keys=True)


def _review_notes(result: dict[str, Any]) -> str:
    return compact_public_text(
        " | ".join(
            item
            for item in (
                f"status={result.get('status')}",
                f"confidence={result.get('confidence')}",
                f"summary={result.get('summary') or result.get('conclusion')}",
                f"blocker={result.get('block_reason') or result.get('blocker')}",
                f"next={result.get('next_action')}",
            )
            if item and not item.endswith("=None") and not item.endswith("=")
        ),
        max_chars=800,
    )


def _target_id(conn: sqlite3.Connection, target_name: str) -> int | None:
    row = conn.execute(
        "SELECT id FROM targets WHERE target_name = ? ORDER BY id ASC LIMIT 1",
        (target_name,),
    ).fetchone()
    return int(row["id"]) if row is not None else None


def _risk_title(value: Any) -> str:
    text = str(value or "Medium").strip().lower()
    return {"low": "Low", "medium": "Medium", "high": "High", "critical": "Critical"}.get(text, "Medium")
