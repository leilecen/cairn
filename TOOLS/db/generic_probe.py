"""Generic progressive low-risk probe planning for logic_probe work_items.

This module is deliberately a planner/contract layer only.  It does not send
network traffic and does not implement scanner or exploit logic.  The main
session can use it to seed one compact ``logic_probe`` work_item per safe probe
family, while operator-gated probes are returned as gate plans for explicit
human approval.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from db.work_queue import create_work_item
from db.worker_result import compact_public_payload, normalize_worker_result

RULES_PATH = "rules/generic_probe_families.json"
RULES_ABSPATH = Path(__file__).resolve().parents[2] / RULES_PATH

SAFE_LEVELS = {"L0_PASSIVE", "L1_LOW_RISK"}
GATED_LEVELS = {"L2_SENSITIVE", "L3_STATE_CHANGING", "L4_HIGH_RISK"}
GATED_RISK_CLASSES = {"sensitive_read", "state_changing", "high_risk"}
SENSITIVE_TERMS = {"cookie", "authorization", "bearer", "password", "passwd", "secret", "token"}
MAX_SUMMARY_CHARS = 360
VALID_COVERAGE_STATUSES = {"covered", "unknown", "uncovered", "blocked"}


@dataclass(frozen=True)
class ProbeFamily:
    key: str
    category: str
    level: str
    risk_class: str
    auth_requirement: str
    title: str
    summary: str
    signals: tuple[str, ...]
    safe_actions: tuple[str, ...]
    gate_triggers: tuple[str, ...] = ()

    @property
    def auto_dispatchable(self) -> bool:
        return self.level in SAFE_LEVELS and self.risk_class not in GATED_RISK_CLASSES


PROBE_FAMILIES: tuple[ProbeFamily, ...] = (
    ProbeFamily(
        key="bbzl_oss",
        category="exposure_boundary",
        level="L1_LOW_RISK",
        risk_class="safe_passive",
        auth_requirement="optional",
        title="OSS object-storage path predictability probe",
        summary=(
            "Low-volume HEAD probes for OSS path predictability: confirm "
            "YYYY-MM/random-name layout, check common sensitive filenames, "
            "and map which monthly directories exist via 403/404 oracle."
        ),
        signals=("oss", "object_storage", "path_predictability", "directory_oracle"),
        safe_actions=(
            "HEAD-only low-frequency checks (>=2s interval)",
            "reuse already-known OSS path formats",
            "never download file bodies",
        ),
        gate_triggers=("accessible sensitive file content", "bulk directory enumeration"),
    ),
    ProbeFamily(
        key="input_error_diff",
        category="input_boundary",
        level="L1_LOW_RISK",
        risk_class="safe_replay",
        auth_requirement="optional",
        title="Input encoding and error-difference probe",
        summary=("Compare benign boundary values for input type, quote escaping, parser errors, and status/body-shape deltas."),
        signals=("input_type", "quote_escape", "error_diff", "status_diff"),
        safe_actions=("single benign replay per selected endpoint", "semantic response summary only"),
    ),
    ProbeFamily(
        key="method_content_type_auth_headers",
        category="protocol_boundary",
        level="L1_LOW_RISK",
        risk_class="safe_replay",
        auth_requirement="optional",
        title="Method, Content-Type, and auth-header boundary probe",
        summary=("Check non-mutating method handling, content-type mismatch, missing auth-header shape, and safe OPTIONS metadata."),
        signals=("method", "content_type", "auth_header_presence", "options_allow"),
        safe_actions=("GET/HEAD/OPTIONS or dry-run equivalent only", "do not attempt privileged actions"),
    ),
    ProbeFamily(
        key="id_state_replay_shape",
        category="state_boundary",
        level="L1_LOW_RISK",
        risk_class="safe_replay",
        auth_requirement="optional",
        title="ID, state, and duplicate-submit shape probe",
        summary=("Look for ID/status/retry hints using known benign requests; block before reading sensitive records or changing state."),
        signals=("id_shape", "status_field", "duplicate_submit_hint", "idempotency_hint"),
        safe_actions=("metadata comparison only", "no cross-user object reads without explicit gate"),
        gate_triggers=("cross-account object access", "state transition", "duplicate order/payment/action"),
    ),
    ProbeFamily(
        key="cors_origin_host",
        category="trust_boundary",
        level="L1_LOW_RISK",
        risk_class="safe_replay",
        auth_requirement="none",
        title="CORS, Origin, and Host trust-boundary probe",
        summary="Inspect CORS/Origin/Host response metadata with benign origins and no credential exfiltration.",
        signals=("cors", "origin", "host", "cache_vary"),
        safe_actions=("header-only response summary", "no browser credentialed exploit flow"),
    ),
    ProbeFamily(
        key="file_export_debug_config_discovery",
        category="exposure_boundary",
        level="L1_LOW_RISK",
        risk_class="safe_passive",
        auth_requirement="optional",
        title="File, export, debug, and config exposure discovery",
        summary=("Plan low-volume discovery for file/export/debug/config signals already present in collected URLs or summaries."),
        signals=("file", "export", "debug", "config", "download"),
        safe_actions=("reuse known endpoints", "do not enumerate paths aggressively"),
        gate_triggers=("sensitive file read", "bulk export", "private config content"),
    ),
    ProbeFamily(
        key="filedownload-notoken-shape",
        category="exposure_boundary",
        level="L1_LOW_RISK",
        risk_class="safe_passive",
        auth_requirement="none",
        title="noToken whitelist file-download shape probe",
        summary=(
            "Low-volume shape probe on a gateway noToken whitelist "
            "fileDownload endpoint: param-name enumeration, method and "
            "Content-Type variants, response-shape differences (empty "
            "body/error/redirect/Content-Disposition). No real file reads."
        ),
        signals=("noToken", "file_download", "param_shape", "response_shape", "gate_bypass"),
        safe_actions=(
            "single low-frequency benign requests (>=2s interval)",
            "param-name/method/Content-Type shape variants only",
            "never fetch real file bodies or enumerate directories",
        ),
        gate_triggers=("accessible sensitive file content", "path traversal signal", "bulk enumeration"),
    ),
    ProbeFamily(
        key="auth2-login-shape",
        category="auth_boundary",
        level="L1_LOW_RISK",
        risk_class="safe_passive",
        auth_requirement="none",
        title="External auth2 login endpoint shape probe",
        summary=(
            "Low-volume shape probe on an external (outer) login endpoint: "
            "JSON type-juggling, parameter-name and Content-Type variants, "
            "root non-object/batch/malformed shapes, and response-shape "
            "differences. No credential enumeration, guessing, or brute force."
        ),
        signals=("auth2", "login_shape", "json_type_juggling", "param_shape", "response_shape"),
        safe_actions=(
            "single low-frequency benign requests (>=2s interval)",
            "param-name/value-type/Content-Type shape variants only",
            "never attempt credentials, weak passwords, or enumeration",
        ),
        gate_triggers=(
            "credential attempt or account enumeration signal",
            "auth boundary or lockout impact",
        ),
    ),
    ProbeFamily(
        key="api_graphql_swagger_sourcemap",
        category="api_surface",
        level="L1_LOW_RISK",
        risk_class="safe_passive",
        auth_requirement="optional",
        title="API, GraphQL, Swagger, and source-map surface probe",
        summary=("Check whether already discovered API docs, GraphQL endpoints, Swagger, source maps, or chunks need scoped follow-up."),
        signals=("api_prefix", "graphql", "swagger", "openapi", "source_map", "chunk"),
        safe_actions=(
            "metadata fetch only",
            "schema/introspection requires local rules and operator gate if target policy is unclear",
        ),
        gate_triggers=("GraphQL introspection against restricted endpoint", "source map contains secrets"),
    ),
    ProbeFamily(
        key="weak_password_or_auth_boundary",
        category="auth_boundary",
        level="L4_HIGH_RISK",
        risk_class="high_risk",
        auth_requirement="required",
        title="Weak-password or authentication-boundary probe",
        summary="Any weak password, brute force, lockout, MFA, or account-boundary test requires operator approval.",
        signals=("weak_password", "bruteforce", "lockout", "mfa", "role_boundary"),
        safe_actions=(),
        gate_triggers=("weak credential attempt", "authentication boundary", "rate/lockout impact"),
    ),
    ProbeFamily(
        key="state_changing_or_high_load",
        category="safety_boundary",
        level="L3_STATE_CHANGING",
        risk_class="state_changing",
        auth_requirement="unknown",
        title="State-changing, destructive, concurrent, or high-load probe",
        summary=("Mutation, deletion, upload, purchase, workflow transition, concurrency, and load probes must not run automatically."),
        signals=("mutation", "delete", "upload", "purchase", "concurrency", "high_load"),
        safe_actions=(),
        gate_triggers=("state change", "destructive action", "concurrency/high load"),
    ),
)


def build_generic_probe_plan(*, target_name: str, target_summary: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build a compact provider-neutral generic probe plan.

    The plan is open-ended: it does not require a business checklist or semantic
    profile.  Unknown/uncovered/blocked coverage is kept explicit.
    """

    summary = compact_public_payload(target_summary or {}, max_chars=MAX_SUMMARY_CHARS)
    probes = [_family_plan(family, target_name=target_name, target_summary=summary) for family in PROBE_FAMILIES]
    return {
        "target_name": target_name,
        "rules_path": RULES_PATH,
        "progressive_levels": {
            "L0_PASSIVE": "metadata-only planning; no network action",
            "L1_LOW_RISK": "low-volume benign probes may be auto-dispatched as one work_item per family",
            "L2_SENSITIVE": "sensitive data/auth boundary requires operator gate",
            "L3_STATE_CHANGING": "state-changing/concurrency/high-load requires operator gate",
            "L4_HIGH_RISK": "destructive, weak credential, or high-risk validation requires operator gate",
        },
        "probes": probes,
        "auto_probe_keys": [item["key"] for item in probes if item["auto_dispatchable"]],
        "operator_gates": [item["operator_gate"] for item in probes if item["operator_gate"]],
        "worker_result_contract": {
            "required": [
                "status",
                "conclusion",
                "summary",
                "evidence_refs",
                "confidence",
                "blocker",
                "block_reason",
                "next_action",
            ],
            "optional": ["risk_level", "anomaly", "hypothesis", "upgrade_request"],
            "large_data_policy": ("never include raw HTML/JS/Burp bodies, Cookie, Authorization, or full request/response data"),
        },
        "coverage_contract": {
            "table": "coverage_ledger",
            "statuses": ["covered", "unknown", "uncovered", "blocked"],
            "rule": "untested signals remain unknown/uncovered/blocked; never mark untested areas safe",
        },
    }


def create_generic_probe_work_items(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    subject_table: str = "targets",
    subject_id: str = "generic",
    target_summary: dict[str, Any] | None = None,
    priority: int = 55,
) -> dict[str, Any]:
    """Create one ``logic_probe`` work_item for each auto-safe probe family.

    Operator-gated families are returned in the plan but are not inserted as
    automatic work_items.
    """

    plan = build_generic_probe_plan(target_name=target_name, target_summary=target_summary)
    created: list[dict[str, Any]] = []
    for probe in plan["probes"]:
        if not probe["auto_dispatchable"]:
            continue
        work_item_id = create_work_item(
            conn,
            target_name=target_name,
            lane="logic_probe",
            subtype=f"generic_probe:{probe['key']}",
            subject_table=subject_table,
            subject_id=f"{subject_id}:{probe['key']}",
            title=probe["title"],
            objective=json.dumps(
                {
                    "probe_key": probe["key"],
                    "rules_path": RULES_PATH,
                    "summary": probe["summary"],
                    "signals": probe["signals"],
                    "safe_actions": probe["safe_actions"],
                    "worker_result_contract": plan["worker_result_contract"],
                    "coverage_contract": plan["coverage_contract"],
                },
                ensure_ascii=False,
                sort_keys=True,
            ),
            priority=priority,
            model_tier="sonnet",
            reasoning_tier="low",
            auth_requirement=probe["auth_requirement"],
            risk_class=probe["risk_class"],
            timebox_minutes=10,
            heartbeat_minutes=5,
        )
        created.append({"probe_key": probe["key"], "work_item_id": work_item_id})
    return {"plan": plan, "created_work_items": created, "operator_gates": plan["operator_gates"]}


def build_operator_gate_for_probe(
    *,
    target_name: str,
    probe_key: str,
    related_work_item_id: int | None = None,
) -> dict[str, Any]:
    """Return an operator_inbox-compatible gate payload for a gated probe."""

    family = _family_by_key(probe_key)
    if family.auto_dispatchable:
        raise ValueError(f"probe {probe_key!r} is auto-dispatchable and does not require a gate")
    return {
        "target_name": target_name,
        "related_work_item_id": related_work_item_id,
        "kind": "confirm_high_risk" if family.risk_class == "high_risk" else "manual_review",
        "title": f"Operator gate required: {family.title}",
        "detail": family.summary,
        "suggested_action": ("Confirm authorization, scope, rate, accounts, and rollback/safety constraints before any execution."),
        "probe_key": family.key,
        "gate_triggers": list(family.gate_triggers),
    }


def normalize_probe_worker_result(
    payload: dict[str, Any],
    *,
    expected_status: str | None = None,
) -> dict[str, Any]:
    """Normalize worker_result and preserve compact anomaly/hypothesis metadata."""

    result = normalize_worker_result(payload, expected_status=expected_status)
    for key in ("anomaly", "hypothesis"):
        if key in payload:
            result[key] = compact_public_payload(payload[key], max_chars=MAX_SUMMARY_CHARS)
    if "coverage_status" in payload:
        status = str(payload["coverage_status"]).strip().lower()
        if status not in VALID_COVERAGE_STATUSES:
            raise ValueError("coverage_status must be covered, unknown, uncovered, or blocked")
        result["coverage_status"] = status
    return result


def sync_logic_probe_result(
    conn: sqlite3.Connection,
    *,
    work_item: sqlite3.Row,
    worker_result: dict[str, Any],
) -> None:
    """Idempotently sync a generic ``logic_probe`` worker_result to facts.

    This is intentionally small and queue-oriented: the worker still reports a
    compact provider-neutral result, while this hook updates coverage lifecycle
    and creates a suspicious point only when the result includes a compact
    anomaly or hypothesis summary.
    """

    probe_key = _probe_key_from_work_item(work_item)
    if probe_key is None:
        return

    result = normalize_probe_worker_result(worker_result)
    coverage_status = _coverage_status_from_result(result)
    upsert_probe_coverage(
        conn,
        target_name=work_item["target_name"],
        work_item_id=int(work_item["id"]),
        probe_key=probe_key,
        status=coverage_status,
        confidence=result["confidence"],
        evidence_refs=result["evidence_refs"],
        summary=result["summary"] or result["conclusion"],
        blocker_reason=result["block_reason"] or result["blocker"],
        next_action=result["next_action"],
        profile_id=None,
    )
    if result.get("anomaly") or result.get("hypothesis"):
        upsert_probe_suspicious_point(
            conn,
            target_name=work_item["target_name"],
            work_item_id=int(work_item["id"]),
            probe_key=probe_key,
            worker_result=result,
        )


def upsert_probe_suspicious_point(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    work_item_id: int,
    probe_key: str,
    worker_result: dict[str, Any],
) -> str:
    """Create/update one compact suspicious point per target/work_item/probe."""

    _family_by_key(probe_key)
    sp_id = f"GP-{work_item_id}-{probe_key}"
    fingerprint = f"{target_name}:generic_probe:{work_item_id}:{probe_key}"
    evidence_refs = _merge_suspicious_evidence_refs(
        conn,
        sp_id=sp_id,
        evidence_refs=worker_result.get("evidence_refs", []),
    )
    anomaly = compact_public_payload(worker_result.get("anomaly") or {}, max_chars=MAX_SUMMARY_CHARS)
    hypothesis = compact_public_payload(worker_result.get("hypothesis") or "", max_chars=MAX_SUMMARY_CHARS)
    reasoning = {
        "summary": worker_result.get("summary") or worker_result.get("conclusion") or "",
        "anomaly": anomaly,
        "hypothesis": hypothesis,
        "confidence": worker_result.get("confidence", "unknown"),
        "next_action": worker_result.get("next_action", ""),
    }
    reasoning_json = json.dumps(
        compact_public_payload(reasoning, max_chars=MAX_SUMMARY_CHARS),
        ensure_ascii=False,
        sort_keys=True,
    )
    risk = _risk_from_worker_result(worker_result)
    conn.execute(
        """
        INSERT INTO suspicious_points (
            id, page_url, url, param, method, test_type, evidence, source, reasoning,
            risk, test_status, notes, endpoint_fingerprint, response_summary, risk_score,
            signal_value, signal_reason
        ) VALUES (?, ?, ?, '', 'GET', ?, ?, 'generic_logic_probe', ?, ?, 'untested',
                  ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            evidence=excluded.evidence,
            reasoning=excluded.reasoning,
            risk=excluded.risk,
            notes=excluded.notes,
            response_summary=excluded.response_summary,
            risk_score=excluded.risk_score,
            signal_value=excluded.signal_value,
            signal_reason=excluded.signal_reason
        """,
        (
            sp_id,
            f"work_items:{work_item_id}",
            f"logic_probe:{probe_key}",
            f"generic_probe:{probe_key}",
            json.dumps(evidence_refs, ensure_ascii=False),
            reasoning_json,
            risk,
            worker_result.get("next_action", ""),
            fingerprint,
            worker_result.get("summary") or worker_result.get("conclusion") or "",
            _risk_score(risk),
            json.dumps(anomaly, ensure_ascii=False, sort_keys=True),
            str(hypothesis),
        ),
    )
    # If an older row was created through the partial unique index, keep it in
    # sync too.  The primary-key path above is the stable idempotency contract.
    conn.execute(
        """
        UPDATE suspicious_points
        SET evidence = ?, reasoning = ?, notes = ?, response_summary = ?
        WHERE source = 'generic_logic_probe'
          AND endpoint_fingerprint = ?
          AND test_type = ?
        """,
        (
            json.dumps(evidence_refs, ensure_ascii=False),
            reasoning_json,
            worker_result.get("next_action", ""),
            worker_result.get("summary") or worker_result.get("conclusion") or "",
            fingerprint,
            f"generic_probe:{probe_key}",
        ),
    )
    return sp_id


def upsert_probe_coverage(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    work_item_id: int,
    probe_key: str,
    status: str,
    confidence: str = "unknown",
    evidence_refs: list[str] | None = None,
    summary: str = "",
    blocker_reason: str = "",
    next_action: str = "",
    profile_id: int | None = None,
) -> None:
    """Record compact probe coverage without treating untested areas as safe."""

    if status not in VALID_COVERAGE_STATUSES:
        raise ValueError("coverage status must be covered, unknown, uncovered, or blocked")
    if confidence not in {"low", "medium", "high", "unknown"}:
        raise ValueError("coverage confidence must be low, medium, high, or unknown")
    item_key = f"generic_probe:{probe_key}"
    family = _family_by_key(probe_key)
    evidence_refs_json = json.dumps(evidence_refs or [], ensure_ascii=False)
    compact_summary = str(compact_public_payload(summary, max_chars=MAX_SUMMARY_CHARS))
    compact_blocker_reason = str(compact_public_payload(blocker_reason, max_chars=MAX_SUMMARY_CHARS))
    compact_next_action = str(compact_public_payload(next_action, max_chars=MAX_SUMMARY_CHARS))

    existing = conn.execute(
        """
        SELECT id
        FROM coverage_ledger
        WHERE target_name = ?
          AND item_key = ?
          AND (profile_id IS ? OR profile_id = ?)
        LIMIT 1
        """,
        (target_name, item_key, profile_id, profile_id),
    ).fetchone()
    if existing is not None:
        conn.execute(
            """
            UPDATE coverage_ledger
            SET work_item_id = ?,
                category = ?,
                status = ?,
                confidence = ?,
                evidence_refs_json = ?,
                summary = ?,
                blocker_reason = ?,
                next_action = ?,
                updated_at = datetime('now','localtime')
            WHERE id = ?
            """,
            (
                work_item_id,
                family.category,
                status,
                confidence,
                evidence_refs_json,
                compact_summary,
                compact_blocker_reason,
                compact_next_action,
                existing["id"],
            ),
        )
        conn.commit()
        return

    conn.execute(
        """
        INSERT INTO coverage_ledger (
            target_name, profile_id, work_item_id, item_key, category, status, confidence,
            evidence_refs_json, summary, blocker_reason, next_action, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now','localtime'))
        ON CONFLICT(target_name, profile_id, item_key) DO UPDATE SET
            work_item_id=excluded.work_item_id,
            category=excluded.category,
            status=excluded.status,
            confidence=excluded.confidence,
            evidence_refs_json=excluded.evidence_refs_json,
            summary=excluded.summary,
            blocker_reason=excluded.blocker_reason,
            next_action=excluded.next_action,
            updated_at=datetime('now','localtime')
        """,
        (
            target_name,
            profile_id,
            work_item_id,
            item_key,
            family.category,
            status,
            confidence,
            evidence_refs_json,
            compact_summary,
            compact_blocker_reason,
            compact_next_action,
        ),
    )
    conn.commit()


def write_rules_file(path: Path = RULES_ABSPATH) -> None:
    """Write the static rules metadata file used by worker prompts."""

    payload = {
        "schema": "generic_probe_families.v1",
        "note": "Planner metadata only; not an exploit or scanner algorithm.",
        "families": [asdict(family) | {"auto_dispatchable": family.auto_dispatchable} for family in PROBE_FAMILIES],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _family_plan(family: ProbeFamily, *, target_name: str, target_summary: Any) -> dict[str, Any]:
    gate = None if family.auto_dispatchable else build_operator_gate_for_probe(target_name=target_name, probe_key=family.key)
    return {
        **asdict(family),
        "signals": list(family.signals),
        "safe_actions": list(family.safe_actions),
        "gate_triggers": list(family.gate_triggers),
        "auto_dispatchable": family.auto_dispatchable,
        "operator_gate": gate,
        "target_summary": target_summary,
    }


def _family_by_key(probe_key: str) -> ProbeFamily:
    for family in PROBE_FAMILIES:
        if family.key == probe_key:
            return family
    raise ValueError(f"unknown probe family: {probe_key}")


def _probe_key_from_work_item(work_item: sqlite3.Row) -> str | None:
    if work_item["lane"] != "logic_probe":
        return None
    subtype = work_item["subtype"] or ""
    prefix = "generic_probe:"
    if not subtype.startswith(prefix):
        return None
    probe_key = subtype.removeprefix(prefix)
    _family_by_key(probe_key)
    return probe_key


def _coverage_status_from_result(result: dict[str, Any]) -> str:
    explicit = result.get("coverage_status")
    if explicit in VALID_COVERAGE_STATUSES:
        if explicit == "uncovered":
            return "uncovered"
        return str(explicit)
    if result["status"] == "blocked":
        return "blocked"
    if result["status"] == "partial":
        return "unknown"
    if result["status"] == "done" and result.get("evidence_refs"):
        return "covered"
    return "unknown"


def _merge_suspicious_evidence_refs(
    conn: sqlite3.Connection,
    *,
    sp_id: str,
    evidence_refs: list[str],
) -> list[str]:
    merged: list[str] = []
    row = conn.execute("SELECT evidence FROM suspicious_points WHERE id = ?", (sp_id,)).fetchone()
    if row is not None:
        try:
            existing = json.loads(row["evidence"] or "[]")
        except json.JSONDecodeError:
            existing = []
        if isinstance(existing, list):
            merged.extend(str(item) for item in existing if item)
    for ref in evidence_refs:
        text = str(compact_public_payload(ref, max_chars=120))
        if text and text not in merged:
            merged.append(text)
    return merged


def _risk_from_worker_result(result: dict[str, Any]) -> str:
    risk_level = result.get("risk_level") or "medium"
    return {
        "low": "Low",
        "medium": "Medium",
        "high": "High",
        "critical": "Critical",
        "unknown": "Medium",
    }.get(str(risk_level).lower(), "Medium")


def _risk_score(risk: str) -> int:
    return {"Low": 20, "Medium": 50, "High": 80, "Critical": 95}.get(risk, 50)
