"""Offline parameter-name semantics and bounded generic-probe routing."""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
from pathlib import Path
from typing import Any, Iterable

_TOOLS = Path(__file__).resolve().parent.parent
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))

from db.db_utils import connect, find_db  # noqa: E402
from db.entry_recursion import _validate_focus_gate  # noqa: E402
from db.identity_classification import validate_compact_text, validate_evidence_refs  # noqa: E402
from db.work_queue import create_work_item  # noqa: E402

PROBE_SUBTYPE = "generic_probe:input_error_diff"
COVERAGE_KEY = "endpoint:param_semantic_classification"
_PARAM = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,79}")
_FAMILY_TERMS = {
    "db_structure": ("table", "tablename", "schema", "column", "field", "entity"),
    "query_filter": ("filter", "where", "query", "search", "sort", "order", "page", "limit"),
    "data_action": ("action", "operation", "method", "command", "cmd", "status", "type"),
    "file_flow": ("file", "filename", "filepath", "upload", "download", "export", "attachment"),
    "auth_flow": ("token", "auth", "session", "role", "userid", "username", "account"),
}


def _parameter(value: Any) -> str:
    return validate_compact_text(value, field="parameter name", max_chars=80, allow_empty=False, pattern=_PARAM)


def classify_parameter_names(names: Iterable[Any]) -> dict[str, list[str]]:
    """Classify names only; values and exploit strings are never accepted."""

    values = list(dict.fromkeys(_parameter(item) for item in names))
    result: dict[str, list[str]] = {}
    for name in values:
        folded = re.sub(r"[^a-z0-9]", "", name.casefold())
        for family, terms in _FAMILY_TERMS.items():
            if any(term in folded for term in terms):
                result.setdefault(family, []).append(name)
    return result


def _scope_endpoint(conn: sqlite3.Connection, *, target_name: str, system_id: int, endpoint_id: int) -> sqlite3.Row:
    if conn.execute("SELECT 1 FROM targets WHERE target_name=?", (target_name,)).fetchone() is None:
        raise ValueError("target_name does not exactly match the database targets")
    if conn.execute("SELECT 1 FROM target_systems WHERE id=? AND target_name=?", (system_id, target_name)).fetchone() is None:
        raise ValueError("system does not match target")
    endpoint = conn.execute(
        """SELECT e.* FROM endpoint_observations e
           JOIN system_asset_links l ON l.asset_id=e.asset_id AND l.target_name=e.target_name
           JOIN target_assets a ON a.id=e.asset_id
           WHERE e.id=? AND e.target_name=? AND l.system_id=?
             AND a.scope_status='in_scope' AND a.scope_class IN ('owned','authorized_vendor')
             AND a.authorization_state<>'revoked'""",
        (endpoint_id, target_name, system_id),
    ).fetchone()
    if endpoint is None:
        raise ValueError("endpoint is not linked to the requested system")
    return endpoint


def _outcome(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = validate_compact_text(value, field="outcome", max_chars=40, allow_empty=False).lower()
    if normalized in {"no_difference", "no_observed_difference"}:
        return "no_observed_difference"
    if normalized not in {"difference_observed", "inconclusive", "blocked"}:
        raise ValueError("unsupported semantic observation outcome")
    return normalized


def _profile_id(conn: sqlite3.Connection, target_name: str, asset_id: int) -> int | None:
    row = conn.execute(
        """SELECT p.id FROM attack_surface_profiles p JOIN soft_targets s ON s.id=p.soft_target_id
           WHERE p.target_name=? AND s.asset_id=? ORDER BY p.id LIMIT 1""",
        (target_name, asset_id),
    ).fetchone()
    return int(row[0]) if row else None


def reconcile_param_semantics(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    system_id: int,
    endpoint_id: int,
    evidence_refs: list[str],
    public_confirmed: bool,
    state_change: bool,
    outcome: str | None = None,
    apply: bool = False,
    sample_size: int = 10,
) -> dict[str, Any]:
    """Classify one endpoint and optionally queue the sole allowed probe family."""

    if not 0 <= sample_size <= 100:
        raise ValueError("sample_size must be between 0 and 100")
    if type(public_confirmed) is not bool or type(state_change) is not bool:  # noqa: E721
        raise ValueError("public_confirmed and state_change must be booleans")
    refs = validate_evidence_refs(evidence_refs, allow_empty=False)
    observed_outcome = _outcome(outcome)
    nested = conn.in_transaction
    if apply:
        conn.execute("SAVEPOINT m9_param_semantics" if nested else "BEGIN IMMEDIATE")
    try:
        _validate_focus_gate(conn, target_name, system_id)
        endpoint = _scope_endpoint(conn, target_name=target_name, system_id=system_id, endpoint_id=endpoint_id)
        try:
            raw_names = json.loads(endpoint["parameter_names_json"] or "[]")
        except json.JSONDecodeError as exc:
            raise ValueError("endpoint parameter_names_json is invalid") from exc
        if not isinstance(raw_names, list):
            raise ValueError("endpoint parameter names must be a list")
        families = classify_parameter_names(raw_names)
        eligible = (
            public_confirmed
            and not state_change
            and endpoint["auth_state"] == "public"
            and str(endpoint["method"] or "GET").upper() in {"GET", "HEAD", "OPTIONS"}
        )
        work_items_inserted = coverage_inserted = coverage_updated = 0
        if apply:
            profile_id = _profile_id(conn, target_name, int(endpoint["asset_id"]))
            existing_cov = conn.execute(
                """SELECT id,status FROM coverage_ledger WHERE target_name=? AND item_key=?
                   AND (profile_id IS ? OR profile_id=?) ORDER BY id LIMIT 1""",
                (target_name, COVERAGE_KEY, profile_id, profile_id),
            ).fetchone()
            summary = json.dumps(
                {
                    "schema": "param_semantics.v1",
                    "system_id": system_id,
                    "endpoint_ref": f"endpoint_observations:{endpoint_id}",
                    "families": families,
                    "outcome": observed_outcome,
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            if observed_outcome == "blocked":
                coverage_status = "blocked"
            elif families and eligible:
                coverage_status = "covered"
            else:
                coverage_status = "unknown"
            if existing_cov is None:
                conn.execute(
                    """INSERT INTO coverage_ledger(
                           target_name,profile_id,item_key,category,status,confidence,evidence_refs_json,summary,next_action)
                       VALUES(?,?,?,'entry_recursion',?,'medium',?,?,?)""",
                    (
                        target_name,
                        profile_id,
                        COVERAGE_KEY,
                        coverage_status,
                        json.dumps(refs, ensure_ascii=False, separators=(",", ":")),
                        summary,
                        "route one bounded input/error-shape hypothesis" if eligible else "retain as classified hypothesis",
                    ),
                )
                coverage_inserted = 1
            elif existing_cov["status"] not in {"covered", "blocked"}:
                conn.execute(
                    """UPDATE coverage_ledger SET status=?,confidence='medium',evidence_refs_json=?,summary=?,
                           next_action=?,updated_at=datetime('now','localtime') WHERE id=?""",
                    (
                        coverage_status,
                        json.dumps(refs, ensure_ascii=False, separators=(",", ":")),
                        summary,
                        "route one bounded input/error-shape hypothesis" if eligible else "retain as classified hypothesis",
                        existing_cov["id"],
                    ),
                )
                coverage_updated = 1
            if eligible and families and observed_outcome is None:
                exists = conn.execute(
                    """SELECT 1 FROM work_items WHERE target_name=? AND system_id=? AND lane='logic_probe'
                       AND subtype=? AND subject_table='endpoint_observations' AND subject_id=? LIMIT 1""",
                    (target_name, system_id, PROBE_SUBTYPE, str(endpoint_id)),
                ).fetchone()
                if exists is None:
                    objective = json.dumps(
                        {
                            "schema": "param_semantics.v1",
                            "endpoint_ref": f"endpoint_observations:{endpoint_id}",
                            "families": families,
                            "plan": "L0/L1 benign input and error-shape difference only",
                            "evidence_refs": refs,
                            "network_request_count": 0,
                        },
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    create_work_item(
                        conn,
                        target_name=target_name,
                        system_id=system_id,
                        lane="logic_probe",
                        subtype=PROBE_SUBTYPE,
                        subject_table="endpoint_observations",
                        subject_id=str(endpoint_id),
                        title="Classify bounded input/error response difference",
                        objective=objective,
                        priority=58,
                        risk_class="safe_replay",
                        auth_requirement="none",
                        commit=False,
                    )
                    work_items_inserted = 1
            if nested:
                conn.execute("RELEASE SAVEPOINT m9_param_semantics")
            else:
                conn.commit()
    except Exception:
        if apply:
            if nested:
                conn.execute("ROLLBACK TO SAVEPOINT m9_param_semantics")
                conn.execute("RELEASE SAVEPOINT m9_param_semantics")
            else:
                conn.rollback()
        raise
    return {
        "target_name": target_name,
        "system_id": system_id,
        "endpoint_id": endpoint_id,
        "mode": "apply" if apply else "preview",
        "families": families,
        "probe_subtype": PROBE_SUBTYPE,
        "auto_plan_level": "L0/L1" if eligible and families and observed_outcome is None else None,
        "observation_outcome": observed_outcome,
        "work_items_inserted": work_items_inserted,
        "coverage_inserted": coverage_inserted,
        "coverage_updated": coverage_updated,
        "network_request_count": 0,
        "sample": [{"family": key, "parameter_names": value[:sample_size]} for key, value in list(families.items())[:sample_size]],
    }


def _path(target: str, file: str | None) -> Path:
    path = Path(file) if file else find_db(target)
    if not path.is_file():
        raise FileNotFoundError(f"database file does not exist: {path}")
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline endpoint parameter semantics")
    parser.add_argument("--target", required=True)
    parser.add_argument("--file")
    parser.add_argument("--system-id", required=True, type=int)
    parser.add_argument("--endpoint-id", required=True, type=int)
    parser.add_argument("--evidence-ref", action="append", required=True)
    parser.add_argument("--public-confirmed", action="store_true")
    parser.add_argument("--state-change", action="store_true")
    parser.add_argument("--outcome")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    try:
        conn = connect(_path(args.target, args.file))
        try:
            result = reconcile_param_semantics(
                conn,
                target_name=args.target,
                system_id=args.system_id,
                endpoint_id=args.endpoint_id,
                evidence_refs=args.evidence_ref,
                public_confirmed=args.public_confirmed,
                state_change=args.state_change,
                outcome=args.outcome,
                apply=args.apply,
            )
        finally:
            conn.close()
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return 1
    print(json.dumps({"ok": True, **result}, ensure_ascii=False, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
