"""Offline, evidence-driven recursive entry expansion for one focused system."""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

_TOOLS = Path(__file__).resolve().parent.parent
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))

from db.db_utils import connect, find_db  # noqa: E402
from db.identity_classification import (  # noqa: E402
    normalize_host,
    validate_compact_text,
    validate_evidence_refs,
)
from db.recon_readiness import evaluate_readiness  # noqa: E402
from db.work_queue import create_work_item  # noqa: E402

TRUSTED_SEED_SOURCES = {"html", "js", "har", "burp", "archive", "peer_document_reviewed"}
RECURSIVE_KINDS = {"html", "js", "source_map"}
BLOCKING_RESPONSE_CLASSES = {"soft_404", "auth_blocked", "captcha", "download", "state_change"}
MAX_DEPTH = 2
MAX_PER_ENTRY = 20
MAX_PER_SYSTEM_TICK = 50
M9_KEYS = (
    "entry:mobile_h5_discovery",
    "entry:recursive_js_expansion",
    "entry:lazy_chunk_coverage",
    "endpoint:param_semantic_classification",
)
_SECRET = re.compile(
    r"(?:GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+\S+\s+HTTP/|"
    r"(?:authorization|cookie|set-cookie|password|passwd|secret|api[_-]?key|access[_-]?token)\s*[:=]|"
    r"bearer\s+\S+",
    re.I,
)


def _reject_secret(value: Any) -> None:
    if _SECRET.search(json.dumps(value, ensure_ascii=False)):
        raise ValueError("raw HTTP or credential material is not accepted")


def normalize_observed_url(value: Any) -> str:
    _reject_secret(value)
    raw = validate_compact_text(value, field="url", max_chars=1000, allow_empty=False)
    parsed = urlparse(raw)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("url must be an absolute HTTP(S) URL without userinfo")
    host = normalize_host(parsed.hostname)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("url port is invalid") from exc
    default = 80 if parsed.scheme.lower() == "http" else 443
    netloc = f"[{host}]" if ":" in host else host
    if port is not None and port != default:
        netloc += f":{port}"
    query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)))
    return urlunparse((parsed.scheme.lower(), netloc, parsed.path or "/", "", query, ""))


def _origin(url: str) -> tuple[str, str, int]:
    parsed = urlparse(url)
    return parsed.scheme, str(parsed.hostname), parsed.port or (443 if parsed.scheme == "https" else 80)


def _bounded_budget(value: int, hard_max: int, field: str) -> tuple[int, bool]:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{field} must be a non-negative integer")
    return min(value, hard_max), value > hard_max


def plan_entry_recursion(
    fixture: Mapping[str, Any],
    *,
    per_entry_budget: int = MAX_PER_ENTRY,
    per_system_budget: int = MAX_PER_SYSTEM_TICK,
    already_scheduled: int = 0,
    allowed_origins: set[tuple[str, str, int]] | None = None,
) -> dict[str, Any]:
    """Classify an offline observation graph; this function never performs I/O."""

    _reject_secret(fixture)
    if already_scheduled < 0:
        raise ValueError("already_scheduled must be non-negative")
    entry_cap, entry_over = _bounded_budget(per_entry_budget, MAX_PER_ENTRY, "per_entry_budget")
    system_cap, system_over = _bounded_budget(per_system_budget, MAX_PER_SYSTEM_TICK, "per_system_budget")
    system_remaining = max(0, system_cap - already_scheduled)
    capacity = min(entry_cap, system_remaining)

    seed_raw = fixture.get("seed")
    if not isinstance(seed_raw, Mapping):
        raise ValueError("fixture must contain one seed object")
    seed_source = validate_compact_text(seed_raw.get("source_kind"), field="seed source", max_chars=40, allow_empty=False).lower()
    if seed_source not in TRUSTED_SEED_SOURCES:
        raise ValueError("seed source is not trusted")
    if seed_raw.get("observed", True) is not True or seed_raw.get("guessed", False) is True:
        raise ValueError("seed must be an observed non-guessed fact")
    seed_url = normalize_observed_url(seed_raw.get("url"))
    seed_refs = validate_evidence_refs(seed_raw.get("evidence_refs"), allow_empty=False)
    seed_depth = seed_raw.get("depth", 0)
    if isinstance(seed_depth, bool) or not isinstance(seed_depth, int) or seed_depth < 0:
        raise ValueError("seed depth must be a non-negative integer")
    permitted = {_origin(seed_url)} if allowed_origins is None else set(allowed_origins)
    if _origin(seed_url) not in permitted:
        raise ValueError("seed origin is not linked to the requested system")

    observations = fixture.get("observations", [])
    if not isinstance(observations, list):
        raise ValueError("observations must be a list")
    items: list[dict[str, Any]] = []
    seen: set[str] = set()
    queued = 0
    budget_exhausted = entry_over or system_over
    for raw in observations:
        if not isinstance(raw, Mapping):
            raise ValueError("each observation must be an object")
        source = validate_compact_text(raw.get("source_kind"), field="observation source", max_chars=40, allow_empty=False).lower()
        if source not in TRUSTED_SEED_SOURCES:
            raise ValueError("observation source is not trusted")
        refs = validate_evidence_refs(raw.get("evidence_refs"), allow_empty=False)
        normalized = normalize_observed_url(raw.get("url"))
        parent = normalize_observed_url(raw.get("parent_url") or seed_url)
        depth = raw.get("depth", seed_depth + 1)
        if isinstance(depth, bool) or not isinstance(depth, int) or depth < 0:
            raise ValueError("observation depth must be a non-negative integer")
        kind = validate_compact_text(raw.get("kind") or "html", field="kind", max_chars=40, allow_empty=False)
        response_class = validate_compact_text(raw.get("response_class"), field="response class", max_chars=40).lower()
        observed = raw.get("observed", True) is True
        guessed = raw.get("guessed", False) is True
        blocker = ""
        auto_queue = kind in RECURSIVE_KINDS
        if not observed or guessed:
            blocker, auto_queue = "guessed_or_unobserved", False
        elif response_class in BLOCKING_RESPONSE_CLASSES:
            blocker, auto_queue = response_class, False
        elif depth > MAX_DEPTH:
            blocker, auto_queue, budget_exhausted = "depth_exhausted", False, True
        elif _origin(normalized) not in permitted:
            blocker, auto_queue = "cross_origin", False
        elif normalized in seen:
            blocker, auto_queue = "duplicate_or_cycle", False
        seen.add(normalized)
        method = validate_compact_text(raw.get("method") or "GET", field="method", max_chars=12).upper()
        if method not in {"GET", "HEAD", "OPTIONS"}:
            blocker, auto_queue = "state_change", False
        if auto_queue:
            if queued >= capacity:
                blocker, auto_queue, budget_exhausted = "budget_exhausted", False, True
            else:
                queued += 1
        persist_fact = (
            observed
            and not guessed
            and not blocker
            and response_class not in BLOCKING_RESPONSE_CLASSES
            and _origin(normalized) in permitted
        )
        params = raw.get("parameter_names", [])
        if not isinstance(params, list):
            raise ValueError("parameter_names must be a list")
        parameter_names = [validate_compact_text(x, field="parameter name", max_chars=80, allow_empty=False) for x in params[:50]]
        items.append(
            {
                "parent_url": parent,
                "normalized_url": normalized,
                "source_kind": source,
                "kind": kind,
                "method": method,
                "parameter_names": list(dict.fromkeys(parameter_names)),
                "evidence_refs": refs,
                "depth": depth,
                "response_class": response_class or "observed",
                "auto_queue": auto_queue,
                "persist_fact": persist_fact,
                "blocker": blocker,
            }
        )
    status = (
        "blocked" if capacity == 0 and any(x["kind"] in RECURSIVE_KINDS for x in items) else ("partial" if budget_exhausted else "done")
    )
    return {
        "seed": {"url": seed_url, "source_kind": seed_source, "evidence_refs": seed_refs, "depth": seed_depth},
        "items": items,
        "queued_count": sum(1 for item in items if item["auto_queue"]),
        "status": status,
        "coverage_status": "blocked" if status == "blocked" else "unknown",
        "network_request_count": 0,
        "budget": {"depth": MAX_DEPTH, "per_entry": capacity, "per_system_tick": system_cap},
        "next_action": (
            "resume the same seed within a renewed bounded offline budget"
            if status in {"partial", "blocked"}
            else "review persisted entry, script, endpoint, and parameter-semantic facts"
        ),
    }


def _validate_scope(conn: sqlite3.Connection, target_name: str, system_id: int) -> set[tuple[str, str, int]]:
    if conn.execute("SELECT 1 FROM targets WHERE target_name=?", (target_name,)).fetchone() is None:
        raise ValueError("target_name does not exactly match the database targets")
    system = conn.execute(
        "SELECT canonical_url,scope_class FROM target_systems WHERE id=? AND target_name=?", (system_id, target_name)
    ).fetchone()
    if system is None:
        raise ValueError("system does not match target")
    if system["scope_class"] not in {"owned", "authorized_vendor"}:
        raise ValueError("system is not authorized for recursive expansion")
    rows = conn.execute(
        """SELECT a.asset_value,a.port,a.scope_status,a.scope_class,a.authorization_state
           FROM system_asset_links l JOIN target_assets a ON a.id=l.asset_id
           WHERE l.target_name=? AND l.system_id=?""",
        (target_name, system_id),
    ).fetchall()
    allowed: set[tuple[str, str, int]] = set()
    for row in rows:
        if row["scope_status"] != "in_scope" or row["scope_class"] not in {"owned", "authorized_vendor"}:
            continue
        if row["authorization_state"] == "revoked":
            continue
        value = str(row["asset_value"] or "")
        host = urlparse(value if "://" in value else f"//{value}").hostname
        if not host:
            continue
        port = int(row["port"] or 443)
        allowed.add(("https" if port == 443 else "http", normalize_host(host), port))
    if system["canonical_url"]:
        allowed.add(_origin(normalize_observed_url(system["canonical_url"])))
    if not allowed:
        raise ValueError("system has no eligible in-scope asset")
    return allowed


def _schema_version(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()
    return int(row[0] or 0)


def _validate_focus_gate(conn: sqlite3.Connection, target_name: str, system_id: int) -> None:
    """Reuse the schema-33/34 focus and readiness facts, fail closed for modern DBs."""

    if _schema_version(conn) < 33:
        return
    if conn.execute("SELECT 1 FROM target_systems WHERE target_name=? AND id=?", (target_name, system_id)).fetchone() is None:
        raise ValueError("system does not match target")
    version = _schema_version(conn)
    if version >= 34:
        session = conn.execute(
            """SELECT 1 FROM hunt_sessions WHERE target_name=? AND system_id=?
               AND status='active' AND selected_by='operator'
               AND operator_acknowledged_at IS NOT NULL LIMIT 1""",
            (target_name, system_id),
        ).fetchone()
    else:
        # Schema 33 compatibility predates the mandatory acknowledgement timestamp.
        session = conn.execute(
            """SELECT 1 FROM hunt_sessions WHERE target_name=? AND system_id=?
               AND status='active' AND selected_by='operator' LIMIT 1""",
            (target_name, system_id),
        ).fetchone()
    if session is None:
        raise ValueError("operator-focused active hunt session is required")
    if version >= 34:
        focused = conn.execute(
            """SELECT 1 FROM system_soft_targets WHERE target_name=? AND system_id=?
               AND eligibility_status='eligible' AND status='focused'
               AND timebox_until IS NOT NULL AND timebox_until>datetime('now','localtime') LIMIT 1""",
            (target_name, system_id),
        ).fetchone()
        if focused is None:
            raise ValueError("eligible focused system with a live timebox is required")
    readiness = evaluate_readiness(conn, target_name=target_name, system_id=system_id)
    if readiness["state"] != "ready":
        raise ValueError(f"system readiness is {readiness['state']}, expected ready")


def _asset_id_for_url(conn: sqlite3.Connection, target_name: str, system_id: int, url: str) -> int | None:
    scheme, host, port = _origin(url)
    row = conn.execute(
        """SELECT a.id FROM system_asset_links l JOIN target_assets a ON a.id=l.asset_id
           WHERE l.target_name=? AND l.system_id=? AND lower(a.asset_value)=?
             AND COALESCE(a.port,?)=? AND a.scope_status='in_scope'
             AND a.scope_class IN ('owned','authorized_vendor') AND a.authorization_state<>'revoked'
           ORDER BY CASE l.relationship WHEN 'primary' THEN 0 ELSE 1 END,a.id LIMIT 1""",
        (target_name, system_id, host, port, port),
    ).fetchone()
    return int(row[0]) if row else None


def _profile_id(conn: sqlite3.Connection, target_name: str, system_id: int) -> int | None:
    row = conn.execute(
        """SELECT p.id FROM attack_surface_profiles p
           JOIN soft_targets s ON s.id=p.soft_target_id
           JOIN system_asset_links l ON l.asset_id=s.asset_id
           WHERE p.target_name=? AND l.target_name=? AND l.system_id=?
           ORDER BY CASE p.status WHEN 'active' THEN 0 ELSE 1 END,p.id LIMIT 1""",
        (target_name, target_name, system_id),
    ).fetchone()
    return int(row[0]) if row else None


def _upsert_coverage(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    profile_id: int | None,
    key: str,
    status: str,
    refs: list[str],
    summary: str,
    next_action: str,
) -> None:
    row = conn.execute(
        "SELECT id,status FROM coverage_ledger WHERE target_name=? AND profile_id IS ? AND item_key=?",
        (target_name, profile_id, key),
    ).fetchone()
    payload = json.dumps(refs[:20], ensure_ascii=False, separators=(",", ":"))
    if row is None:
        conn.execute(
            """INSERT INTO coverage_ledger(
                   target_name,profile_id,item_key,category,status,confidence,evidence_refs_json,summary,next_action)
               VALUES(?,?,?,'entry_recursion',?,'medium',?,?,?)""",
            (target_name, profile_id, key, status, payload, summary, next_action),
        )
    elif row["status"] not in {"covered", "blocked"}:
        conn.execute(
            """UPDATE coverage_ledger SET status=?,confidence='medium',evidence_refs_json=?,summary=?,next_action=?,
                   updated_at=datetime('now','localtime') WHERE id=?""",
            (status, payload, summary, next_action, row["id"]),
        )


def reconcile_entry_recursion(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    system_id: int,
    fixture: Mapping[str, Any],
    apply: bool = False,
    include_items: bool = False,
    sample_size: int = 10,
    per_entry_budget: int = MAX_PER_ENTRY,
    per_system_budget: int = MAX_PER_SYSTEM_TICK,
) -> dict[str, Any]:
    if not 0 <= sample_size <= 100:
        raise ValueError("sample_size must be between 0 and 100")
    nested = conn.in_transaction
    if apply:
        conn.execute("SAVEPOINT m9_entry_recursion" if nested else "BEGIN IMMEDIATE")
    try:
        _validate_focus_gate(conn, target_name, system_id)
        allowed = _validate_scope(conn, target_name, system_id)
        existing_count = conn.execute(
            """SELECT COUNT(*) FROM work_items WHERE target_name=? AND system_id=?
               AND subtype LIKE 'entry_recursion:%' AND status IN ('queued','claimed','partial')""",
            (target_name, system_id),
        ).fetchone()[0]
        plan = plan_entry_recursion(
            fixture,
            per_entry_budget=per_entry_budget,
            per_system_budget=per_system_budget,
            already_scheduled=int(existing_count),
            allowed_origins=allowed,
        )
        sources_inserted = work_items_inserted = endpoints_inserted = 0
        entries_inserted = pages_inserted = scripts_inserted = 0
        if apply:
            seed = plan["seed"]
            seed_asset_id = _asset_id_for_url(conn, target_name, system_id, seed["url"])
            if seed_asset_id is None:
                raise ValueError("seed origin is not backed by an eligible linked asset")
            before = conn.total_changes
            conn.execute(
                """INSERT OR IGNORE INTO entry_observations(
                       target_name,asset_id,url,entry_type,source,status,confidence,response_class,evidence_refs_json)
                   VALUES(?,?,?,'mobile_h5','entry_recursion','observed','high','observed',?)""",
                (target_name, seed_asset_id, seed["url"], json.dumps(seed["evidence_refs"], separators=(",", ":"))),
            )
            entries_inserted += conn.total_changes - before
            before = conn.total_changes
            conn.execute(
                """INSERT OR IGNORE INTO pages(url,canonical_url,depth,status,source)
                   VALUES(?,?,?,'observed','entry_recursion')""",
                (seed["url"], seed["url"], seed["depth"]),
            )
            pages_inserted += conn.total_changes - before
            seed_page_id = int(conn.execute("SELECT id FROM pages WHERE url=?", (seed["url"],)).fetchone()[0])
            conn.execute(
                """INSERT OR IGNORE INTO page_asset_links(page_id,asset_id,relation,confidence,evidence_ref)
                   VALUES(?,?,'same_host','high',?)""",
                (seed_page_id, seed_asset_id, seed["evidence_refs"][0]),
            )
            for item in plan["items"]:
                payload = {
                    "schema": "entry_recursion.v1",
                    "system_id": system_id,
                    "parent_url": item["parent_url"],
                    "url": item["normalized_url"],
                    "kind": item["kind"],
                    "depth": item["depth"],
                    "evidence_refs": item["evidence_refs"],
                    "blocker": item["blocker"],
                }
                result_json = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                before = conn.total_changes
                conn.execute(
                    """INSERT OR IGNORE INTO recon_sources(target_name,source_kind,query,result_json,status)
                       VALUES(?,?,?,?,?)""",
                    (
                        target_name,
                        "entry_recursion_seed",
                        item["normalized_url"],
                        result_json,
                        "queued" if item["auto_queue"] else ("blocked" if item["blocker"] else "observed"),
                    ),
                )
                sources_inserted += conn.total_changes - before
                source_id = int(
                    conn.execute(
                        """SELECT id FROM recon_sources WHERE target_name=? AND source_kind='entry_recursion_seed'
                           AND query=? AND result_json=?""",
                        (target_name, item["normalized_url"], result_json),
                    ).fetchone()[0]
                )
                asset_id = _asset_id_for_url(conn, target_name, system_id, item["normalized_url"])
                if item["persist_fact"] and asset_id is not None and item["kind"] in {"js", "source_map"}:
                    before = conn.total_changes
                    conn.execute(
                        """INSERT OR IGNORE INTO js_files(
                               url,page_url,source_kind,source_map_status,extraction_status)
                           VALUES(?,?,?,'observed','pending')""",
                        (item["normalized_url"], item["parent_url"], item["kind"]),
                    )
                    scripts_inserted += conn.total_changes - before
                    js_id = int(conn.execute("SELECT id FROM js_files WHERE url=?", (item["normalized_url"],)).fetchone()[0])
                    conn.execute(
                        """INSERT OR IGNORE INTO js_asset_links(js_file_id,asset_id,relation,confidence,evidence_ref)
                           VALUES(?,?,'same_host','medium',?)""",
                        (js_id, asset_id, item["evidence_refs"][0]),
                    )
                elif item["persist_fact"] and asset_id is not None and item["kind"] == "html":
                    before = conn.total_changes
                    conn.execute(
                        """INSERT OR IGNORE INTO pages(url,canonical_url,depth,status,source)
                           VALUES(?,?,?,'observed','entry_recursion')""",
                        (item["normalized_url"], item["normalized_url"], item["depth"]),
                    )
                    pages_inserted += conn.total_changes - before
                    page_id = int(conn.execute("SELECT id FROM pages WHERE url=?", (item["normalized_url"],)).fetchone()[0])
                    conn.execute(
                        """INSERT OR IGNORE INTO page_asset_links(page_id,asset_id,relation,confidence,evidence_ref)
                           VALUES(?,?,'same_host','medium',?)""",
                        (page_id, asset_id, item["evidence_refs"][0]),
                    )
                if item["kind"] == "endpoint" and item["persist_fact"] and asset_id is not None:
                    parsed = urlparse(item["normalized_url"])
                    before = conn.total_changes
                    conn.execute(
                        """INSERT OR IGNORE INTO endpoint_observations(
                               target_name,asset_id,source_table,source_id,canonical_url,host,path,method,source,
                               parameter_names_json,evidence_refs_json,confidence,resolution_status,scope_class)
                           SELECT ?,l.asset_id,'recon_sources',?,?,?,?,?, 'entry_recursion',?,?,
                                  'medium','resolved',a.scope_class
                           FROM system_asset_links l JOIN target_assets a ON a.id=l.asset_id
                           WHERE l.target_name=? AND l.system_id=? AND lower(a.asset_value)=? LIMIT 1""",
                        (
                            target_name,
                            str(source_id),
                            item["normalized_url"],
                            parsed.hostname,
                            parsed.path or "/",
                            item["method"],
                            json.dumps(item["parameter_names"], ensure_ascii=False, separators=(",", ":")),
                            json.dumps(item["evidence_refs"], ensure_ascii=False, separators=(",", ":")),
                            target_name,
                            system_id,
                            str(parsed.hostname).lower(),
                        ),
                    )
                    endpoints_inserted += conn.total_changes - before
                if item["auto_queue"]:
                    subtype = f"entry_recursion:{item['kind']}"
                    exists = conn.execute(
                        """SELECT 1 FROM work_items WHERE target_name=? AND system_id=? AND lane=? AND subtype=?
                           AND subject_table='recon_sources' AND subject_id=? LIMIT 1""",
                        (
                            target_name,
                            system_id,
                            "js_reverse" if item["kind"] in {"js", "source_map"} else "entry_explore",
                            subtype,
                            str(source_id),
                        ),
                    ).fetchone()
                    if exists is None:
                        create_work_item(
                            conn,
                            target_name=target_name,
                            system_id=system_id,
                            lane="js_reverse" if item["kind"] in {"js", "source_map"} else "entry_explore",
                            subtype=subtype,
                            subject_table="recon_sources",
                            subject_id=str(source_id),
                            title=f"Offline recurse observed {item['kind']} seed",
                            objective=json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
                            priority=60,
                            risk_class="safe_passive",
                            auth_requirement="none",
                            commit=False,
                        )
                        work_items_inserted += 1
            profile_id = _profile_id(conn, target_name, system_id)
            observed = [item for item in plan["items"] if item["persist_fact"]]
            refs = list(dict.fromkeys(seed["evidence_refs"] + [ref for item in observed for ref in item["evidence_refs"]]))
            supported = {
                "entry:mobile_h5_discovery": True,
                "entry:recursive_js_expansion": any(x["kind"] in {"js", "source_map"} for x in observed),
                "entry:lazy_chunk_coverage": any(x["kind"] == "source_map" for x in observed),
                # Parameter names are only input facts; param_semantics owns
                # classification settlement and may still be blocked by auth,
                # side effects, or dynamic signatures.
                "endpoint:param_semantic_classification": False,
            }
            for key in M9_KEYS:
                if plan["status"] == "done" and supported[key]:
                    coverage_status = "covered"
                else:
                    coverage_status = "blocked" if plan["status"] == "blocked" else "unknown"
                _upsert_coverage(
                    conn,
                    target_name=target_name,
                    profile_id=profile_id,
                    key=key,
                    status=coverage_status,
                    refs=refs,
                    summary=f"offline recursive entry reconciliation: {plan['status']}",
                    next_action=plan["next_action"],
                )
            if nested:
                conn.execute("RELEASE SAVEPOINT m9_entry_recursion")
            else:
                conn.commit()
    except Exception:
        if apply:
            if nested:
                conn.execute("ROLLBACK TO SAVEPOINT m9_entry_recursion")
                conn.execute("RELEASE SAVEPOINT m9_entry_recursion")
            else:
                conn.rollback()
        raise
    result: dict[str, Any] = {
        "target_name": target_name,
        "system_id": system_id,
        "mode": "apply" if apply else "preview",
        "status": plan["status"],
        "coverage_status": plan["coverage_status"],
        "network_request_count": 0,
        "planned": len(plan["items"]),
        "queued_count": plan["queued_count"],
        "sources_inserted": sources_inserted,
        "work_items_inserted": work_items_inserted,
        "endpoints_inserted": endpoints_inserted,
        "entries_inserted": entries_inserted,
        "pages_inserted": pages_inserted,
        "scripts_inserted": scripts_inserted,
        "next_action": plan["next_action"],
        "sample": [
            {
                "url": item["normalized_url"][:180],
                "kind": item["kind"],
                "depth": item["depth"],
                "auto_queue": item["auto_queue"],
                "blocker": item["blocker"],
            }
            for item in plan["items"][:sample_size]
        ],
        "omitted": max(0, len(plan["items"]) - sample_size),
    }
    if include_items:
        result["items"] = plan["items"]
    return result


def _path(target: str, file: str | None) -> Path:
    path = Path(file) if file else find_db(target)
    if not path.is_file():
        raise FileNotFoundError(f"database file does not exist: {path}")
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline evidence-driven entry recursion")
    parser.add_argument("--target", required=True)
    parser.add_argument("--file")
    parser.add_argument("--fixture", required=True)
    parser.add_argument("--system-id", required=True, type=int)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    try:
        fixture = json.loads(Path(args.fixture).read_text(encoding="utf-8"))
        conn = connect(_path(args.target, args.file))
        try:
            result = reconcile_entry_recursion(conn, target_name=args.target, system_id=args.system_id, fixture=fixture, apply=args.apply)
        finally:
            conn.close()
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return 1
    print(json.dumps({"ok": True, **result}, ensure_ascii=False, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
