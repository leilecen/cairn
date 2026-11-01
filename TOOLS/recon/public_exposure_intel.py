"""Offline contracts and transactional import for public-exposure intelligence."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from typing import Any
from urllib.parse import unquote, urlsplit, urlunsplit

try:
    from .recon_store import record_source
except ImportError:  # pragma: no cover - direct script execution
    from recon_store import record_source  # type: ignore[no-redef]  # 回退分支与包内导入同一批名字

FAMILIES = {
    "public_docs_search",
    "public_share_search",
    "public_file_search",
    "code_search_external",
    "package_registry_search",
    "public_object_storage",
    "leak_intel_external",
}
STATUSES = {
    "not_run",
    "anchor_insufficient",
    "searched_empty",
    "hits",
    "login_required",
    "captcha",
    "quota",
    "extraction_code",
    "tool_failed",
    "manual_required",
    "no_adapter",
}
BLOCKED = {"login_required", "captcha", "quota", "extraction_code", "tool_failed", "manual_required"}
REF_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}:[A-Za-z0-9_.:-]{1,100}\Z")
SECRET_RE = re.compile(
    r"(?i)(authorization\s*:\s*[^\r\n,;]+|cookie\s*:\s*[^\r\n,;]+|bearer\s+[A-Za-z0-9._~-]+|"
    r"(?:password|passwd|token|secret|提取码)\s*[:=]\s*[^\s,;]+|"
    r"AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,})"
)


def _redact_text(value: Any, limit: int) -> str:
    text = str(value or "").strip()[:limit]
    if not text:
        return ""
    return SECRET_RE.sub(lambda match: f"[redacted:{hashlib.sha256(match.group(0).encode()).hexdigest()[:12]}]", text)


def _url(value: Any) -> str:
    parsed = urlsplit(str(value or "").strip())
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("hit.url must be an absolute public http(s) URL")
    if parsed.username or parsed.password:
        raise ValueError("hit.url must not contain credentials")
    path = unquote(parsed.path or "/")
    fragment = unquote(parsed.fragment or "")
    if SECRET_RE.search(path) or SECRET_RE.search(fragment):
        raise ValueError("hit.url path or fragment contains credential material")
    try:
        host = parsed.hostname.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("hit.url contains an invalid IDN hostname") from exc
    default_port = (parsed.scheme.lower(), parsed.port) in {("http", 80), ("https", 443)}
    port = f":{parsed.port}" if parsed.port and not default_port else ""
    # Query values are not required for URL+family identity and may contain secrets.
    return urlunsplit((parsed.scheme.lower(), f"{host}{port}", parsed.path or "/", "", ""))


def _refs(value: Any) -> list[str]:
    if not isinstance(value, list):
        raise ValueError("evidence_refs must be a list")
    refs = []
    for item in value[:20]:
        text = str(item or "").strip()
        if not REF_RE.fullmatch(text):
            raise ValueError("evidence_refs must contain compact scalar references")
        if text not in refs:
            refs.append(text)
    return refs


def normalize_import(family: str, payload: Any) -> dict[str, Any]:
    if family not in FAMILIES:
        raise ValueError(f"unsupported public exposure family: {family}")
    if not isinstance(payload, dict):
        raise ValueError("import payload must be an object")
    status = str(payload.get("status") or "").strip().lower()
    if status not in STATUSES:
        raise ValueError(f"invalid public exposure status: {status}")
    provider = _redact_text(payload.get("provider"), 80)
    query = _redact_text(payload.get("query"), 500)
    refs = _refs(payload.get("evidence_refs", []))
    raw_hits = payload.get("hits", [])
    if not isinstance(raw_hits, list):
        raise ValueError("hits must be a list")
    if status != "hits" and raw_hits:
        raise ValueError(f"{status} cannot contain hits")
    if status in {"hits", "searched_empty"} and (not query or not provider):
        raise ValueError(f"{status} requires non-empty query and provider")
    hits: dict[str, dict[str, Any]] = {}
    for raw in raw_hits:
        if not isinstance(raw, dict):
            raise ValueError("each hit must be an object")
        # Unknown fields are deliberately ignored, including secret-key fields.
        url = _url(raw.get("url"))
        matched_anchor = _redact_text(raw.get("matched_anchor"), 160)
        hit_refs = _refs(raw.get("evidence_refs", []))
        if not matched_anchor:
            raise ValueError("each hit requires matched_anchor")
        if not hit_refs:
            raise ValueError("each hit requires compact hit evidence_refs")
        hits.setdefault(
            url,
            {
                "url": url,
                "title": _redact_text(raw.get("title"), 240),
                "snippet": _redact_text(raw.get("snippet"), 500),
                "matched_anchor": matched_anchor,
                "evidence_refs": hit_refs,
            },
        )
    if status == "hits" and not hits:
        raise ValueError("hits status requires at least one valid hit")
    return {
        "schema": "public_exposure_import/v1",
        "family": family,
        "query": query,
        "provider": provider,
        "status": status,
        "result_count": len(raw_hits),
        "dedup_count": len(hits),
        "evidence_refs": refs,
        "hits": list(hits.values()),
    }


def _coverage_status(item: dict[str, Any]) -> str:
    if item["status"] in {"not_run", "anchor_insufficient"}:
        return "unknown"
    if item["status"] in {"searched_empty", "hits"}:
        evidence = item["evidence_refs"] or [ref for hit in item["hits"] for ref in hit["evidence_refs"]]
        return "covered" if evidence else "unknown"
    if item["status"] in BLOCKED:
        return "blocked"
    return "uncovered"


def _validate_target(conn: sqlite3.Connection, target_name: str) -> None:
    if not conn.execute("SELECT 1 FROM targets WHERE target_name=?", (target_name,)).fetchone():
        raise ValueError("target_name does not exactly match the database targets")


def import_public_exposure(conn: sqlite3.Connection, *, target_name: str, family: str, payload: Any, apply: bool = False) -> dict[str, Any]:
    """Preview or transactionally import one offline provider result."""
    if not apply:
        _validate_target(conn, target_name)
        item = normalize_import(family, payload)
        return _result(target_name, item, _coverage_status(item), applied=False)
    if conn.in_transaction:
        raise RuntimeError("public exposure apply requires a transaction boundary owned by the importer")
    try:
        conn.execute("BEGIN IMMEDIATE")
        _validate_target(conn, target_name)
        item = normalize_import(family, payload)
        coverage = _coverage_status(item)
        digest_input = json.dumps(item["hits"], ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        hit_digest = hashlib.sha256(digest_input.encode()).hexdigest()
        execution = {
            **{key: value for key, value in item.items() if key != "hits"},
            "hit_digest": hit_digest,
            "sample": item["hits"][:10],
            "omitted": max(0, len(item["hits"]) - 10),
        }
        execution_query = f"{item['query']}#digest={hit_digest}"
        if not conn.execute(
            "SELECT 1 FROM recon_sources WHERE target_name=? AND source_kind=? AND query=? LIMIT 1",
            (target_name, family, execution_query),
        ).fetchone():
            record_source(
                conn,
                target_name=target_name,
                source_kind=family,
                query=execution_query,
                result=execution,
                status=item["status"],
                ensure_schema=False,
                commit=False,
            )
        hit_kind = f"{family}:hit"
        for hit in item["hits"]:
            existing_hit = conn.execute(
                "SELECT id FROM recon_sources WHERE target_name=? AND source_kind=? AND query=? ORDER BY id LIMIT 1",
                (target_name, hit_kind, hit["url"]),
            ).fetchone()
            hit_result = {
                "schema": "public_exposure_hit/v1",
                "family": family,
                "provider": item["provider"],
                **hit,
            }
            hit_json = json.dumps(hit_result, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
            if existing_hit:
                conn.execute(
                    """UPDATE recon_sources SET result_json=?,status='needs_review',error=NULL,
                       observed_at=datetime('now','localtime') WHERE id=?""",
                    (hit_json, existing_hit["id"]),
                )
            else:
                conn.execute(
                    """INSERT INTO recon_sources(target_name,source_kind,query,result_json,status)
                       VALUES(?,?,?,?, 'needs_review')""",
                    (target_name, hit_kind, hit["url"], hit_json),
                )
        key = f"public_exposure:{family}"
        existing = conn.execute(
            """SELECT id,status,evidence_refs_json,summary,blocker_reason,next_action FROM coverage_ledger
               WHERE target_name=? AND profile_id IS NULL AND item_key=? ORDER BY id LIMIT 1""",
            (target_name, key),
        ).fetchone()
        coverage_refs = list(dict.fromkeys([*item["evidence_refs"], *(ref for hit in item["hits"] for ref in hit["evidence_refs"])]))[:20]
        preserve_existing = False
        if existing:
            try:
                prior_refs = json.loads(existing["evidence_refs_json"] or "[]")
            except json.JSONDecodeError:
                prior_refs = []
            coverage_refs = list(dict.fromkeys([*prior_refs, *coverage_refs]))[:20]
            rank = {"unknown": 0, "uncovered": 1, "blocked": 2, "covered": 3}
            if rank.get(existing["status"], 0) > rank[coverage]:
                coverage = existing["status"]
                preserve_existing = True
        refs_json = json.dumps(coverage_refs, ensure_ascii=True, separators=(",", ":"))
        summary = f"provider={item['provider'] or 'unknown'} execution={item['status']} results={item['result_count']}"
        blocker = item["status"] if coverage == "blocked" else ""
        next_action = "operator review required" if item["status"] == "hits" else "retain source coverage state"
        if preserve_existing:
            summary = existing["summary"]
            blocker = existing["blocker_reason"]
            next_action = existing["next_action"]
        if existing:
            conn.execute(
                """UPDATE coverage_ledger SET category='public_exposure',status=?,confidence='medium',
                   evidence_refs_json=?,summary=?,blocker_reason=?,next_action=?,updated_at=datetime('now','localtime')
                   WHERE id=?""",
                (coverage, refs_json, summary, blocker, next_action, existing["id"]),
            )
        else:
            conn.execute(
                """INSERT INTO coverage_ledger(
                     target_name,profile_id,item_key,category,status,confidence,evidence_refs_json,
                     summary,blocker_reason,next_action
                   ) VALUES(?,NULL,?,'public_exposure',?,'medium',?,?,?,?)""",
                (target_name, key, coverage, refs_json, summary, blocker, next_action),
            )
        conn.commit()
        return _result(target_name, item, coverage, applied=True)
    except Exception:
        conn.rollback()
        raise


def _result(target_name: str, item: dict[str, Any], coverage: str, *, applied: bool) -> dict[str, Any]:
    return {
        "target_name": target_name,
        "family": item["family"],
        "status": item["status"],
        "coverage_status": coverage,
        "result_count": item["result_count"],
        "dedup_count": item["dedup_count"],
        "sample": item["hits"][:10],
        "omitted": max(0, len(item["hits"]) - 10),
        "applied": applied,
    }


def build_adapter_contract(*, provider: str, query: str, family: str, trusted_base: str | None = None) -> dict[str, Any]:
    """Describe a provider request without executing network I/O."""
    if family not in FAMILIES:
        raise ValueError(f"unsupported public exposure family: {family}")
    if provider not in {"searxng", "gitlab", "huggingface"}:
        raise ValueError(f"unsupported provider: {provider}")
    contract = {"provider": provider, "family": family, "query": _redact_text(query, 500), "network_allowed": False}
    if provider == "searxng":
        parsed = urlsplit(str(trusted_base or ""))
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("searxng requires an explicit trusted https base URL")
        contract["endpoint"] = str(trusted_base).rstrip("/") + "/search"
    else:
        contract["adapter_status"] = "contract_only"
    return contract


def parse_adapter_fixture(*, provider: str, family: str, query: str, payload: Any, evidence_ref: str) -> dict[str, Any]:
    """Parse a local provider fixture into the unified import schema."""
    if provider == "searxng":
        rows = payload.get("results", []) if isinstance(payload, dict) else []
    elif provider in {"gitlab", "huggingface"}:
        rows = payload if isinstance(payload, list) else payload.get("items", []) if isinstance(payload, dict) else []
    else:
        raise ValueError(f"unsupported provider: {provider}")
    hits = [
        {
            "url": row.get("url") or row.get("web_url") or row.get("html_url"),
            "title": row.get("title") or row.get("name") or "",
            "snippet": row.get("content") or row.get("description") or "",
            "matched_anchor": query,
            "evidence_refs": [evidence_ref],
        }
        for row in rows
        if isinstance(row, dict) and (row.get("url") or row.get("web_url") or row.get("html_url"))
    ]
    return normalize_import(
        family,
        {
            "query": query,
            "provider": provider,
            "status": "hits" if hits else "searched_empty",
            "result_count": len(rows),
            "dedup_count": len(hits),
            "evidence_refs": [evidence_ref],
            "hits": hits,
        },
    )
