"""Passive SSLMate Certificate Transparency search with scope-safe persistence."""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

_TOOLS_DIR = Path(__file__).resolve().parent.parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

from db.db_utils import session  # noqa: E402

try:
    from .recon_intel import run_source_adapter, store_subfinder_candidates
    from .recon_store import record_source
except ImportError:  # pragma: no cover - direct script execution
    from recon_intel import run_source_adapter, store_subfinder_candidates  # type: ignore[no-redef]  # 回退分支与包内导入同一批名字
    from recon_store import record_source  # type: ignore[no-redef]  # 回退分支与包内导入同一批名字


API_URL = "https://api.certspotter.com/v1/issuances"


def _normalize_domain(value: str) -> str:
    domain = value.strip().lower().rstrip(".")
    if not domain or "://" in domain or "/" in domain or "@" in domain:
        raise ValueError("--domain must be a hostname, not a URL or account")
    return domain


def _same_root_name(name: str, root_domain: str) -> str | None:
    normalized = name.strip().lower().rstrip(".")
    if normalized.startswith("*."):
        normalized = normalized[2:]
    if normalized == root_domain or normalized.endswith(f".{root_domain}"):
        return normalized
    return None


def _compact_issuance(item: Any, root_domain: str) -> tuple[dict[str, Any], list[str]]:
    issuance = item if isinstance(item, dict) else {}
    names = sorted(
        {
            candidate
            for raw_name in issuance.get("dns_names", [])
            if isinstance(raw_name, str)
            if (candidate := _same_root_name(raw_name, root_domain))
        }
    )
    issuer = issuance.get("issuer")
    issuer_name = issuer.get("friendly_name", "") if isinstance(issuer, dict) else ""
    return (
        {
            "id": issuance.get("id"),
            "tbs_sha256": issuance.get("tbs_sha256", ""),
            "cert_sha256": issuance.get("cert_sha256", ""),
            "dns_names": names,
            "issuer": issuer_name,
            "not_before": issuance.get("not_before", ""),
            "not_after": issuance.get("not_after", ""),
            "revoked": bool(issuance.get("revoked", False)),
        },
        names,
    )


def run_sslmate_ct_search(
    domain: str,
    *,
    api_key: str = "",
    after: int | None = None,
    include_subdomains: bool = True,
    match_wildcards: bool = True,
    timeout: int = 30,
) -> dict[str, Any]:
    """Query SSLMate's CT API once; return only compact, same-root certificate facts."""
    root_domain = _normalize_domain(domain)
    if not api_key:
        return {"status": "not_configured", "provider": "sslmate_ct", "domain": root_domain, "items": []}

    params: list[tuple[str, str]] = [("domain", root_domain), ("expand", "dns_names"), ("expand", "issuer")]
    if include_subdomains:
        params.append(("include_subdomains", "true"))
    if match_wildcards:
        params.append(("match_wildcards", "true"))
    if after is not None:
        params.append(("after", str(after)))
    request = urllib.request.Request(  # noqa: S310 - API_URL is a fixed HTTPS constant
        f"{API_URL}?{urllib.parse.urlencode(params)}",
        headers={"Authorization": f"Bearer {api_key}", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - fixed SSLMate API URL
            payload = json.loads(response.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        if exc.code in {401, 402, 403}:
            status = "provider_auth_error"
        elif exc.code == 429:
            status = "provider_limited"
        else:
            status = "provider_failed"
        return {
            "status": status,
            "provider": "sslmate_ct",
            "domain": root_domain,
            "items": [],
            "error": f"http_{exc.code}",
        }
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, UnicodeDecodeError):
        return {
            "status": "provider_unavailable",
            "provider": "sslmate_ct",
            "domain": root_domain,
            "items": [],
            "error": "request_failed",
        }

    if not isinstance(payload, list):
        return {
            "status": "provider_failed",
            "provider": "sslmate_ct",
            "domain": root_domain,
            "items": [],
            "error": "unexpected_response",
        }
    compact_items: list[dict[str, Any]] = []
    candidates: set[str] = set()
    for item in payload:
        compact, names = _compact_issuance(item, root_domain)
        compact_items.append(compact)
        candidates.update(names)
    return {
        "status": "observed",
        "provider": "sslmate_ct",
        "domain": root_domain,
        "items": compact_items,
        "candidate_hosts": sorted(candidates),
        "next_after": compact_items[-1]["id"] if compact_items else None,
    }


def persist_sslmate_ct_result(conn, *, target_name: str, domain: str, result: dict[str, Any]) -> int:
    """Record passive evidence and write same-root hostnames as review-only candidates."""
    source_id = record_source(
        conn,
        target_name=target_name,
        source_kind="sslmate_ct",
        query=domain,
        result=result,
        status=str(result["status"]),
        error=str(result.get("error", "")),
    )
    candidate_result = {"items": [{"host": host} for host in result.get("candidate_hosts", [])]}
    return store_subfinder_candidates(
        conn,
        target_name=target_name,
        root_domain=domain,
        result=candidate_result,
        source_id=source_id,
    )


def _require_target_in_db(conn, target_name: str) -> None:
    """Refuse a cross-target write before a provider is invoked."""
    if not target_name.strip():
        raise ValueError("target is required")
    row = conn.execute("SELECT 1 FROM targets WHERE target_name=? LIMIT 1", (target_name,)).fetchone()
    if row is None:
        raise ValueError("target is not present in the explicit database")


def main() -> int:
    parser = argparse.ArgumentParser(description="Passive SSLMate CT search; credentials come only from SSLMATE_API_KEY")
    parser.add_argument("--target", required=True, help="explicit authorized target name")
    parser.add_argument("--db", required=True, help="explicit target SQLite DB")
    parser.add_argument("--domain", required=True, help="authorized root domain")
    parser.add_argument("--after", type=int, help="continue after a prior issuance id")
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--no-subdomains", action="store_true")
    parser.add_argument("--no-match-wildcards", action="store_true")
    args = parser.parse_args()

    try:
        db_path = Path(args.db)
        if not db_path.is_file():
            raise ValueError(f"database file not found: {db_path}")
        domain = _normalize_domain(args.domain)
        with session(db_path) as conn:
            _require_target_in_db(conn, args.target)
            result = run_source_adapter(
                conn,
                target_name=args.target,
                source_kind="sslmate_ct",
                adapter="sslmate_ct",
                input_data={
                    "domain": domain,
                    "include_subdomains": not args.no_subdomains,
                    "match_wildcards": not args.no_match_wildcards,
                },
                budget={"timeout_seconds": args.timeout},
                retry_cursor={"after": args.after} if args.after is not None else None,
                runner=lambda: run_sslmate_ct_search(
                    domain,
                    api_key=os.environ.get("SSLMATE_API_KEY", ""),
                    after=args.after,
                    include_subdomains=not args.no_subdomains,
                    match_wildcards=not args.no_match_wildcards,
                    timeout=args.timeout,
                ),
            )
            result["review_candidates_written"] = persist_sslmate_ct_result(conn, target_name=args.target, domain=domain, result=result)
        print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
        return 0 if result["status"] == "observed" else 1
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=True, separators=(",", ":")))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
