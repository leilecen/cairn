"""API-first public source intelligence adapters."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable

_TOOLS_DIR = Path(__file__).resolve().parent.parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

from utils.egress import load_identity  # noqa: E402

try:
    from .fofa_relay import local_relay_key
    from .public_exposure_intel import FAMILIES, import_public_exposure
    from .recon_runtime import begin_recon_run, update_recon_run
    from .recon_store import record_source
except ImportError:  # pragma: no cover - direct script execution
    from fofa_relay import local_relay_key  # type: ignore[no-redef]  # 回退分支与包内导入同一批名字
    from public_exposure_intel import FAMILIES, import_public_exposure  # type: ignore[no-redef]  # 回退分支与包内导入同一批名字
    from recon_runtime import begin_recon_run, update_recon_run  # type: ignore[no-redef]  # 回退分支与包内导入同一批名字
    from recon_store import record_source  # type: ignore[no-redef]  # 回退分支与包内导入同一批名字


@lru_cache(maxsize=1)
def intel_user_agent() -> str:
    """第三方情报 API 使用的中性 UA（不再自报名号）。

    情报 API 不是目标侧（目标看不到这些请求），因此不需要 Egress 节拍与台账；
    但自报名号（原 `src-recon/1.0`）同样等于把工具清单交给第三方，且容易被
    第三方风控直接封禁。这里复用 egress 统一身份 UA，保持出口身份口径一致。
    """
    return load_identity().user_agent


TIANYAN_COMPANY_KINDS = {
    "registration-info",
    "equity-tree",
    "actual-controller",
    "beneficial-owners",
}
UNCOVER_ENGINES = {
    "binaryedge",
    "censys",
    "criminalip",
    "fofa",
    "greynoise",
    "hunter",
    "netlas",
    "onyphe",
    "quake",
    "shodan",
    "shodan-idb",
    "zoomeye",
}
PASSIVE_DNS_PROVIDERS = {"securitytrails", "virustotal", "robtex"}


def resolve_fofa_capability(
    *,
    environ: dict[str, str] | None = None,
    provider_config_path: Path | None = None,
    local_fallback: bool = False,
) -> dict[str, str | None | list[str]]:
    """Resolve the project's FOFA capability using the relay only.

    ``uncover`` has its own provider configuration and is intentionally not a
    fallback here: selecting it would make workers use a different credential
    source than the one documented for this project.  The optional config
    path remains in the signature for compatibility with callers/tests, but is
    deliberately ignored.
    """
    del provider_config_path
    environment = os.environ if environ is None else environ
    # An explicitly injected environ is the controlled/test path and is honoured
    # verbatim; only the real process environment may fall back to the local
    # gitignored credential file.
    relay_key = environment.get("FOFA_RELAY_KEY", "").strip()
    if not relay_key and local_fallback:
        relay_key = local_relay_key()
    if relay_key:
        return {
            "status": "available",
            "provider": "fofa",
            "adapter": "relay",
            "credential_source": "FOFA_RELAY_KEY",
            "policy": "relay_only",
        }
    return {
        "status": "not_configured",
        "provider": "fofa",
        "adapter": None,
        "credential_source": None,
        "allowed_adapters": ["relay"],
        "policy": "relay_only",
    }


def _api_response(request: urllib.request.Request, *, timeout: int) -> dict[str, Any]:
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - fixed provider API URL
        return json.loads(response.read().decode("utf-8", errors="replace"))


def run_securitytrails_passive_dns(domain: str, *, api_key: str = "", timeout: int = 30) -> dict[str, Any]:
    """Read historical A records without contacting the observed IP addresses."""
    if not api_key:
        return {"status": "not_configured", "provider": "securitytrails", "domain": domain, "items": []}
    request = urllib.request.Request(
        f"https://api.securitytrails.com/v1/history/{urllib.parse.quote(domain, safe='')}/dns/a",
        headers={"APIKEY": api_key, "Accept": "application/json"},
    )
    try:
        payload = _api_response(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        status = "provider_limited" if exc.code in {401, 403, 429} else "unknown"
        return {"status": status, "provider": "securitytrails", "domain": domain, "items": [], "http_status": exc.code}
    except (OSError, json.JSONDecodeError) as exc:
        return {"status": "unknown", "provider": "securitytrails", "domain": domain, "items": [], "error": str(exc)}

    items: list[dict[str, Any]] = []
    for record in payload.get("records", []):
        for value in record.get("values", []):
            ip = value.get("ip") if isinstance(value, dict) else None
            if ip:
                items.append(
                    {
                        "ip": str(ip),
                        "first_seen": record.get("first_seen"),
                        "last_seen": record.get("last_seen"),
                    }
                )
    return {"status": "observed", "provider": "securitytrails", "domain": domain, "items": items}


def run_robtex_passive_dns(domain: str, *, timeout: int = 30) -> dict[str, Any]:
    """Read historical A/AAAA records from Robtex's free passive-DNS API.

    Robtex needs no API key, which makes it the free replacement for
    SecurityTrails here.  Only DNS metadata is read; no observed IP is
    contacted, so this stays a passive observation.
    """
    request = urllib.request.Request(
        f"https://freeapi.robtex.com/pdns/forward/{urllib.parse.quote(domain, safe='')}",
        headers={"Accept": "application/json", "User-Agent": intel_user_agent()},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - fixed provider API URL
            body = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        status = "provider_limited" if exc.code in {401, 403, 429} else "unknown"
        return {"status": status, "provider": "robtex", "domain": domain, "items": [], "http_status": exc.code}
    except (OSError, json.JSONDecodeError) as exc:
        return {"status": "unknown", "provider": "robtex", "domain": domain, "items": [], "error": str(exc)}

    items: list[dict[str, Any]] = []
    for line in body.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        rows = record if isinstance(record, list) else [record]
        for row in rows:
            if not isinstance(row, dict) or row.get("rrtype") not in {"A", "AAAA"}:
                continue
            items.append(
                {
                    "ip": str(row.get("rrdata", "")),
                    "record_type": row.get("rrtype"),
                    "first_seen": row.get("time_first"),
                    "last_seen": row.get("time_last"),
                    "count": row.get("count"),
                }
            )
    return {"status": "observed", "provider": "robtex", "domain": domain, "items": items}


def run_virustotal_passive_dns(domain: str, *, api_key: str = "", timeout: int = 30) -> dict[str, Any]:
    """Read VirusTotal domain-resolution history without submitting or scanning anything."""
    if not api_key:
        return {"status": "not_configured", "provider": "virustotal", "domain": domain, "items": []}
    request = urllib.request.Request(
        f"https://www.virustotal.com/api/v3/domains/{urllib.parse.quote(domain, safe='')}/resolutions?limit=40",
        headers={"x-apikey": api_key, "Accept": "application/json"},
    )
    try:
        payload = _api_response(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        status = "provider_limited" if exc.code in {401, 403, 429} else "unknown"
        return {"status": status, "provider": "virustotal", "domain": domain, "items": [], "http_status": exc.code}
    except (OSError, json.JSONDecodeError) as exc:
        return {"status": "unknown", "provider": "virustotal", "domain": domain, "items": [], "error": str(exc)}

    items = []
    for item in payload.get("data", []):
        attributes = item.get("attributes", {})
        ip = attributes.get("ip_address")
        if ip:
            items.append({"ip": str(ip), "observed_at": attributes.get("date"), "resolver": attributes.get("resolver")})
    return {"status": "observed", "provider": "virustotal", "domain": domain, "items": items}


def github_code_search(target_name: str, query: str, *, token: str = "", timeout: int = 15) -> dict[str, Any]:
    params = urllib.parse.urlencode({"q": query, "per_page": 20})
    request = urllib.request.Request(
        f"https://api.github.com/search/code?{params}",
        headers={"Accept": "application/vnd.github+json", **({"Authorization": f"Bearer {token}"} if token else {})},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - fixed GitHub API URL
            payload = json.loads(response.read().decode("utf-8", errors="replace"))
            items = [
                {
                    "name": item.get("name"),
                    "path": item.get("path"),
                    "url": item.get("html_url"),
                    "repository": (item.get("repository") or {}).get("full_name"),
                }
                for item in payload.get("items", [])
            ]
            return {"status": "observed", "items": items, "total": payload.get("total_count", len(items))}
    except urllib.error.HTTPError as exc:
        status = "search_limited" if exc.code in {401, 403, 429} else "unknown"
        return {"status": status, "http_status": exc.code, "items": [], "error": str(exc)}
    except (OSError, json.JSONDecodeError) as exc:
        return {"status": "unknown", "items": [], "error": str(exc)}


def run_subfinder(domain: str, *, executable: str = "subfinder", timeout: int = 90) -> dict[str, Any]:
    """Collect passive subdomains without resolving or contacting candidate hosts."""
    command = [executable, "-d", domain, "-oJ", "-cs", "-silent", "-duc"]
    if not shutil.which(executable):
        return {"status": "tool_missing", "domain": domain, "items": [], "command": command}
    try:
        completed = subprocess.run(  # noqa: S603 - exact executable and fixed argument structure
            command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"status": "unknown", "domain": domain, "items": [], "error": str(exc)}

    items: list[dict[str, Any]] = []
    for line in completed.stdout.splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = str(row.get("host", "")).strip().lower().rstrip(".")
        if host:
            items.append({"host": host, "sources": sorted(str(source) for source in row.get("sources", []) if source)})
    status = "observed" if completed.returncode == 0 else "tool_failed"
    result: dict[str, Any] = {"status": status, "domain": domain, "items": items}
    if completed.returncode:
        result["error"] = completed.stderr[-1000:]
    return result


def run_amass(domain: str, *, executable: str = "amass", timeout: int = 150) -> dict[str, Any]:
    """Collect passive Amass names without DNS resolution, brute force, or active checks."""
    resolved = resolve_executable(executable)
    if not resolved:
        return {"status": "tool_missing", "domain": domain, "items": []}
    # Amass v4 dropped the -src flag; passive is the default and host lines are
    # emitted as plain names with -silent.
    command = [resolved, "enum", "-d", domain, "-timeout", "2", "-silent", "-nocolor"]
    try:
        completed = subprocess.run(  # noqa: S603 - exact executable and fixed argument structure
            command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"status": "unknown", "domain": domain, "items": [], "error": str(exc)}

    items: list[dict[str, Any]] = []
    for line in completed.stdout.splitlines():
        match = re.match(r"^\[([^\]]+)]\s+([A-Za-z0-9][A-Za-z0-9.-]+)$", line.strip())
        host = match.group(2).lower().rstrip(".") if match else line.strip().lower().rstrip(".")
        if re.fullmatch(r"[a-z0-9][a-z0-9.-]*", host):
            sources = [match.group(1)] if match else []
            items.append({"host": host, "sources": sources})
    status = "observed" if completed.returncode == 0 else "tool_failed"
    result: dict[str, Any] = {"status": status, "domain": domain, "items": items}
    if completed.returncode:
        result["error"] = completed.stderr[-1000:]
    return result


def run_uncover(
    query: str, *, engine: str, executable: str = "uncover", limit: int = 50, rate_limit: int = 1, timeout: int = 90
) -> dict[str, Any]:
    """Query one configured third-party index; results remain source observations."""
    if engine not in UNCOVER_ENGINES:
        raise ValueError(f"unsupported uncover engine: {engine}")
    resolved = resolve_executable(executable)
    if not resolved:
        return {"status": "tool_missing", "query": query, "engine": engine, "items": []}
    command = [
        resolved,
        "-e",
        engine,
        "-q",
        query,
        "-l",
        str(limit),
        "-rl",
        str(rate_limit),
        "-j",
        "-silent",
        "-duc",
    ]
    try:
        completed = subprocess.run(  # noqa: S603 - exact executable and fixed argument structure
            command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"status": "unknown", "query": query, "engine": engine, "items": [], "error": str(exc)}

    items: list[dict[str, Any]] = []
    for line in completed.stdout.splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        item = {key: row[key] for key in ("host", "ip", "port", "url") if row.get(key) is not None}
        if item:
            items.append(item)
    stderr_tail = completed.stderr[-1000:]
    # uncover 无 key/engine 未配置时返回非零并以 "requires keys"/"no keys" 报错，
    # 此时不是工具失败而是 provider 未配置：返回 not_configured（与
    # securitytrails/virustotal 适配器一致），避免把英文 stderr 当错误转述。
    if completed.returncode and ("requires keys" in stderr_tail or "no keys" in stderr_tail):
        return {
            "status": "not_configured",
            "query": query,
            "engine": engine,
            "items": [],
            "error": stderr_tail,
        }
    status = "observed" if completed.returncode == 0 else "tool_failed"
    result: dict[str, Any] = {"status": status, "query": query, "engine": engine, "items": items}
    if completed.returncode:
        result["error"] = stderr_tail
    return result


def run_fofa_relay(query: str, *, key: str, limit: int) -> dict[str, Any]:
    """Use the local relay adapter and return only compact, credential-free results."""
    try:
        try:
            from . import fofa_relay
        except ImportError:  # pragma: no cover - direct script execution
            import fofa_relay  # type: ignore[no-redef]  # 回退分支与包内导入同一批名字

        raw = fofa_relay.search(key, query, size=limit)
        normalized = fofa_relay.normalize(raw, query)
    except Exception as exc:  # relay errors can contain credential-bearing request URLs
        response = getattr(exc, "response", None)
        code = getattr(response, "status_code", None)
        status = "provider_limited" if code in {401, 403, 429} else "unknown"
        result: dict[str, Any] = {
            "status": status,
            "provider": "fofa",
            "adapter": "relay",
            "query": query,
            "items": [],
        }
        if code is not None:
            result["http_status"] = code
        return result
    return {
        "status": "observed",
        "provider": "fofa",
        "adapter": "relay",
        "query": query,
        "items": normalized["results"],
        "total": normalized.get("total"),
        "remaining": normalized.get("_remaining"),
    }


def run_fofa(
    query: str,
    *,
    limit: int,
    rate_limit: int = 1,
    capability: dict[str, Any] | None = None,
    relay_key: str | None = None,
) -> dict[str, Any]:
    """Run the one selected FOFA adapter, or return one compact unavailable result."""
    selected = capability or resolve_fofa_capability()
    if selected["status"] != "available":
        return {**selected, "query": query, "items": []}
    if selected["adapter"] != "relay":
        return {
            "status": "disabled_by_policy" if selected.get("adapter") == "uncover" else selected["status"],
            "provider": "fofa",
            "adapter": None,
            "allowed_adapters": ["relay"],
            "policy": "relay_only",
            "query": query,
            "items": [],
        }
    key = relay_key if relay_key is not None else (os.environ.get("FOFA_RELAY_KEY", "").strip() or local_relay_key())
    if not key:
        return {
            "status": "not_configured",
            "provider": "fofa",
            "adapter": None,
            "allowed_adapters": ["relay"],
            "policy": "relay_only",
            "query": query,
            "items": [],
        }
    return run_fofa_relay(query, key=key, limit=limit)


def _url_without_query(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def run_gau(domain: str, *, executable: str = "gau", timeout: int = 150) -> dict[str, Any]:
    """Read public archive URL leads without retaining URL query values."""
    resolved = resolve_executable(executable)
    if not resolved:
        return {"status": "tool_missing", "domain": domain, "items": []}
    command = [
        resolved,
        "--providers",
        "wayback,commoncrawl,otx,urlscan",
        "--json",
        "--threads",
        "1",
        "--timeout",
        "30",
        domain,
    ]
    try:
        completed = subprocess.run(  # noqa: S603 - exact executable and fixed argument structure
            command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"status": "unknown", "domain": domain, "items": [], "error": str(exc)}

    items: list[dict[str, str]] = []
    for line in completed.stdout.splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        url = str(row.get("url", "")).strip()
        if url:
            items.append({"url": _url_without_query(url), "source": str(row.get("source", ""))})
    status = "observed" if completed.returncode == 0 else "tool_failed"
    result: dict[str, Any] = {"status": status, "domain": domain, "items": items}
    if completed.returncode:
        result["error"] = completed.stderr[-1000:]
    return result


def run_asnmap(value: str, *, lookup_type: str, executable: str = "asnmap", timeout: int = 90) -> dict[str, Any]:
    """Map an organization or ASN through public network intelligence only."""
    if lookup_type not in {"org", "asn"}:
        raise ValueError(f"unsupported asnmap lookup type: {lookup_type}")
    resolved = resolve_executable(executable)
    if not resolved:
        return {"status": "tool_missing", "lookup_type": lookup_type, "query": value, "items": []}
    flag = "-org" if lookup_type == "org" else "-a"
    command = [resolved, flag, value, "-j", "-silent", "-duc"]
    try:
        completed = subprocess.run(  # noqa: S603 - exact executable and fixed argument structure
            command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"status": "unknown", "lookup_type": lookup_type, "query": value, "items": [], "error": str(exc)}

    items: list[dict[str, Any]] = []
    for line in completed.stdout.splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        item = {key: row[key] for key in ("asn", "org", "country", "cidr", "ip") if row.get(key) is not None}
        if item:
            items.append(item)
    status = "observed" if completed.returncode == 0 else "tool_failed"
    result: dict[str, Any] = {"status": status, "lookup_type": lookup_type, "query": value, "items": items}
    if completed.returncode:
        result["error"] = completed.stderr[-1000:]
    return result


def resolve_executable(name: str) -> str | None:
    """Resolve a tool name to an absolute executable path.

    On Windows, npm-installed CLIs only ship a `.cmd`/`.ps1` shim (no real
    .exe), and subprocess with shell=False does not apply PATHEXT lookup.  So
    resolve via shutil.which and prefer a real .exe; fall back to the shim.
    """
    resolved = shutil.which(name)
    if not resolved:
        return None
    if os.name != "nt":
        return resolved
    # shutil.which on Windows already appends PATHEXT; just make sure it is absolute.
    return os.path.abspath(resolved)


def run_tianyan_company(company: str, *, kind: str, executable: str = "tyc", timeout: int = 45) -> dict[str, Any]:
    """Run an official TYC CLI query and retain only its structured public response."""
    if kind not in TIANYAN_COMPANY_KINDS:
        raise ValueError(f"unsupported tianyan kind: {kind}")
    resolved = resolve_executable(executable)
    if not resolved:
        return {"status": "tool_missing", "company": company, "kind": kind, "result": {}}
    command = [resolved, "company", kind, company, "--compact"]
    try:
        completed = subprocess.run(  # noqa: S603 - exact executable and fixed argument structure
            command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"status": "unknown", "company": company, "kind": kind, "result": {}, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001 - surface any shim/launch failure as tool error
        return {
            "status": "tool_failed",
            "company": company,
            "kind": kind,
            "result": {},
            "error": f"{type(exc).__name__}: {exc}",
        }

    try:
        payload: Any = json.loads(completed.stdout)
    except json.JSONDecodeError:
        payload = {"output": completed.stdout[-4000:]}
    status = "observed" if completed.returncode == 0 else "tool_failed"
    result = {"status": status, "company": company, "kind": kind, "result": payload}
    if completed.returncode:
        result["error"] = completed.stderr[-1000:]
    return result


def store_subfinder_candidates(conn, *, target_name: str, root_domain: str, result: dict[str, Any], source_id: int | None) -> int:
    """Persist public hostname leads as review-only assets; never queue or validate them."""
    inserted = 0
    suffix = root_domain.lower().strip().rstrip(".")
    for item in result.get("items", []):
        host = str(item.get("host", "")).lower().strip().rstrip(".")
        if not host or (host != suffix and not host.endswith(f".{suffix}")):
            continue
        asset_type = "domain" if host == suffix else "subdomain"
        cur = conn.execute(
            """INSERT OR IGNORE INTO target_assets
               (target_name, asset_type, asset_value, protocol, source, status, scope_status,
                scope_class, authorization_state, relation_to_target, source_query, source_snapshot)
               VALUES (?, ?, ?, 'https', 'other', 'new', 'needs_review', 'unknown', 'unknown',
                       'passive_candidate', ?, ?)""",
            (target_name, asset_type, host, root_domain, str(source_id or "")),
        )
        inserted += int(cur.rowcount > 0)
    conn.commit()
    return inserted


def import_result_file(conn, *, target_name: str, source_kind: str, query: str, path: str, apply: bool = False) -> dict[str, Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if source_kind in FAMILIES:
        if query and isinstance(payload, dict) and not payload.get("query"):
            payload = {**payload, "query": query}
        return import_public_exposure(conn, target_name=target_name, family=source_kind, payload=payload, apply=apply)
    record_source(
        conn,
        target_name=target_name,
        source_kind=source_kind,
        query=query,
        result=payload,
        status=payload.get("status", "observed") if isinstance(payload, dict) else "observed",
    )
    return {"target": target_name, "source_kind": source_kind, "status": "observed"}


def _run_reason(result: dict[str, Any]) -> str:
    status = result.get("status")
    if status == "observed":
        return "succeeded" if result.get("items") else "empty"
    if status == "not_configured":
        return "not_configured"
    if status in {"provider_limited", "search_limited"}:
        return "rate_limited"
    if "timeout" in str(result.get("error", "")).lower():
        return "timeout"
    return "failed"


def run_source_adapter(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    source_kind: str,
    adapter: str,
    input_data: dict[str, Any],
    budget: dict[str, Any],
    runner: Callable[[], dict[str, Any]],
    retry_cursor: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Execute one adapter while retaining only compact, resumable run state."""
    run = begin_recon_run(
        conn,
        target_name=target_name,
        source=source_kind,
        input_data={"adapter": adapter, **input_data},
        budget=budget,
    )
    try:
        result = runner()
    except Exception:
        update_recon_run(
            conn,
            run_id=run["id"],
            status="blocked",
            cursor={"completed": False, "items": 0},
            summary={"adapter": adapter, "reason": "failed", "source_status": "exception"},
        )
        raise
    reason = _run_reason(result)
    items = result.get("items", [])
    item_count = len(items) if isinstance(items, list) else 0
    cursor = {"completed": reason in {"succeeded", "empty"}, "items": item_count}
    if retry_cursor:
        cursor.update(retry_cursor)
    if result.get("next_after") is not None:
        cursor["after"] = result["next_after"]
    update_recon_run(
        conn,
        run_id=run["id"],
        status="succeeded" if reason in {"succeeded", "empty"} else "blocked",
        cursor=cursor,
        summary={"adapter": adapter, "reason": reason, "source_status": result.get("status", "unknown")},
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="API-first recon intelligence adapter")
    parser.add_argument("--target", required=True)
    parser.add_argument("--db", required=True)
    parser.add_argument("--github-query")
    parser.add_argument("--subfinder-domain")
    parser.add_argument("--subfinder-bin", default="subfinder")
    parser.add_argument("--amass-domain")
    parser.add_argument("--amass-bin", default="amass")
    parser.add_argument("--uncover-query")
    parser.add_argument("--uncover-engine", choices=sorted(UNCOVER_ENGINES))
    parser.add_argument("--uncover-bin", default="uncover")
    parser.add_argument("--uncover-limit", type=int, default=50)
    parser.add_argument("--uncover-rate-limit", type=int, default=1)
    parser.add_argument("--gau-domain")
    parser.add_argument("--gau-bin", default="gau")
    parser.add_argument("--passive-dns-domain")
    parser.add_argument("--passive-dns-provider", choices=sorted(PASSIVE_DNS_PROVIDERS))
    asnmap_group = parser.add_mutually_exclusive_group()
    asnmap_group.add_argument("--asnmap-org")
    asnmap_group.add_argument("--asnmap-asn")
    parser.add_argument("--asnmap-bin", default="asnmap")
    parser.add_argument("--tianyan-company")
    parser.add_argument("--tianyan-kind", choices=sorted(TIANYAN_COMPANY_KINDS), action="append")
    parser.add_argument("--tianyan-bin", default="tyc")
    parser.add_argument("--import-json")
    parser.add_argument("--source-kind", default="external_import")
    parser.add_argument("--query", default="")
    parser.add_argument("--apply", action="store_true", help="apply public exposure imports; default is preview")
    args = parser.parse_args()
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from db.db_utils import connect

    try:
        db_path = Path(args.db)
        if not db_path.is_file():
            raise ValueError(f"database file not found: {db_path}")
        conn = connect(db_path)
        if args.github_query:
            result = run_source_adapter(
                conn,
                target_name=args.target,
                source_kind="github_code",
                adapter="github_code_search",
                input_data={"query": args.github_query},
                budget={"timeout_seconds": 15},
                runner=lambda: github_code_search(args.target, args.github_query, token=os.environ.get("GITHUB_TOKEN", "")),
            )
            record_source(
                conn,
                target_name=args.target,
                source_kind="github_code",
                query=args.github_query,
                result=result,
                status=result["status"],
                error=result.get("error", ""),
            )
            print(json.dumps(result, ensure_ascii=False))
        elif args.subfinder_domain:
            result = run_source_adapter(
                conn,
                target_name=args.target,
                source_kind="subfinder_passive",
                adapter="subfinder",
                input_data={"domain": args.subfinder_domain},
                budget={"timeout_seconds": 90},
                runner=lambda: run_subfinder(args.subfinder_domain, executable=args.subfinder_bin),
            )
            source_id = record_source(
                conn,
                target_name=args.target,
                source_kind="subfinder_passive",
                query=args.subfinder_domain,
                result=result,
                status=result["status"],
                error=result.get("error", ""),
            )
            result["review_candidates_written"] = store_subfinder_candidates(
                conn, target_name=args.target, root_domain=args.subfinder_domain, result=result, source_id=source_id
            )
            print(json.dumps(result, ensure_ascii=False))
        elif args.amass_domain:
            result = run_source_adapter(
                conn,
                target_name=args.target,
                source_kind="amass_passive",
                adapter="amass",
                input_data={"domain": args.amass_domain},
                budget={"timeout_seconds": 150},
                runner=lambda: run_amass(args.amass_domain, executable=args.amass_bin),
            )
            source_id = record_source(
                conn,
                target_name=args.target,
                source_kind="amass_passive",
                query=args.amass_domain,
                result=result,
                status=result["status"],
                error=result.get("error", ""),
            )
            result["review_candidates_written"] = store_subfinder_candidates(
                conn, target_name=args.target, root_domain=args.amass_domain, result=result, source_id=source_id
            )
            print(json.dumps(result, ensure_ascii=False))
        elif args.uncover_query:
            if not args.uncover_engine:
                parser.error("--uncover-engine is required with --uncover-query")
            if args.uncover_engine == "fofa":
                capability = resolve_fofa_capability(local_fallback=True)
                source_kind = "fofa_relay"
                adapter = "fofa_relay"
                result = run_source_adapter(
                    conn,
                    target_name=args.target,
                    source_kind=source_kind,
                    adapter=adapter,
                    input_data={"query": args.uncover_query, "engine": "fofa"},
                    budget={"limit": args.uncover_limit, "rate_limit": args.uncover_rate_limit},
                    runner=lambda: run_fofa(
                        args.uncover_query,
                        limit=args.uncover_limit,
                        rate_limit=args.uncover_rate_limit,
                        capability=capability,
                    ),
                )
            else:
                source_kind = f"uncover_{args.uncover_engine}"
                result = run_source_adapter(
                    conn,
                    target_name=args.target,
                    source_kind=source_kind,
                    adapter="uncover",
                    input_data={"query": args.uncover_query, "engine": args.uncover_engine},
                    budget={"limit": args.uncover_limit, "rate_limit": args.uncover_rate_limit, "timeout_seconds": 90},
                    runner=lambda: run_uncover(
                        args.uncover_query,
                        engine=args.uncover_engine,
                        executable=args.uncover_bin,
                        limit=args.uncover_limit,
                        rate_limit=args.uncover_rate_limit,
                    ),
                )
            if args.uncover_engine == "fofa" and result.get("adapter") == "relay":
                source_kind = "fofa_relay"
            record_source(
                conn,
                target_name=args.target,
                source_kind=source_kind,
                query=args.uncover_query,
                result=result,
                status=result["status"],
                error=result.get("error", ""),
            )
            print(json.dumps(result, ensure_ascii=False))
        elif args.gau_domain:
            result = run_source_adapter(
                conn,
                target_name=args.target,
                source_kind="gau_archive",
                adapter="gau",
                input_data={"domain": args.gau_domain},
                budget={"timeout_seconds": 150},
                runner=lambda: run_gau(args.gau_domain, executable=args.gau_bin),
            )
            record_source(
                conn,
                target_name=args.target,
                source_kind="gau_archive",
                query=args.gau_domain,
                result=result,
                status=result["status"],
                error=result.get("error", ""),
            )
            print(json.dumps(result, ensure_ascii=False))
        elif args.passive_dns_domain:
            if not args.passive_dns_provider:
                parser.error("--passive-dns-provider is required with --passive-dns-domain")
            if args.passive_dns_provider == "securitytrails":
                adapter = "securitytrails"

                def runner() -> dict[str, Any]:
                    return run_securitytrails_passive_dns(args.passive_dns_domain, api_key=os.environ.get("SECURITYTRAILS_API_KEY", ""))

            elif args.passive_dns_provider == "robtex":
                adapter = "robtex"

                def runner() -> dict[str, Any]:
                    return run_robtex_passive_dns(args.passive_dns_domain)

            else:
                adapter = "virustotal"

                def runner() -> dict[str, Any]:
                    return run_virustotal_passive_dns(args.passive_dns_domain, api_key=os.environ.get("VIRUSTOTAL_API_KEY", ""))

            result = run_source_adapter(
                conn,
                target_name=args.target,
                source_kind=f"passive_dns_{args.passive_dns_provider}",
                adapter=adapter,
                input_data={"domain": args.passive_dns_domain, "provider": args.passive_dns_provider},
                budget={"timeout_seconds": 30},
                runner=runner,
            )
            record_source(
                conn,
                target_name=args.target,
                source_kind=f"passive_dns_{args.passive_dns_provider}",
                query=args.passive_dns_domain,
                result=result,
                status=result["status"],
                error=result.get("error", ""),
            )
            print(json.dumps(result, ensure_ascii=False))
        elif args.asnmap_org or args.asnmap_asn:
            lookup_type = "org" if args.asnmap_org else "asn"
            query = args.asnmap_org or args.asnmap_asn
            result = run_source_adapter(
                conn,
                target_name=args.target,
                source_kind=f"asnmap_{lookup_type}",
                adapter="asnmap",
                input_data={"query": query, "lookup_type": lookup_type},
                budget={"timeout_seconds": 90},
                runner=lambda: run_asnmap(query, lookup_type=lookup_type, executable=args.asnmap_bin),
            )
            record_source(
                conn,
                target_name=args.target,
                source_kind=f"asnmap_{lookup_type}",
                query=query,
                result=result,
                status=result["status"],
                error=result.get("error", ""),
            )
            print(json.dumps(result, ensure_ascii=False))
        elif args.tianyan_company:
            kinds = args.tianyan_kind or ["registration-info"]
            results = []

            def _make_runner(company: str, kind_value: str, executable: str | None):
                def runner() -> dict[str, Any]:
                    return run_tianyan_company(company, kind=kind_value, executable=executable or "tianyancha")

                return runner

            for kind in kinds:
                result = run_source_adapter(
                    conn,
                    target_name=args.target,
                    source_kind=f"tianyan_{kind}",
                    adapter="tianyan_company",
                    input_data={"company": args.tianyan_company, "kind": kind},
                    budget={"timeout_seconds": 45},
                    runner=_make_runner(args.tianyan_company, kind, args.tianyan_bin),
                )
                record_source(
                    conn,
                    target_name=args.target,
                    source_kind=f"tianyan_{kind}",
                    query=args.tianyan_company,
                    result=result,
                    status=result["status"],
                    error=result.get("error", ""),
                )
                results.append(result)
            print(json.dumps({"target": args.target, "results": results}, ensure_ascii=False))
        elif args.import_json:
            imported = run_source_adapter(
                conn,
                target_name=args.target,
                source_kind=args.source_kind,
                adapter="import_json",
                input_data={"query": args.query, "source_kind": args.source_kind},
                budget={"apply": args.apply},
                runner=lambda: import_result_file(
                    conn,
                    target_name=args.target,
                    source_kind=args.source_kind,
                    query=args.query,
                    path=args.import_json,
                    apply=args.apply,
                ),
            )
            print(json.dumps({"ok": True, **imported}, ensure_ascii=True, separators=(",", ":")))
        else:
            parser.error("one source option is required")
        return 0
    except (ValueError, RuntimeError, OSError, json.JSONDecodeError, sqlite3.Error) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=True, separators=(",", ":")))
        return 1
    finally:
        if "conn" in locals():
            conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
