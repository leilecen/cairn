"""Offline contracts for the Phase-A URLFinder, jsluice, x8, and JS-restoration
(webcrack / source-map / Retire.js / gitleaks) adapters.

These helpers deliberately construct commands and parse captured fixtures only.
Calling a real binary is left to the operator-approved runtime phase. Secret
values (e.g. gitleaks Match/Secret) are never emitted by the parsers.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import urlsplit, urlunsplit

TOOLS = {"urlfinder", "jsluice", "x8", "webcrack", "retirejs", "gitleaks"}
_SECRET = re.compile(r"(?i)(?:authorization|cookie|token|secret|password)\s*[:=]\s*[^\s,;]+|bearer\s+\S+")
_HEADER = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,79}$")
_VERSION = re.compile(r"(?<![\d.])v?(\d+(?:\.\d+)+)(?![\d.])", re.I)


def _compact(value: Any, limit: int = 180) -> str:
    text = str(value or "").strip()[:limit]
    return _SECRET.sub(lambda hit: f"[redacted:{hashlib.sha256(hit.group().encode()).hexdigest()[:12]}]", text)


def _url(value: Any, *, require_absolute: bool = True) -> str:
    parsed = urlsplit(str(value or "").strip())
    if _SECRET.search(parsed.path) or _SECRET.search(parsed.query) or _SECRET.search(parsed.fragment):
        raise ValueError("URL contains sensitive material")
    if require_absolute:
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("URL must be an absolute http(s) URL without credentials")
        host = parsed.hostname.encode("idna").decode("ascii").lower()
        port = parsed.port
        default = (parsed.scheme.lower() == "https" and port == 443) or (parsed.scheme.lower() == "http" and port == 80)
        netloc = host if port is None or default else f"{host}:{port}"
        return urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, ""))
    # Absolute http(s) URLs still normalize; a relative URL (e.g. "/api/user?id=1"
    # from jsluice) keeps path+query as-is; other schemes are dropped.
    if parsed.scheme:
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("URL must be an http(s) URL without credentials")
        host = parsed.hostname.encode("idna").decode("ascii").lower()
        port = parsed.port
        default = (parsed.scheme.lower() == "https" and port == 443) or (parsed.scheme.lower() == "http" and port == 80)
        netloc = host if port is None or default else f"{host}:{port}"
        return urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, ""))
    return urlunsplit(("", "", parsed.path or "/", parsed.query, ""))


def health_contract(
    tool: str,
    *,
    binary_path: str | Path | None,
    expected_version: str = "",
    version_flag: str = "--version",
    output_limit: int = 180,
    runner: Callable[[Sequence[str]], Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Check a version response through an injected runner; never resolve PATH.

    Tool-specific flags: URLFinder has no ``--version`` flag (version only in the
    ``-h`` banner, e.g. "Update: 2026.6.16" far behind its ASCII-art banner, so
    ``output_limit`` must be raised past it), jsluice prints no numeric version,
    so ``expected_version=""`` with ``version_flag="--help"`` is the health
    contract for it (exit 0 + non-empty output); real capability is proven by
    fixture parsing afterwards.
    """
    if tool not in TOOLS:
        raise ValueError("unsupported Phase-A tool")
    if not binary_path:
        return {"tool": tool, "status": "blocked", "blocker": "tool_missing", "command": []}
    command = [str(binary_path), version_flag]
    if runner is None:
        return {"tool": tool, "status": "blocked", "blocker": "offline_runner_required", "command": command}
    try:
        result = runner(command)
    except Exception as exc:  # pragma: no cover - defensive adapter boundary
        return {
            "tool": tool,
            "status": "blocked",
            "blocker": "health_check_failed",
            "detail": _compact(exc),
            "command": command,
        }
    output = _compact(result.get("stdout") or result.get("stderr"), output_limit)
    if int(result.get("returncode", 1)) != 0:
        return {
            "tool": tool,
            "status": "blocked",
            "blocker": "health_check_failed",
            "detail": output,
            "command": command,
        }
    expected = expected_version.strip().lstrip("vV")
    if expected:
        if expected not in _VERSION.findall(output):
            return {"tool": tool, "status": "blocked", "blocker": "wrong_version", "command": command}
        return {"tool": tool, "status": "ready", "version": expected_version.strip(), "command": command}
    return {"tool": tool, "status": "ready", "version": None, "command": command}


def build_urlfinder_command(binary_path: str | Path, seed_url: str, *, depth: int = 1) -> list[str]:
    if depth not in {1, 2, 3}:
        raise ValueError("URLFinder depth must be 1, 2, or 3")
    return [str(binary_path), "-u", _url(seed_url), "-m", str(depth)]


def build_jsluice_command(binary_path: str | Path, fixture_path: str | Path) -> list[str]:
    path = Path(fixture_path)
    if not path.name:
        raise ValueError("jsluice fixture path is required")
    # Real jsluice urls mode has no --format flag ("--format json" opens a file
    # named "json") and emits one JSON object per line (NDJSON).
    return [str(binary_path), "urls", str(path)]


def build_x8_command(binary_path: str | Path, seed_url: str, wordlist_path: str | Path) -> list[str]:
    wordlist = Path(wordlist_path)
    if not wordlist.name:
        raise ValueError("x8 wordlist path is required")
    return [str(binary_path), "-u", _url(seed_url), "-w", str(wordlist), "--headers", "--output-format", "json"]


def build_webcrack_command(binary_path: str | Path, fixture_path: str | Path, out_dir: str | Path) -> list[str]:
    """webcrack <file> -o <outdir>; restored files land under out_dir."""
    path = Path(fixture_path)
    if not path.name:
        raise ValueError("webcrack fixture path is required")
    return [str(binary_path), str(path), "-o", str(out_dir)]


def build_retirejs_command(binary_path: str | Path, scan_dir: str | Path) -> list[str]:
    """retire --path <dir> --outputformat json (known-vulnerable library scan)."""
    if not Path(scan_dir).name:
        raise ValueError("retirejs scan dir is required")
    return [str(binary_path), "--path", str(scan_dir), "--outputformat", "json"]


def build_gitleaks_command(binary_path: str | Path, source_dir: str | Path, report_path: str | Path | None = None) -> list[str]:
    """gitleaks detect --source <dir> --no-git [--report-format json --report-path <file>].

    --no-git forces filesystem-only scanning: without it gitleaks walks up to
    the nearest .git and scans repository history, which escapes the intended
    directory (observed with real binary 2026-08-14). Without report_path the
    report is emitted on stdout; callers must keep the parsed result compact
    (Secret/Match are redacted by parse_gitleaks_fixture).
    """
    if not Path(source_dir).name:
        raise ValueError("gitleaks source dir is required")
    command = [str(binary_path), "detect", "--source", str(source_dir), "--no-git"]
    if report_path is not None:
        command += ["--report-format", "json", "--report-path", str(report_path)]
    return command


def _blocker(tool: str, reason: str) -> dict[str, Any]:
    return {"tool": tool, "status": "blocked", "blocker": reason, "items": []}


def parse_urlfinder_fixture(payload: str) -> dict[str, Any]:
    try:
        values = [line.strip() for line in payload.splitlines() if line.strip()]
        urls = list(dict.fromkeys(_url(value) for value in values))
    except ValueError:
        return _blocker("urlfinder", "parse_failed")
    return {"tool": "urlfinder", "status": "observed", "items": [{"url": value} for value in urls]}


def parse_jsluice_fixture(payload: Any) -> dict[str, Any]:
    try:
        if isinstance(payload, str):
            # Real jsluice urls output is NDJSON: one {"url":..., "queryParams":...}
            # object per line; blank lines are skipped.
            rows: list[Any] = []
            for line in payload.splitlines():
                if not line.strip():
                    continue
                rows.append(json.loads(line))
        else:
            rows = payload.get("urls", []) if isinstance(payload, dict) else payload
            if not isinstance(rows, list):
                raise ValueError
        # Per-row tolerance (B7 lesson): a bad line is skipped, only all-bad
        # input fails the whole parse.
        urls = []
        for row in rows:
            value = row.get("url") if isinstance(row, dict) else row
            try:
                urls.append(_url(value, require_absolute=False))
            except ValueError:
                continue
        if not urls:
            raise ValueError("no parseable URL rows")
        return {
            "tool": "jsluice",
            "status": "observed",
            "items": [{"url": value} for value in list(dict.fromkeys(urls))],
        }
    except (TypeError, ValueError, json.JSONDecodeError):
        return _blocker("jsluice", "parse_failed")


def parse_x8_fixture(payload: Any) -> dict[str, Any]:
    try:
        data = json.loads(payload) if isinstance(payload, str) else payload
        # Real x8 --output-format json emits an array of RunnerOutput objects,
        # each carrying found_params: [{"name": ...}]. Legacy "params" keys are
        # kept for compatibility with hand-written fixtures.
        if isinstance(data, dict):
            rows = data.get("found_params") or data.get("params") or data.get("parameters") or []
        else:
            rows = []
            for item in data:
                if isinstance(item, dict):
                    rows.extend(item.get("found_params") or [])
        if not isinstance(rows, list):
            raise ValueError
        names = []
        for row in rows:
            name = row.get("name") if isinstance(row, dict) else row
            name = _compact(name, 80)
            if not _HEADER.fullmatch(name):
                raise ValueError
            names.append(name)
        return {"tool": "x8", "status": "observed", "items": [{"header": item} for item in list(dict.fromkeys(names))]}
    except (TypeError, ValueError, json.JSONDecodeError):
        return _blocker("x8", "parse_failed")


def parse_webcrack_fixture(payload: Any) -> dict[str, Any]:
    """Normalize a webcrack restoration manifest into a compact file list.

    webcrack has no machine JSON output; the runtime phase enumerates the
    restored files under out_dir into {"files": [{"path", "bytes"}]} (or a raw
    JSON string of it). Paths are validated against traversal.
    """
    try:
        data = json.loads(payload) if isinstance(payload, str) else payload
        files = data.get("files") if isinstance(data, dict) else None
        if not isinstance(files, list) or not files:
            raise ValueError
        items = []
        for row in files:
            path = str(row.get("path") if isinstance(row, dict) else row).strip()
            if not path or ".." in path.replace("\\", "/").split("/") or path.startswith(("/", "\\")):
                raise ValueError
            size = int(row.get("bytes", 0)) if isinstance(row, dict) else 0
            items.append({"file": path, "bytes": size})
        return {"tool": "webcrack", "status": "observed", "items": items}
    except (TypeError, ValueError, json.JSONDecodeError):
        return _blocker("webcrack", "parse_failed")


def parse_retirejs_fixture(payload: Any) -> dict[str, Any]:
    """Normalize Retire.js JSON output into compact component/CVE hits.

    Real shape (observed with retire 5.4.3, 2026-08-14) is a top-level
    {"version", "start", "data": [{"file", "results": [{"component",
    "version", "detection", "vulnerabilities": [{"info", "severity",
    "below", "identifiers": {"CVE": [...]}}]}]}]}. The legacy flat
    {"results": [...]} shape is still accepted. Identifiers may use "CVE" or
    "cve". An empty results list is a valid observed empty (searched_empty !=
    not_run) and stays an observed response, not a blocker. Note: retire exits
    with code 1 when vulnerabilities are found; parsing must not depend on the
    exit code.
    """
    try:
        data = json.loads(payload) if isinstance(payload, str) else payload
        if isinstance(data, dict):
            # 注意：必须按「键是否存在」取，不能按真值取——真实的「扫了但没命中」是
            # {"data": []}，用 `or` 会掉到 None 从而误判为 parse_failed（与本文档
            # 「empty results 是合法 observed empty」自相矛盾，2026-10-10 实测命中）。
            rows = data["data"] if "data" in data else data.get("results")
        else:
            rows = data
        if not isinstance(rows, list):
            raise ValueError
        items = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            if "results" in row:
                results = row["results"]
            else:
                results = [row]  # legacy flat shape: row is a component result
            if not isinstance(results, list):
                continue
            for result in results:
                if not isinstance(result, dict):
                    continue
                component = str(result.get("component") or "").strip()
                version = str(result.get("version") or "").strip()
                vulns = result.get("vulnerabilities") or []
                if not isinstance(vulns, list):
                    continue
                for vuln in vulns:
                    if not isinstance(vuln, dict):
                        continue
                    ids = vuln.get("identifiers") or {}
                    cves = ids.get("CVE") or ids.get("cve") or []
                    severity = _compact(vuln.get("severity"), 24) or "unknown"
                    for cve in cves:
                        items.append({"component": component, "version": version, "severity": severity, "cve": str(cve)})
        return {"tool": "retirejs", "status": "observed", "items": items}
    except (TypeError, ValueError, json.JSONDecodeError):
        return _blocker("retirejs", "parse_failed")


def parse_gitleaks_fixture(payload: Any) -> dict[str, Any]:
    """Normalize gitleaks JSON report into compact rule/file/line hits.

    Never emit the Secret or Match values (sensitive material). An empty array
    is a valid observed empty (searched_empty), not a blocker.
    """
    try:
        data = json.loads(payload) if isinstance(payload, str) else payload
        if not isinstance(data, list):
            raise ValueError
        items = []
        for row in data:
            if not isinstance(row, dict):
                continue
            rule = str(row.get("RuleID") or row.get("rule") or "").strip()
            if not rule:
                continue
            file_path = str(row.get("File") or row.get("file") or "").strip() or "?"
            raw_line = row.get("StartLine") or row.get("line")
            try:
                line = int(str(raw_line))
            except (TypeError, ValueError):
                line = 0
            commit = str(row.get("Commit") or row.get("commit") or "").strip()
            items.append({"rule": rule, "file": file_path, "line": line, "commit": (commit or "?")[:12]})
        return {"tool": "gitleaks", "status": "observed", "items": items}
    except (TypeError, ValueError, json.JSONDecodeError):
        return _blocker("gitleaks", "parse_failed")


def plan_sourcemap_reconstruction(source_entries: Sequence[Mapping[str, Any]], out_dir: str | Path) -> list[dict[str, Any]]:
    """Plan which reconstructed source files to write under out_dir.

    Input mirrors TOOLS/utils/source_map_utils.parse_source_map_text output
    ([{"source": ..., "content": ...}]), so this contract is testable offline
    without fetching anything. Scheme prefixes (webpack:/// etc.) and leading
    slashes are stripped; traversal or absolute paths are dropped. Files with
    empty content are skipped. Returned "file" values are relative to out_dir.
    """
    root = Path(out_dir)
    try:
        root_resolved = root.resolve()
    except OSError:  # pragma: no cover - defensive boundary
        root_resolved = root.absolute()
    planned: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entry in source_entries:
        source = str(entry.get("source") or "").strip()
        content = entry.get("content")
        if not source or not content:
            continue
        relative = source.split("://", 1)[-1].replace("\\", "/").lstrip("/")
        if not relative or ".." in relative.split("/"):
            continue
        try:
            target = (root / relative).resolve()
        except OSError:  # pragma: no cover - defensive boundary
            continue
        if not str(target).startswith(str(root_resolved)):
            continue
        rel = target.relative_to(root_resolved).as_posix()
        if rel in seen:
            continue
        seen.add(rel)
        planned.append({"file": rel, "bytes": len(content)})
    return planned
