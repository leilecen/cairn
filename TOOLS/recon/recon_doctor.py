"""Offline reconnaissance capability diagnosis.

The doctor only inspects local configuration and executable paths. It only
uses a fixed local ``-version`` probe to identify httpx; it makes no network
request and never serializes secret values.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Iterable, Mapping

_TOOLS_DIR = Path(__file__).resolve().parent.parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

from db.db_utils import session  # noqa: E402

try:
    from .recon_intel import resolve_fofa_capability
except ImportError:  # pragma: no cover - direct script execution
    from recon_intel import resolve_fofa_capability  # type: ignore[no-redef]  # 回退分支与包内导入同一批名字


_EMPTY_CONFIG_VALUES = {"", "[]", "{}", "null", "~", "''", '""'}
_SUBFINDER_PROVIDERS = {
    "alienvault",
    "anubis",
    "bevigil",
    "binaryedge",
    "bufferover",
    "builtwith",
    "c99",
    "censys",
    "certspotter",
    "chaos",
    "chinaz",
    "cloudflare",
    "dnsdb",
    "fofa",
    "fullhunt",
    "github",
    "hackertarget",
    "hunter",
    "intelx",
    "leakix",
    "netlas",
    "passivetotal",
    "quake",
    "redhuntlabs",
    "robtex",
    "securitytrails",
    "shodan",
    "threatbook",
    "virustotal",
    "whoisxmlapi",
    "zoomeye",
}


def _default_provider_config(environ: Mapping[str, str], tool_name: str) -> Path:
    appdata = environ.get("APPDATA")
    if appdata:
        return Path(appdata) / tool_name / "provider-config.yaml"
    return Path.home() / ".config" / tool_name / "provider-config.yaml"


def _path_entries(environ: Mapping[str, str]) -> list[Path]:
    return [Path(value) for value in environ.get("PATH", "").split(os.pathsep) if value]


def _executable_candidates(name: str, path_entries: Iterable[Path]) -> list[Path]:
    suffixes = (".exe", ".cmd", ".bat", "") if os.name == "nt" else ("",)
    seen: set[Path] = set()
    candidates: list[Path] = []
    for directory in path_entries:
        for suffix in suffixes:
            candidate = directory / f"{name}{suffix}"
            if candidate.is_file():
                resolved = candidate.resolve()
                if resolved not in seen:
                    seen.add(resolved)
                    candidates.append(resolved)
    return candidates


def _is_python_scripts_shim(path: Path) -> bool:
    """Identify the common Python-package CLI location without running it."""
    return path.parent.name.lower() == "scripts"


def _httpx_capability(path_entries: Iterable[Path]) -> dict[str, object]:
    candidates = _executable_candidates("httpx", path_entries)
    python_cli_paths = [str(path) for path in candidates if _is_python_scripts_shim(path)]
    projectdiscovery_paths: list[Path] = []
    for candidate in candidates:
        try:
            completed = subprocess.run(  # noqa: S603 - local PATH candidate, fixed no-network version probe
                [str(candidate), "-version"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        output = f"{completed.stdout}\n{completed.stderr}".lower()
        if "projectdiscovery" in output and not _is_python_scripts_shim(candidate):
            projectdiscovery_paths.append(candidate)
    return {
        "status": "ready" if projectdiscovery_paths else "tool_missing",
        "path": str(projectdiscovery_paths[0]) if projectdiscovery_paths else None,
        "python_cli_paths": python_cli_paths,
    }


def _count_configured_subfinder_providers(path: Path) -> int | None:
    """Count known non-empty provider sections without retaining credential values."""
    try:
        handle = path.open(encoding="utf-8", errors="replace")
    except OSError:
        return 0

    configured = 0
    current_provider = False
    current_configured = False
    try:
        for raw_line in handle:
            if not raw_line.strip() or raw_line.lstrip().startswith("#"):
                continue
            match = re.match(r"^([A-Za-z0-9_-]+):\s*(.*)$", raw_line)
            if match:
                configured += int(current_provider and current_configured)
                if match.group(1).lower() not in _SUBFINDER_PROVIDERS:
                    return None
                current_provider = True
                current_configured = match.group(2).strip().lower() not in _EMPTY_CONFIG_VALUES
            elif current_provider and raw_line[:1].isspace():
                current_configured = current_configured or _line_contains_nonempty_value(raw_line)
            else:
                return None
    finally:
        handle.close()
    if current_provider and current_configured:
        configured += 1
    return configured


def _line_contains_nonempty_value(line: str) -> bool:
    """Inspect one YAML field transiently; do not return or retain its value."""
    if ":" in line:
        return line.split(":", 1)[1].strip().lower() not in _EMPTY_CONFIG_VALUES
    return line.lstrip().lstrip("-").strip().lower() not in _EMPTY_CONFIG_VALUES


def _subfinder_capability(path_entries: Iterable[Path], provider_config_path: Path) -> dict[str, object]:
    candidates = _executable_candidates("subfinder", path_entries)
    if not candidates:
        return {"status": "tool_missing", "path": None, "configured_providers": 0}
    configured = _count_configured_subfinder_providers(provider_config_path)
    if configured is None:
        return {"status": "unknown_config_format", "path": str(candidates[0]), "configured_providers": None}
    return {
        "status": "ready" if configured else "degraded",
        "path": str(candidates[0]),
        "configured_providers": configured,
    }


def _require_target(db_path: Path, target: str) -> None:
    if not db_path.is_file():
        raise ValueError(f"database file not found: {db_path}")
    with session(db_path, read_only=True) as conn:
        row = conn.execute("SELECT 1 FROM targets WHERE target_name=? LIMIT 1", (target,)).fetchone()
    if row is None:
        raise ValueError(f"target not found in database: {target}")


def build_manifest(
    *,
    target: str,
    db_path: Path,
    environ: Mapping[str, str] | None = None,
    path_entries: Iterable[Path] | None = None,
    fofa_provider_config_path: Path | None = None,
    subfinder_provider_config_path: Path | None = None,
    local_fallback: bool = False,
) -> dict[str, object]:
    """Build a local-only, credential-free recon capability manifest."""
    _require_target(db_path, target)
    environment = os.environ if environ is None else environ
    paths = list(_path_entries(environment) if path_entries is None else path_entries)
    # FOFA is intentionally relay-only for this project.  The uncover config
    # path is retained in the function signature for compatibility, but must
    # not influence the capability manifest.
    del fofa_provider_config_path
    subfinder_config = subfinder_provider_config_path or _default_provider_config(environment, "subfinder")
    return {
        "target": target,
        "network": "not_used",
        "fofa": resolve_fofa_capability(environ=dict(environment), local_fallback=local_fallback),
        "httpx": _httpx_capability(paths),
        "subfinder": _subfinder_capability(paths, subfinder_config),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="offline reconnaissance capability doctor")
    parser.add_argument("--target", required=True)
    parser.add_argument("--db", required=True)
    args = parser.parse_args(argv)
    try:
        manifest = build_manifest(target=args.target, db_path=Path(args.db), local_fallback=True)
    except (OSError, sqlite3.Error, ValueError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=True, separators=(",", ":")))
        return 1
    print(json.dumps({"ok": True, **manifest}, ensure_ascii=False, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
