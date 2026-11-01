"""Optional, bounded network observation adapters."""

from __future__ import annotations

import shutil
import subprocess
from typing import Any, Iterable


def bounded_ports(ports: Iterable[int], *, allowed: set[int] | None = None) -> list[int]:
    values = sorted({int(port) for port in ports if 1 <= int(port) <= 65535})
    if allowed is not None:
        values = [port for port in values if port in allowed]
    return values


def run_nmap_service_probe(
    host: str, ports: Iterable[int], *, allowed: set[int] | None = None, waf: bool = False, timeout: int = 60
) -> dict[str, Any]:
    selected = bounded_ports(ports, allowed=allowed)
    binary = shutil.which("nmap")
    if not binary:
        return {"status": "blocked", "reason": "nmap_not_found", "host": host, "ports": selected}
    if not selected:
        return {"status": "blocked", "reason": "no_allowed_ports", "host": host, "ports": []}
    command = [binary, "-Pn", "-sV", "--version-light", "-p", ",".join(map(str, selected))]
    if waf:
        command.extend(["--script", "http-waf-detect"])
    command.append(host)
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)  # noqa: S603 -- binary 来自 shutil.which，参数为本模块构造
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"status": "unknown", "reason": exc.__class__.__name__, "host": host, "ports": selected}
    return {
        "status": "observed" if completed.returncode == 0 else "unknown",
        "host": host,
        "ports": selected,
        "returncode": completed.returncode,
        "summary": " ".join(completed.stdout.split())[:1200],
        "error": " ".join(completed.stderr.split())[:400],
        "waf_requested": waf,
    }
