"""Resolve endpoint candidates without promoting service names to hosts."""

from __future__ import annotations

from urllib.parse import urljoin, urlparse


def normalize_endpoint(
    raw_endpoint: str,
    *,
    page_url: str = "",
    js_url: str = "",
    base_url: str = "",
    target_hosts: set[str] | None = None,
) -> dict[str, object]:
    raw = (raw_endpoint or "").strip()
    targets = {item.lower().strip(".") for item in (target_hosts or set()) if item}
    source_base = base_url or js_url or page_url
    resolved = ""
    status = "unresolved"
    if raw.startswith(("http://", "https://")):
        resolved = raw
    elif raw.startswith("//") and source_base:
        scheme = urlparse(source_base).scheme or "https"
        resolved = f"{scheme}:{raw}"
    elif raw.startswith("/") and source_base:
        resolved = urljoin(source_base, raw)
    if resolved:
        parsed = urlparse(resolved)
        host = (parsed.hostname or "").lower().strip(".")
        if host and parsed.scheme in {"http", "https"}:
            status = "resolved"
            scope = "owned" if any(host == item or host.endswith(f".{item}") for item in targets) else "third_party"
            return {
                "raw_endpoint": raw,
                "resolved_url": resolved,
                "base_url": source_base or None,
                "origin_host": host,
                "path": parsed.path or "/",
                "route_kind": "absolute" if raw.startswith("http") else "relative",
                "service_hint": None,
                "resolution_status": status,
                "scope_class": scope,
            }
    return {
        "raw_endpoint": raw,
        "resolved_url": None,
        "base_url": source_base or None,
        "origin_host": None,
        "path": raw if raw.startswith("/") else None,
        "route_kind": "relative" if raw.startswith("/") else "unknown",
        "service_hint": raw.split("/", 1)[0] if raw and not raw.startswith("/") else None,
        "resolution_status": status,
        "scope_class": "unknown",
    }
