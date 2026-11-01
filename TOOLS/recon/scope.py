"""Asset scope classification used by passive and active recon lanes."""

from __future__ import annotations

from urllib.parse import urlparse

SCOPE_CLASSES = {"owned", "authorized_vendor", "intel_only", "unknown"}
ACTIVE_SCOPE_CLASSES = {"owned", "authorized_vendor"}


def _host(value: str | None) -> str:
    raw = (value or "").strip().lower()
    parsed = urlparse(raw if "://" in raw else f"//{raw}")
    return (parsed.hostname or raw).strip(".")


def classify_asset_scope(host: str, target_domain: str, *, relation: str | None = None) -> str:
    """Return a conservative class; vendor domains require explicit authorization."""
    if relation in SCOPE_CLASSES:
        return relation
    actual = _host(host)
    root = _host(target_domain)
    if actual and root and (actual == root or actual.endswith(f".{root}")):
        return "owned"
    return "unknown"


def is_active_scope(scope_class: str | None, scope_status: str | None) -> bool:
    return scope_class in ACTIVE_SCOPE_CLASSES and scope_status == "in_scope"
