"""Low-volume, source-driven equivalent entry enumeration."""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

from db.cognitive_contract import normalize_auth_state

ENTRY_TYPES = {
    "login": ("login", "signin", "sign-in", "auth", "passport", "sso", "oauth"),
    "register": ("register", "signup", "sign-up", "registration", "join"),
    "admin": ("admin", "manage", "console", "backend", "portal"),
    "api": ("api", "swagger", "openapi", "graphql", "docs"),
}
PREFIXES = ("", "/app", "/wx", "/weixin", "/h5", "/wap", "/mobile", "/m", "/portal")


@dataclass(frozen=True)
class EntryCandidate:
    url: str
    entry_type: str
    source: str
    confidence: str


def classify_entry_path(path: str) -> str | None:
    normalized = path.lower()
    for entry_type, words in ENTRY_TYPES.items():
        if any(re.search(rf"(?:^|[/_.-]){re.escape(word)}(?:[/_.?-]|$)", normalized) for word in words):
            return entry_type
    return None


def generate_candidates(
    base_url: str, known_urls: list[str] | tuple[str, ...] = (), tech_stack: list[str] | tuple[str, ...] = ()
) -> list[EntryCandidate]:
    """Generate bounded candidates; never performs requests."""
    parsed = urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}/"
    candidates: dict[tuple[str, str], EntryCandidate] = {}

    def add(path: str, entry_type: str, source: str, confidence: str) -> None:
        url = urljoin(root, "/" + path.lstrip("/"))
        candidates.setdefault((url, entry_type), EntryCandidate(url, entry_type, source, confidence))

    for path in known_urls:
        parsed_path = urlparse(path).path or "/"
        kind = classify_entry_path(parsed_path)
        if kind:
            add(parsed_path, kind, "known_url", "medium")
            tail = parsed_path.strip("/").split("/")[-1]
            for prefix in PREFIXES:
                add(f"{prefix}/{tail}", kind, "family_variant", "low")

    # The probe budget is small and bounded (per_asset_cap is typically 12), so
    # breadth across entry families matters more than every path-prefix variant
    # of one family.  Emitting every /login variant first meant /admin and /api
    # were never probed at all; root-level paths now come before /app, /wx, ...
    # Interleave by word rank across families so the first three slots cover
    # login + admin + api rather than exhausting one family before starting the
    # next.  With a small per_asset_cap this is the difference between probing
    # one entry family and probing all three.
    for prefix in PREFIXES:
        for rank in range(4):
            for kind, words in ENTRY_TYPES.items():
                if rank < len(words):
                    add(f"{prefix}/{words[rank]}", kind, "entry_family", "low")

    lowered = " ".join(tech_stack).lower()
    if "swagger" in lowered or "spring" in lowered or "asp.net" in lowered:
        for path in ("/swagger", "/swagger-ui.html", "/v2/api-docs", "/api-docs"):
            add(path, "api", "technology_hint", "medium")
    return list(candidates.values())


def _is_slash_normalisation(request_url: str, location: str) -> bool:
    """True when a redirect only adds or drops a trailing slash on the same path.

    ``301 /login -> /login/`` matches the auth-redirect heuristic because the
    location contains ``login``, but it is path normalisation and says nothing
    about authentication.
    """
    if not request_url or not location:
        return False
    request_path = urlparse(request_url).path.rstrip("/")
    location_path = urlparse(location).path.rstrip("/")
    return bool(request_path) and request_path == location_path


def classify_response(status_code: int, location: str = "", body_hint: str = "", request_url: str = "") -> tuple[str, str]:
    """Return response class and confidence without treating 200 as success blindly."""
    location_lower = (location or "").lower()
    body_lower = (body_hint or "").lower()
    if status_code in {301, 302, 303, 307, 308} and any(token in location_lower for token in ("login", "signin", "auth")):
        if not _is_slash_normalisation(request_url, location):
            return normalize_auth_state("auth_redirect"), "high"
    if status_code in {401, 403}:
        return normalize_auth_state("restricted"), "medium"
    if status_code == 404:
        return normalize_auth_state("not_found"), "high"
    if status_code == 200 and any(token in body_lower for token in ("password", "验证码", "captcha", "登录")):
        return normalize_auth_state("login_like"), "medium"
    if status_code == 200:
        return normalize_auth_state("ok_unknown"), "low"
    return normalize_auth_state("unknown"), "low"
