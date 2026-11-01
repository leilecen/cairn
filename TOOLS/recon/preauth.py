"""Low-risk pre-auth response classification and request budget gates."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from db.cognitive_contract import normalize_auth_state


def classify_response(status_code: int, *, location: str = "", body: str = "") -> str:
    location_l = (location or "").lower()
    body_l = (body or "").lower()
    waf_tokens = ("waf", "blocked", "too many requests", "rate limit", "aliyun", "cloudflare")
    if status_code in {429, 451} or any(token in body_l for token in waf_tokens):
        return normalize_auth_state("waf_blocked")
    if status_code in {301, 302, 303, 307, 308} and any(token in location_l for token in ("login", "signin", "auth", "sso", "oauth")):
        return normalize_auth_state("auth_redirect")
    if status_code == 401:
        return normalize_auth_state("auth_required")
    if status_code == 403:
        return normalize_auth_state("restricted")
    if status_code == 404:
        return normalize_auth_state("not_found")
    if status_code == 200:
        if any(token in body_l for token in ("password", "captcha", "登录", "sign in", "signin")):
            return normalize_auth_state("auth_required")
        if "<script" in body_l and "root" in body_l and len(body_l) < 5000:
            return normalize_auth_state("spa_shell")
        return normalize_auth_state("public")
    return normalize_auth_state("unknown")


@dataclass
class ProbeBudget:
    max_requests: int = 30
    min_interval_seconds: float = 2.0
    request_count: int = 0
    last_request_at: float | None = None
    stop_reason: str | None = None

    def allow(self, *, now: float) -> bool:
        if self.stop_reason or self.request_count >= self.max_requests:
            return False
        if self.last_request_at is not None and now - self.last_request_at < self.min_interval_seconds:
            return False
        return True

    def record(self, *, now: float) -> None:
        if not self.allow(now=now):
            raise RuntimeError("preauth probe budget denied")
        self.request_count += 1
        self.last_request_at = now

    def stop(self, reason: str) -> None:
        self.stop_reason = reason


def compact_auth_blocker(
    *,
    login_url: str,
    auth_provider: str,
    redirect_chain: list[str],
    pre_auth_endpoints: list[str],
    js_candidates: list[str],
    tenant_clues: list[str],
    public_candidates: list[str],
    blocker_reason: str,
    next_safe_action: str,
) -> dict[str, Any]:
    return {
        "login_url": login_url[:300],
        "auth_provider": auth_provider[:80],
        "redirect_chain": redirect_chain[:10],
        "pre_auth_endpoints": pre_auth_endpoints[:20],
        "js_candidates": js_candidates[:20],
        "tenant_clues": tenant_clues[:30],
        "public_candidates": public_candidates[:30],
        "blocker_reason": blocker_reason[:300],
        "next_safe_action": next_safe_action[:300],
    }
