"""Rule-based JS asset classifier for prioritization and suppression."""

from __future__ import annotations

from dataclasses import dataclass

THIRD_PARTY_HINTS = ("jquery", "vue", "react", "swiper", "bootstrap", "lodash", "moment", "echarts")
LOGIN_HINTS = ("login", "auth", "signin", "passport")
CAPTCHA_HINTS = ("captcha", "verifycode", "slider", "smscode", "sms")
LOAN_HINTS = ("loan", "credit", "borrow", "repay", "mortgage")
CRYPTO_HINTS = ("sign", "signature", "rsa", "aes", "encrypt", "crypto")
API_HINTS = ("api", "client", "service", "request", "gateway")
SUPPRESSION_HINTS = ("<%=", "%>", "${", "{{", "}}", "pkg.version", "mod_<%= pkg.version%>.min.js")


@dataclass
class JsClassification:
    role: str
    confidence: float
    reasons: list[str]
    suppression_status: str | None = None


def _contains_any(text: str, needles: tuple[str, ...]) -> list[str]:
    lowered = text.lower()
    return [needle for needle in needles if needle in lowered]


def classify_js(url: str, content: str = "") -> JsClassification:
    combined = f"{url}\n{content}".lower()
    reasons: list[str] = []

    suppression_hits = _contains_any(combined, SUPPRESSION_HINTS)
    if suppression_hits:
        return JsClassification(
            role="unknown",
            confidence=0.99,
            reasons=[f"template marker: {hit}" for hit in suppression_hits[:3]],
            suppression_status="suppressed_template_asset",
        )

    third_party_hits = _contains_any(combined, THIRD_PARTY_HINTS)
    if third_party_hits:
        reasons.extend(f"third-party hint: {hit}" for hit in third_party_hits[:3])
        return JsClassification(
            role="third_party_library",
            confidence=0.97,
            reasons=reasons,
            suppression_status="suppressed_third_party_library",
        )

    login_hits = _contains_any(combined, LOGIN_HINTS)
    captcha_hits = _contains_any(combined, CAPTCHA_HINTS)
    loan_hits = _contains_any(combined, LOAN_HINTS)
    crypto_hits = _contains_any(combined, CRYPTO_HINTS)
    api_hits = _contains_any(combined, API_HINTS)

    if login_hits:
        return JsClassification("business_login", 0.92, [f"path/content hint: {hit}" for hit in login_hits[:3]])
    if captcha_hits:
        return JsClassification("business_captcha", 0.9, [f"path/content hint: {hit}" for hit in captcha_hits[:3]])
    if loan_hits:
        return JsClassification("business_loan", 0.9, [f"path/content hint: {hit}" for hit in loan_hits[:3]])
    if crypto_hits:
        details = [f"path/content hint: {hit}" for hit in crypto_hits[:3]]
        if "timestamp" in combined:
            details.append("contains timestamp")
        if "nonce" in combined:
            details.append("contains nonce")
        if any(token in combined for token in ("cryptojs", "jsencrypt", "rsakey", "sha256", "md5")):
            details.append("contains crypto primitive")
        return JsClassification("signature_or_crypto", 0.94, details)
    if api_hits or any(token in combined for token in ("authorization", "x-sign", "/api/", "fetch(", "axios")):
        details = [f"path/content hint: {hit}" for hit in api_hits[:3]]
        if "authorization" in combined:
            details.append("contains Authorization")
        if "x-sign" in combined:
            details.append("contains X-Sign")
        return JsClassification("api_client", 0.82, details or ["contains API call signal"])
    if any(token in combined for token in ("runtime", "chunk-vendor", "__webpack", "vite/client")):
        return JsClassification("framework_runtime", 0.8, ["framework runtime marker"])
    if content.strip():
        return JsClassification("business_js", 0.65, ["non-empty same-scope JS"])
    return JsClassification("unknown", 0.4, ["insufficient signal"])


def classification_priority(role: str, suppression_status: str | None = None) -> int:
    if suppression_status:
        return -10
    priorities = {
        "business_login": 100,
        "business_captcha": 95,
        "signature_or_crypto": 92,
        "business_loan": 90,
        "api_client": 85,
        "business_js": 70,
        "framework_runtime": 30,
        "third_party_library": 10,
        "unknown": 20,
    }
    return priorities.get(role, 20)
