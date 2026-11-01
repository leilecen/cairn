"""Low-cost JS intelligence extractors."""

from __future__ import annotations

import json
import re
from urllib.parse import urljoin, urlparse

from utils.js_value_flow import fold_request_value_flow

API_PATH_RE = re.compile(
    r"(?P<quote>['\"`])"
    r"(?P<path>(?:https?://[^\s'\"`]+|"
    r"/(?:api|v\d|graphql|admin|user|auth|account|order|pay|upload|download)[^'\"`\s]*))"
    r"(?P=quote)"
)
FETCH_RE = re.compile(r"fetch\(\s*(?P<url>[^,\)]+)(?:,\s*(?P<options>\{.*?\}))?\s*\)", re.DOTALL)
AXIOS_METHOD_RE = re.compile(r"axios\.(?P<method>get|post|put|delete|patch)\(\s*(?P<url>[^,\)]+)(?:,\s*(?P<body>.*?))?\)", re.DOTALL)
AXIOS_RE = re.compile(r"axios\(\s*(?P<options>\{.*?\})\s*\)", re.DOTALL)
XHR_RE = re.compile(r"\.open\(\s*(?P<method>['\"][A-Z]+['\"])\s*,\s*(?P<url>[^,\)]+)", re.DOTALL)
JQUERY_RE = re.compile(r"\$\.ajax\(\s*(?P<options>\{.*?\})\s*\)", re.DOTALL)
WRAPPER_RE = re.compile(
    r"(?<![\w.])(?P<name>request|http|service|apiClient)\(\s*(?P<options>\{.*?\}|[^,\)]+)",
    re.DOTALL,
)
WX_REQUEST_RE = re.compile(r"wx\.request\(\s*(?P<options>\{.*?\})\s*\)", re.DOTALL)
ROUTE_RE = re.compile(r"(?:router\.push|path|route)\s*[:(]\s*(?P<quote>['\"`])(?P<path>/[^'\"`\s]+)(?P=quote)")
IMPORT_RE = re.compile(r"import\(\s*(?P<quote>['\"`])(?P<path>[^'\"`]+)(?P=quote)\s*\)")
GRAPHQL_RE = re.compile(r"\b(query|mutation|subscription)\b\s+[A-Za-z0-9_]+")
WS_RE = re.compile(r"(?P<quote>['\"`])(?P<url>wss?://[^'\"`\s]+)(?P=quote)")
BASE_URL_RE = re.compile(r"baseURL\s*:\s*(?P<quote>['\"`])(?P<url>[^'\"`]+)(?P=quote)")
HEADER_AUTH_RE = re.compile(r"Authorization|Bearer|X-Token|access_token", re.IGNORECASE)
SIGNATURE_RE = re.compile(
    r"\b(sign|signature|nonce|timestamp|hmac|md5|sha1|sha256|aes|rsa)\b",
    re.IGNORECASE,
)
PARAM_RE = re.compile(r"\b(userId|uid|orderId|studentId|orgId|tenantId|openid|unionid|id|token|nonce|timestamp|sign)\b")
THIRD_PARTY_RE = re.compile(r"(google-analytics|sentry|datadog|bugsnag|mixpanel|doubleclick|hm\.baidu)")


def _line_number(content: str, index: int) -> int:
    return content.count("\n", 0, max(index, 0)) + 1


def _normalize_dynamic(value: str) -> str:
    value = value.strip().strip("'\"`")
    value = re.sub(r"\$\{[^}]+\}", "{dynamic}", value)
    return value


def fold_static_url_parts(content: str) -> dict[str, str]:
    constants: dict[str, str] = {}
    for match in re.finditer(r"\b(const|let|var)\s+(\w+)\s*=\s*(['\"`])([^'\"`]+)\3", content):
        constants[match.group(2)] = match.group(4)
    for match in re.finditer(r"\b(\w+)\s*=\s*(\w+)\s*\+\s*(['\"`])([^'\"`]+)\3", content):
        base_name = match.group(2)
        if base_name in constants:
            constants[match.group(1)] = constants[base_name] + match.group(4)
    return constants


def _expand_url(raw_url: str, constants: dict[str, str], base_url: str = "") -> str:
    candidate = raw_url.strip()
    for name, value in constants.items():
        candidate = candidate.replace(f"${{{name}}}", value)
    candidate = _normalize_dynamic(candidate)
    if candidate in constants:
        candidate = constants[candidate]
    else:
        plus_match = re.match(r"(\w+)\s*\+\s*(['\"`])([^'\"`]+)\2", candidate)
        if plus_match and plus_match.group(1) in constants:
            candidate = constants[plus_match.group(1)] + plus_match.group(3)
    if candidate.startswith("/") and base_url:
        base_origin = "{0.scheme}://{0.netloc}".format(urlparse(base_url))
        return urljoin(base_origin, candidate)
    return candidate


def _build_signal(
    signal_type: str,
    *,
    method: str | None = None,
    url: str | None = None,
    path: str | None = None,
    params: list[str] | None = None,
    evidence_snippet: str = "",
    evidence_location: str = "",
    caller_hint: str = "",
    protocol: str = "http",
    auth_hint: str = "",
    signature_hint: str = "",
) -> dict:
    final_url = url or path or ""
    parsed = urlparse(final_url) if final_url else None
    final_path = path or (parsed.path if parsed else final_url)
    return {
        "signal_type": signal_type,
        "protocol": protocol,
        "method": method,
        "url": final_url,
        "path": final_path,
        "host": parsed.netloc if parsed else "",
        "params": params or [],
        "headers": [],
        "evidence_snippet": evidence_snippet[:220],
        "evidence_location": evidence_location,
        "caller_hint": caller_hint,
        "auth_hint": auth_hint,
        "signature_hint": signature_hint,
    }


def extract_regex_signals(content: str, base_url: str = "") -> list[dict]:
    constants = fold_static_url_parts(content)
    signals: list[dict] = []
    for match in API_PATH_RE.finditer(content):
        raw = match.group("path")
        line = _line_number(content, match.start())
        url = _expand_url(raw, constants, base_url)
        signal_type = "graphql" if "graphql" in url else "api_endpoint"
        signals.append(
            _build_signal(
                signal_type,
                method="GET",
                url=url,
                params=PARAM_RE.findall(match.group(0)),
                evidence_snippet=match.group(0),
                evidence_location=f"line:{line}",
            )
        )
    for match in WS_RE.finditer(content):
        line = _line_number(content, match.start())
        signals.append(
            _build_signal(
                "websocket",
                url=match.group("url"),
                protocol="websocket",
                evidence_snippet=match.group(0),
                evidence_location=f"line:{line}",
            )
        )
    for match in GRAPHQL_RE.finditer(content):
        line = _line_number(content, match.start())
        signals.append(
            _build_signal(
                "graphql",
                method="POST",
                path="/graphql",
                evidence_snippet=match.group(0),
                evidence_location=f"line:{line}",
            )
        )
    return signals


def extract_request_signals(content: str, base_url: str = "") -> list[dict]:
    constants = fold_static_url_parts(content)
    signals: list[dict] = []
    patterns = [
        (
            FETCH_RE,
            "fetch",
            lambda m: (
                "GET" if "method" not in (m.group("options") or "") else None,
                m.group("url"),
                m.group("options") or "",
            ),
        ),
        (
            AXIOS_METHOD_RE,
            "axios",
            lambda m: (m.group("method").upper(), m.group("url"), m.group(0)),
        ),
        (
            AXIOS_RE,
            "axios",
            lambda m: (
                _extract_option_value(m.group("options"), "method") or "GET",
                _extract_option_value(m.group("options"), "url") or "",
                m.group("options"),
            ),
        ),
        (
            XHR_RE,
            "xhr",
            lambda m: (m.group("method").strip("'\""), m.group("url"), m.group(0)),
        ),
        (
            JQUERY_RE,
            "jquery",
            lambda m: (
                _extract_option_value(m.group("options"), "method") or "GET",
                _extract_option_value(m.group("options"), "url") or "",
                m.group("options"),
            ),
        ),
        (
            WRAPPER_RE,
            "wrapper",
            lambda m: (
                _extract_option_value(m.group("options"), "method") or "GET",
                _extract_option_value(m.group("options"), "url") or m.group("options"),
                m.group(0),
            ),
        ),
        (
            WX_REQUEST_RE,
            "wx.request",
            lambda m: (
                _extract_option_value(m.group("options"), "method") or "GET",
                _extract_option_value(m.group("options"), "url") or "",
                m.group("options"),
            ),
        ),
    ]
    for pattern, caller, builder in patterns:
        for match in pattern.finditer(content):
            method, raw_url, snippet = builder(match)
            line = _line_number(content, match.start())
            url = _expand_url(raw_url, constants, base_url)
            auth_hint = "auth_header" if HEADER_AUTH_RE.search(snippet) else ""
            signature_hint = "signature" if SIGNATURE_RE.search(snippet) else ""
            data_match = re.search(r"\bdata\s*:\s*(\{.*\})", snippet, re.DOTALL)
            value_flow = fold_request_value_flow(
                content,
                raw_url,
                data_match.group(1) if data_match else "",
                file_path=base_url or "<memory>",
                line=line,
            )
            signals.append(
                _build_signal(
                    "api_endpoint",
                    method=method,
                    url=url,
                    params=sorted(set(PARAM_RE.findall(snippet))),
                    evidence_snippet=snippet,
                    evidence_location=f"line:{line}",
                    caller_hint=caller,
                    auth_hint=auth_hint,
                    signature_hint=signature_hint,
                )
            )
            signals[-1]["value_flow"] = value_flow
    return signals


def _extract_option_value(options: str, key: str) -> str | None:
    match = re.search(rf"{key}\s*:\s*([^,\n}}]+)", options)
    return _normalize_dynamic(match.group(1)) if match else None


def extract_route_signals(content: str, base_url: str = "") -> list[dict]:
    signals: list[dict] = []
    for match in ROUTE_RE.finditer(content):
        line = _line_number(content, match.start())
        signals.append(
            _build_signal(
                "route_entry",
                path=match.group("path"),
                evidence_snippet=match.group(0),
                evidence_location=f"line:{line}",
            )
        )
    for match in IMPORT_RE.finditer(content):
        line = _line_number(content, match.start())
        signals.append(
            _build_signal(
                "dynamic_import",
                path=match.group("path"),
                evidence_snippet=match.group(0),
                evidence_location=f"line:{line}",
            )
        )
    for match in BASE_URL_RE.finditer(content):
        line = _line_number(content, match.start())
        signals.append(
            _build_signal(
                "base_url",
                url=match.group("url"),
                evidence_snippet=match.group(0),
                evidence_location=f"line:{line}",
            )
        )
    return signals


def extract_crypto_signals(content: str) -> list[dict]:
    signals: list[dict] = []
    for match in SIGNATURE_RE.finditer(content):
        line = _line_number(content, match.start())
        token = match.group(1)
        signals.append(
            _build_signal(
                "signature_function" if token.lower() in {"sign", "signature"} else "crypto_hint",
                evidence_snippet=token,
                evidence_location=f"line:{line}",
                signature_hint=token,
            )
        )
    return signals


def score_signal(signal: dict) -> int:
    score = 0
    text = " ".join(
        str(signal.get(key, ""))
        for key in (
            "url",
            "path",
            "caller_hint",
            "auth_hint",
            "signature_hint",
            "evidence_snippet",
        )
    )
    method = (signal.get("method") or "").upper()
    params = [str(p) for p in signal.get("params", [])]
    if signal.get("caller_hint"):
        score += 30
    if signal.get("signal_type") in {"graphql", "websocket", "upload_download"}:
        score += 15
    if any(token in text.lower() for token in ("admin", "teacher", "manage", "system", "staff")):
        score += 20
    if any(token in text.lower() for token in ("upload", "download", "export", "import")):
        score += 20
    if method in {"POST", "PUT", "DELETE", "PATCH"}:
        score += 20
    if any(param.lower() in {"id", "userid", "uid", "orderid", "studentid", "orgid", "tenantid", "openid", "unionid"} for param in params):
        score += 20
    if signal.get("auth_hint") or signal.get("signature_hint"):
        score += 15
    if THIRD_PARTY_RE.search(text.lower()):
        score -= 50
    if "cdn" in text.lower() or "vendor" in text.lower():
        score -= 50
    if not signal.get("caller_hint") and signal.get("signal_type") == "api_endpoint":
        score -= 20
    return max(score, 0)


def extract_all_signals(content: str, base_url: str = "") -> list[dict]:
    signals = []
    for extractor in (extract_regex_signals, extract_request_signals, extract_route_signals):
        signals.extend(extractor(content, base_url))
    signals.extend(extract_crypto_signals(content))
    deduped: dict[str, dict] = {}
    for signal in signals:
        signal["risk_score"] = score_signal(signal)
        signal["confidence"] = 80 if signal.get("caller_hint") else 50
        key = json.dumps(
            [signal.get("signal_type"), signal.get("method"), signal.get("path"), signal.get("evidence_location")],
            ensure_ascii=False,
        )
        deduped[key] = signal
    return list(deduped.values())
