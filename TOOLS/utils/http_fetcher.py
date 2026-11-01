"""Unified HTTP fetcher for scanners, analyzers, and enumerators.

出口策略（`docs/modules/egress-traffic-shaping.md`）：
- **目标侧**请求（默认 `audience="target"`）自动经 Burp 代理（`EGRESS_BURP`，默认
  `http://127.0.0.1:8080`）。Burp 不可用时请求会失败（不静默直连），这是有意行为。
- **第三方情报 API** 传 `audience="intel"`（或显式 `proxies=None`）才直连。
- **不使用环境代理**：`use_env_proxy=False`（默认）时会忽略 `HTTP_PROXY`/`HTTPS_PROXY`/
  `ALL_PROXY`。本机环境变量里挂着 Clash（`127.0.0.1:9870`），若让它生效，目标侧就会从
  Clash 节点出口发包（IP 不稳定、可能被 WAF 拦），而且完全是隐式的。只有操作员明确要求
  走 Clash 时才设 `EGRESS_USE_ENV_PROXY=1`。
  注意 `requests` 的坑：即使传 `proxies={"http": None, "https": None}`，只要环境里有
  `ALL_PROXY`，`select_proxy()` 仍会命中 `all` 键而走代理——所以这里用 `Session.trust_env`。
- 完整形态治理（固定身份、抖动节拍、会话连续性、熔断、台账）走 `TOOLS/utils/egress.py`；
  本模块只是传输层，目标侧调用应优先使用 `Egress`。
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import ssl
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

# Burp 默认 UA（Chrome 串）：与「操作员用浏览器 + Burp」的工作流一致。
DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

DEFAULT_BURP_URL = "http://127.0.0.1:8080"
DEFAULT_YAKIT_MITM_URL = "http://127.0.0.1:8083"

# `proxies` 未传（哨兵）与显式传 None（有意直连）必须区分开。
_PROXY_UNSET: Any = object()


def default_proxy_url(audience: str = "target", env: dict[str, str] | None = None) -> str | None:
    """返回默认代理 URL。

    - `audience="intel"` 或 `EGRESS_MODE=direct` → None（直连）
    - `EGRESS_MODE=burp` → Burp（`EGRESS_BURP`，默认 8080）
    - 其余（默认 `EGRESS_MODE=yakit`）→ Yakit MITM（`EGRESS_YAKIT_MITM`，默认 8083）
      说明：目标侧受治理路径是 `Egress` → Yakit MCP（`do_http_request`）；这里给的是
      「直连 `http_fetcher` 的老调用方」的兜底出口，仍是 Yakit 的代理端口。
    """
    resolved_env: Mapping[str, str] = os.environ if env is None else env
    if audience == "intel":
        return None
    mode = str(resolved_env.get("EGRESS_MODE", "yakit")).lower()
    if mode == "direct":
        return None
    if mode == "burp":
        return resolved_env.get("EGRESS_BURP") or DEFAULT_BURP_URL
    return resolved_env.get("EGRESS_YAKIT_MITM") or DEFAULT_YAKIT_MITM_URL


def default_proxies(audience: str = "target", env: dict[str, str] | None = None) -> dict[str, str] | None:
    url = default_proxy_url(audience, env)
    return {"http": url, "https": url} if url else None


def _resolve_proxies(proxies: Any, audience: str, env: dict[str, str] | None) -> dict[str, str] | None:
    if proxies is _PROXY_UNSET:
        return default_proxies(audience, env)
    return proxies


def default_use_env_proxy(env: dict[str, str] | None = None) -> bool:
    """是否允许环境代理（`HTTP_PROXY`/`ALL_PROXY`，本机即 Clash）。

    默认 **False**：Clash 只在操作员口头指定时使用（`EGRESS_USE_ENV_PROXY=1`）。
    """
    resolved: Mapping[str, str] = os.environ if env is None else env
    return str(resolved.get("EGRESS_USE_ENV_PROXY", "0")).lower() in {"1", "true", "on", "yes"}


@dataclass
class FetchResult:
    url: str
    final_url: str
    status_code: int
    headers: dict[str, str]
    content_type: str
    body: bytes
    size_bytes: int
    elapsed_ms: int | None
    backend: str
    error: str | None = None

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="ignore")


def _build_headers(headers: dict[str, str] | None) -> dict[str, str]:
    merged = {"User-Agent": DEFAULT_UA}
    if headers:
        merged.update(headers)
    return merged


def _truncate(body: bytes, max_bytes: int | None) -> bytes:
    if max_bytes is None or len(body) <= max_bytes:
        return body
    return body[:max_bytes]


def _ssl_context(verify: bool) -> ssl.SSLContext:
    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def _requests_available() -> bool:
    return importlib.util.find_spec("requests") is not None


def _apply_params(url: str, params: dict[str, Any] | None) -> str:
    if not params:
        return url
    separator = "&" if "?" in url else "?"
    return f"{url}{separator}{urlencode(params, doseq=True)}"


def _normalize_data(data: bytes | str | dict[str, Any] | None) -> bytes | None:
    if data is None:
        return None
    if isinstance(data, bytes):
        return data
    if isinstance(data, str):
        return data.encode("utf-8")
    return urlencode(data, doseq=True).encode("utf-8")


def _urllib_opener(proxies: dict[str, str] | None, use_env_proxy: bool) -> Any:
    """构造 urllib opener；返回 None 表示沿用模块级 `urlopen`（默认 opener）。

    - 有代理 → ProxyHandler(proxies)；
    - 无代理且不允许环境代理 → ProxyHandler({})：显式屏蔽 `HTTP_PROXY`/`ALL_PROXY`；
    - 允许环境代理 → None（默认 opener 会读环境变量）。
    """
    if not proxies and use_env_proxy:
        return None
    import urllib.request as ur  # noqa: PLC0415

    return ur.build_opener(ur.ProxyHandler(proxies or {}))


def _fetch_urllib(
    url: str,
    *,
    method: str,
    timeout: float,
    verify: bool,
    headers: dict[str, str] | None,
    max_bytes: int | None,
    params: dict[str, Any] | None,
    data: bytes | str | dict[str, Any] | None,
    proxies: dict[str, str] | None,
    use_env_proxy: bool = False,
) -> FetchResult:
    started = time.perf_counter()
    request = Request(  # noqa: S310 - scheme 由调用方传入的 URL 决定
        _apply_params(url, params),
        headers=_build_headers(headers),
        data=_normalize_data(data),
        method=method,
    )
    opener = _urllib_opener(proxies, use_env_proxy)
    try:
        open_fn = opener.open if opener is not None else urlopen
        kwargs: dict[str, Any] = {"timeout": timeout}
        if opener is None:
            kwargs["context"] = _ssl_context(verify)
        with open_fn(request, **kwargs) as response:  # noqa: S310 - urlopen/opener.open，scheme 由调用方 URL 决定
            body = _truncate(response.read(), max_bytes)
            content_type = response.headers.get("Content-Type", "")
            return FetchResult(
                url=url,
                final_url=response.geturl(),
                status_code=getattr(response, "status", 200),
                headers=dict(response.headers.items()),
                content_type=content_type,
                body=body,
                size_bytes=len(body),
                elapsed_ms=int((time.perf_counter() - started) * 1000),
                backend="urllib",
            )
    except HTTPError as exc:
        body = _truncate(exc.read() if hasattr(exc, "read") else b"", max_bytes)
        header_map = dict(exc.headers.items()) if exc.headers else {}
        return FetchResult(
            url=url,
            final_url=exc.geturl() or url,
            status_code=exc.code,
            headers=header_map,
            content_type=header_map.get("Content-Type", ""),
            body=body,
            size_bytes=len(body),
            elapsed_ms=int((time.perf_counter() - started) * 1000),
            backend="urllib",
            error=str(exc),
        )
    except Exception as exc:  # noqa: BLE001
        return FetchResult(
            url=url,
            final_url=url,
            status_code=0,
            headers={},
            content_type="",
            body=b"",
            size_bytes=0,
            elapsed_ms=int((time.perf_counter() - started) * 1000),
            backend="urllib",
            error=str(exc),
        )


def _fetch_requests(
    url: str,
    *,
    method: str,
    timeout: float,
    verify: bool,
    headers: dict[str, str] | None,
    max_bytes: int | None,
    params: dict[str, Any] | None,
    data: bytes | str | dict[str, Any] | None,
    files: dict[str, tuple[str, bytes, str]] | None,
    proxies: dict[str, str] | None,
    allow_redirects: bool,
    use_env_proxy: bool = False,
) -> FetchResult:
    started = time.perf_counter()
    import requests  # noqa: PLC0415

    session = requests.Session()
    # trust_env=False 才会真正忽略 HTTP_PROXY/ALL_PROXY（proxies 传 None 值拦不住 "all" 键）
    session.trust_env = use_env_proxy
    try:
        response = session.request(
            method,
            url,
            headers=_build_headers(headers),
            timeout=timeout,
            verify=verify,
            allow_redirects=allow_redirects,
            params=params,
            data=None if files else data,
            files=files,
            proxies=proxies,
        )
        body = _truncate(response.content, max_bytes)
        return FetchResult(
            url=url,
            final_url=str(response.url),
            status_code=response.status_code,
            headers=dict(response.headers),
            content_type=response.headers.get("Content-Type", ""),
            body=body,
            size_bytes=len(body),
            elapsed_ms=int((time.perf_counter() - started) * 1000),
            backend="requests",
        )
    except Exception as exc:  # noqa: BLE001
        return FetchResult(
            url=url,
            final_url=url,
            status_code=0,
            headers={},
            content_type="",
            body=b"",
            size_bytes=0,
            elapsed_ms=int((time.perf_counter() - started) * 1000),
            backend="requests",
            error=str(exc),
        )


def _fetch_curl(
    url: str,
    *,
    method: str,
    timeout: float,
    verify: bool,
    headers: dict[str, str] | None,
    max_bytes: int | None,
    params: dict[str, Any] | None,
    data: bytes | str | dict[str, Any] | None,
    proxies: dict[str, str] | None,
    allow_redirects: bool,
    use_env_proxy: bool = False,
) -> FetchResult:
    started = time.perf_counter()
    curl_bin = shutil.which("curl") or shutil.which("curl.exe")
    if not curl_bin:
        return FetchResult(
            url=url,
            final_url=url,
            status_code=0,
            headers={},
            content_type="",
            body=b"",
            size_bytes=0,
            elapsed_ms=0,
            backend="curl",
            error="curl not found",
        )
    request_url = _apply_params(url, params)
    header_file = tempfile.NamedTemporaryFile(delete=False)
    body_file = tempfile.NamedTemporaryFile(delete=False)
    header_file.close()
    body_file.close()
    resolved_ua = _build_headers(headers).get("User-Agent") or DEFAULT_UA
    command = [
        curl_bin,
        "-sS",
        "-X",
        method,
        "--max-time",
        str(int(timeout)),
        "-A",
        resolved_ua,
        "-D",
        header_file.name,
        "-o",
        body_file.name,
        request_url,
    ]
    if allow_redirects:
        command.insert(1, "-L")
    if not verify:
        command.insert(1, "-k")
    if proxies:
        proxy_value = proxies.get("https") or proxies.get("http")
        if proxy_value:
            command.extend(["--proxy", proxy_value])
    elif not use_env_proxy:
        # curl 自身也读 HTTP_PROXY/ALL_PROXY，必须显式关掉
        command.extend(["--noproxy", "*"])
    for key, value in _build_headers(headers).items():
        if key.lower() == "user-agent":
            continue
        command.extend(["-H", f"{key}: {value}"])
    normalized_data = _normalize_data(data)
    if normalized_data is not None:
        command.extend(["--data-binary", "@-"])
    try:
        completed = subprocess.run(  # noqa: S603
            command,
            capture_output=True,
            timeout=timeout + 5,
            check=False,
            input=normalized_data,
        )
        header_text = Path(header_file.name).read_text(encoding="iso-8859-1", errors="ignore")
        body = _truncate(Path(body_file.name).read_bytes(), max_bytes)
    except Exception as exc:  # noqa: BLE001
        return FetchResult(
            url=url,
            final_url=url,
            status_code=0,
            headers={},
            content_type="",
            body=b"",
            size_bytes=0,
            elapsed_ms=int((time.perf_counter() - started) * 1000),
            backend="curl",
            error=str(exc),
        )
    finally:
        for path in (header_file.name, body_file.name):
            try:
                os.unlink(path)
            except OSError:
                pass
    status_code = 0
    header_map: dict[str, str] = {}
    for line in header_text.splitlines():
        if line.startswith("HTTP/"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                status_code = int(parts[1])
                header_map = {}
        elif ":" in line:
            key, value = line.split(":", 1)
            header_map[key.strip()] = value.strip()
    return FetchResult(
        url=url,
        final_url=request_url,
        status_code=status_code,
        headers=header_map,
        content_type=header_map.get("Content-Type", ""),
        body=body,
        size_bytes=len(body),
        elapsed_ms=int((time.perf_counter() - started) * 1000),
        backend="curl",
        error=completed.stderr.decode("utf-8", errors="ignore").strip() if completed.returncode != 0 else None,
    )


def fetch(
    url: str,
    *,
    method: str = "GET",
    timeout: float = 10,
    verify: bool = False,
    headers: dict[str, str] | None = None,
    max_bytes: int | None = None,
    params: dict[str, Any] | None = None,
    data: bytes | str | dict[str, Any] | None = None,
    files: dict[str, tuple[str, bytes, str]] | None = None,
    proxies: dict[str, str] | None | Any = _PROXY_UNSET,
    allow_redirects: bool = True,
    backends: tuple[str, ...] = ("urllib", "requests", "curl"),
    audience: str = "target",
    env: dict[str, str] | None = None,
    use_env_proxy: bool | None = None,
) -> FetchResult:
    proxies = _resolve_proxies(proxies, audience, env)
    if use_env_proxy is None:
        use_env_proxy = default_use_env_proxy(env)
    last_result: FetchResult | None = None
    if files:
        backends = tuple(backend for backend in backends if backend != "urllib")
    for backend in backends:
        if backend == "urllib":
            result = _fetch_urllib(
                url,
                method=method,
                timeout=timeout,
                verify=verify,
                headers=headers,
                max_bytes=max_bytes,
                params=params,
                data=data,
                proxies=proxies,
                use_env_proxy=use_env_proxy,
            )
        elif backend == "requests":
            if not _requests_available():
                continue
            result = _fetch_requests(
                url,
                method=method,
                timeout=timeout,
                verify=verify,
                headers=headers,
                max_bytes=max_bytes,
                params=params,
                data=data,
                files=files,
                proxies=proxies,
                allow_redirects=allow_redirects,
                use_env_proxy=use_env_proxy,
            )
        elif backend == "curl":
            if files:
                continue
            result = _fetch_curl(
                url,
                method=method,
                timeout=timeout,
                verify=verify,
                headers=headers,
                max_bytes=max_bytes,
                params=params,
                data=data,
                proxies=proxies,
                allow_redirects=allow_redirects,
                use_env_proxy=use_env_proxy,
            )
        else:
            continue
        last_result = result
        if result.status_code > 0:
            return result
    if last_result is None:
        return FetchResult(
            url=url,
            final_url=url,
            status_code=0,
            headers={},
            content_type="",
            body=b"",
            size_bytes=0,
            elapsed_ms=0,
            backend="none",
            error="no backend available",
        )
    return last_result


async def async_fetch(
    url: str,
    *,
    method: str = "GET",
    timeout: float = 10,
    verify: bool = False,
    headers: dict[str, str] | None = None,
    max_bytes: int | None = None,
    data: bytes | None = None,
    proxy: str | None | Any = _PROXY_UNSET,
    allow_redirects: bool = True,
    http2: bool = False,
    audience: str = "target",
    env: dict[str, str] | None = None,
    use_env_proxy: bool | None = None,
) -> FetchResult:
    started = time.perf_counter()
    if proxy is _PROXY_UNSET:
        proxy = default_proxy_url(audience, env)
    if use_env_proxy is None:
        use_env_proxy = default_use_env_proxy(env)
    try:
        import httpx  # noqa: PLC0415

        async with httpx.AsyncClient(
            http2=http2,
            verify=verify,
            proxy=proxy,
            timeout=timeout,
            follow_redirects=allow_redirects,
            trust_env=use_env_proxy,
        ) as client:
            response = await client.request(method, url, headers=_build_headers(headers), content=data)
        body = _truncate(response.content, max_bytes)
        return FetchResult(
            url=url,
            final_url=str(response.url),
            status_code=response.status_code,
            headers=dict(response.headers),
            content_type=response.headers.get("Content-Type", ""),
            body=body,
            size_bytes=len(body),
            elapsed_ms=int((time.perf_counter() - started) * 1000),
            backend="httpx",
        )
    except Exception as exc:  # noqa: BLE001
        return FetchResult(
            url=url,
            final_url=url,
            status_code=0,
            headers={},
            content_type="",
            body=b"",
            size_bytes=0,
            elapsed_ms=int((time.perf_counter() - started) * 1000),
            backend="httpx",
            error=str(exc),
        )
