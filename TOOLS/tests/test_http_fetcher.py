"""传输层测试：这些用例打的是 example.com（第三方），因此显式声明 audience="intel"。

目标侧出口策略（默认经 Burp、fail-closed）由 `test_default_proxy_policy_*` 与
`TOOLS/tests/test_egress.py` 覆盖。
"""

from subprocess import CompletedProcess
from unittest.mock import Mock

import pytest
from utils import http_fetcher

INTEL = {"audience": "intel"}


@pytest.fixture
def transport_only(monkeypatch):
    """只验证传输行为的用例：把出口解析旁路掉，落到被 mock 的模块级 urlopen。

    出口解析（Burp / 环境代理屏蔽）由 `test_urllib_direct_disables_ambient_proxy`
    与 `test_http_fetcher.py::test_use_env_proxy_defaults_to_off` 专门覆盖。
    """
    monkeypatch.setattr(http_fetcher, "_urllib_opener", lambda *args, **kwargs: None)


def test_urllib_success(transport_only, monkeypatch):
    fake_response = Mock()
    fake_response.read.return_value = b"hello"
    fake_response.geturl.return_value = "https://example.com/final"
    fake_response.status = 200
    fake_response.headers = {"Content-Type": "text/plain"}
    fake_cm = Mock()
    fake_cm.__enter__ = Mock(return_value=fake_response)
    fake_cm.__exit__ = Mock(return_value=None)
    monkeypatch.setattr(http_fetcher, "urlopen", lambda *args, **kwargs: fake_cm)

    result = http_fetcher.fetch("https://example.com", **INTEL)

    assert result.status_code == 200
    assert result.final_url == "https://example.com/final"
    assert result.backend == "urllib"
    assert result.body == b"hello"


def test_fallback_to_requests(transport_only, monkeypatch):
    monkeypatch.setattr(http_fetcher, "urlopen", Mock(side_effect=RuntimeError("tls fail")))
    monkeypatch.setattr(http_fetcher, "_requests_available", lambda: True)

    class FakeResponse:
        status_code = 200
        url = "https://example.com/ok"
        headers = {"Content-Type": "application/javascript"}
        content = b"console.log(1)"

    monkeypatch.setattr(
        "requests.sessions.Session.request",
        lambda self, *args, **kwargs: FakeResponse(),
    )

    result = http_fetcher.fetch("https://example.com/app.js", **INTEL)

    assert result.status_code == 200
    assert result.backend == "requests"


def test_fallback_to_curl(transport_only, monkeypatch):
    monkeypatch.setattr(http_fetcher, "urlopen", Mock(side_effect=RuntimeError("tls fail")))
    monkeypatch.setattr(http_fetcher, "_requests_available", lambda: True)
    monkeypatch.setattr("requests.sessions.Session.request", Mock(side_effect=RuntimeError("requests fail")))
    monkeypatch.setattr("shutil.which", lambda name: "curl.exe")

    def fake_run(*args, **kwargs):
        header_path = args[0][args[0].index("-D") + 1]
        body_path = args[0][args[0].index("-o") + 1]
        with open(header_path, "w", encoding="iso-8859-1") as fh:
            fh.write("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n")
        with open(body_path, "wb") as fh:
            fh.write(b"<html/>")
        return CompletedProcess(args[0], 0, b"", b"")

    monkeypatch.setattr("subprocess.run", fake_run)

    result = http_fetcher.fetch("https://example.com", backends=("urllib", "requests", "curl"), **INTEL)

    assert result.backend == "curl"
    assert result.status_code == 200
    assert result.body == b"<html/>"


def test_http_403_is_returned_not_raised(transport_only, monkeypatch):
    from urllib.error import HTTPError

    error = HTTPError("https://example.com/private", 403, "Forbidden", {"Content-Type": "text/html"}, None)
    error.read = lambda: b"denied"
    monkeypatch.setattr(http_fetcher, "urlopen", Mock(side_effect=error))

    result = http_fetcher.fetch("https://example.com/private", **INTEL)

    assert result.status_code == 403
    assert result.body == b"denied"


def test_verify_false_reaches_requests(transport_only, monkeypatch):
    monkeypatch.setattr(http_fetcher, "urlopen", Mock(side_effect=RuntimeError("fail")))
    monkeypatch.setattr(http_fetcher, "_requests_available", lambda: True)
    captured = {}

    class FakeResponse:
        status_code = 200
        url = "https://example.com"
        headers = {"Content-Type": "text/plain"}
        content = b"ok"

    def fake_request(self, method, url, headers, timeout, verify, allow_redirects, **_kwargs):
        captured["verify"] = verify
        captured["trust_env"] = self.trust_env
        return FakeResponse()

    monkeypatch.setattr("requests.sessions.Session.request", fake_request)
    result = http_fetcher.fetch("https://example.com", verify=False, **INTEL)
    assert result.status_code == 200
    assert captured["verify"] is False
    assert captured["trust_env"] is False, "默认必须忽略环境代理（本机 HTTP_PROXY→Clash）"


def test_max_bytes_truncates(transport_only, monkeypatch):
    fake_response = Mock()
    fake_response.read.return_value = b"abcdef"
    fake_response.geturl.return_value = "https://example.com/final"
    fake_response.status = 200
    fake_response.headers = {"Content-Type": "text/plain"}
    fake_cm = Mock()
    fake_cm.__enter__ = Mock(return_value=fake_response)
    fake_cm.__exit__ = Mock(return_value=None)
    monkeypatch.setattr(http_fetcher, "urlopen", lambda *args, **kwargs: fake_cm)

    result = http_fetcher.fetch("https://example.com", max_bytes=3, **INTEL)

    assert result.body == b"abc"
    assert result.size_bytes == 3


def test_timeout_error_reported(transport_only, monkeypatch):
    monkeypatch.setattr(http_fetcher, "urlopen", Mock(side_effect=TimeoutError("boom")))
    monkeypatch.setattr(http_fetcher, "_requests_available", lambda: False)
    result = http_fetcher.fetch("https://example.com", backends=("urllib",), **INTEL)
    assert result.status_code == 0
    assert "boom" in (result.error or "")


# ── 出口策略 ──────────────────────────────────────────────────────────────────


def test_default_proxy_policy_target_goes_through_yakit_mitm():
    """默认出口是 Yakit（MCP 发包）；直连 http_fetcher 的老调用方兜底走 Yakit MITM。"""
    assert http_fetcher.default_proxy_url("target", {}) == "http://127.0.0.1:8083"
    assert http_fetcher.default_proxies("target", {}) == {
        "http": "http://127.0.0.1:8083",
        "https": "http://127.0.0.1:8083",
    }


def test_default_proxy_policy_burp_mode_uses_burp():
    assert http_fetcher.default_proxy_url("target", {"EGRESS_MODE": "burp"}) == "http://127.0.0.1:8080"
    assert (
        http_fetcher.default_proxy_url("target", {"EGRESS_MODE": "burp", "EGRESS_BURP": "http://127.0.0.1:9999"}) == "http://127.0.0.1:9999"
    )


def test_default_proxy_policy_intel_is_direct():
    assert http_fetcher.default_proxy_url("intel", {}) is None
    assert http_fetcher.default_proxies("intel", {}) is None


def test_default_proxy_policy_honours_env_opt_out():
    assert http_fetcher.default_proxy_url("target", {"EGRESS_MODE": "direct"}) is None
    assert (
        http_fetcher.default_proxy_url("target", {"EGRESS_MODE": "yakit", "EGRESS_YAKIT_MITM": "http://127.0.0.1:9999"})
        == "http://127.0.0.1:9999"
    )


def test_explicit_proxies_none_still_means_direct(transport_only, monkeypatch):
    fake_response = Mock()
    fake_response.read.return_value = b"ok"
    fake_response.geturl.return_value = "https://example.com"
    fake_response.status = 200
    fake_response.headers = {"Content-Type": "text/plain"}
    fake_cm = Mock()
    fake_cm.__enter__ = Mock(return_value=fake_response)
    fake_cm.__exit__ = Mock(return_value=None)
    monkeypatch.setattr(http_fetcher, "urlopen", lambda *args, **kwargs: fake_cm)
    result = http_fetcher.fetch("https://example.com", proxies=None, backends=("urllib",))
    assert result.status_code == 200


# ── 环境代理（Clash）默认关闭 ─────────────────────────────────────────────────


def test_use_env_proxy_defaults_to_off():
    assert http_fetcher.default_use_env_proxy({}) is False
    assert http_fetcher.default_use_env_proxy({"HTTP_PROXY": "http://127.0.0.1:9870"}) is False
    assert http_fetcher.default_use_env_proxy({"EGRESS_USE_ENV_PROXY": "1"}) is True


def test_urllib_direct_disables_ambient_proxy(monkeypatch):
    """ProxyHandler({}) 才挡得住 HTTP_PROXY/ALL_PROXY；opener 必须被真正使用。"""
    captured = {}

    class FakeOpener:
        def open(self, request, **kwargs):  # noqa: ARG002
            fake = Mock()
            fake.read.return_value = b"ok"
            fake.geturl.return_value = "https://example.com"
            fake.status = 200
            fake.headers = {"Content-Type": "text/plain"}
            fake.__enter__ = Mock(return_value=fake)
            fake.__exit__ = Mock(return_value=None)
            return fake

    def fake_build_opener(*handlers):
        captured["handlers"] = [type(h).__name__ for h in handlers]
        captured["mapping"] = getattr(handlers[0], "proxies", None)
        return FakeOpener()

    monkeypatch.setattr("urllib.request.build_opener", fake_build_opener)
    result = http_fetcher.fetch("https://example.com", proxies=None, backends=("urllib",), use_env_proxy=False)
    assert result.status_code == 200
    assert captured["handlers"] == ["ProxyHandler"]
    assert captured["mapping"] == {}, "直连时必须显式清空代理映射"


def test_curl_direct_passes_noproxy(monkeypatch):
    monkeypatch.setattr(http_fetcher, "urlopen", Mock(side_effect=RuntimeError("skip")))
    monkeypatch.setattr("shutil.which", lambda name: "curl.exe")
    captured: dict = {}

    def fake_run(command, **_kwargs):
        captured["command"] = command
        header_path = command[command.index("-D") + 1]
        body_path = command[command.index("-o") + 1]
        with open(header_path, "w", encoding="iso-8859-1") as fh:
            fh.write("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n")
        with open(body_path, "wb") as fh:
            fh.write(b"<html/>")
        return CompletedProcess(command, 0, b"", b"")

    monkeypatch.setattr("subprocess.run", fake_run)
    http_fetcher.fetch("https://example.com", proxies=None, backends=("curl",), use_env_proxy=False)
    assert "--noproxy" in captured["command"], "curl 自身也读环境代理，必须显式关闭"
    assert captured["command"][captured["command"].index("--noproxy") + 1] == "*"


def test_curl_uses_identity_ua_not_hardcoded_default(monkeypatch):
    """回归：curl 后端以前写死 -A DEFAULT_UA，会静默覆盖调用方身份。"""
    monkeypatch.setattr(http_fetcher, "urlopen", Mock(side_effect=RuntimeError("skip")))
    monkeypatch.setattr("shutil.which", lambda name: "curl.exe")
    captured: dict = {}

    def fake_run(command, **_kwargs):
        captured["command"] = command
        header_path = command[command.index("-D") + 1]
        body_path = command[command.index("-o") + 1]
        with open(header_path, "w", encoding="iso-8859-1") as fh:
            fh.write("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n")
        with open(body_path, "wb") as fh:
            fh.write(b"<html/>")
        return CompletedProcess(command, 0, b"", b"")

    monkeypatch.setattr("subprocess.run", fake_run)
    http_fetcher.fetch(
        "https://example.com",
        proxies=None,
        backends=("curl",),
        headers={"User-Agent": "Mozilla/5.0 (custom-identity)"},
    )
    assert captured["command"][captured["command"].index("-A") + 1] == "Mozilla/5.0 (custom-identity)"
