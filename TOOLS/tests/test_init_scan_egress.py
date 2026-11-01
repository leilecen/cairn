"""基线扫描的出口治理：httpx CLI 必须带统一身份、Burp 出口与限速，且 fail-closed。

对应 `docs/modules/egress-traffic-shaping.md` P2：L0/L1 基线是目标侧第一波也是最响的
接触，必须（1）不自报 httpx UA、（2）不绕过 Burp、（3）不按默认并发猛打。
"""

from __future__ import annotations

import pipeline.init_scan as init_scan
import pytest
from utils import egress as eg


@pytest.fixture(autouse=True)
def _clear_caches():
    """lru_cache 会把「Burp 是否可达」的结果跨用例带过去。"""
    for cached in (init_scan._baseline_identity_ua, init_scan._egress_proxy_url, init_scan._egress_rate_limit):
        cached.cache_clear()
    yield
    for cached in (init_scan._baseline_identity_ua, init_scan._egress_proxy_url, init_scan._egress_rate_limit):
        cached.cache_clear()


def test_httpx_args_carry_identity_proxy_and_rate_limit(monkeypatch):
    monkeypatch.setattr(eg, "host_port_open", lambda *a, **k: True)
    args = init_scan._httpx_egress_args()
    assert "-proxy" in args
    assert args[args.index("-proxy") + 1] == eg.DEFAULT_YAKIT_MITM, "默认出口是 Yakit MITM"
    ua_arg = args[args.index("-H") + 1]
    assert ua_arg.startswith("User-Agent: Mozilla/5.0")
    assert "httpx" not in ua_arg.lower(), "httpx CLI 默认 UA 会自报工具名"
    assert "-rl" in args


def test_httpx_args_use_burp_when_mode_is_burp(monkeypatch):
    monkeypatch.setattr(eg, "host_port_open", lambda *a, **k: True)
    monkeypatch.setenv("EGRESS_MODE", "burp")
    init_scan._egress_proxy_url.cache_clear()
    args = init_scan._httpx_egress_args()
    assert args[args.index("-proxy") + 1] == eg.DEFAULT_BURP
    init_scan._egress_proxy_url.cache_clear()


def test_httpx_args_fail_closed_when_proxy_down(monkeypatch):
    monkeypatch.setattr(eg, "host_port_open", lambda *a, **k: False)
    with pytest.raises(eg.EgressUnavailable):
        init_scan._httpx_egress_args()


def test_httpx_args_follow_pacing_knobs(monkeypatch):
    monkeypatch.setattr(eg, "host_port_open", lambda *a, **k: True)
    monkeypatch.setenv("EGRESS_MAX_RPS", "4")
    init_scan._egress_rate_limit.cache_clear()
    args = init_scan._httpx_egress_args()
    assert args[args.index("-rl") + 1] == "4"


def test_entry_probe_fetcher_uses_proxy(monkeypatch):
    """基线入口探测不能直连目标（否则 Chrome UA + Python TLS 自相矛盾）。"""
    seen: dict = {}

    class FakeResponse:
        status = 200
        headers = {"Content-Type": "text/plain"}

        def read(self, _n=None):
            return b"ok"

        def getcode(self):
            return 200

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

    class FakeOpener:
        def open(self, request, timeout=None):  # noqa: ARG002
            seen["url"] = request.full_url
            return FakeResponse()

    def fake_build_opener(*handlers):
        seen["handlers"] = [type(h).__name__ for h in handlers]
        return FakeOpener()

    monkeypatch.setattr(init_scan, "build_opener", fake_build_opener)
    monkeypatch.setattr(init_scan, "_egress_proxy_url", lambda: "http://127.0.0.1:8080")
    result = init_scan._baseline_entry_fetcher("https://a.example/login", "GET")
    assert result["status_code"] == 200
    assert "ProxyHandler" in seen["handlers"], "基线入口探测必须经 Burp 出口"
