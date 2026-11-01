"""TOOLS/utils/egress.py 的单元测试。

覆盖：身份自洽与持久化、抖动节奏、突发上限、熔断、fail-closed、台账与摘要。
不涉及真实网络：fetch 由 fake 注入，Burp 可达性由 monkeypatch 控制。
"""

from __future__ import annotations

import json
import random
import sqlite3
from dataclasses import dataclass
from pathlib import Path

import pytest
from utils import egress as eg

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "TOOLS" / "db" / "schema.sql"


@dataclass
class FakeResult:
    url: str = "https://example.test/a"
    final_url: str = "https://example.test/a"
    status_code: int = 200
    headers: dict | None = None
    content_type: str = "text/html"
    body: bytes = b"ok"
    size_bytes: int = 2
    elapsed_ms: int = 5
    backend: str = "fake"
    error: str | None = None

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="ignore")


class FakeFetch:
    """记录调用参数并返回可编排的响应。"""

    def __init__(self, results: list[FakeResult] | None = None) -> None:
        self.calls: list[dict] = []
        self.results = list(results or [])
        self.default = FakeResult()

    def __call__(self, url, **kwargs):
        self.calls.append({"url": url, **kwargs})
        if self.results:
            return self.results.pop(0)
        return self.default


def make_egress(tmp_path: Path, *, fetch=None, mode="direct", audience="intel", **kwargs) -> eg.Egress:
    return eg.Egress(
        target="unit-test",
        identity=kwargs.pop("identity", eg.Identity(marker="acme")),
        mode=mode,
        audience=audience,
        allow_direct=True,
        pacer=kwargs.pop("pacer", eg.Pacer(eg.PacingPolicy(enabled=False), sleep=lambda _s: None)),
        jsonl_dir=tmp_path,
        fetch_fn=fetch or FakeFetch(),
        **kwargs,
    )


# ── 身份 ──────────────────────────────────────────────────────────────────────


def test_default_identity_is_consistent_browser_identity():
    identity = eg.Identity()
    assert identity.consistency_problems() == []


@pytest.mark.parametrize(
    "ua",
    [
        "python-requests/2.32.0",
        "curl/8.4.0",
        "httpx/0.27",
        "SRC-preauth-probe/1.0",
        "src-recon-baseline/1.0",
        "ai-key-searcher",
        "sqlmap/1.8",
    ],
)
def test_self_naming_user_agents_are_rejected(ua):
    problems = eg.Identity(user_agent=ua).consistency_problems()
    assert problems, f"{ua} 应被判为身份泄漏"


def test_identity_headers_are_ordered_and_carry_marker():
    headers = eg.Identity(marker="acme").headers(profile="repeater")
    keys = list(headers)
    assert keys[0] == "User-Agent"
    assert headers["X-Pentest-Engagement"] == "acme"
    browser = eg.Identity().headers(profile="browser")
    assert browser["Sec-Fetch-Mode"] == "navigate"
    assert "Sec-Fetch-Mode" not in keys


def test_non_ascii_marker_is_encoded_not_dropped():
    """真实缺陷回归：中文委托方名直接进 header 会让每个请求抛 latin-1 编码错误。"""
    identity = eg.Identity(marker="测试委托方")
    headers = identity.headers()
    value = headers["X-Pentest-Engagement"]
    assert value.isascii() and value.startswith("=?utf-8?B?"), value
    # 任何标准 encoded-word 解码器都能还原原文
    import base64

    payload = value[len("=?utf-8?B?") : -2]
    assert base64.b64decode(payload).decode("utf-8") == "测试委托方"


def test_all_identity_headers_are_sendable():
    headers = eg.Identity(marker="测试委托方").headers(profile="browser")
    for value in headers.values():
        value.encode("latin-1")  # 不可编码即视为回归


def test_unencodable_extra_header_is_reported_and_refused(tmp_path):
    identity = eg.Identity(extra=(("X-Note", "中文值"),))
    assert any("latin-1" in problem for problem in identity.consistency_problems())
    with pytest.raises(eg.EgressUnavailable):
        eg.Egress(target="t", identity=identity, mode="direct", audience="intel", jsonl_dir=tmp_path, fetch_fn=FakeFetch())


def test_transport_failure_is_recorded_as_error_not_sent(tmp_path):
    """status=0 的传输失败必须记成 error，否则台账上看不出整轮请求其实全丢了。"""
    fetch = FakeFetch([FakeResult(status_code=0, error="connection refused")])
    client = make_egress(tmp_path, fetch=fetch)
    result = client.get("https://a.test/x")
    row = client.ledger.records[0]
    assert result.status_code == 0
    assert row["decision"] == "error"
    assert "connection refused" in row["note"]
    assert client.summary()["errors"] == 1


def test_load_identity_is_stable_across_loads(tmp_path):
    """身份必须持久化：多次加载（含无关环境变量变化）不得换 UA。"""
    path = tmp_path / "identity.json"
    first = eg.load_identity(path=path, env={})
    second = eg.load_identity(path=path, env={})
    third = eg.load_identity(path=path, env={"EGRESS_IDENTITY_NAME": "other"})
    assert first.user_agent == second.user_agent == third.user_agent


def test_load_identity_honours_marker_env(tmp_path):
    identity = eg.load_identity(path=tmp_path / "i.json", env={"EGRESS_ENGAGEMENT_MARKER": "客户A"})
    assert identity.marker == "客户A"


def test_load_identity_env_overrides_persisted_marker(tmp_path):
    """委托方/测试标记是按委托变化的，不能因为身份文件已存在就被忽略。"""
    path = tmp_path / "i.json"
    eg.load_identity(path=path, env={})
    updated = eg.load_identity(path=path, env={"EGRESS_ENGAGEMENT_MARKER": "客户B"})
    assert updated.marker == "客户B"
    assert eg.load_identity(path=path, env={}).marker == "客户B", "覆盖应落盘"
    ua_env = eg.load_identity(path=path, env={"EGRESS_UA": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"})
    assert ua_env.user_agent.startswith("Mozilla/5.0 (Macintosh")


# ── 节奏 ──────────────────────────────────────────────────────────────────────


def test_pacer_burst_then_gap():
    policy = eg.PacingPolicy(max_rps=0.5, min_gap_ms=500, burst=3)
    pacer = eg.Pacer(policy, rng=random.Random(7))  # noqa: S311 - 固定种子保证可复现
    gaps = [pacer.plan_gap_ms("a.test") for _ in range(5)]
    assert gaps[:3] == [0.0, 0.0, 0.0], "突发预算内的请求应立即可发"
    assert gaps[3] > 0 and gaps[4] > 0


def test_pacing_is_jittered_not_uniform():
    policy = eg.PacingPolicy(enabled=True, max_rps=0.5, min_gap_ms=200, burst=1, sigma=0.6, think_every=0)
    pacer = eg.Pacer(policy, rng=random.Random(11))  # noqa: S311 - 固定种子保证可复现
    gaps = []
    for _ in range(40):
        pacer.plan_gap_ms("a.test")  # 消费令牌
        gaps.append(policy.sample_gap_ms(pacer.rng, 1))
    assert len(set(round(g, 3) for g in gaps)) > 30, "间隔必须抖动，均匀间隔=扫描器特征"
    assert max(gaps) / min(gaps) > 3


def test_think_pause_is_inserted_periodically():
    policy = eg.PacingPolicy(max_rps=1.0, min_gap_ms=100, think_every=5, think_ms_min=8000, think_ms_max=8000, burst=1)
    pacer = eg.Pacer(policy, rng=random.Random(3))  # noqa: S311 - 固定种子保证可复现
    gaps = [pacer.policy.sample_gap_ms(pacer.rng, n) for n in range(1, 6)]
    assert gaps[-1] >= 8000, "每 N 个请求后应有一次长停顿（读响应/改 payload）"
    assert gaps[0] < 8000


def test_pacing_disabled_has_no_delay():
    pacer = eg.Pacer(eg.PacingPolicy(enabled=False))
    assert [pacer.plan_gap_ms("a.test") for _ in range(3)] == [0.0, 0.0, 0.0]


# ── 熔断 ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("status", "body", "expected"),
    [
        (200, "", ""),
        (429, "", "rate_limited"),
        (403, "<html>Cloudflare Ray ID</html>", "waf_detected"),
        (403, "id=1 不存在", ""),
        (503, "Too Many Requests", "waf_detected"),
    ],
)
def test_classify_response(status, body, expected):
    assert eg.classify_response(status, body) == expected


def test_breaker_opens_after_threshold_and_preserves_stop_reason():
    breaker = eg.CircuitBreaker(threshold=3)
    assert breaker.observe(429) == "rate_limited"
    assert breaker.observe(429) == "rate_limited"
    breaker.raise_if_open()  # 未达阈值仍可发
    assert breaker.observe(429) == "rate_limited"
    with pytest.raises(eg.EgressBlocked) as exc:
        breaker.raise_if_open()
    assert exc.value.reason == "rate_limited"
    assert breaker.stop_reason == "rate_limited"


def test_request_stops_after_breaker_opens(tmp_path):
    fetch = FakeFetch([FakeResult(status_code=429) for _ in range(3)])
    client = make_egress(tmp_path, fetch=fetch, breaker=eg.CircuitBreaker(threshold=3))
    for _ in range(3):
        client.get("https://example.test/api")
    with pytest.raises(eg.EgressBlocked):
        client.get("https://example.test/api")
    assert client.ledger.stop_reason() == "rate_limited"


# ── fail-closed ───────────────────────────────────────────────────────────────


def test_burp_mode_refuses_to_send_when_burp_is_down(tmp_path, monkeypatch):
    monkeypatch.setattr(eg, "host_port_open", lambda *a, **k: False)
    with pytest.raises(eg.EgressUnavailable) as exc:
        eg.Egress(target="t", identity=eg.Identity(), mode="burp", jsonl_dir=tmp_path, fetch_fn=FakeFetch())
    assert "fail-closed" in str(exc.value)


def test_burp_mode_sends_through_proxy_when_up(tmp_path, monkeypatch):
    monkeypatch.setattr(eg, "host_port_open", lambda *a, **k: True)
    fetch = FakeFetch()
    client = eg.Egress(
        target="t",
        identity=eg.Identity(),
        mode="burp",
        pacer=eg.Pacer(eg.PacingPolicy(enabled=False), sleep=lambda _s: None),
        jsonl_dir=tmp_path,
        fetch_fn=fetch,
    )
    client.get("https://example.test/a")
    assert fetch.calls[0]["proxies"] == {"http": eg.DEFAULT_BURP, "https": eg.DEFAULT_BURP}


def test_direct_target_mode_requires_explicit_opt_in(tmp_path):
    with pytest.raises(eg.EgressUnavailable):
        eg.Egress(
            target="t",
            identity=eg.Identity(),
            mode="direct",
            audience="target",
            jsonl_dir=tmp_path,
            fetch_fn=FakeFetch(),
        )


def test_direct_mode_rejected_for_inconsistent_identity(tmp_path):
    with pytest.raises(eg.EgressUnavailable):
        make_egress(tmp_path, identity=eg.Identity(user_agent="python-requests/2.32.0"))


# ── 发包形态 ──────────────────────────────────────────────────────────────────


def test_sent_request_carries_unified_identity(tmp_path):
    fetch = FakeFetch()
    client = make_egress(tmp_path, fetch=fetch)
    client.get("https://example.test/api?v=1")
    sent = fetch.calls[0]
    assert sent["headers"]["User-Agent"].startswith("Mozilla/5.0")
    assert sent["headers"]["X-Pentest-Engagement"] == "acme"
    assert sent["backends"] == ("requests",), "单后端：避免 urllib→curl 静默降级与重复发包"
    assert sent["proxies"] is None  # intel audience 直连


def test_caller_supplied_user_agent_is_refused(tmp_path):
    client = make_egress(tmp_path)
    with pytest.raises(eg.EgressUnavailable):
        client.get("https://example.test/a", headers={"User-Agent": "curl/8"})


def test_navigate_builds_referer_chain_for_followup_xhr(tmp_path):
    fetch = FakeFetch()
    client = make_egress(tmp_path, fetch=fetch)
    client.navigate("https://example.test/console/list")
    client.get("https://example.test/api/items")
    assert fetch.calls[1]["headers"]["Referer"] == "https://example.test/console/list"
    assert fetch.calls[0]["headers"]["Sec-Fetch-Mode"] == "navigate"


def test_post_sets_origin_only_for_same_origin(tmp_path):
    fetch = FakeFetch()
    client = make_egress(tmp_path, fetch=fetch)
    client.navigate("https://example.test/form")
    client.post("https://example.test/api/save", data="a=1")
    client.post("https://other.test/api/save", data="a=1")
    assert fetch.calls[1]["headers"]["Origin"] == "https://example.test"
    assert "Origin" not in fetch.calls[2]["headers"]


# ── 台账 ──────────────────────────────────────────────────────────────────────


def test_ledger_jsonl_fallback_records_no_query_string(tmp_path):
    client = make_egress(tmp_path)
    client.get("https://example.test/api/items?id=1'&token=SECRET")
    ledger_file = client.ledger._jsonl_path()
    line = json.loads(ledger_file.read_text(encoding="utf-8").strip().splitlines()[0])
    assert line["url_path"] == "/api/items"
    assert "SECRET" not in json.dumps(line, ensure_ascii=False)


def test_ledger_writes_egress_log_table(tmp_path):
    db_path = tmp_path / "t.db"
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA.read_text(encoding="utf-8"))
    conn.commit()
    conn.close()
    client = make_egress(tmp_path, db_path=db_path)
    client.get("https://example.test/api/items")
    conn = sqlite3.connect(db_path)
    rows = conn.execute("SELECT host, method, url_path, decision, identity FROM egress_log").fetchall()
    conn.close()
    assert rows == [("example.test", "GET", "/api/items", "sent", client.identity.name)]


def test_summary_reports_traffic_shape(tmp_path):
    fetch = FakeFetch([FakeResult(), FakeResult(status_code=404)])
    client = make_egress(tmp_path, fetch=fetch)
    client.get("https://a.test/1")
    client.get("https://a.test/2")
    summary = client.summary()
    assert summary["sent"] == 2
    assert summary["peak_rps"] >= 1
    assert summary["status_codes"] == {"200": 1, "404": 1}
    assert summary["hosts"] == {"a.test": 2}
    assert summary["preflight"]["mode"] == "direct"


# ── 例外通道（竞态等） ────────────────────────────────────────────────────────


def test_unpaced_window_is_auditable(tmp_path):
    policy = eg.PacingPolicy(enabled=True, max_rps=0.5, min_gap_ms=1000, burst=1)
    client = make_egress(tmp_path, pacer=eg.Pacer(policy, sleep=lambda _s: None))
    assert policy.enabled is True
    with client.unpaced("race-window"):
        assert policy.enabled is False
        client.get("https://a.test/race")
    assert policy.enabled is True
    row = client.ledger.records[0]
    assert row["note"] == "unpaced:race-window"
    assert row["planned_gap_ms"] == 0


def test_note_external_uses_breaker_stop_reason(tmp_path):
    client = make_egress(tmp_path, breaker=eg.CircuitBreaker(threshold=1))
    client.breaker.observe(429)
    client.note_external("https://a.test/fanout?x=1", method="POST", status=200, note="async-race")
    row = client.ledger.records[0]
    assert row["url_path"] == "/fanout"
    assert row["stop_reason"] == "rate_limited"
    assert row["method"] == "POST"
    assert client.ledger.stop_reason() == "rate_limited"


# ── Yakit MCP 传输 ────────────────────────────────────────────────────────────

YAKIT_PACKET = (
    "[info] request: GET http://127.0.0.1:7278/echo?x=1\r\n"
    "[info] request packet (118 bytes):\r\n"
    "GET /echo?x=1 HTTP/1.1\r\nHost: 127.0.0.1:7278\r\nUser-Agent: Mozilla/5.0 (probe-identity)\r\n"
    "X-Pentest-Engagement: acme\r\n\r\n\r\n"
    "[info] response: HTTP/1.0 200 OK (body size: 33)\r\n"
    "[info] response packet (178 bytes):\r\n"
    "HTTP/1.0 200 OK\r\nServer: BaseHTTP/0.6 Python/3.12.13\r\nContent-Type: application/json\r\n"
    "Content-Length: 33\r\n\r\n"
    '{"ok": true, "path": "/echo?x=1"}\n'
)


class FakeYakitResult:
    def __init__(self, data, texts, is_error=False):
        self.data = data
        self.texts = texts
        self.is_error = is_error

    def text(self):
        return "\n".join(self.texts)


class FakeYakitClient:
    def __init__(self, result):
        self.result = result
        self.calls = []

    def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        return self.result


def test_parse_yakit_packet_extracts_headers_and_body():
    """用实测报文做回归：response packet 的行必须能解出 header 与 body。"""
    headers, body = eg.parse_yakit_packet(YAKIT_PACKET)
    assert headers["Content-Type"] == "application/json"
    assert headers["Server"].startswith("BaseHTTP")
    assert json.loads(body.decode()) == {"ok": True, "path": "/echo?x=1"}


def test_yakit_result_adapter_builds_fetch_result():
    summary = {
        "body_size": 33,
        "duration_ms": 3,
        "redirect_count": 0,
        "request_built": True,
        "request_sent": True,
        "response_received": True,
        "status_code": 200,
        "transport_error": None,
    }
    result = eg.yakit_result_to_fetch_result("http://t/echo", summary, [YAKIT_PACKET, json.dumps(summary)])
    assert result.status_code == 200
    assert result.backend == "yakit-mcp"
    assert result.elapsed_ms == 3
    assert json.loads(result.text)["ok"] is True
    assert result.headers["Content-Type"] == "application/json"


def test_yakit_transport_error_surfaces_as_failure():
    summary = {"status_code": 0, "transport_error": "dial tcp: i/o timeout", "body_size": 0}
    result = eg.yakit_result_to_fetch_result("http://t/", summary, ["", json.dumps(summary)])
    assert result.status_code == 0
    assert "i/o timeout" in (result.error or "")


def test_yakit_mode_sends_via_mcp_with_identity(tmp_path, monkeypatch):
    monkeypatch.setattr("utils.yakit_mcp.mcp_available", lambda *a, **k: True)
    summary = {"status_code": 200, "duration_ms": 5, "body_size": 20}
    fake = FakeYakitClient(FakeYakitResult(summary, [YAKIT_PACKET, json.dumps(summary)]))
    client = eg.Egress(
        target="t",
        identity=eg.Identity(marker="acme"),
        mode="yakit",
        pacer=eg.Pacer(eg.PacingPolicy(enabled=False), sleep=lambda _s: None),
        jsonl_dir=tmp_path,
    )
    client._yakit = fake
    result = client.get("https://target.test/api/items", params={"a": "1"})
    assert result.status_code == 200
    name, arguments = fake.calls[0]
    assert name == "do_http_request"
    assert arguments["url"] == "https://target.test/api/items?a=1"
    assert arguments["headers"]["User-Agent"].startswith("Mozilla/5.0")
    assert arguments["headers"]["X-Pentest-Engagement"] == "acme"
    assert arguments["redirect-times"] == 5
    assert client.ledger.records[0]["mode"] == "yakit"
    assert client.ledger.records[0]["decision"] == "sent"


def test_yakit_mode_fails_closed_when_mcp_down(tmp_path, monkeypatch):
    monkeypatch.setattr("utils.yakit_mcp.mcp_available", lambda *a, **k: False)
    with pytest.raises(eg.EgressUnavailable) as exc:
        eg.Egress(target="t", identity=eg.Identity(), jsonl_dir=tmp_path)
    assert "Yakit MCP" in str(exc.value)


def test_yakit_mode_passes_upstream_proxy(tmp_path, monkeypatch):
    """EGRESS_UPSTREAM 用于让 Yakit 经上游（例如 VPS）出口。"""
    monkeypatch.setattr("utils.yakit_mcp.mcp_available", lambda *a, **k: True)
    summary = {"status_code": 200, "duration_ms": 1}
    fake = FakeYakitClient(FakeYakitResult(summary, ["", json.dumps(summary)]))
    client = eg.Egress(
        target="t",
        identity=eg.Identity(),
        mode="yakit",
        config=eg.EgressConfig(upstream="http://vps:8080"),
        pacer=eg.Pacer(eg.PacingPolicy(enabled=False), sleep=lambda _s: None),
        jsonl_dir=tmp_path,
    )
    client._yakit = fake
    client.get("https://target.test/")
    assert fake.calls[0][1]["proxy"] == "http://vps:8080"


# ── 自检 ──────────────────────────────────────────────────────────────────────


def test_preflight_report_flags_missing_yakit(tmp_path, monkeypatch):
    monkeypatch.setattr("utils.yakit_mcp.mcp_available", lambda *a, **k: False)
    env = {"EGRESS_IDENTITY_FILE": str(tmp_path / "i.json"), "EGRESS_ENGAGEMENT_MARKER": "acme"}
    report = eg.preflight_report(env)
    assert report["mode"] == "yakit", "默认出口应是 Yakit"
    assert report["ready"] is False
    assert report["reachable"] is False
    assert any("Yakit MCP" in hint for hint in report["hints"])
    assert report["identity"]["marker"] == "acme"


def test_preflight_report_ready_when_yakit_up(tmp_path, monkeypatch):
    monkeypatch.setattr("utils.yakit_mcp.mcp_available", lambda *a, **k: True)
    env = {"EGRESS_IDENTITY_FILE": str(tmp_path / "i.json")}
    report = eg.preflight_report(env)
    assert report["ready"] is True
    assert report["mode"] == "yakit"
    assert report["pacing"]["enabled"] is True


def test_preflight_report_burp_mode_still_supported(tmp_path, monkeypatch):
    monkeypatch.setattr(eg, "host_port_open", lambda *a, **k: False)
    env = {"EGRESS_IDENTITY_FILE": str(tmp_path / "i.json"), "EGRESS_MODE": "burp"}
    report = eg.preflight_report(env)
    assert report["mode"] == "burp"
    assert report["burp_reachable"] is False
    assert any("Burp" in hint for hint in report["hints"])


def test_preflight_cli_exit_code_reflects_readiness(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("utils.yakit_mcp.mcp_available", lambda *a, **k: False)
    monkeypatch.setenv("EGRESS_IDENTITY_FILE", str(tmp_path / "i.json"))
    assert eg.main(["--preflight"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["ready"] is False
