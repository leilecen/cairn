"""Yakit MCP 客户端测试（不依赖真实 Yakit：注入 fake session / fake post）。

SSE 校验按实测语义：`event: endpoint` 给出 POST 地址；JSON-RPC 响应在 POST 响应体里；
session 失效（-32602 Invalid session ID）要能自动重建一次。
"""

from __future__ import annotations

import json

import pytest
from utils import yakit_mcp as ym


class FakeResponse:
    def __init__(self, lines: list[str], payload: dict | None = None, status_code: int = 202):
        self._lines = lines
        self._payload = payload
        self.status_code = status_code
        self.text = json.dumps(payload) if payload is not None else ""
        self.closed = False

    def iter_lines(self, decode_unicode=True):  # noqa: ARG002
        yield from self._lines

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload

    def close(self):
        self.closed = True


class FakeSession:
    """按调用顺序返回 SSE 行；POST 由外部 post_fn 处理。"""

    def __init__(self, base: str = "http://127.0.0.1:11432") -> None:
        self.base = base
        self.trust_env = True

    def get(self, url, stream=False, timeout=None):  # noqa: ARG002
        session_id = "abc"
        return FakeResponse(
            [
                "event: endpoint",
                f"data: {self.base}/message?sessionId={session_id}",
            ]
        )

    def post(self, *args, **kwargs):  # pragma: no cover - 由 post_fn 取代
        raise AssertionError("应使用注入的 post_fn")

    def close(self):
        return None


def make_client(handler) -> ym.YakitMCP:
    """handler(body) -> payload_dict | (payload_dict, status_code)"""
    calls: list[dict] = []

    def post_fn(endpoint: str, body: dict):
        calls.append(body)
        out = handler(body)
        return out[0] if isinstance(out, tuple) else out

    client = ym.YakitMCP(session_factory=FakeSession, post_fn=post_fn)
    client.calls = calls  # type: ignore[attr-defined]
    return client


def _result(body, texts: list[str]) -> dict:
    return {"jsonrpc": "2.0", "id": body.get("id"), "result": {"content": [{"type": "text", "text": t} for t in texts]}}


def test_handshake_and_tool_call_read_response_from_post_body():
    def handler(body):
        method = body.get("method")
        if method == "initialize":
            return {"jsonrpc": "2.0", "id": body["id"], "result": {"serverInfo": {"name": "Yaklang MCP Server"}}}, 202
        if method == "tools/call":
            return {
                "jsonrpc": "2.0",
                "id": body["id"],
                "result": {
                    "content": [
                        {"type": "text", "text": "[info] response: HTTP/1.1 200 OK (body size: 2)"},
                        {
                            "type": "text",
                            "text": json.dumps({"status_code": 200, "duration_ms": 7, "transport_error": None}),
                        },
                    ]
                },
            }, 202
        return {"jsonrpc": "2.0", "id": body.get("id"), "result": {}}, 202

    client = make_client(handler)
    result = client.call_tool("do_http_request", {"url": "http://x/"})
    assert result.is_error is False
    assert result.data == {"status_code": 200, "duration_ms": 7, "transport_error": None}
    methods = [call["method"] for call in client.calls]
    assert methods[0] == "initialize"
    assert "notifications/initialized" in methods
    assert methods[-1] == "tools/call"
    assert client.calls[-1]["params"]["name"] == "do_http_request"


def test_session_invalid_is_recovered_once():
    state = {"fail": 1}

    def handler(body):
        if body.get("method") == "initialize":
            return {"jsonrpc": "2.0", "id": body.get("id"), "result": {}}
        if body.get("method") == "notifications/initialized":
            return {}
        if state["fail"]:
            state["fail"] -= 1
            return {"jsonrpc": "2.0", "id": None, "error": {"code": -32602, "message": "Invalid session ID"}}
        return _result(body, ["ok"])

    client = make_client(handler)
    result = client.call_tool("query_http_flow", {})
    assert result.texts == ["ok"]
    assert client.reconnects == 1


def test_tool_error_surfaces_as_error_result():
    def handler(body):
        if body.get("method") in {"initialize", "notifications/initialized"}:
            return {"jsonrpc": "2.0", "id": body.get("id"), "result": {}}
        return {"jsonrpc": "2.0", "id": body.get("id"), "error": {"code": -32601, "message": "unknown tool"}}

    client = make_client(handler)
    with pytest.raises(ym.YakitMCPError):
        client.call_tool("nope", {})


def test_bad_json_rpc_payload_raises():
    def handler(body):
        return {"jsonrpc": "2.0", "id": body.get("id"), "error": {"code": -32000, "message": "boom"}}

    client = make_client(handler)
    with pytest.raises(ym.YakitMCPError) as exc:
        client.call_tool("do_http_request", {})
    assert "-32000" in str(exc.value)


def test_probe_returns_false_when_endpoint_missing():
    class BadSession(FakeSession):
        def get(self, url, stream=False, timeout=None):  # noqa: ARG002
            return FakeResponse(["event: message", "data: {}"])

    client = ym.YakitMCP(
        session_factory=BadSession,
        post_fn=lambda endpoint, body: {"jsonrpc": "2.0", "id": body.get("id"), "result": {}},
        handshake_timeout=0.5,
    )
    assert client.probe() is False


def test_mcp_available_uses_tcp_probe(monkeypatch):
    import socket

    class FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: FakeSocket())
    assert ym.mcp_available("http://127.0.0.1:11432") is True

    def boom(*a, **k):
        raise OSError("refused")

    monkeypatch.setattr(socket, "create_connection", boom)
    assert ym.mcp_available("http://127.0.0.1:11432") is False


def test_client_disables_env_proxy():
    """本机 HTTP_PROXY 指向 Clash，MCP 调用必须直连 127.0.0.1。"""
    client = ym.YakitMCP(session_factory=FakeSession, post_fn=lambda e, b: {"jsonrpc": "2.0", "id": b.get("id"), "result": {}})
    session = client._new_session()
    assert session.trust_env is False


def test_notification_with_empty_body_is_not_parsed():
    """真实回归：通知类请求返回 202 + 空 body，不能去解析 JSON。"""

    class HttpSession(FakeSession):
        def __init__(self):
            super().__init__()
            self.posted: list[dict] = []

        def post(self, url, json=None, timeout=None):  # noqa: A002, ARG002
            self.posted.append(json)
            if json.get("method") == "notifications/initialized":
                return FakeResponse([], payload=None, status_code=202)  # 空 body
            if json.get("method") == "initialize":
                return FakeResponse([], payload={"jsonrpc": "2.0", "id": json["id"], "result": {}}, status_code=202)
            return FakeResponse(
                [],
                payload={"jsonrpc": "2.0", "id": json["id"], "result": {"content": [{"type": "text", "text": "done"}]}},
                status_code=202,
            )

    session = HttpSession()
    client = ym.YakitMCP(session_factory=lambda: session)
    result = client.call_tool("do_http_request", {"url": "http://x/"})
    assert result.texts == ["done"]
    assert [body["method"] for body in session.posted][:3] == ["initialize", "notifications/initialized", "tools/call"]
