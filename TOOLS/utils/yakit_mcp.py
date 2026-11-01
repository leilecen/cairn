"""Yakit MCP 最小客户端（Streamable/SSE JSON-RPC）。

实测（2026-10-10，Yaklang MCP Server 0.0.2）：
- `GET {base}/sse` 返回 `event: endpoint` + `data: http://127.0.0.1:11432/message?sessionId=...`；
  **该 GET 连接必须保持打开**，关掉后 POST 会返回 `-32602 Invalid session ID`。
- JSON-RPC 的**响应在 POST 的响应体里**（HTTP 202 + application/json），
  大载荷（`tools/list` 约 179 KB）不会走 SSE 流，因此不能只读流。
- 无鉴权，仅监听 127.0.0.1：**不得**把该端口暴露到公网（见 docs/modules/egress-traffic-shaping.md）。

用法:
    client = YakitMCP()
    client.call_tool("do_http_request", {"url": ..., "method": "GET", "headers": {...}})
"""

from __future__ import annotations

import contextlib
import json
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

TOOLS_DIR = Path(__file__).resolve().parent.parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

DEFAULT_MCP_BASE = "http://127.0.0.1:11432"
PROTOCOL_VERSION = "2024-11-05"
CLIENT_INFO = {"name": "dsh-egress", "version": "1"}


class YakitMCPError(RuntimeError):
    """MCP 调用失败（连接、握手、工具错误）。"""


@dataclass
class ToolResult:
    """`tools/call` 结果：文本块 + 末块 JSON（若可解析）+ 是否工具级错误。"""

    texts: list[str] = field(default_factory=list)
    data: dict[str, Any] | None = None
    is_error: bool = False

    def text(self) -> str:
        return "\n".join(self.texts)


class YakitMCP:
    """串行调用 Yakit MCP（Yakit 侧同一 session 不支持并行，调用方需串行）。"""

    def __init__(
        self,
        base: str = DEFAULT_MCP_BASE,
        *,
        timeout: float = 30.0,
        handshake_timeout: float = 10.0,
        session_factory: Any = None,
        post_fn: Any = None,
    ) -> None:
        self.base = (base or DEFAULT_MCP_BASE).rstrip("/")
        self.timeout = timeout
        self.handshake_timeout = handshake_timeout
        self._lock = threading.Lock()
        self._endpoint: str | None = None
        self._stream_thread: threading.Thread | None = None
        self._stream_stop = threading.Event()
        self._session = None
        self._initialized = False
        self.call_count = 0
        self.reconnects = 0
        self._session_factory = session_factory
        self._post_fn = post_fn
        self._tools_cache: list[dict[str, Any]] | None = None

    # -- 会话管理 ---------------------------------------------------------

    def _new_session(self):
        if self._session_factory is not None:
            session = self._session_factory()
        else:  # pragma: no cover - 真实网络路径
            import requests  # noqa: PLC0415

            session = requests.Session()
        # 本机 Clash 环境代理不得参与
        try:
            session.trust_env = False
        except AttributeError:
            pass
        return session

    def _open_stream(self, session) -> str:
        """打开 SSE 流并等 endpoint 事件。

        关键：**只能有一个迭代器**。实测若在读 endpoint 后 `break` 并让生成器被回收，
        底层连接会被关闭，服务端随即把 session 判为失效（POST 返回 -32602 Invalid session ID）。
        因此 endpoint 的解析放在保活线程里做，主线程只等待结果。
        """
        self._endpoint = None
        self._stream_stop = threading.Event()  # 每次重开都是新事件，否则重建 session 时读线程会立刻退出
        response = session.get(f"{self.base}/sse", stream=True, timeout=(self.handshake_timeout, 300))
        threading.Thread(target=self._drain, args=(response,), daemon=True).start()
        deadline = time.monotonic() + self.handshake_timeout
        while self._endpoint is None and time.monotonic() < deadline:
            time.sleep(0.02)
        if self._endpoint is None:
            with contextlib.suppress(Exception):
                response.close()
            raise YakitMCPError("Yakit MCP 未返回 endpoint（/sse 无 event: endpoint）")
        return self._endpoint

    def _drain(self, response) -> None:
        """唯一迭代器：解析 endpoint、忽略消息（响应体在 POST 里），并保活连接。"""
        try:
            event = None
            for raw in response.iter_lines(decode_unicode=True):
                if self._stream_stop.is_set():
                    break
                line = raw or ""
                if line.startswith("event:"):
                    event = line.split(":", 1)[1].strip()
                elif line.startswith("data:") and event == "endpoint" and self._endpoint is None:
                    self._endpoint = line.split(":", 1)[1].strip()
        except Exception:  # noqa: BLE001, S110 - 保活线程静默退出是预期行为
            pass
        finally:
            # 流结束 = session 已失效，下次调用重新建
            self._initialized = False
            with contextlib.suppress(Exception):
                response.close()

    def _ensure_session(self) -> str:
        if self._endpoint and self._initialized:
            return self._endpoint
        if self._session is None:
            self._session = self._new_session()
        self._open_stream(self._session)
        self._rpc_raw(
            "initialize",
            {"protocolVersion": PROTOCOL_VERSION, "capabilities": {}, "clientInfo": CLIENT_INFO},
            notify=False,
        )
        self._rpc_raw("notifications/initialized", {}, notify=True)
        self._initialized = True
        if self._endpoint is None:  # pragma: no cover - _open_stream 成功后必有值
            raise RuntimeError("yakit endpoint not initialized")
        return self._endpoint

    # -- JSON-RPC ---------------------------------------------------------

    def _rpc_raw(self, method: str, params: Mapping[str, Any], *, notify: bool = False) -> dict[str, Any] | None:
        if self._endpoint is None:
            raise YakitMCPError("session 未建立")
        body: dict[str, Any] = {"jsonrpc": "2.0", "method": method, "params": dict(params)}
        if not notify:
            body["id"] = int(time.time() * 1000) % 2_000_000_000
        if self._post_fn is not None:
            payload = self._post_fn(self._endpoint, body)
        else:  # pragma: no cover - 真实网络路径
            if self._session is None or self._endpoint is None:  # pragma: no cover
                raise RuntimeError("yakit session not initialized")
            response = self._session.post(self._endpoint, json=body, timeout=self.timeout)
            if notify:
                # 通知类请求返回 202 + 空 body，**不能**去解析 JSON
                return None
            try:
                payload = response.json()
            except ValueError as exc:
                raise YakitMCPError(f"MCP 返回非 JSON（HTTP {response.status_code}）: {response.text[:200]}") from exc
        if notify:
            return None
        error = payload.get("error")
        if error:
            raise YakitMCPError(f"{error.get('code')}: {error.get('message')}")
        return payload.get("result")

    def _reset_session(self) -> None:
        self._stream_stop.set()
        self._initialized = False
        self._endpoint = None
        if self._session is not None:
            with contextlib.suppress(Exception):
                self._session.close()
        self._session = None
        self.reconnects += 1

    # -- 工具调用 ---------------------------------------------------------

    def call_tool(self, name: str, arguments: Mapping[str, Any] | None = None, *, retry: bool = True) -> ToolResult:
        """调用一个 MCP 工具；session 失效（Invalid session ID）时自动重建一次。"""
        with self._lock:
            self._ensure_session()
            try:
                result = self._rpc_raw("tools/call", {"name": name, "arguments": dict(arguments or {})})
            except YakitMCPError as exc:
                if retry and "session" in str(exc).lower():
                    self._reset_session()
                    self._ensure_session()
                    result = self._rpc_raw("tools/call", {"name": name, "arguments": dict(arguments or {})})
                else:
                    raise
            self.call_count += 1
        return _to_tool_result(result or {})

    def list_tools(self, *, refresh: bool = False) -> list[dict[str, Any]]:
        with self._lock:
            if self._tools_cache is not None and not refresh:
                return self._tools_cache
            self._ensure_session()
            try:
                result = self._rpc_raw("tools/list", {})
            except YakitMCPError as exc:
                if "session" in str(exc).lower():
                    self._reset_session()
                    self._ensure_session()
                    result = self._rpc_raw("tools/list", {})
                else:
                    raise
            tools = list((result or {}).get("tools") or [])
            self._tools_cache = tools
            return tools

    def probe(self) -> bool:
        """握手探测：Yakit MCP 是否可用。不抛错，供 preflight 使用。"""
        try:
            with self._lock:
                self._ensure_session()
            return True
        except Exception:  # noqa: BLE001
            return False

    def close(self) -> None:
        self._reset_session()


def _to_tool_result(result: Mapping[str, Any]) -> ToolResult:
    texts: list[str] = []
    for block in result.get("content") or []:
        if isinstance(block, Mapping) and block.get("type") == "text":
            texts.append(str(block.get("text") or ""))
    data: dict[str, Any] | None = None
    if texts:
        try:
            parsed = json.loads(texts[-1])
            if isinstance(parsed, dict):
                data = parsed
        except (ValueError, TypeError):
            data = None
    return ToolResult(texts=texts, data=data, is_error=bool(result.get("isError")))


def mcp_available(base: str = DEFAULT_MCP_BASE, *, timeout: float = 3.0) -> bool:
    """轻量探测：SSE 端点是否返回 endpoint（fail-closed 判定用）。"""
    import socket  # noqa: PLC0415
    from urllib.parse import urlsplit  # noqa: PLC0415

    parts = urlsplit(base)
    try:
        with socket.create_connection((parts.hostname or "127.0.0.1", parts.port or 11432), timeout=timeout):
            return True
    except OSError:
        return False


__all__ = ["CLIENT_INFO", "DEFAULT_MCP_BASE", "ToolResult", "YakitMCP", "YakitMCPError", "mcp_available"]
