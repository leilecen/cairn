"""真实 Yakit 端到端（默认跳过；`YAKIT_MCP_LIVE=1` 时运行）。

验证 Egress 默认出口真把请求交给本机 Yakit 引擎发出，且身份/台账/响应适配都对。
只打本机回显服务，不接触任何真实目标。
"""

from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from utils import egress as eg

pytestmark = pytest.mark.skipif(os.environ.get("YAKIT_MCP_LIVE") != "1", reason="需要真实 Yakit（YAKIT_MCP_LIVE=1）")

SEEN: list[dict] = []


class Echo(BaseHTTPRequestHandler):
    def _reply(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        payload = self.rfile.read(length) if length else b""
        SEEN.append({"path": self.path, "headers": dict(self.headers), "body": payload.decode("utf-8", "replace")})
        body = json.dumps({"ok": True, "path": self.path}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _reply
    do_POST = _reply

    def log_message(self, *args):
        return


@pytest.fixture
def echo_server():
    SEEN.clear()
    server = ThreadingHTTPServer(("127.0.0.1", 0), Echo)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


def test_yakit_is_default_egress_and_sends_with_identity(tmp_path, echo_server):
    client = eg.Egress(
        target="live-test",
        identity=eg.Identity(marker="acme-live"),
        jsonl_dir=tmp_path,
        pacer=eg.Pacer(eg.PacingPolicy(enabled=False), sleep=lambda _s: None),
    )
    try:
        assert client.config.mode == "yakit", "默认出口应为 yakit"
        response = client.get(f"{echo_server}/api/items", params={"q": "1"})
        assert response.status_code == 200, response.error
        assert response.backend == "yakit-mcp"
        assert json.loads(response.text)["ok"] is True

        assert SEEN, "本机回显服务没收到请求"
        headers = SEEN[0]["headers"]
        assert headers["User-Agent"].startswith("Mozilla/5.0")
        assert headers["X-Pentest-Engagement"] == "acme-live"
        assert SEEN[0]["path"] == "/api/items?q=1"

        post = client.post(f"{echo_server}/api/save", data="a=1", headers={"Content-Type": "application/x-www-form-urlencoded"})
        assert post.status_code == 200
        assert SEEN[1]["body"] == "a=1"

        rows = client.ledger.records
        assert [row["decision"] for row in rows] == ["sent", "sent"]
        assert {row["mode"] for row in rows} == {"yakit"}
    finally:
        if client._yakit is not None:
            client._yakit.close()
