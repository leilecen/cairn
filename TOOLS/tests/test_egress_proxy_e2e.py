"""端到端验证：目标侧请求确实经配置的代理出口发出，且携带统一身份。

用本地「假 Burp」代理 + 本地目标服务替代真实目标，证明：
1. 请求是 absolute-form 经代理发出的（= 真的过 Burp，而不是直连）；
2. 身份头统一（UA / Accept-Language / X-Pentest-Engagement），调用方塞不进自己的 UA；
3. Burp 端口不可达时 fail-closed（抛 EgressUnavailable，不静默直连）；
4. 台账与节拍真的生效（planned_gap_ms / peak_rps）。
"""

from __future__ import annotations

import json
import socket
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.request import Request, build_opener

import pytest
from utils.egress import Egress, EgressUnavailable, Identity, Pacer, PacingPolicy

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "TOOLS" / "db" / "schema.sql"

SEEN_BY_PROXY: list[dict] = []
SEEN_BY_TARGET: list[dict] = []


class _Target(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        SEEN_BY_TARGET.append({"path": self.path, "headers": dict(self.headers)})
        body = json.dumps({"ok": True}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # 静音
        return


class _Proxy(BaseHTTPRequestHandler):
    """只处理 absolute-form 的假 Burp 代理（HTTPS CONNECT 不在本用例范围）。"""

    def do_GET(self):  # noqa: N802
        if not self.path.startswith("http://"):
            self.send_error(400, "expected absolute-form request")
            return
        SEEN_BY_PROXY.append({"request_line": self.requestline, "path": self.path, "headers": dict(self.headers)})
        forwarded = {key: value for key, value in self.headers.items() if key.lower() not in {"proxy-connection", "connection", "host"}}
        forwarded["Host"] = self.headers.get("Host", "")
        with build_opener().open(
            Request(self.path, headers=forwarded),  # noqa: S310 - 本地假代理转发，路径来自本用例自建服务
            timeout=5,
        ) as resp:
            body = resp.read()
            status = resp.status
            ctype = resp.headers.get("Content-Type", "text/plain")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # 静音
        return


def _serve(handler) -> tuple[ThreadingHTTPServer, int]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


@pytest.fixture
def chain(tmp_path):
    SEEN_BY_PROXY.clear()
    SEEN_BY_TARGET.clear()
    target, target_port = _serve(_Target)
    proxy, proxy_port = _serve(_Proxy)
    yield {"target_port": target_port, "proxy_port": proxy_port, "tmp": tmp_path}
    target.shutdown()
    proxy.shutdown()


def _egress(chain, *, burp_port=None, policy=None) -> Egress:
    db_path = chain["tmp"] / "t.db"
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA.read_text(encoding="utf-8"))
    conn.commit()
    conn.close()
    return Egress(
        target="smoke",
        identity=Identity(marker="acme"),
        mode="burp",
        burp=f"http://127.0.0.1:{burp_port or chain['proxy_port']}",
        db_path=db_path,
        pacer=Pacer(policy or PacingPolicy(enabled=False), sleep=lambda _s: None),
        jsonl_dir=chain["tmp"],
    )


def test_traffic_really_goes_through_proxy_with_unified_identity(chain):
    client = _egress(chain)
    url = f"http://127.0.0.1:{chain['target_port']}/api/items?id=1"
    result = client.get(url)
    assert result.status_code == 200

    assert SEEN_BY_PROXY, "请求没有经过代理出口（说明是直连）"
    proxied = SEEN_BY_PROXY[0]
    assert proxied["request_line"].startswith("GET http://127.0.0.1:"), "必须是 absolute-form 代理请求"

    headers = SEEN_BY_TARGET[0]["headers"]
    assert headers["User-Agent"].startswith("Mozilla/5.0")
    assert headers["Accept-Language"] == "zh-CN,zh;q=0.9,en;q=0.8"
    assert headers["X-Pentest-Engagement"] == "acme"
    assert "python" not in headers["User-Agent"].lower()

    row = client.ledger.records[0]
    assert row["decision"] == "sent" and row["status_code"] == 200
    assert row["url_path"] == "/api/items"
    assert "acme" not in json.dumps(row)  # 台账不记 header/凭据


def test_fail_closed_when_burp_port_closed(chain):
    closed = _free_port()
    with pytest.raises(EgressUnavailable):
        _egress(chain, burp_port=closed)


def test_pacing_really_delays_between_requests(chain):
    policy = PacingPolicy(enabled=True, max_rps=10, min_gap_ms=150, burst=1, sigma=0.6, think_every=0)
    client = _egress(chain, policy=policy)
    url = f"http://127.0.0.1:{chain['target_port']}/api/items"
    started = time.perf_counter()
    for _ in range(4):
        client.get(url)
    elapsed = time.perf_counter() - started
    assert elapsed >= 0.3, f"节拍没有生效：4 个请求只用了 {elapsed:.3f}s"
    gaps = [r["planned_gap_ms"] for r in client.ledger.records]
    assert sum(1 for g in gaps if g > 0) >= 3


def test_summary_exposes_shape_for_compliance(chain):
    client = _egress(chain)
    client.get(f"http://127.0.0.1:{chain['target_port']}/a")
    client.navigate(f"http://127.0.0.1:{chain['target_port']}/b")
    summary = client.summary()
    assert summary["sent"] == 2
    assert summary["preflight"]["mode"] == "burp"
    assert summary["preflight"]["burp"].endswith(str(chain["proxy_port"]))
    assert summary["hosts"] == {"127.0.0.1": 2}


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
