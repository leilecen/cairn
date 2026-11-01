"""把落盘的原始报文证据渲染成可直接复制执行的复现块。

为什么需要
----------
证据层（`tmp/<target>/rN/*.txt`）保存的是原始报文：

    === REQUEST ===
    GET https://host/path?a=1
    X-Access-Token: <redacted>

    === RESPONSE ===
    status: 200 size: 421
    {"success":true,...}

但报告写作时把它**转述成了散文**（「请求 xxx 接口，返回 total」），于是读者拿不到
任何可执行的东西。本模块负责把同一个证据源直接渲染成 curl + 原始 HTTP + 响应片段，
使报告与证据同源、不靠人工转述。

脱敏策略（重要，别重犯）
------------------------
`reports/` 在 `.gitignore` 里，交付报告**本来就不入库**。所以对报告里的内网 IP 做
掩码是零隐私收益、纯损失可复现性的操作。因此：

- `redact=False`（默认，用于 `reports/` 下的交付报告）：保留真实值，只把凭据类
  占位符（token/cookie/password）替换成可操作提示。
- `redact=True`：用于确实要外发/入库的场合，IP 掩码但**必须**配合 `mask_map` 给出映射，
  且禁止在复现指令里要求检索掩码值。

用法
----
    from lib.evidence_render import parse_evidence_file, render_repro_markdown

    rec = parse_evidence_file("tmp/demo/r16/sample-user.txt")
    md = render_repro_markdown(rec, note="客户提供的测试账号会话")
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

# 凭据类 header / 字段：值必须脱敏，但键名要保留（读者要知道带什么）
_CREDENTIAL_HEADERS = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-access-token",
    "x-auth-token",
    "x-token",
    "token",
    "x-api-key",
    "api-key",
    "x-csrf-token",
}

# 证据文件里的三段标记
_REQ_MARK = "=== REQUEST ==="
_RESP_MARK = "=== RESPONSE ==="

_STATUS_RE = re.compile(r"^status:\s*(\d{3})(?:\s+size:\s*(\d+))?", re.IGNORECASE)

# RFC 7230 token 形态的 header 行：`Name: value`，名字只允许字母数字与连字符
_HEADER_LINE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9\-]{0,63}\s*:")
_REQ_LINE_RE = re.compile(r"^(?P<method>[A-Z]+)\s+(?P<url>\S+)$")


@dataclass
class EvidenceRecord:
    """一条原始报文证据。"""

    method: str = ""
    url: str = ""
    req_headers: dict[str, str] = field(default_factory=dict)
    req_body: str = ""
    status: int = 0
    resp_size: int | None = None
    resp_headers: dict[str, str] = field(default_factory=dict)
    resp_body: str = ""
    source: str = ""

    @property
    def path(self) -> str:
        """URL 的 path+query 部分。"""
        match = re.match(r"^[a-z]+://[^/]+(?P<rest>/.*)?$", self.url, re.IGNORECASE)
        return (match.group("rest") or "/") if match else self.url

    @property
    def host(self) -> str:
        match = re.match(r"^[a-z]+://(?P<host>[^/]+)", self.url, re.IGNORECASE)
        return match.group("host") if match else ""


def parse_evidence_text(text: str, *, source: str = "") -> EvidenceRecord | None:
    """解析 `=== REQUEST ===` / `=== RESPONSE ===` 格式。解析不出返回 None。"""
    if _REQ_MARK not in text:
        return None

    req_part, _, rest = text.partition(_REQ_MARK)
    req_part, _, resp_part = rest.partition(_RESP_MARK)

    rec = EvidenceRecord(source=source)

    # ---- 请求 ----
    lines = req_part.splitlines()
    # 跳过空行直到请求行
    index = 0
    while index < len(lines) and not lines[index].strip():
        index += 1
    if index >= len(lines):
        return None
    match = _REQ_LINE_RE.match(lines[index].strip())
    if not match:
        return None
    rec.method = match.group("method")
    rec.url = match.group("url")
    index += 1

    headers, body = _split_headers_body(lines[index:])
    rec.req_headers = headers
    rec.req_body = body

    # ---- 响应 ----
    resp_lines = resp_part.splitlines()
    index = 0
    while index < len(resp_lines) and not resp_lines[index].strip():
        index += 1
    if index < len(resp_lines):
        status_match = _STATUS_RE.match(resp_lines[index].strip())
        if status_match:
            rec.status = int(status_match.group(1))
            if status_match.group(2):
                rec.resp_size = int(status_match.group(2))
            index += 1
    rec.resp_headers, rec.resp_body = _split_headers_body(resp_lines[index:])
    return rec


def parse_evidence_file(path: Path | str) -> EvidenceRecord | None:
    p = Path(path)
    try:
        return parse_evidence_text(p.read_text(encoding="utf-8", errors="replace"), source=str(p))
    except OSError:
        return None


def _split_headers_body(lines: list[str]) -> tuple[dict[str, str], str]:
    """在 header 段与 body 段之间切分。

    坑：响应体的第一行常常就是 JSON（`{"success":true,...`），里面含冒号。
    早期实现「见到冒号就当 header」，会把整个 JSON 解析成一条名为 `{"success"`
    的 header，导致**响应体整段丢失**（实测踩过）。
    因此 header 名必须匹配 RFC 7230 的 token 形态才认。
    """
    headers: dict[str, str] = {}
    index = 0
    while index < len(lines):
        line = lines[index].rstrip()
        if not line.strip():
            index += 1
            break
        if not _HEADER_LINE_RE.match(line):
            break
        name, _, value = line.partition(":")
        headers[name.strip()] = value.strip()
        index += 1
    body = "\n".join(lines[index:]).strip()
    return headers, body


def _is_credential(name: str) -> bool:
    return name.strip().lower() in _CREDENTIAL_HEADERS


def mask_ip(ip: str) -> str:
    """把 IPv4 掩成 `10.x.x.83`（保留末位，便于在内部版对照）。"""
    parts = ip.split(".")
    if len(parts) != 4:
        return ip
    return f"{parts[0]}.x.x.{parts[3]}"


def _render_headers(headers: dict[str, str], *, redact: bool, indent: str = "") -> list[str]:
    out: list[str] = []
    for name, value in headers.items():
        if _is_credential(name):
            out.append(f"{indent}{name}: <REDACTED-填入你的会话凭据>")
        else:
            out.append(f"{indent}{name}: {value}")
    return out


def render_repro_markdown(
    rec: EvidenceRecord,
    *,
    note: str = "",
    redact: bool = False,
    resp_body_max: int = 1200,
) -> str:
    """渲染成 Markdown：curl + 原始请求 + 响应片段。

    `redact=True` 时掩码 IP，调用方**必须**同时给出映射（见模块 docstring）。
    """
    url = rec.url
    host = rec.host
    if redact:
        url = re.sub(
            r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b",
            lambda m: mask_ip(m.group(0)),
            url,
        )
        # Host 头必须一起掩——否则 URL 掩了、Host 没掩，脱敏自相矛盾（实测漏过）
        host = re.sub(
            r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b",
            lambda m: mask_ip(m.group(0)),
            host,
        )

    # ---- curl ----
    curl_lines = [f"curl -sS -i '{url}'"]
    if rec.method and rec.method.upper() != "GET":
        curl_lines.append(f"  -X {rec.method.upper()}")
    for name, value in rec.req_headers.items():
        if _is_credential(name):
            curl_lines.append(f"  -H '{name}: <REDACTED-填入你的会话凭据>'")
        else:
            curl_lines.append(f"  -H '{name}: {value}'")
    if rec.req_body:
        body_one_line = rec.req_body.replace("\n", " ")
        curl_lines.append(f"  --data-raw '{body_one_line}'")

    # ---- 原始请求 ----
    raw_req = [f"{rec.method} {rec.path} HTTP/1.1", f"Host: {host}"]
    raw_req.extend(_render_headers(rec.req_headers, redact=redact))
    if rec.req_body:
        raw_req.append("")
        raw_req.append(rec.req_body)

    # ---- 响应 ----
    resp_body = rec.resp_body
    truncated = False
    if len(resp_body) > resp_body_max:
        resp_body = resp_body[:resp_body_max]
        truncated = True
    raw_resp = [f"HTTP/1.1 {rec.status}"]
    keep_headers = {k: v for k, v in rec.resp_headers.items() if k.lower() in {"content-type", "content-length", "location", "server"}}
    raw_resp.extend(_render_headers(keep_headers, redact=False))
    if resp_body:
        raw_resp.append("")
        raw_resp.append(resp_body + ("\n...（已截断，完整正文见证据文件）" if truncated else ""))

    parts: list[str] = []
    if note:
        parts.append(note)
        parts.append("")
    curl_block = " \\\n  ".join(curl_lines)
    parts.extend(
        [
            "```bash",
            curl_block,
            "```",
            "",
            "请求原文：",
            "",
            "```http",
            "\n".join(raw_req),
            "```",
            "",
            "实测响应：",
            "",
            "```http",
            "\n".join(raw_resp),
            "```",
        ]
    )
    return "\n".join(parts)
