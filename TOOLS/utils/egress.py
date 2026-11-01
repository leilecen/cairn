"""目标侧出口统一治理层（egress）。

所有发往目标站点的请求都从这里走：身份固定、节奏受控、异常熔断，并把每次请求
记入 `egress_log`，作为复核与合规留痕的依据。

硬约束（改动前先读）：
- 唯一出口：目标侧请求必须经 `Egress.request()`。脚本里禁止裸 requests/urlopen 打目标。
- fail-closed：`mode="burp"` 且 Burp 不可达时抛 `EgressUnavailable`，绝不静默直连。
- 身份固定：禁止随机 UA。同一次委托内 UA 与 header 集保持不变。
- 单后端：固定一个传输后端（默认 requests），避免 urllib→curl 静默降级造成
  TLS 指纹漂移与重复发包（重复发包既是痕迹也是额外影响）。
- 不回显敏感值：台账只记 host + path，不记 query/body/cookie。
"""

from __future__ import annotations

import contextlib
import json
import math
import os
import random
import socket
import sys
import time
import uuid
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_BURP = "http://127.0.0.1:8080"
DEFAULT_YAKIT_MCP = "http://127.0.0.1:11432"
DEFAULT_YAKIT_MITM = "http://127.0.0.1:8083"
DEFAULT_IDENTITY_FILE = PROJECT_ROOT / "tmp" / "egress" / "identity.json"
DEFAULT_LEDGER_DIR = PROJECT_ROOT / "tmp" / "egress"

# Burp 默认 UA（Chrome 串）：与「操作员用 Burp」的工作流一致，
# 且 Burp Repeater 发出的请求本来就是这个形态。
BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

# 自报名号 / 工具 UA 标记：出现即视为身份泄漏（守卫测试同样使用这份清单）。
TOOL_UA_MARKERS = (
    "python-requests",
    "python-urllib",
    "urllib",
    "httpx",
    "aiohttp",
    "requests/",
    "curl/",
    "wget/",
    "go-http-client",
    "okhttp",
    "java/",
    "libwww",
    "scrapy",
    "sqlmap",
    "nuclei",
    "nikto",
    "masscan",
    "nmap",
    "-recon",
    "recon-baseline",
    "src-recon",
    "preauth-probe",
    "ai-key",
    "openai",
    "gpt-",
    "claude",
    "langchain",
    "src-hunter",
    "warroom",
)

BROWSER_HEADERS: tuple[tuple[str, str], ...] = (
    ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"),
    ("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8"),
    ("Accept-Encoding", "gzip, deflate, br"),
    ("Upgrade-Insecure-Requests", "1"),
    ("Sec-Fetch-Dest", "document"),
    ("Sec-Fetch-Mode", "navigate"),
    ("Sec-Fetch-Site", "none"),
    ("Sec-Fetch-User", "?1"),
    ("Cache-Control", "max-age=0"),
    ("Connection", "keep-alive"),
)

# Burp Repeater / 工具发出的请求形态：最小 header 集 + 同一 UA。
REPEATER_HEADERS: tuple[tuple[str, str], ...] = (
    ("Accept", "*/*"),
    ("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8"),
    ("Accept-Encoding", "gzip, deflate, br"),
    ("Connection", "keep-alive"),
)


class EgressError(RuntimeError):
    """出口治理层基类异常。"""


class EgressUnavailable(EgressError):
    """出口不可用（Burp 未监听、身份不自洽）。fail-closed，不降级直连。"""


class EgressBlocked(EgressError):
    """熔断打开（rate_limited / waf_detected），停止发包并回写 stop_reason。"""

    def __init__(self, reason: str, *, cooldown_left_s: float = 0.0) -> None:
        super().__init__(f"egress blocked: {reason} (cooldown {cooldown_left_s:.0f}s)")
        self.reason = reason
        self.cooldown_left_s = cooldown_left_s


def header_value_encodable(value: str) -> bool:
    """HTTP header 值必须能按 latin-1 编码（`requests`/`urllib` 都按此约束发送）。"""
    try:
        str(value).encode("latin-1")
        return True
    except UnicodeEncodeError:
        return False


def ascii_header_value(value: str) -> str:
    """把任意文本转成可发送的 header 值。

    HTTP header 只允许 ASCII/latin-1 字节。中文委托方名（`测试委托方`）直接放进
    `X-Pentest-Engagement` 会让**每一个请求**在发送前就抛
    `'latin-1' codec can't encode ...`——静默丢掉整轮测试。这里按 RFC 2047
    编码为 encoded-word，任何标准 header 解析器都能还原原文。
    """
    text = str(value)
    if header_value_encodable(text):
        return text
    import base64  # noqa: PLC0415 - 仅在需要编码时加载

    return "=?utf-8?B?" + base64.b64encode(text.encode("utf-8")).decode("ascii") + "?="


# ── 身份 ──────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Identity:
    """一次委托内固定的请求身份。禁止随机化。"""

    name: str = "burp-chrome-win"
    user_agent: str = BROWSER_UA
    marker: str | None = None
    extra: tuple[tuple[str, str], ...] = ()

    def marker_headers(self) -> list[tuple[str, str]]:
        if not self.marker:
            return []
        return [("X-Pentest-Engagement", ascii_header_value(self.marker))]

    def headers(self, profile: str = "repeater", extra: Mapping[str, str] | None = None) -> dict[str, str]:
        """按 profile 生成完整 header 集（保持插入顺序：先 UA，再语义 header，再标记）。"""
        base = BROWSER_HEADERS if profile == "browser" else REPEATER_HEADERS
        items: list[tuple[str, str]] = [("User-Agent", self.user_agent)]
        items.extend(base)
        items.extend(self.extra)
        items.extend(self.marker_headers())
        if extra:
            items.extend((k, v) for k, v in extra.items())
        merged: dict[str, str] = {}
        for key, value in items:
            merged[key] = value
        return merged

    def consistency_problems(self) -> list[str]:
        """自洽性自检：UA 必须是浏览器串且不含任何工具/自报名号标记；header 值必须可发。"""
        problems: list[str] = []
        if not self.user_agent.startswith("Mozilla/5.0"):
            problems.append("user_agent 不是浏览器串")
        lowered = self.user_agent.lower()
        for token in TOOL_UA_MARKERS:
            if token in lowered:
                problems.append(f"user_agent 含工具/自报名号标记: {token}")
        for key, value in self.extra:
            if key.lower() == "user-agent" and value != self.user_agent:
                problems.append("extra 中存在与身份冲突的 User-Agent")
            if not header_value_encodable(value):
                problems.append(f"header {key} 的值无法用 latin-1 编码（HTTP header 不允许）: {value[:24]!r}")
        return problems

    def to_json(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "user_agent": self.user_agent,
            "marker": self.marker,
            "extra": [list(pair) for pair in self.extra],
        }

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> "Identity":
        extra = tuple((str(k), str(v)) for k, v in (data.get("extra") or []))
        marker = data.get("marker")
        return cls(
            name=str(data.get("name") or "burp-chrome-win"),
            user_agent=str(data.get("user_agent") or BROWSER_UA),
            marker=str(marker) if marker else None,
            extra=extra,
        )


def load_identity(
    name: str | None = None,
    *,
    path: Path | str | None = None,
    env: Mapping[str, str] | None = None,
) -> Identity:
    """读取持久化身份；不存在则以当前配置创建一次并落盘（避免每次运行换 UA）。

    环境变量在**每次调用**都优先生效（`EGRESS_UA` / `EGRESS_ENGAGEMENT_MARKER`）：
    委托方/测试标记是按委托变化的，不能因为身份文件已存在就被永久忽略。
    """
    env = os.environ if env is None else env
    target_path = Path(path or env.get("EGRESS_IDENTITY_FILE") or DEFAULT_IDENTITY_FILE)
    env_ua = env.get("EGRESS_UA") or ""
    env_marker = env.get("EGRESS_ENGAGEMENT_MARKER") or env.get("PENTEST_ENGAGEMENT") or ""
    persisted: Identity | None = None
    if target_path.exists():
        try:
            persisted = Identity.from_json(json.loads(target_path.read_text(encoding="utf-8")))
        except (OSError, ValueError, TypeError):
            persisted = None
    if persisted is not None:
        identity = replace(
            persisted,
            name=name or persisted.name,
            user_agent=env_ua or persisted.user_agent,
            marker=env_marker or persisted.marker,
        )
        if identity != persisted:
            _write_identity(target_path, identity)
        return identity
    identity = Identity(
        name=name or env.get("EGRESS_IDENTITY_NAME") or "burp-chrome-win",
        user_agent=env_ua or BROWSER_UA,
        marker=env_marker or None,
    )
    _write_identity(target_path, identity)
    return identity


def _write_identity(path: Path, identity: Identity) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(identity.to_json(), ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError:
        pass


# ── 节奏 ──────────────────────────────────────────────────────────────────────


@dataclass
class PacingPolicy:
    """每 host 的节奏策略：令牌桶 + 对数正态抖动 + 突发上限 + 周期性长停顿。

    均匀间隔是扫描器最强特征，因此默认抖动为对数正态（人类间隔是长短混合）。
    """

    enabled: bool = True
    max_rps: float = 0.5
    min_gap_ms: int = 900
    sigma: float = 0.55
    burst: int = 3
    burst_window_s: float = 10.0
    think_every: int = 12
    think_ms_min: int = 4000
    think_ms_max: int = 15000
    max_gap_ms: int = 30000

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "PacingPolicy":
        env = os.environ if env is None else env

        def num(key: str, default: float) -> float:
            raw = env.get(key)
            if raw is None or raw == "":
                return default
            try:
                return float(raw)
            except ValueError:
                return default

        return cls(
            enabled=str(env.get("EGRESS_PACING", "1")).lower() not in {"0", "false", "off"},
            max_rps=num("EGRESS_MAX_RPS", 0.5),
            min_gap_ms=int(num("EGRESS_MIN_GAP_MS", 900)),
            sigma=num("EGRESS_JITTER_SIGMA", 0.55),
            burst=int(num("EGRESS_BURST", 3)),
            think_every=int(num("EGRESS_THINK_EVERY", 12)),
            think_ms_min=int(num("EGRESS_THINK_MS_MIN", 4000)),
            think_ms_max=int(num("EGRESS_THINK_MS_MAX", 15000)),
        )

    def sample_gap_ms(self, rng: random.Random, count: int) -> float:
        """抽样下一次发包前的等待毫秒数（含周期性长停顿）。

        均值取 `max(1000/max_rps, min_gap_ms)`，避免 max_rps 与 min_gap_ms 互相矛盾时
        退化成"贴着下限的均匀间隔"（均匀=扫描器特征）。
        """
        mean_gap = max(1000.0 / max(self.max_rps, 1e-6), float(self.min_gap_ms))
        gap = mean_gap * math.exp(rng.gauss(0.0, self.sigma))
        gap = min(max(gap, float(self.min_gap_ms)), float(self.max_gap_ms))
        if self.think_every > 0 and count > 0 and count % self.think_every == 0:
            gap += rng.uniform(float(self.think_ms_min), float(self.think_ms_max))
        return gap


class Pacer:
    """按 host 维护突发预算 + 抖动间隔 + 硬下限。"""

    def __init__(
        self,
        policy: PacingPolicy | None = None,
        *,
        rng: random.Random | None = None,
        clock=time.monotonic,
        sleep=time.sleep,
    ) -> None:
        self.policy = policy or PacingPolicy()
        self.rng = rng or random.Random()  # noqa: S311 - 抖动节拍用非密码学随机源
        self._clock = clock
        self._sleep = sleep
        self._state: dict[str, dict[str, float]] = {}

    def _host(self, host: str) -> dict[str, float]:
        return self._state.setdefault(
            host,
            {"last": 0.0, "count": 0.0, "window_start": 0.0, "window_count": 0.0},
        )

    def plan_gap_ms(self, host: str) -> float:
        """计算并消费间隔预算；返回本次应等待的毫秒数（未真正睡眠）。"""
        state = self._host(host)
        count = int(state["count"])
        state["count"] = count + 1
        if not self.policy.enabled:
            return 0.0
        now = self._clock()
        if state["window_start"] == 0.0 or now - state["window_start"] > self.policy.burst_window_s:
            state["window_start"] = now
            state["window_count"] = 0.0
        if state["window_count"] < self.policy.burst:
            # 突发预算：模拟人类打开页面时连续触发的一组 XHR，允许贴近发送。
            state["window_count"] += 1
            gap = 0.0
        else:
            gap = self.policy.sample_gap_ms(self.rng, count)
            if state["last"]:
                floor_left = float(self.policy.min_gap_ms) - (now - state["last"]) * 1000.0
                gap = max(gap, floor_left)
        state["last"] = now + gap / 1000.0
        return gap

    def wait(self, host: str) -> float:
        gap_ms = self.plan_gap_ms(host)
        if gap_ms > 0:
            self._sleep(gap_ms / 1000.0)
        return gap_ms


# ── 熔断 ──────────────────────────────────────────────────────────────────────


WAF_BODY_KEYWORDS = (
    "waf",
    "blocked",
    "modsecurity",
    "access denied",
    "request rejected",
    "cloudflare ray id",
    "captcha",
    "challenge",
    "too many requests",
    "rate limit",
    "安全拦截",
    "访问被拒绝",
    "请求被拦截",
    "您的访问已被拦截",
    "IP黑名单",
)


def classify_response(status_code: int, body: str = "") -> str:
    """返回 ''（正常）或 stop_reason（rate_limited / waf_detected）。"""
    if status_code == 429:
        return "rate_limited"
    lowered = (body or "")[:4096].lower()
    if status_code in {420, 503} and any(k in lowered for k in WAF_BODY_KEYWORDS):
        return "waf_detected"
    if status_code == 403:
        if any(k in lowered for k in WAF_BODY_KEYWORDS):
            return "waf_detected"
        return ""
    return ""


class CircuitBreaker:
    """连续命中限速/WAF 即全局停止。

    与 `TOOLS/recon/baseline_entries.py` 的 stop_reason 枚举保持一致
    （`rate_limited` / `waf_detected`）。
    """

    def __init__(
        self,
        *,
        threshold: int = 3,
        window_s: float = 120.0,
        cooldown_s: float = 300.0,
        clock=time.monotonic,
    ) -> None:
        self.threshold = threshold
        self.window_s = window_s
        self.cooldown_s = cooldown_s
        self._clock = clock
        self._hits: list[tuple[float, str]] = []
        self._open_reason = ""
        self._open_at = 0.0
        self.stop_reason = ""

    def observe(self, status_code: int, body: str = "") -> str:
        reason = classify_response(status_code, body)
        if not reason:
            return ""
        now = self._clock()
        self._hits.append((now, reason))
        self._hits = [(ts, r) for ts, r in self._hits if now - ts <= self.window_s]
        if len(self._hits) >= self.threshold:
            self._open_reason = reason
            self._open_at = now
            self.stop_reason = reason
        return reason

    def cooldown_left_s(self) -> float:
        if not self._open_reason:
            return 0.0
        return max(0.0, self.cooldown_s - (self._clock() - self._open_at))

    def raise_if_open(self) -> None:
        if self._open_reason:
            raise EgressBlocked(self._open_reason, cooldown_left_s=self.cooldown_left_s())

    def reset(self) -> None:
        self._hits.clear()
        self._open_reason = ""
        self.stop_reason = ""


# ── 台账 ──────────────────────────────────────────────────────────────────────


class Ledger:
    """egress_log 记录器：有目标库走 DB（StoreKit），否则回退 JSONL。"""

    def __init__(
        self,
        *,
        target: str | None = None,
        db_path: Path | str | None = None,
        jsonl_dir: Path | str | None = None,
    ) -> None:
        self.target = target
        self.db_path = Path(db_path) if db_path else None
        self.jsonl_dir = Path(jsonl_dir or DEFAULT_LEDGER_DIR)
        self.records: list[dict[str, Any]] = []
        self.db_error: str = ""
        self.run_id = uuid.uuid4().hex[:12]

    def _jsonl_path(self) -> Path:
        return self.jsonl_dir / f"egress-{time.strftime('%Y%m%d')}.jsonl"

    def record(self, entry: Mapping[str, Any]) -> None:
        row = {
            "target_name": self.target or "",
            "run_id": self.run_id,
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        row.update({k: v for k, v in entry.items() if v is not None})
        self.records.append(row)
        if self.db_path is not None and not self.db_error:
            try:
                self._record_db(row)
                return
            except Exception as exc:  # noqa: BLE001 - 台账失败不得影响发包
                self.db_error = f"{type(exc).__name__}: {exc}"
                print(f"[egress] 台账写库失败，回退 JSONL: {self.db_error}", file=sys.stderr)
        self._record_jsonl(row)

    def _record_db(self, row: Mapping[str, Any]) -> None:
        sys.path.insert(0, str(PROJECT_ROOT / "TOOLS"))
        from lib.store_kit import StoreKit  # noqa: PLC0415

        with StoreKit(db_path=self.db_path) as db:
            db.insert("egress_log", dict(row), log=False)

    def _record_jsonl(self, row: Mapping[str, Any]) -> None:
        try:
            self.jsonl_dir.mkdir(parents=True, exist_ok=True)
            with self._jsonl_path().open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(row, ensure_ascii=False) + "\n")
        except OSError as exc:
            print(f"[egress] 台账落盘失败: {exc}", file=sys.stderr)

    def summary(self) -> dict[str, Any]:
        rows = self.records
        sent = [r for r in rows if r.get("decision") == "sent"]
        stamps = sorted(float(r.get("epoch", 0.0)) for r in sent if r.get("epoch"))
        peak_rps = 0.0
        for index, ts in enumerate(stamps):
            count = 1
            for later in stamps[index + 1 :]:
                if later - ts <= 1.0:
                    count += 1
                else:
                    break
            peak_rps = max(peak_rps, float(count))
        gaps = sorted(float(r.get("planned_gap_ms", 0.0)) for r in sent if r.get("planned_gap_ms"))
        hosts: dict[str, int] = {}
        statuses: dict[str, int] = {}
        for row in sent:
            hosts[str(row.get("host", ""))] = hosts.get(str(row.get("host", "")), 0) + 1
            key = str(row.get("status_code", 0))
            statuses[key] = statuses.get(key, 0) + 1

        def _pick(seq: list[float], ratio: float) -> float:
            if not seq:
                return 0.0
            return seq[min(len(seq) - 1, int(len(seq) * ratio))]

        return {
            "run_id": self.run_id,
            "total": len(rows),
            "sent": len(sent),
            "blocked": sum(1 for r in rows if r.get("decision") == "blocked"),
            "skipped": sum(1 for r in rows if r.get("decision") == "skipped"),
            "errors": sum(1 for r in rows if r.get("decision") == "error"),
            "peak_rps": peak_rps,
            "gap_ms": {
                "min": gaps[0] if gaps else 0.0,
                "median": _pick(gaps, 0.5),
                "p90": _pick(gaps, 0.9),
                "max": gaps[-1] if gaps else 0.0,
            },
            "hosts": hosts,
            "status_codes": statuses,
            "stop_reason": self.stop_reason(),
        }

    def stop_reason(self) -> str:
        """最近一次非空停止原因（熔断判定），供 worker_result / coverage_ledger 复用。"""
        for row in reversed(self.records):
            reason = str(row.get("stop_reason") or "")
            if reason:
                return reason
        return ""


# ── 出口 ──────────────────────────────────────────────────────────────────────


def burp_port_open(burp: str = DEFAULT_BURP, *, timeout: float = 0.6) -> bool:
    return host_port_open(burp, timeout=timeout)


def host_port_open(url: str, *, timeout: float = 0.6) -> bool:
    """TCP 探测 host:port 是否在监听（用于 fail-closed 预检）。"""
    parts = urlsplit(url)
    host = parts.hostname or "127.0.0.1"
    if parts.port:
        port = parts.port
    else:
        port = 443 if parts.scheme == "https" else 80
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def proxy_map(burp: str = DEFAULT_BURP) -> dict[str, str]:
    return {"http": burp, "https": burp}


# ── Yakit MCP 响应适配 ────────────────────────────────────────────────────────


def _normalize_body(data: Any) -> str | None:
    """把 Egress 的 data 参数转成 Yakit `do_http_request` 能收的字符串。"""
    if data is None:
        return None
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    if isinstance(data, str):
        return data
    if isinstance(data, Mapping):
        from urllib.parse import urlencode  # noqa: PLC0415

        return urlencode(data, doseq=True)
    return str(data)


def _with_query(url: str, params: Mapping[str, Any]) -> str:
    from urllib.parse import urlencode  # noqa: PLC0415

    separator = "&" if "?" in url else "?"
    return f"{url}{separator}{urlencode(params, doseq=True)}"


def _fetch_result_type() -> Any:
    from utils.http_fetcher import FetchResult  # noqa: PLC0415

    return FetchResult


def failed_fetch_result(url: str, error: str) -> Any:
    """构造一个 status=0 的失败结果（Egress 会把它记成 decision=error）。"""
    result_type = _fetch_result_type()
    return result_type(
        url=url,
        final_url=url,
        status_code=0,
        headers={},
        content_type="",
        body=b"",
        size_bytes=0,
        elapsed_ms=0,
        backend="yakit-mcp",
        error=error,
    )


def parse_yakit_packet(text: str) -> tuple[dict[str, str], bytes]:
    """从 Yakit 的响应包文本里解析 header 与 body。

    Yakit `do_http_request` 的第一个文本块形如：
        [info] response packet (178 bytes):
        HTTP/1.0 200 OK\\r\\nContent-Type: ...\\r\\n\\r\\n{...}
    """
    marker = "response packet ("
    if marker not in text:
        return {}, b""
    packet = text.split(marker, 1)[1]
    packet = packet.split("\n", 1)[1] if "\n" in packet else ""
    if not packet:
        return {}, b""
    head, _, body = packet.partition("\r\n\r\n")
    if not _:
        head, _, body = packet.partition("\n\n")
    headers: dict[str, str] = {}
    for line in head.replace("\r\n", "\n").split("\n")[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip()] = value.strip()
    # 工具会给文本块补一个换行，去掉一个尾随换行避免 body 虚增 1 字节
    raw = body.encode("utf-8", errors="replace")
    if raw.endswith(b"\n") and len(raw) - 1 == 0:
        raw = b""
    return headers, raw


def yakit_result_to_fetch_result(url: str, summary: Mapping[str, Any] | None, texts: list[str]) -> Any:
    """把 Yakit MCP 的返回（结构化摘要 + 报文文本）适配成 `FetchResult`。"""
    result_type = _fetch_result_type()
    data = dict(summary or {})
    packet_text = texts[0] if texts else ""
    headers, body = parse_yakit_packet(packet_text)
    status = int(data.get("status_code") or 0)
    transport_error = data.get("transport_error") or ""
    error = f"yakit_transport: {transport_error}" if transport_error else None
    body_size = int(data.get("body_size") or len(body))
    return result_type(
        url=url,
        final_url=url,
        status_code=status,
        headers=headers,
        content_type=headers.get("Content-Type", headers.get("content-type", "")),
        body=body,
        size_bytes=body_size,
        elapsed_ms=int(data.get("duration_ms") or 0),
        backend="yakit-mcp",
        error=error,
    )


def target_proxy_map(env: Mapping[str, str] | None = None, *, check: bool = True) -> dict[str, str] | None:
    """目标侧默认出口代理映射。供持有自建传输的适配器复用：

    - `mode="yakit"`（默认）→ Yakit MITM 端口；`check=True` 且端口未监听时抛 `EgressUnavailable`
      （fail-closed：不在 Yakit 里启动 MITM 就不发包）
    - `mode="burp"` → Burp 代理；不可达同样 fail-closed
    - `mode="direct"` → None（调用方自行承担 TLS 指纹不自洽的后果）
    """
    config = EgressConfig.from_env(env)
    url = config.target_proxy_url()
    if url is None:
        return None
    if check and not host_port_open(url):
        raise EgressUnavailable(
            f"{config.mode} 出口未在 {url} 监听；拒绝直连发包（fail-closed）。"
            + ("先在 Yakit 中启动 MITM（或设 EGRESS_YAKIT_MITM 指向实际端口）" if config.mode == "yakit" else "先启动 Burp")
        )
    return proxy_map(url)


def target_proxy_url(env: Mapping[str, str] | None = None, *, check: bool = True) -> str | None:
    """目标侧默认代理 URL（供 httpx/nuclei 等外部 CLI 的 `-proxy` 参数使用）。"""
    mapping = target_proxy_map(env, check=check)
    return mapping["http"] if mapping else None


@dataclass
class EgressConfig:
    """出口配置。`mode` 默认 **yakit**（Yakit MCP 发包）；`burp`/`direct` 为备选。"""

    mode: str = "yakit"
    burp: str = DEFAULT_BURP
    yakit_mcp: str = DEFAULT_YAKIT_MCP
    yakit_mitm: str = DEFAULT_YAKIT_MITM
    upstream: str = ""
    audience: str = "target"
    allow_direct: bool = False
    backend: str = "requests"
    use_env_proxy: bool = False

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "EgressConfig":
        env = os.environ if env is None else env
        return cls(
            mode=str(env.get("EGRESS_MODE", "yakit")).lower(),
            burp=env.get("EGRESS_BURP") or DEFAULT_BURP,
            yakit_mcp=env.get("EGRESS_YAKIT_MCP") or DEFAULT_YAKIT_MCP,
            yakit_mitm=env.get("EGRESS_YAKIT_MITM") or DEFAULT_YAKIT_MITM,
            upstream=env.get("EGRESS_UPSTREAM") or "",
            audience=str(env.get("EGRESS_AUDIENCE", "target")).lower(),
            allow_direct=str(env.get("EGRESS_ALLOW_DIRECT", "0")).lower() in {"1", "true", "on", "yes"},
            backend=str(env.get("EGRESS_BACKEND", "requests")),
            # 环境代理（本机=Clash 127.0.0.1:9870）默认关闭：只有操作员明确要求才走 Clash。
            use_env_proxy=str(env.get("EGRESS_USE_ENV_PROXY", "0")).lower() in {"1", "true", "on", "yes"},
        )

    def target_proxy_url(self) -> str | None:
        """需要走 HTTP 代理的外部 CLI（httpx 等）在目标侧应使用的出口。

        - `yakit`：Yakit MITM（Yakit 的代理端口，需在 Yakit 里启动 MITM）
        - `burp`：Burp 代理
        - `direct`：None
        """
        if self.mode == "yakit":
            return self.yakit_mitm
        if self.mode == "burp":
            return self.burp
        return None


class Egress:
    """目标侧唯一出口。所有脚本发包都走这里。"""

    def __init__(
        self,
        *,
        host: str | None = None,
        target: str | None = None,
        db_path: Path | str | None = None,
        identity: Identity | None = None,
        policy: PacingPolicy | None = None,
        config: EgressConfig | None = None,
        mode: str | None = None,
        burp: str | None = None,
        allow_direct: bool | None = None,
        audience: str | None = None,
        env: Mapping[str, str] | None = None,
        pacer: Pacer | None = None,
        breaker: CircuitBreaker | None = None,
        ledger: Ledger | None = None,
        jsonl_dir: Path | str | None = None,
        fetch_fn: Any = None,
    ) -> None:
        env = os.environ if env is None else env
        base = config or EgressConfig.from_env(env)
        self.config = replace(
            base,
            mode=(mode or base.mode).lower(),
            burp=burp or base.burp,
            audience=(audience or base.audience).lower(),
            allow_direct=base.allow_direct if allow_direct is None else allow_direct,
        )
        self.host = host or ""
        self.target = target or ""
        self.identity = identity or load_identity(env=env)
        self.pacer = pacer or Pacer(policy or PacingPolicy.from_env(env))
        self.breaker = breaker or CircuitBreaker()
        self.ledger = ledger or Ledger(target=target, db_path=db_path, jsonl_dir=jsonl_dir)
        self._fetch_fn = fetch_fn
        self._yakit: Any = None
        self._preflight_cache: tuple[float, dict[str, Any]] | None = None
        self._last_page_url = ""
        self._note_override = ""
        self._preflight()

    # -- 出口校验 ---------------------------------------------------------

    def _resolve_fetch(self) -> Any:
        if self._fetch_fn is not None:
            return self._fetch_fn
        sys.path.insert(0, str(PROJECT_ROOT / "TOOLS"))
        from utils.http_fetcher import fetch  # noqa: PLC0415

        return fetch

    def _preflight(self) -> dict[str, Any]:
        problems = self.identity.consistency_problems()
        if problems:
            raise EgressUnavailable("身份不自洽，拒绝发包: " + "; ".join(problems))
        if self.config.mode == "burp":
            ok = host_port_open(self.config.burp)
            if not ok:
                raise EgressUnavailable(
                    f"Burp 未在 {self.config.burp} 监听；拒绝直连发包（fail-closed）。"
                    "先启动 Burp，或改用默认的 yakit 出口 / 显式 EGRESS_MODE=direct 且 EGRESS_ALLOW_DIRECT=1。"
                )
        elif self.config.mode == "yakit":
            from utils.yakit_mcp import mcp_available  # noqa: PLC0415

            if not mcp_available(self.config.yakit_mcp):
                raise EgressUnavailable(
                    f"Yakit MCP 未在 {self.config.yakit_mcp} 监听；拒绝直连发包（fail-closed）。启动 Yakit 后重试，或设 EGRESS_MODE=burp。"
                )
        elif self.config.mode != "direct":
            raise EgressUnavailable(f"未知 EGRESS_MODE: {self.config.mode}（可选 yakit|burp|direct）")
        if self.config.mode == "direct" and self.config.audience == "target" and not self.config.allow_direct:
            raise EgressUnavailable(
                "mode=direct 直连目标会暴露 Python TLS 指纹（与 UA 不自洽）。"
                "确需直连请设置 EGRESS_ALLOW_DIRECT=1；情报 API 请设置 audience=intel。"
            )
        info = {
            "mode": self.config.mode,
            "burp": self.config.burp if self.config.mode == "burp" else "",
            "yakit_mcp": self.config.yakit_mcp if self.config.mode == "yakit" else "",
            "yakit_mitm": self.config.yakit_mitm,
            "upstream": self.config.upstream,
            "audience": self.config.audience,
            "identity": self.identity.name,
            "use_env_proxy": self.config.use_env_proxy,
            "pacing": {
                "max_rps": self.pacer.policy.max_rps,
                "min_gap_ms": self.pacer.policy.min_gap_ms,
                "sigma": self.pacer.policy.sigma,
                "burst": self.pacer.policy.burst,
            },
        }
        self._preflight_cache = (time.monotonic(), info)
        return info

    def preflight(self) -> dict[str, Any]:
        if self._preflight_cache is None:
            return self._preflight()
        return self._preflight_cache[1]

    # -- 发包 -------------------------------------------------------------

    def _proxies(self) -> dict[str, str] | None:
        if self.config.mode == "burp":
            return proxy_map(self.config.burp)
        return None

    def proxy_kwargs(self) -> dict[str, str] | None:
        """供自建 async 出口或外部 CLI 复用同一出口配置，避免绕过治理层。

        - `burp` → Burp 代理映射；
        - `yakit` → None（发包由 Yakit MCP 完成，不经本地代理）；
        - 给 httpx/nuclei 之类外部 CLI 用时取 `EgressConfig.target_proxy_url()`。
        """
        return self._proxies()

    def yakit_client(self) -> Any:
        """惰性创建 Yakit MCP 客户端（同一次运行内复用 session）。"""
        if self._yakit is None:
            from utils.yakit_mcp import YakitMCP  # noqa: PLC0415

            self._yakit = YakitMCP(self.config.yakit_mcp)
        return self._yakit

    def _send_via_transport(
        self,
        url: str,
        *,
        method: str,
        headers: Mapping[str, str],
        params: Mapping[str, Any] | None,
        data: Any,
        timeout: float,
        max_bytes: int | None,
        allow_redirects: bool,
    ) -> Any:
        """按 mode 选传输：yakit（MCP 发包）或 http_fetcher（Burp / 直连）。"""
        if self.config.mode == "yakit":
            target = _with_query(url, params) if params else url
            return self._send_yakit(
                target,
                method=method,
                headers=headers,
                data=data,
                timeout=timeout,
                allow_redirects=allow_redirects,
            )
        return self._resolve_fetch()(
            url,
            method=method.upper(),
            timeout=timeout,
            verify=False,
            headers=dict(headers),
            max_bytes=max_bytes,
            params=dict(params) if params else None,
            data=data,
            proxies=self._proxies(),
            allow_redirects=allow_redirects,
            backends=(self.config.backend,),
            use_env_proxy=self.config.use_env_proxy,
        )

    def _send_yakit(
        self,
        url: str,
        *,
        method: str,
        headers: Mapping[str, str],
        data: Any,
        timeout: float,
        allow_redirects: bool,
    ) -> Any:
        """经 Yakit MCP `do_http_request` 发包，并把 Yakit 返回适配成 FetchResult。"""
        from utils.yakit_mcp import YakitMCPError  # noqa: PLC0415

        arguments: dict[str, Any] = {
            "url": url,
            "method": method.upper(),
            "headers": dict(headers),
            "timeout": int(max(1, timeout)),
            "redirect-times": 5 if allow_redirects else 0,
        }
        body = _normalize_body(data)
        if body is not None:
            arguments["body"] = body
        if self.config.upstream:
            # 让 Yakit 经上游代理出口（例如 VPS），用于换出口 IP
            arguments["proxy"] = self.config.upstream
        try:
            result = self.yakit_client().call_tool("do_http_request", arguments)
        except YakitMCPError as exc:
            return failed_fetch_result(url, f"yakit_mcp: {exc}")
        if result.is_error:
            return failed_fetch_result(url, f"yakit_tool_error: {result.text()[:200]}")
        return yakit_result_to_fetch_result(url, result.data, result.texts)

    def _host_of(self, url: str) -> str:
        return (urlsplit(url).hostname or self.host or "").lower()

    def _path_of(self, url: str) -> str:
        parts = urlsplit(url)
        return parts.path or "/"

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        data: Any = None,
        params: Mapping[str, Any] | None = None,
        cookies: Mapping[str, str] | None = None,
        referer: str | None = None,
        profile: str = "repeater",
        timeout: float = 10.0,
        max_bytes: int | None = None,
        allow_redirects: bool = True,
        note: str = "",
    ) -> Any:
        """经治理层发出单个请求。返回 http_fetcher.FetchResult。"""
        host = self._host_of(url)
        try:
            self.breaker.raise_if_open()
        except EgressBlocked as blocked:
            self._record(
                host=host,
                url=url,
                method=method,
                status=0,
                elapsed_ms=0,
                planned_gap_ms=0,
                epoch=time.time(),
                decision="blocked",
                stop_reason=blocked.reason,
                note=note,
            )
            raise
        extra = dict(headers or {})
        if cookies:
            extra["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
        if referer:
            extra["Referer"] = referer
        elif self._last_page_url and profile != "browser":
            parts, last = urlsplit(url), urlsplit(self._last_page_url)
            if parts.netloc == last.netloc:
                extra["Referer"] = self._last_page_url
                if method.upper() in {"POST", "PUT", "PATCH", "DELETE"}:
                    extra["Origin"] = f"{parts.scheme}://{parts.netloc}"
        if any(key.lower() == "user-agent" for key in extra):
            raise EgressUnavailable("调用方自带 User-Agent 会破坏身份一致性；请用 identity 统一身份")
        merged = self.identity.headers(profile=profile, extra=extra)
        unencodable = [key for key, value in merged.items() if not header_value_encodable(value)]
        if unencodable:
            raise EgressUnavailable(
                "以下 header 含非 latin-1 字符，发送会直接失败（改为 Identity.marker 或自行编码）: " + ", ".join(sorted(unencodable))
            )

        gap_ms = self.pacer.plan_gap_ms(host)
        if gap_ms > 0:
            time.sleep(gap_ms / 1000.0)

        started_epoch = time.time()
        started = time.perf_counter()
        try:
            result = self._send_via_transport(
                url,
                method=method,
                headers=merged,
                params=params,
                data=data,
                timeout=timeout,
                max_bytes=max_bytes,
                allow_redirects=allow_redirects,
            )
        except Exception as exc:  # noqa: BLE001
            self._record(
                host=host,
                url=url,
                method=method,
                status=0,
                elapsed_ms=int((time.perf_counter() - started) * 1000),
                planned_gap_ms=gap_ms,
                epoch=started_epoch,
                decision="error",
                stop_reason=type(exc).__name__,
                note=note or str(exc)[:120],
            )
            raise
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        status = int(getattr(result, "status_code", 0) or 0)
        body = ""
        if status in {403, 420, 429, 503}:
            try:
                body = result.text[:4096]
            except Exception:  # noqa: BLE001
                body = ""
        stop_reason = self.breaker.observe(status, body) if status > 0 else ""
        # status=0 表示传输层失败（DNS/连接/编码错误）。必须记成 error：曾出现过
        # 「全轮请求 status=0 却记成 sent」的静默失败，台账上看不出来。
        transport_error = str(getattr(result, "error", "") or "")
        decision = "sent" if status > 0 else "error"
        self._record(
            host=host,
            url=url,
            method=method,
            status=status,
            elapsed_ms=elapsed_ms,
            planned_gap_ms=gap_ms,
            epoch=started_epoch,
            decision=decision,
            stop_reason=stop_reason,
            note=note or (transport_error[:200] if decision == "error" else ""),
        )
        if str(getattr(result, "content_type", "")).startswith("text/html"):
            self._last_page_url = url
        return result

    def get(self, url: str, **kwargs: Any) -> Any:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> Any:
        return self.request("POST", url, **kwargs)

    def navigate(self, url: str, **kwargs: Any) -> Any:
        """浏览器式导航：用 browser profile 打页面，为后续 XHR 建立 Referer 链。"""
        kwargs.setdefault("profile", "browser")
        return self.request("GET", url, **kwargs)

    @contextlib.contextmanager
    def unpaced(self, reason: str):
        """临时关闭节奏控制（竞态窗口等）。

        必须在调用点显式写出原因，且 `note_external` / 台账会把该窗口的峰值 RPS 暴露出来，
        便于在强度声明里说明「哪里刻意没有抖动」。
        """
        previous = self.pacer.policy.enabled
        self.pacer.policy.enabled = False
        self._note_override = f"unpaced:{reason}"
        try:
            yield self
        finally:
            self.pacer.policy.enabled = previous
            self._note_override = ""

    def note_external(
        self,
        url: str,
        *,
        method: str = "GET",
        status: int = 0,
        note: str = "external",
        stop_reason: str = "",
        decision: str = "sent",
    ) -> None:
        """为不经 `request()` 发出的目标侧请求补一条台账（如 async 竞态扇出）。

        仍必须使用 `self.identity.headers()` 与 `self.proxy_kwargs()` 取身份和出口，
        否则形态不受治理。
        """
        self._record(
            host=self._host_of(url),
            url=url,
            method=method,
            status=status,
            elapsed_ms=0,
            planned_gap_ms=0,
            epoch=time.time(),
            decision=decision,
            stop_reason=stop_reason or self.breaker.stop_reason,
            note=note,
        )

    # -- 台账 -------------------------------------------------------------

    def _record(
        self,
        *,
        host: str,
        url: str,
        method: str,
        status: int,
        elapsed_ms: int,
        planned_gap_ms: float,
        epoch: float,
        decision: str,
        stop_reason: str = "",
        note: str = "",
    ) -> None:
        self.ledger.record(
            {
                "identity": self.identity.name,
                "mode": self.config.mode,
                "host": host,
                "method": method.upper(),
                "url_path": self._path_of(url)[:300],
                "status_code": status,
                "elapsed_ms": elapsed_ms,
                "planned_gap_ms": int(planned_gap_ms),
                "decision": decision,
                "stop_reason": stop_reason,
                "note": (note or self._note_override)[:200],
                "epoch": round(epoch, 3),
            }
        )

    def summary(self) -> dict[str, Any]:
        data = self.ledger.summary()
        data["preflight"] = self.preflight()
        data["target"] = self.target
        return data

    def close(self) -> None:
        return None


def target_egress(target: str | None = None, **kwargs: Any) -> Egress:
    """便捷构造：从环境变量读配置（EGRESS_MODE / EGRESS_BURP / EGRESS_MAX_RPS ...）。"""
    env = kwargs.pop("env", None) or os.environ
    return Egress(target=target, env=env, **kwargs)


def preflight_report(env: Mapping[str, str] | None = None) -> dict[str, Any]:
    """出口就绪自检：身份自洽性 + 出口可达性 + 节拍配置。不向目标发包。"""
    environment = os.environ if env is None else env
    config = EgressConfig.from_env(environment)
    identity = load_identity(env=environment)
    policy = PacingPolicy.from_env(environment)
    problems = identity.consistency_problems()
    reachable: bool | None = None
    if config.mode == "yakit":
        from utils.yakit_mcp import mcp_available  # noqa: PLC0415

        reachable = mcp_available(config.yakit_mcp)
    elif config.mode == "burp":
        reachable = host_port_open(config.burp)
    mitm_ready = host_port_open(config.yakit_mitm) if config.mode == "yakit" else None
    ready = not problems and (config.mode == "direct" or bool(reachable))
    hints: list[str] = []
    if problems:
        hints.append("身份不自洽：" + "; ".join(problems))
    if not identity.marker:
        hints.append(
            "未配置测试标记：设置 EGRESS_ENGAGEMENT_MARKER=<委托方> 后每个请求会带 "
            "X-Pentest-Engagement（AGENTS.md 规定按委托要求设置，默认不得静默省略）"
        )
    elif not identity.marker.isascii():
        hints.append(
            f"测试标记 `{identity.marker}` 非 ASCII，已按 RFC 2047 编码发送"
            f"（{ascii_header_value(identity.marker)}）——日志里肉眼不可读，"
            "建议直接设 ASCII slug（如 taizhou-college）"
        )
    env_proxy_vars = [key for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy") if environment.get(key)]
    if env_proxy_vars and not config.use_env_proxy:
        hints.append(
            "环境代理已忽略（默认不启用 Clash）：检测到 "
            + ", ".join(sorted(env_proxy_vars))
            + "——出口由 Egress 决定。确需走 Clash 才设 EGRESS_USE_ENV_PROXY=1"
        )
    if config.mode == "yakit" and not reachable:
        hints.append(f"Yakit MCP 未在 {config.yakit_mcp} 监听：启动 Yakit 后重试（引擎默认 11432）；或设 EGRESS_MODE=burp")
    if config.mode == "yakit" and reachable:
        hints.append(
            "Egress 发出的请求会落进 Yakit **当前项目库**：开跑前用 get_current_database_context "
            "确认它就是本轮目标（Yakit 文档要求，避免把其他项目的流量混进来）"
        )
    if config.mode == "yakit" and mitm_ready is False:
        hints.append(
            f"Yakit MITM 未在 {config.yakit_mitm} 监听：Egress 默认路径（MCP 发包）不需要它，"
            "但 httpx 等外部 CLI 的 -proxy 需要；要用就在 Yakit 里启动 MITM"
        )
    if config.mode == "burp" and not reachable:
        hints.append(f"Burp 未在 {config.burp} 监听：启动 Burp 并确认代理监听端口为 8080（本机启动入口见 HANDOFF.md）")
        hints.append("确需绕过：EGRESS_MODE=direct EGRESS_ALLOW_DIRECT=1（会暴露 Python TLS 指纹，仅限情报 API 或操作员明确批准）")
    return {
        "ready": ready,
        "mode": config.mode,
        "audience": config.audience,
        "burp": config.burp,
        "yakit_mcp": config.yakit_mcp,
        "yakit_mitm": config.yakit_mitm,
        "upstream": config.upstream,
        "reachable": reachable,
        "yakit_mitm_ready": mitm_ready,
        "burp_reachable": reachable if config.mode == "burp" else None,
        "use_env_proxy": config.use_env_proxy,
        "identity": identity.to_json(),
        "pacing": {
            "enabled": policy.enabled,
            "max_rps": policy.max_rps,
            "min_gap_ms": policy.min_gap_ms,
            "sigma": policy.sigma,
            "burst": policy.burst,
            "burst_window_s": policy.burst_window_s,
            "think_every": policy.think_every,
        },
        "hints": hints,
    }


def main(argv: list[str] | None = None) -> int:
    """CLI：`python TOOLS/utils/egress.py --preflight`（退出码 0=就绪，1=不就绪）。"""
    import argparse

    parser = argparse.ArgumentParser(description="目标侧出口治理层自检（不向目标发包）")
    parser.add_argument("--preflight", action="store_true", help="打印身份/出口/节拍配置与 Burp 可达性")
    args = parser.parse_args(argv)
    del args
    try:
        sys.path.insert(0, str(PROJECT_ROOT / "TOOLS"))
        from db.db_utils import force_utf8_stdout  # noqa: PLC0415

        force_utf8_stdout()
    except Exception as exc:  # noqa: BLE001 - 仅影响控制台编码，不影响自检结果
        print(f"[egress] 控制台 UTF-8 设置失败（忽略）: {exc}", file=sys.stderr)
    report = preflight_report()
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["ready"] else 1


def intel_egress(name: str = "intel-api", **kwargs: Any) -> Egress:
    """第三方情报 API 出口：目标侧看不到，允许直连。"""
    kwargs.setdefault("audience", "intel")
    kwargs.setdefault("mode", "direct")
    kwargs.setdefault("allow_direct", True)
    return Egress(host=name, **kwargs)


__all__ = [
    "BROWSER_UA",
    "BROWSER_HEADERS",
    "REPEATER_HEADERS",
    "TOOL_UA_MARKERS",
    "DEFAULT_BURP",
    "DEFAULT_YAKIT_MCP",
    "DEFAULT_YAKIT_MITM",
    "CircuitBreaker",
    "Egress",
    "EgressBlocked",
    "EgressConfig",
    "EgressError",
    "EgressUnavailable",
    "Identity",
    "Ledger",
    "Pacer",
    "PacingPolicy",
    "ascii_header_value",
    "burp_port_open",
    "classify_response",
    "failed_fetch_result",
    "host_port_open",
    "intel_egress",
    "load_identity",
    "main",
    "parse_yakit_packet",
    "preflight_report",
    "proxy_map",
    "target_egress",
    "target_proxy_map",
    "target_proxy_url",
    "yakit_result_to_fetch_result",
]

if __name__ == "__main__":
    raise SystemExit(main())
