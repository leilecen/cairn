# -*- coding: utf-8 -*-
"""认证面发现（auth surface discovery）。

把 app-a.example.com:9999 那次"漏掉 lazy chunk 里的默认口令"的教训固化成流程：

    HTML → 入口 JS → **受控 chunk 展开**（只取认证相关命名） → 规则扫描 → 候选

四个必须存在的检查（对应四类漏检）：

1. ``default_credential``      —— 表单默认值/赋值里的弱口令（一次实测里的 admin/123456）
2. ``sso_ui_gate_only``        —— SSO 只挡 UI（openSso + casBaseUrl + location.href）
3. ``local_login_endpoint``    —— 本地登录接口仍在（配合 2 即认证旁路候选）
4. ``runtime_config_dead_code``—— HTML 引用了 *.config.js 但产物内联了 env（配置改了不生效）

边界（硬约束）：

- 只消费**已观测**页面里明文引用的资源（HTML 的 script/link、入口 JS 明文 import/preload），
  不做路径爆破、不枚举未引用 chunk。
- chunk 展开**有预算**（``--max-chunks``）且**有命名白名单**，默认只取认证相关命名。
- 所有目标侧请求经 ``TOOLS/utils/egress.py``；``--offline-dir`` 模式零发包（回归测试用）。
- 默认只产出 candidate 与建议动作；``--store`` 才写库，且写的是 suspicious_points/endpoint_observations。

用法：

    python TOOLS/recon/auth_surface.py --target "江南布衣" --url https://app-a.example.com:9999/
    python TOOLS/recon/auth_surface.py --url https://app-a.example.com:9999/ --offline-dir tmp/<case>/evidence
    python TOOLS/recon/auth_surface.py --target X --url https://x/ --store --json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urljoin, urlsplit

_TOOLS_DIR = Path(__file__).resolve().parent.parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

# ── 规则数据 ────────────────────────────────────────────────────────────────

WEAK_ACCOUNTS = (
    "admin",
    "administrator",
    "root",
    "test",
    "guest",
    "sa",
    "system",
    "demo",
    "operator",
    "user",
)
WEAK_PASSWORDS = (
    "123456",
    "1234567",
    "12345678",
    "123456789",
    "1234567890",
    "admin",
    "admin123",
    "admin888",
    "admin@123",
    "Admin@123",
    "password",
    "passw0rd",
    "P@ssw0rd",
    "root",
    "qwerty",
    "abc123",
    "111111",
    "000000",
    "888888",
    "666666",
    "123123",
    "1qaz2wsx",
    "iloveyou",
    "test",
    "test123",
    "letmein",
    "changeme",
)

_ACCOUNT_KEY = r"(?:account|userName|username|loginName|loginname|user|login|userId)"
_PASSWORD_KEY = r"(?:password|passwd|pwd|pass|userPwd|userPassword)"  # noqa: S105 -- 字段名正则片段，非硬编码口令
_QUOTED = r"[\"'`]"
# 键名可能带引号也可能不带（`{account:"admin"}` 与 `"account":"admin"` 都要命中），
# 且左侧必须是非标识符字符，避免命中 `myaccount:` 这类子串。
_KEY_PREFIX = r"(?:^|[^A-Za-z0-9_$])[\"'`]?"

# 认证相关 chunk 命名白名单（命中才允许消耗展开预算）
AUTH_CHUNK_TOKENS = (
    "login",
    "signin",
    "sign-in",
    "auth",
    "user",
    "admin",
    "account",
    "password",
    "pwd",
    "sso",
    "cas",
    "oauth",
    "token",
    "register",
    "forgot",
    "reset",
    "captcha",
    "mobile",
    "qrcode",
    "third",
)

_HTML_ASSET_RE = re.compile(
    r"""<(?:script|link)\b[^>]*?\b(?:src|href)\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE,
)
_VITE_PRELOAD_RE = re.compile(r"""__vitePreload\(\s*\(\)\s*=>\s*import\(\s*["']([^"']+)["']\s*\)(?:\s*,\s*\[([^\]]*)\])?""")
_IMPORT_RE = re.compile(r"""\bimport\(\s*["']([^"']+)["']\s*\)""")
_STATIC_JS_RE = re.compile(r"""["']((?:\.{0,2}/)?(?:assets|static|js|_assets)/[A-Za-z0-9_\-./]+\.js)["']""")
# webpack：__webpack_require__.e("chunkId") 以及 .e("chunkId").then(__webpack_require__.bind(null,"./src/...vue"))
_WEBPACK_E_RE = re.compile(r"""__webpack_require__\.e\(\s*(?:/\*.*?\*/\s*)?["']([^"']{2,180})["']""")
_WEBPACK_E_TARGET_RE = re.compile(
    r"""__webpack_require__\.e\(\s*(?:/\*.*?\*/\s*)?["']([^"']{2,180})["']\s*\)\s*\.then\(\s*"""
    r"""__webpack_require__\.bind\(\s*null\s*,\s*(?:/\*.*?\*/\s*)?["']([^"']{2,200})["']"""
)
# chunkId → 文件名映射（本项目为自映射："user~._src_a":"user~._src_a"）
_WEBPACK_CHUNK_MAP_RE = re.compile(r"""["']([A-Za-z0-9_~.\-@]{3,180})["']\s*:\s*["']([A-Za-z0-9_~.\-@/]{3,180}\.js?)["']""")
_API_URL_RE = re.compile(r"""url\s*:\s*["'`]([^"'`]{2,120})["'`]""")
_PATH_LIKE_RE = re.compile(r"""["'`](/(?:api|sys|auth|user|admin|gateway|oauth|cas|login)[A-Za-z0-9_\-./{}$:]{0,80})["'`]""")

#: Yakit/egress 文本通道的截断标记。大 body（如 3.58MB 的 SPA bundle）会在这里被切断，
#: 而 chunk 引用往往在几百 KB 之后 —— 不识别它就会"静默返回 0 个 chunk"。
TRUNCATION_MARKERS = ("truncated; set save-packet", "... (truncated", "(truncated to 10KB)")
#: 超过这个体积就不再展开（避免把预算烧在巨型产物上）
DEFAULT_MAX_ASSET_BYTES = 12 * 1024 * 1024


@dataclass
class Finding:
    rule: str
    severity: str
    summary: str
    source_asset: str
    evidence: str
    next_action: str
    sp_kind: str = "weak_credential"


@dataclass
class ChunkRef:
    """一个被明文引用的 lazy chunk：URL + 语义提示（如 webpack 的模块路径）。"""

    url: str
    hint: str = ""


@dataclass
class ScanResult:
    url: str
    fetched: list[dict] = field(default_factory=list)
    chunks_selected: list[str] = field(default_factory=list)
    chunks_available: int = 0
    fingerprints: list[dict] = field(default_factory=list)
    default_credentials: list[dict] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    #: 取数不完整/被截断等"看得见"的覆盖告警——绝不允许静默为空
    coverage_warnings: list[str] = field(default_factory=list)

    def to_json(self) -> dict:
        data = asdict(self)
        return data


# ── 纯函数：资源发现 ────────────────────────────────────────────────────────


def extract_assets(html: str, base_url: str) -> list[str]:
    """从 HTML 抽取明文引用的 script/link 资源（绝对化、去重保序）。"""
    out: list[str] = []
    for raw in _HTML_ASSET_RE.findall(html or ""):
        href = raw.strip()
        if not href or href.startswith(("data:", "javascript:", "#")):
            continue
        full = urljoin(base_url, href)
        if full not in out:
            out.append(full)
    return out


def same_origin(url: str, base_url: str) -> bool:
    """是否与起始 URL 同源。跨域（CDN/图床）资源默认不取——它们是第三方资产，越界。"""
    a, b = urlsplit(url), urlsplit(base_url)
    return (a.scheme, a.hostname, a.port) == (b.scheme, b.hostname, b.port)


def _resolve(base_url: str, ref: str) -> str:
    """把 chunk 引用解析成绝对 URL。

    注意 vite 的两种写法基准不同：``import("./X.js")`` 相对于**当前文件目录**，
    而 ``__vitePreload(..., ["assets/Y.js"])`` 里的数组元素相对于**站点根**。
    混用会得到 ``/assets/assets/Y.js`` 这种双前缀脏 URL（曾真实发生）。
    """
    ref = ref.strip().strip("\"'")
    if not ref:
        return ""
    if ref.startswith(("http://", "https://")):
        return ref
    parts = urlsplit(base_url)
    origin = f"{parts.scheme}://{parts.netloc}"
    if ref.startswith(("./", "../")):
        base_dir = parts.path.rsplit("/", 1)[0].rstrip("/") + "/"
        return urljoin(f"{origin}{base_dir}", ref)
    return urljoin(origin + "/", ref)


def extract_chunk_candidates(js: str, base_url: str) -> list[str]:
    """向后兼容入口：只返回 URL 列表。"""
    return [ref.url for ref in extract_chunk_refs(js, base_url)]


def extract_chunk_refs(js: str, base_url: str) -> list[ChunkRef]:
    """从入口 JS 抽取**明文引用**的 chunk（vite + webpack 两种产物都要认）。

    - vite：``__vitePreload(()=>import("./X.js"), ["assets/Y.js"])``
    - webpack：``__webpack_require__.e("user~._src_a").then(__webpack_require__.bind(null,"./src/views/user/Login.vue"))``
      + 自映射表 ``"user~._src_a":"user~._src_a"`` → 文件 ``/user~._src_a.js``

    webpack 的 chunk 名常常**不含语义**（`user~._src_a`），真正的线索在旁边那句模块路径里，
    所以要把两件事一起带出来（``hint``），否则登录页 chunk 会因为"名字不像 login"被排序丢掉。
    """
    js = js or ""
    refs: list[ChunkRef] = []
    seen: set[str] = set()

    def _add(url: str, hint: str = "") -> None:
        if url and url not in seen:
            seen.add(url)
            refs.append(ChunkRef(url=url, hint=hint))

    for imp, arr in _VITE_PRELOAD_RE.findall(js):
        _add(_resolve(base_url, imp))
        for item in re.findall(r"""["']([^"']+\.js)["']""", arr or ""):
            _add(_resolve(base_url, item))
    for ref in _IMPORT_RE.findall(js):
        _add(_resolve(base_url, ref))
    for ref in _STATIC_JS_RE.findall(js):
        _add(_resolve(base_url, ref))

    # webpack：chunk 名 → 文件名（自映射或 xxx.js）+ 模块路径提示
    chunk_map = {k: v for k, v in _WEBPACK_CHUNK_MAP_RE.findall(js)}
    origin = f"{urlsplit(base_url).scheme}://{urlsplit(base_url).netloc}/"
    path_hints: dict[str, str] = {}
    for cid, module_path in _WEBPACK_E_TARGET_RE.findall(js):
        path_hints.setdefault(cid, module_path)
    for cid in set(_WEBPACK_E_RE.findall(js)) | set(chunk_map):
        filename = chunk_map.get(cid, cid)
        if not filename.endswith(".js"):
            filename += ".js"
        _add(urljoin(origin, filename), path_hints.get(cid, ""))
    return refs


def _name_and_hint(url: str, hint: str = "") -> str:
    """参与匹配的文本 = URL 文件名 + 语义提示（webpack 模块路径）。"""
    name = urlsplit(url).path.rsplit("/", 1)[-1].lower()
    return f"{name} {hint.lower()}" if hint else name


def is_auth_interesting(url: str, hint: str = "") -> bool:
    """chunk 名（或它的模块路径提示）是否落在认证白名单（决定是否消耗展开预算）。"""
    blob = _name_and_hint(url, hint)
    return any(token in blob for token in AUTH_CHUNK_TOKENS)


#: 认证相关命名权重：登录表单本体 > 认证组件 > 泛化 user/admin 业务块。
#: 预算有限时必须先拿到"登录表单"所在 chunk，否则等于白展开。
_CHUNK_WEIGHTS: tuple[tuple[str, int], ...] = (
    ("loginform", 10),
    ("views/user/login", 10),
    ("login", 8),
    ("signin", 8),
    ("sign-in", 8),
    ("forget", 6),
    ("reset", 6),
    ("register", 5),
    ("qrcode", 5),
    ("captcha", 5),
    ("sso", 6),
    ("cas", 6),
    ("oauth", 6),
    ("third", 4),
    ("password", 6),
    ("pwd", 6),
    ("mobile", 3),
    ("token", 3),
    ("auth", 2),
    ("account", 2),
    ("admin", 1),
    ("user", 1),
)


def chunk_priority(url: str, hint: str = "") -> int:
    """按命名/模块路径给 chunk 打分（越大越优先展开）。"""
    blob = _name_and_hint(url, hint)
    return sum(weight for token, weight in _CHUNK_WEIGHTS if token in blob)


def select_chunks(
    candidates: Sequence[str | ChunkRef],
    *,
    max_chunks: int,
    allow_all: bool = False,
    hints: Mapping[str, str] | None = None,
) -> tuple[list[str], int]:
    """按"认证命名权重"排序后截断到预算；返回 (选中, 可用总数)。"""
    hint_map = dict(hints or {})
    unique: list[str] = []
    for item in candidates:
        url = item.url if isinstance(item, ChunkRef) else item
        if isinstance(item, ChunkRef) and item.hint:
            hint_map.setdefault(item.url, item.hint)
        if url and url not in unique:
            unique.append(url)
    interesting = [u for u in unique if is_auth_interesting(u, hint_map.get(u, ""))]
    interesting.sort(key=lambda u: -chunk_priority(u, hint_map.get(u, "")))  # 稳定排序：同分保持发现顺序
    ordered = interesting + ([u for u in unique if u not in interesting] if allow_all else [])
    return ordered[:max_chunks], len(unique)


def extract_endpoints(texts: Mapping[str, str], *, limit: int = 80) -> list[str]:
    """抽取 API 路径/登录端点线索（只做清单，不做探测）。"""
    out: list[str] = []
    for text in texts.values():
        for m in _API_URL_RE.findall(text or ""):
            if m.startswith("/") and m not in out:
                out.append(m)
        for m in _PATH_LIKE_RE.findall(text or ""):
            if m not in out:
                out.append(m)
    return out[:limit]


# ── 纯函数：规则扫描 ────────────────────────────────────────────────────────


def _snippet(text: str, index: int, width: int = 160) -> str:
    start = max(0, index - width // 2)
    return re.sub(r"\s+", " ", text[start : start + width])


def scan_default_credentials(texts: Mapping[str, str]) -> list[Finding]:
    """弱/默认口令：要求"凭据语义"（键名 + 弱值），避免命中 base64 字符表之类的噪音。"""
    findings: list[Finding] = []
    pair_re = re.compile(
        _KEY_PREFIX + _ACCOUNT_KEY + r"[\"'`]?\s*[:=]\s*" + _QUOTED + r"(" + "|".join(WEAK_ACCOUNTS) + r")" + _QUOTED,
        re.IGNORECASE,
    )
    pwd_re = re.compile(
        _KEY_PREFIX + _PASSWORD_KEY + r"[\"'`]?\s*[:=]\s*" + _QUOTED + r"(" + "|".join(map(re.escape, WEAK_PASSWORDS)) + r")" + _QUOTED,
        re.IGNORECASE,
    )
    for name, text in texts.items():
        if not text:
            continue
        account_hits = [(m, m.group(1)) for m in pair_re.finditer(text)]
        pwd_hits = [(m, m.group(1)) for m in pwd_re.finditer(text)]
        used: set[int] = set()
        for am, account in account_hits:
            near = [pm for pm, _ in pwd_hits if abs(pm.start() - am.start()) <= 400]
            if not near:
                continue
            pm = min(near, key=lambda x: abs(x.start() - am.start()))
            if pm.start() in used:
                continue
            used.add(pm.start())
            password = pm.group(1)
            findings.append(
                Finding(
                    rule="default_credential",
                    severity="high",
                    summary=f"登录表单/赋值里出现默认凭据 {account}/{password}（键名与弱值成对出现）",
                    source_asset=name,
                    evidence=_snippet(text, am.start()),
                    next_action=(
                        "定位对应登录接口（本文件里的 url: 常量），取验证码后定点验证；"
                        "验证类动作按弱口令边界执行（可疑默认口令只试少数几个）"
                    ),
                )
            )
        if not account_hits and pwd_hits:
            for pm, password in pwd_hits[:3]:
                findings.append(
                    Finding(
                        rule="default_credential",
                        severity="medium",
                        summary=f"出现弱口令字面量 password={password}（未见配套账号默认值）",
                        source_asset=name,
                        evidence=_snippet(text, pm.start()),
                        next_action="确认该赋值是否用于登录初始化；若是，则按账号来源再定点验证",
                    )
                )
    return findings


def scan_sso_gate(texts: Mapping[str, str]) -> list[Finding]:
    """SSO 只挡 UI：openSso + casBaseUrl + location.href 三者同现。"""
    findings: list[Finding] = []
    for name, text in texts.items():
        low = (text or "").lower()
        if not low:
            continue
        if ("opensso" in low) and ("casbaseurl" in low or "/cas/login" in low) and "location.href" in low:
            idx = low.find("opensso")
            findings.append(
                Finding(
                    rule="sso_ui_gate_only",
                    severity="high",
                    summary="前端在挂载前用 location.href 强制跳 CAS（openSso=true）→ UI 被 SSO 遮蔽",
                    source_asset=name,
                    evidence=_snippet(text, idx),
                    next_action=("立刻核对后端本地登录接口是否仍开放（配合 local_login_endpoint 结果）；UI 强制跳转≠后端关闭本地认证"),
                    sp_kind="auth_bypass",
                )
            )
    return findings


def scan_local_login(texts: Mapping[str, str]) -> list[Finding]:
    """本地登录/注册/短信接口线索：与 sso_ui_gate_only 同现即认证旁路候选。"""
    patterns = {
        "sys/login": "JEECG 本地账号口令登录接口",
        "randomimage": "图形验证码接口（说明存在本地登录流程）",
        "authentication.login": "GraphQL 本地登录 mutation",
        "phonelogin": "手机号登录接口",
        "user/register": "自助注册接口",
        "getloginqrcode": "扫码登录接口",
    }
    hits: dict[str, str] = {}
    sources: set[str] = set()
    for name, text in texts.items():
        low = (text or "").lower()
        for token, desc in patterns.items():
            if token in low and token not in hits:
                hits[token] = desc
                sources.add(name)
    if not hits:
        return []
    return [
        Finding(
            rule="local_login_endpoint",
            severity="medium",
            summary="发现本地登录类接口线索：" + "；".join(f"{k} → {v}" for k, v in hits.items()),
            source_asset=",".join(sorted(sources)),
            evidence=", ".join(sorted(hits)),
            next_action="对每个本地登录接口确认：是否公网可达、是否有前置校验、是否有锁定/限流",
            sp_kind="auth_bypass",
        )
    ]


def scan_runtime_config_dead_code(texts: Mapping[str, str], *, html_asset_names: Iterable[str] = ()) -> list[Finding]:
    """HTML 引用了 *.config.js，但 JS 产物里内联了 env（改了不生效）。"""
    names = {n.lower() for n in html_asset_names}
    has_config_file = any(n.endswith("config.js") or "config.js?" in n for n in names)
    if not has_config_file:
        return []
    for name, text in texts.items():
        low = (text or "").lower()
        if "vite_glob_" in low and ("dev:!0" in low or "dev:true" in low or '"mode":"sandbox"' in low):
            return [
                Finding(
                    rule="runtime_config_dead_code",
                    severity="medium",
                    summary="运行时配置文件是死代码：产物内联了 env（DEV=true/sandbox 构建），改 *_app.config.js 不生效",
                    source_asset=name,
                    evidence=_snippet(text, low.find("vite_glob_")),
                    next_action=("把该文件与产物一起对比；应急场景（如临时关闭 SSO）必须重构建，否则运维以为改了实际没改"),
                    sp_kind="config_defect",
                )
            ]
    return []


def scan_hardcoded_http_service(texts: Mapping[str, str]) -> list[Finding]:
    """service 硬编码 http://（登出/回调会把用户带到 http 端口 → 400）。"""
    pat = re.compile(r"""["']http://["']\s*\+\s*(?:window\.)?location\.host""")
    for name, text in texts.items():
        m = pat.search(text or "")
        if m:
            return [
                Finding(
                    rule="hardcoded_http_service",
                    severity="low",
                    summary='跳转 service 用 "http://"+location.host 硬编码：登出/会话失效会被带到 http 端口',
                    source_asset=name,
                    evidence=_snippet(text, m.start()),
                    next_action="确认 HTTPS 端口对 http 请求的响应（常见 400 plain HTTP to HTTPS port），并核对该链路是否影响正常用户",
                    sp_kind="config_defect",
                )
            ]
    return []


def run_rules(texts: Mapping[str, str], *, html_asset_names: Iterable[str] = ()) -> list[Finding]:
    findings: list[Finding] = []
    findings += scan_default_credentials(texts)
    findings += scan_sso_gate(texts)
    findings += scan_local_login(texts)
    findings += scan_runtime_config_dead_code(texts, html_asset_names=html_asset_names)
    findings += scan_hardcoded_http_service(texts)
    return findings


# ── 编排 ───────────────────────────────────────────────────────────────────


def body_looks_truncated(text: str, headers: Mapping[str, Any] | None = None) -> bool:
    """文本通道被截断的判定（纯函数，可回归测试）。

    真实事故：入口 bundle 3,578,773 B，Yakit MCP 文本在 ~10KB 处截断并附
    ``... (truncated; set save-packet=true ...)``；而 vite 的路由→chunk 映射在文中
    约 1.6MB 处 —— 不识别标记就会得出"该站没有 lazy chunk"的错误结论。
    """
    if not text:
        return False
    if any(marker in text for marker in TRUNCATION_MARKERS):
        return True
    cl = 0
    for key, value in (headers or {}).items():
        if str(key).lower() == "content-length":
            try:
                cl = int(str(value).strip())
            except ValueError:
                cl = 0
    # 响应头声明比实际文本长得多（≥2KB 差距）→ 文本被截断
    return bool(cl and len(text) + 2048 < cl)


def _strip_packet(raw: bytes) -> str:
    """剥掉原始 HTTP 响应包头，必要时解压，返回 body 文本。"""
    idx = raw.find(b"\r\n\r\n")
    head = raw[:idx].decode("latin-1", "replace") if idx >= 0 else ""
    body = raw[idx + 4 :] if idx >= 0 else raw
    encoding = ""
    for line in head.splitlines():
        if line.lower().startswith("content-encoding:"):
            encoding = line.split(":", 1)[1].strip().lower()
    if encoding == "gzip":
        import gzip  # noqa: PLC0415

        try:
            body = gzip.decompress(body)
        except OSError:
            pass
    elif encoding == "deflate":
        import zlib  # noqa: PLC0415

        try:
            body = zlib.decompress(body, -15)
        except zlib.error:
            pass
    return body.decode("utf-8", "replace")


def fetch_with_save_packet(eg: Any, url: str, *, timeout: float, note: str) -> str | None:
    """用 Yakit MCP 的 save-packet 取**完整** body（同一传输、同一身份，附台账）。

    文本通道对 >10KB 的响应必然截断，因此大产物（SPA bundle）只能走这条路。
    """
    client = eg.yakit_client()
    result = client.call_tool(
        "do_http_request",
        {
            "url": url,
            "method": "GET",
            "headers": eg.identity.headers(profile="browser"),
            "https": "auto",
            "save-packet": True,
            "timeout": int(timeout),
            "verbose": False,
        },
    )
    text = result.text()
    m = re.search(r"response packet \[size:\d+\] saved to (?:file: )?([^\r\n]+)", text)
    if not m:
        m = re.search(r"saved to file: ([^\r\n]+)", text)
    status_m = re.search(r"response: HTTP/\d\.\d (\d+)", text)
    eg.note_external(
        url,
        status=int(status_m.group(1)) if status_m else 0,
        note=f"{note} [save-packet 全量取回]",
    )
    if not m:
        return None
    path = Path(m.group(1).strip())
    if not path.exists():
        return None
    try:
        return _strip_packet(path.read_bytes())
    except OSError:
        return None


def fetch_asset(
    eg: Any,
    url: str,
    *,
    timeout: float,
    note: str,
    max_bytes: int = DEFAULT_MAX_ASSET_BYTES,
) -> tuple[str, dict]:
    """取一个资源；文本通道截断时自动改用 save-packet。返回 (body, meta)。"""
    res = eg.get(url, profile="browser", timeout=timeout, note=note)
    text = getattr(res, "text", "") or ""
    meta: dict[str, Any] = {"status": getattr(res, "status_code", 0), "bytes": len(text), "truncated": False}
    if not body_looks_truncated(text, getattr(res, "headers", None)):
        return text, meta
    full = fetch_with_save_packet(eg, url, timeout=timeout, note=note)
    if full and len(full) > len(text):
        meta.update({"bytes": len(full), "truncated": False, "refetched": "save_packet"})
        return full, meta
    meta["truncated"] = True
    return text, meta


def _role_of(url: str) -> str:
    path = urlsplit(url).path.lower()
    filename = path.rsplit("/", 1)[-1]
    suffix = filename.rsplit(".", 1)[-1] if "." in filename else ""
    if suffix == "css":
        return "css"
    if suffix in {"png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "woff", "woff2", "ttf"}:
        return "image"
    if path.endswith((".html", ".htm")) or path in ("", "/"):
        return "html"
    if path.endswith(".json"):
        return "manifest"
    if "config" in path and suffix == "js":
        return "runtime_config"
    if suffix == "js":
        # 框架/依赖 bundle：不承载业务认证逻辑，却常常是几 MB 级
        # （本项目的真实代价：ant-design-vue 8.3MB + chunk-vendors 4.8MB + libs/polyfill，
        #  在 29 个请求里吃掉约 10 个、~30MB 流量，命中 0 条认证线索）
        if any(tok in filename for tok in _VENDOR_MARKERS):
            return "vendor"
        return "js"
    return "other"


_VENDOR_MARKERS = (
    "chunk-vendors",
    "chunk-libs",
    "vendors~",
    "~vendor",
    "polyfill",
    "ant-design",
    "element-ui",
    "node_modules",
    "runtime~",
    "babel",
)


#: 默认不取的角色：CSS/图片/依赖 bundle 几乎不可能承载凭据，却会吃掉资产预算
#: （真实事故：两个 CSS 合计 959 KB 占了 6 个资产预算里的 2 个）。
_SKIPPED_ROLES = frozenset({"css", "image", "vendor"})


def static_scan(
    *,
    url: str,
    texts: Mapping[str, str],
    html_assets: Sequence[str] | None = None,
    chunks_selected: Sequence[str] = (),
    chunks_available: int = 0,
) -> ScanResult:
    """对已取回的文本跑全部规则（零发包，供测试与 offline 模式复用）。

    ``html_assets`` 省略时会自行从文本里识别 HTML 并抽取其明文引用，
    这样 offline 模式（文件名≠URL）与在线模式的行为一致。
    """
    if html_assets is None:
        discovered: list[str] = []
        for body in texts.values():
            low_head = (body or "")[:400].lower()
            if "<!doctype html" in low_head or "<html" in low_head:
                discovered += extract_assets(body, url)
        html_assets = discovered

    result = ScanResult(url=url)
    result.chunks_selected = list(chunks_selected)
    result.chunks_available = chunks_available
    result.findings = run_rules(texts, html_asset_names=[urlsplit(a).path for a in html_assets])
    result.endpoints = extract_endpoints(texts)
    return result


def discover(
    url: str,
    *,
    target: str | None = None,
    max_assets: int = 8,
    max_chunks: int = 12,
    allow_all_chunks: bool = False,
    timeout: float = 20.0,
    max_asset_bytes: int = DEFAULT_MAX_ASSET_BYTES,
    include_all_assets: bool = False,
    dump_dir: Path | None = None,
) -> ScanResult:
    """在线模式：HTML → 入口资源 → 受控 chunk 展开 → 规则。"""
    from utils.egress import target_egress  # noqa: PLC0415

    eg = target_egress(target or url)
    texts: dict[str, str] = {}
    fetched: list[dict] = []
    warnings: list[str] = []
    try:
        html, meta = fetch_asset(eg, url, timeout=timeout, note="auth_surface: root")
        texts[url] = html
        fetched.append({"url": url, "role": "html", **meta})
        if dump_dir is not None:
            dump_body(dump_dir, 0, url, html)
        # 只取可能承载"认证线索"的引用：JS / 运行时配置 / manifest；CSS 与图片默认跳过
        referenced = extract_assets(html, url)
        # 跨域（CDN/图床）资源是第三方资产：默认不取，只记进告警
        for ext in [a for a in referenced if not same_origin(a, url)]:
            warnings.append(f"跳过跨域资产（第三方/CDN，未取回）：{ext}")
        local = [a for a in referenced if same_origin(a, url)]
        candidates = [a for a in local if include_all_assets or _role_of(a) not in _SKIPPED_ROLES]
        priority = {"runtime_config": 0, "js": 1, "manifest": 2}.get
        assets = sorted(candidates, key=lambda a: priority(_role_of(a), 3))[:max_assets]

        js_assets: list[str] = []
        chunk_refs: list[ChunkRef] = []
        for idx, asset in enumerate(assets, 1):
            body, meta = fetch_asset(eg, asset, timeout=timeout, note=f"auth_surface: asset {_role_of(asset)}")
            texts[asset] = body
            fetched.append({"url": asset, "role": _role_of(asset), **meta})
            if dump_dir is not None:
                dump_body(dump_dir, idx, asset, body)
            if meta.get("truncated"):
                warnings.append(f"资源被截断，chunk/端点可能漏检：{asset}（{meta.get('bytes')} B）")
            if _role_of(asset) == "js":
                js_assets.append(asset)
                if meta.get("bytes", 0) <= max_asset_bytes:
                    chunk_refs += extract_chunk_refs(body, asset)

        selected, available = select_chunks(chunk_refs, max_chunks=max_chunks, allow_all=allow_all_chunks)
        for j, chunk_url in enumerate(selected, len(assets) + 1):
            body, meta = fetch_asset(eg, chunk_url, timeout=timeout, note="auth_surface: auth chunk")
            texts[chunk_url] = body
            fetched.append({"url": chunk_url, "role": "chunk", **meta})
            if dump_dir is not None:
                dump_body(dump_dir, j, chunk_url, body)
            if meta.get("truncated"):
                warnings.append(f"auth chunk 被截断，弱口令/端点可能漏检：{chunk_url}")
    finally:
        eg.close()

    result = static_scan(url=url, texts=texts, html_assets=assets, chunks_selected=selected, chunks_available=available)
    result.fetched = fetched
    # 只要展开过 JS 却一个 chunk 都没拿到，就必须显式说明"是没引到，还是没读到"
    if js_assets and available == 0 and not warnings:
        warnings.append("入口 JS 已取回但未解析出任何 lazy chunk 引用：确认资源是否完整（大产物走 save-packet）、以及该站是否使用懒加载")
    result.coverage_warnings = warnings
    return result


def load_offline(directory: Path) -> dict[str, str]:
    """offline 模式：把目录里的 html/js/json 当作"已观测资源"喂给规则（零发包）。"""
    texts: dict[str, str] = {}
    for p in sorted(directory.rglob("*")):
        if not p.is_file() or p.suffix.lower() not in {".html", ".js", ".json", ".txt"}:
            continue
        try:
            texts[p.name] = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
    return texts


def dump_body(dump_dir: Path, index: int, url: str, body: str) -> None:
    """把取回的正文落盘到证据层。

    finding 必须可复核：只报"某文件里有弱口令"而不留原件，等于无法验证，
    也没法在离线模式复算（``--offline-dir`` 就是吃这些落盘文件）。
    """
    if not body:
        return
    parts = urlsplit(url)
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", parts.path.strip("/").replace("/", "_")) or "index"
    suffix = Path(parts.path).suffix or ".txt"
    try:
        dump_dir.mkdir(parents=True, exist_ok=True)
        (dump_dir / f"{index:02d}_{name[:80]}{suffix}").write_text(body, encoding="utf-8")
    except OSError:
        pass


# ── 落库（可选） ───────────────────────────────────────────────────────────


def store_result(target: str, result: ScanResult, *, db_path: Path | str | None = None) -> list[str]:
    """把 finding/端点写进 suspicious_points / endpoint_observations（幂等 id）。"""
    from lib.store_kit import StoreKit  # noqa: PLC0415

    written: list[str] = []
    slug = re.sub(r"[^a-z0-9]+", "-", (urlsplit(result.url).netloc or "target").lower()).strip("-")
    with StoreKit(target, db_path=db_path) as db:
        for i, f in enumerate(result.findings, 1):
            sp_id = f"sp-{slug}-auth{i:02d}"
            evidence_file = f"tmp/auth_surface/{slug}.json"
            db.upsert(
                "suspicious_points",
                {
                    "id": sp_id,
                    "page_url": result.url,
                    "url": result.url,
                    "method": "GET",
                    "test_type": f.sp_kind,
                    "evidence": evidence_file,
                    "source": "auth_surface",
                    "reasoning": f.summary,
                    "canonical_url": result.url,
                    "auth_surface_type": f.rule,
                    "response_summary": f"rule={f.rule} source_asset={f.source_asset}",
                    "risk": {"high": "High", "medium": "Medium", "low": "Low"}.get(f.severity, "Medium"),
                    "test_status": "untested",
                    "risk_score": {"high": 75, "medium": 45, "low": 20}.get(f.severity, 30),
                    "notes": f.next_action,
                    "created_at": None,
                },
                key=["id"],
            )
            written.append(sp_id)
        for ep in result.endpoints[:40]:
            db.upsert(
                "endpoint_observations",
                {
                    "target_name": target,
                    "canonical_url": urljoin(result.url, ep) if ep.startswith("/") else ep,
                    "method": "GET",
                    "source": "auth_surface",
                    "host": urlsplit(result.url).netloc,
                    "auth_state": "unknown",
                    "business_hint": "auth surface 线索（未探测）",
                    "confidence": "medium",
                    "test_status": "not_tested",
                    "first_seen_at": None,
                    "last_seen_at": None,
                    "scope_class": "owned",
                    "resolution_status": "resolved_path",
                },
                key=["target_name", "canonical_url", "method"],
            )
    return written


def render_markdown(result: ScanResult) -> str:
    lines = [f"# auth surface: {result.url}", ""]
    if result.fingerprints:
        lines.append("## 指纹命中")
        for p in result.fingerprints:
            cred = "有出厂口令" if p["has_factory_credential"] else "无出厂口令（不要猜）"
            lines.append(f"- **{p['display_name']}**（{cred}, confidence={p['confidence']}）markers={p['matched_markers']}")
            if p.get("ui_gate_note"):
                lines.append(f"  - 门/绕过提示：{p['ui_gate_note']}")
    if result.default_credentials:
        lines.append("\n## 默认凭据候选（未验证）")
        for c in result.default_credentials:
            lines.append(f"- {c['username']} / {c['password']}  ← {c['display_name']}（{c['confidence']}）")
            lines.append(f"  - 验证：{c['verify_hint']}")
    if result.findings:
        lines.append("\n## 发现")
        for f in result.findings:
            lines.append(f"- **[{f.severity}] {f.rule}** {f.summary}")
            lines.append(f"  - 来源：{f.source_asset}")
            lines.append(f"  - 证据：`{f.evidence[:180]}`")
            lines.append(f"  - 下一步：{f.next_action}")
    lines.append(f"\n## 覆盖\n- chunk 候选 {result.chunks_available} 个，按认证命名取 {len(result.chunks_selected)} 个")
    for u in result.chunks_selected:
        lines.append(f"  - {u}")
    if result.coverage_warnings:
        lines.append("\n### ⚠ 覆盖告警（取数不完整时，不能把空结果当作「没发现」）")
        for w in result.coverage_warnings:
            lines.append(f"  - {w}")
    return "\n".join(lines)


def force_utf8_stdout() -> None:
    """Windows 控制台/重定向管道统一 UTF-8（仓库运行约定）。

    真实事故：中文 Windows 的 GBK 控制台在打印告警里的 ⚠ 时抛 UnicodeEncodeError，
    整条命令以 exit=1 结束 —— 而 JSON 其实已经写好了，容易被误判成"工具坏了"。
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]  # 非常规流可能没有 reconfigure，外层已 catch AttributeError
        except (AttributeError, ValueError):  # pragma: no cover - 老 Python/被替换的流
            pass


def main(argv: list[str] | None = None) -> int:
    force_utf8_stdout()
    ap = argparse.ArgumentParser(description="认证面发现：默认凭据 / SSO 遮蔽 / 本地登录 / 配置死代码")
    ap.add_argument("--target", help="目标名（落库与出口身份用）")
    ap.add_argument("--url", required=True, help="起始 URL")
    ap.add_argument("--offline-dir", help="offline 模式：从该目录读已保存资源，零发包")
    ap.add_argument("--max-assets", type=int, default=8)
    ap.add_argument("--max-chunks", type=int, default=12)
    ap.add_argument("--all-chunks", action="store_true", help="chunk 白名单之外也展开（仍受 --max-chunks 限制）")
    ap.add_argument("--all-assets", action="store_true", help="连 CSS/图片一起取（默认跳过）")
    ap.add_argument("--dump-dir", help="把取回的正文落盘到该目录（默认 tmp/auth_surface/<host>）")
    ap.add_argument("--store", action="store_true", help="写 suspicious_points / endpoint_observations")
    ap.add_argument("--db", help="目标 DB 路径（配合 --store）")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    ap.add_argument("--out", help="把 JSON 报告写到该路径")
    args = ap.parse_args(argv)

    if args.offline_dir:
        texts = load_offline(Path(args.offline_dir))
        chunks: list[str] = []
        for name, body in texts.items():
            if name.endswith(".js"):
                chunks += extract_chunk_candidates(body, args.url)
        selected, available = select_chunks(chunks, max_chunks=args.max_chunks, allow_all=args.all_chunks)
        result = static_scan(url=args.url, texts=texts, chunks_selected=selected, chunks_available=available)
    else:
        slug = re.sub(r"[^a-z0-9]+", "-", (urlsplit(args.url).netloc or "target").lower()).strip("-")
        dump_dir = Path(args.dump_dir) if args.dump_dir else _TOOLS_DIR.parent / "tmp" / "auth_surface" / slug
        result = discover(
            args.url,
            target=args.target,
            max_assets=args.max_assets,
            max_chunks=args.max_chunks,
            allow_all_chunks=args.all_chunks,
            include_all_assets=args.all_assets,
            dump_dir=dump_dir,
        )
        print(f"[dump] 取证落盘目录：{dump_dir}")

    if args.json:
        print(json.dumps(result.to_json(), ensure_ascii=False, indent=2))
    else:
        print(render_markdown(result))

    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(json.dumps(result.to_json(), ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\n[json] {args.out}")

    if args.store:
        if not args.target:
            print("[store] 缺少 --target", file=sys.stderr)
            return 2
        written = store_result(args.target, result, db_path=args.db)
        print(f"[store] 写入 {len(written)} 条 suspicious_points: {written}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
