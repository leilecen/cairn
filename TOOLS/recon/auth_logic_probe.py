# -*- coding: utf-8 -*-
"""认证逻辑面探测（auth logic probe）。

回答的是 auth_surface 之后的第二个问题：**这些认证接口，未认证到底能走到哪一步？**

来自 app-a.example.com:9999 的真实教训（2026-10-12）：

- ``/sys/user/checkOnlyUser`` 未认证、无验证码就回答"账号是否存在" → **用户枚举 oracle**
  （此前只测 ``/sys/login`` 的报错，误判为"没有 oracle"）；
- ``/sys/user/register`` 未认证可达（停在短信校验）；
- 而 ``getLoginQrcode`` / ``third/user/*`` / ``permission/*`` 正确返回 401 → **不是全站裸奔**。

**安全内建（硬约束，不可用参数关闭）**：

1. 只发**空 body**或**明显无效的占位参数**（``zz-nonexist-<rand>``）——不做任何口令/账号猜测；
2. **状态改变类**（注册/短信/改密/建号/导入导出/上传/强制下线）默认 **skip 并记录原因**，
   只有显式 ``--i-approve-state-change`` 才执行（操作员门控）；
3. 存在性校验固定发 **2 个请求**（1 个测试值 + 1 个对照），**不做批量枚举**；
4. 全部经 ``TOOLS/utils/egress.py`` 串行发出；``--offline-dir`` 模式零发包。

用法：

    python TOOLS/recon/auth_logic_probe.py --target "江南布衣" --url https://host:9999 \\
        --from-auth-surface tmp/auth_surface/<slug>.json
    python TOOLS/recon/auth_logic_probe.py --target X --url https://host --endpoint /sys/sms
    python TOOLS/recon/auth_logic_probe.py --url https://host --offline-dir tmp/auth_logic/<slug>
"""

from __future__ import annotations

import argparse
import json
import random
import re
import string
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import urljoin, urlsplit

_TOOLS_DIR = Path(__file__).resolve().parent.parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

# ── 规则表：路径 → 探测类型 ────────────────────────────────────────────────

#: kind, method, state_changing, 语义说明
RULES: tuple[tuple[str, str, str, bool, str], ...] = (
    (r"/sys/user/checkOnlyUser", "existence_check", "GET", False, "账号存在性校验（枚举 oracle 候选）"),
    (r"/sys/phoneLogin", "phone_login", "POST", False, "手机号登录（未认证可达则暴露号码存在性语义）"),
    (r"/sys/user/phoneVerification", "phone_verify", "POST", False, "手机验证"),
    (r"/sys/getLoginQrcode|getQrcodeToken", "qrcode_login", "GET", False, "扫码登录（应鉴权）"),
    (r"/sys/third", "third_party", "POST", False, "第三方登录/建号（应鉴权）"),
    (r"/sys/permission", "permission", "GET", False, "权限码（应鉴权）"),
    (r"/sys/logout", "logout", "GET", False, "注销（应鉴权）"),
    (r"/sys/user/getUserInfo", "user_info", "GET", False, "用户信息（应鉴权）"),
    (r"/sys/tenant", "tenant", "GET", False, "租户查询"),
    (r"/sys/login|/user/login\b", "login", "POST", False, "本地登录（只发空 body，不猜口令）"),
    # 状态改变类
    (r"/sys/user/register|/auth/register", "register", "POST", True, "自助注册"),
    (r"/sys/sms|sendSms|sendMsg|/sys/send", "sms_send", "POST", True, "短信下发"),
    (
        r"/sys/user/passwordChange|forge-?password|resetPassword|/auth/forge",
        "password_reset",
        "POST",
        True,
        "改密/找回口令",
    ),
    (r"/sys/third/user/create|third/user/checkPassword", "third_account", "POST", True, "第三方建号/口令校验"),
    (r"upload/(create|base64)|importFile|exportFile", "file_io", "POST", True, "文件导入导出/上传"),
    (r"forceLogout|online/forceLogout", "force_logout", "POST", True, "强制下线"),
)

#: 这些接口**本应要求鉴权**：若未认证可达即为高危
SHOULD_REQUIRE_AUTH = frozenset(
    {"qrcode_login", "third_party", "permission", "logout", "user_info", "third_account", "force_logout", "file_io"}
)

#: 状态改变类 kind
STATE_CHANGING_KINDS = frozenset({"register", "sms_send", "password_reset", "third_account", "file_io", "force_logout"})

_CONTROL_VALUE = "zz-nonexist-" + "".join(random.choices(string.digits, k=6))  # noqa: S311 -- 占位探测值，非密码学用途


@dataclass
class Probe:
    id: str
    kind: str
    method: str
    url_path: str
    body: dict = field(default_factory=dict)
    state_changing: bool = False
    note: str = ""
    skipped: bool = False
    skip_reason: str = ""


@dataclass
class Verdict:
    status: int
    reachable_unauth: bool
    kind: str  # unauthenticated_reachable / auth_required / not_found / backend_down / rejected_input / unknown
    code: Any = None
    message: str = ""


@dataclass
class Finding:
    rule: str
    severity: str
    subject: str
    summary: str
    evidence: str
    next_action: str


@dataclass
class ProbeResult:
    url: str
    probes: list[dict] = field(default_factory=list)
    verdicts: list[dict] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    coverage_warnings: list[str] = field(default_factory=list)

    def to_json(self) -> dict:
        return asdict(self)


# ── 纯函数 ─────────────────────────────────────────────────────────────────


def classify(status: int, body: str) -> Verdict:
    """把 HTTP 响应归类成"未认证可达 / 需鉴权 / 不存在 / 后端不可用 / 输入被拒"。"""
    text = body or ""
    code: Any = None
    message = ""
    parsed: Mapping[str, Any] | None = None
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            parsed = data
            code = data.get("code")
            message = str(data.get("message") or "")
    except ValueError:
        parsed = None

    if status in (502, 503, 504):
        return Verdict(status, False, "backend_down", code, message or text[:60])
    if status == 404:
        return Verdict(status, False, "not_found", code, message or "not found")
    auth_markers = ("token失效", "请重新登录", "未登录", "unauthorized", "forbidden", "无权限")
    lowered = (message + " " + text[:200]).lower()
    if status in (401, 403) or any(m in lowered for m in auth_markers):
        return Verdict(status, False, "auth_required", code, message or f"HTTP {status}")
    if parsed is not None and "success" in parsed:
        # JEECG 业务态：有 success/code/message 说明请求已被业务处理 → 未认证可达
        return Verdict(status, True, "unauthenticated_reachable", code, message)
    if status == 400:
        return Verdict(status, False, "rejected_input", code, message)
    if status == 200:
        return Verdict(status, True, "unauthenticated_reachable", code, message or "HTTP 200（无业务态）")
    return Verdict(status, False, "unknown", code, message or f"HTTP {status}")


def match_kind(url_path: str) -> tuple[str, str, bool, str]:
    """返回 (kind, method, state_changing, note)。未匹配则按方法给通用类型。"""
    path = urlsplit(url_path).path.lower()
    for pattern, kind, method, state_changing, note in RULES:
        if re.search(pattern, path, re.IGNORECASE):
            return kind, method, state_changing, note
    return "generic", ("POST" if "post" in url_path.lower() else "GET"), False, "未在规则表内（只判可达性）"


def plan_probes(
    endpoints: Sequence[str],
    *,
    approve_state_change: bool = False,
    max_probes: int = 20,
    existence_values: Sequence[str] = ("admin",),
) -> list[Probe]:
    """规划探测。状态改变类默认 skip；存在性校验固定 2 个（测试值 + 对照）。"""
    probes: list[Probe] = []
    for ep in endpoints:
        kind, method, state_changing, note = match_kind(ep)
        path = urlsplit(ep).path
        query = urlsplit(ep).query
        if state_changing and not approve_state_change:
            probes.append(
                Probe(
                    id=f"{kind}:{path}",
                    kind=kind,
                    method=method,
                    url_path=ep.split("?", 1)[0],
                    state_changing=True,
                    note=note,
                    skipped=True,
                    skip_reason="状态改变类：需 --i-approve-state-change（操作员门控）",
                )
            )
            continue
        if kind == "existence_check":
            for label, value in [("test", existence_values[0]), ("control", _CONTROL_VALUE)]:
                probes.append(
                    Probe(
                        id=f"existence_check:{label}",
                        kind=kind,
                        method="GET",
                        url_path=f"{path}?username={value}",
                        state_changing=False,
                        note=f"{note}｜{'真实测试值' if label == 'test' else '对照(必然不存在)'}",
                    )
                )
            continue
        probes.append(
            Probe(
                id=f"{kind}:{path}",
                kind=kind,
                method=method,
                url_path=(ep if method == "GET" else path) + (f"?{query}" if method == "GET" and query else ""),
                body={} if method == "POST" else {},
                state_changing=state_changing,
                note=note,
            )
        )
    active_budget = max_probes
    for p in probes:
        if p.skipped:
            continue
        if active_budget <= 0:
            p.skipped = True
            p.skip_reason = f"超出预算 --max-probes={max_probes}"
            continue
        active_budget -= 1
    return probes


def analyze(probes: Sequence[Probe], responses: Mapping[str, tuple[int, str]]) -> list[Finding]:
    """把 (探测, 响应) 变成 finding（纯函数，可离线回归）。"""
    findings: list[Finding] = []
    verdicts = {p.id: classify(*responses[p.id]) for p in probes if p.id in responses}

    for p in probes:
        v = verdicts.get(p.id)
        if v is None:
            continue
        if p.kind in SHOULD_REQUIRE_AUTH and v.reachable_unauth:
            findings.append(
                Finding(
                    rule="missing_auth_on_protected_endpoint",
                    severity="high",
                    subject=p.url_path,
                    summary=f"本应鉴权的接口未认证可达：{p.note}（HTTP {v.status} code={v.code} msg={v.message}）",
                    evidence=f"{p.method} {p.url_path}",
                    next_action="核对网关/服务鉴权配置；确认该接口的实际数据权限范围（是否只读元数据）",
                )
            )

    # 存在性校验：对照差异 → 枚举 oracle
    test = next((p for p in probes if p.id == "existence_check:test"), None)
    control = next((p for p in probes if p.id == "existence_check:control"), None)
    if test and control and test.id in verdicts and control.id in verdicts:
        vt, vc = verdicts[test.id], verdicts[control.id]
        if vt.reachable_unauth and vc.reachable_unauth and (vt.code, vt.message) != (vc.code, vc.message):
            findings.append(
                Finding(
                    rule="user_enumeration_oracle",
                    severity="medium",
                    subject=test.url_path,
                    summary=(f"未认证即可判断账号是否存在（枚举 oracle）：测试值 → {vt.message!r}；对照值 → {vc.message!r}"),
                    evidence=f"GET {test.url_path} / GET {control.url_path}",
                    next_action="按最小化取证只保留这一组对照；不要批量枚举用户名；建议加验证码/限流并统一报错文案",
                )
            )

    for p in probes:
        v = verdicts.get(p.id)
        if v is None:
            continue
        if v.kind == "backend_down":
            findings.append(
                Finding(
                    rule="auth_backend_unavailable",
                    severity="info",
                    subject=p.url_path,
                    summary=f"认证后端不可用（HTTP {v.status}）：{p.url_path}",
                    evidence=f"{p.method} {p.url_path}",
                    next_action="该环境的认证面无法验证，记 blocked 而不是 refuted；换存活环境或等恢复",
                )
            )
            break
    return findings


def summarize(probes: Sequence[Probe], responses: Mapping[str, tuple[int, str]]) -> list[dict]:
    out: list[dict] = []
    for p in probes:
        if p.skipped:
            out.append(
                {
                    "probe": p.id,
                    "path": p.url_path,
                    "status": None,
                    "kind": "skipped",
                    "note": p.skip_reason,
                    "message": "",
                }
            )
            continue
        status, body = responses.get(p.id, (0, ""))
        v = classify(status, body)
        out.append(
            {
                "probe": p.id,
                "path": p.url_path,
                "status": status,
                "kind": v.kind,
                "note": p.note,
                "message": v.message,
                "code": v.code,
            }
        )
    return out


# ── 执行 ───────────────────────────────────────────────────────────────────


def load_endpoints(
    *,
    endpoint: Sequence[str] = (),
    from_auth_surface: Path | None = None,
    max_endpoints: int = 40,
) -> list[str]:
    out: list[str] = list(endpoint)
    if from_auth_surface and from_auth_surface.exists():
        data = json.loads(from_auth_surface.read_text(encoding="utf-8"))
        out += [e for e in (data.get("endpoints") or []) if isinstance(e, str)]
    seen: list[str] = []
    for e in out:
        if e and e not in seen:
            seen.append(e)
    # 只保留认证相关（避免把纯业务接口也打一遍）
    keep = [e for e in seen if match_kind(e)[0] != "generic"]
    return (keep or seen)[:max_endpoints]


def run_probes(
    base: str, probes: Sequence[Probe], *, target: str | None, dump_dir: Path | None, timeout: float = 25.0
) -> dict[str, tuple[int, str]]:
    from utils.egress import target_egress  # noqa: PLC0415

    eg = target_egress(target or base)
    responses: dict[str, tuple[int, str]] = {}
    try:
        for p in probes:
            if p.skipped:
                continue
            url = p.url_path if p.url_path.startswith("http") else urljoin(base.rstrip("/") + "/", p.url_path.lstrip("/"))
            if p.method == "GET":
                r = eg.get(url, referer=f"{base}/login", timeout=timeout, note=f"auth_logic: {p.id} :: {p.note[:60]}")
            else:
                r = eg.request(
                    "POST",
                    url,
                    headers={"Content-Type": "application/json"},
                    data=json.dumps(p.body or {}),
                    referer=f"{base}/login",
                    timeout=timeout,
                    note=f"auth_logic: {p.id} :: {p.note[:60]}",
                )
            body = getattr(r, "text", "") or ""
            responses[p.id] = (getattr(r, "status_code", 0), body)
            if dump_dir is not None:
                safe = re.sub(r"[^A-Za-z0-9._-]+", "_", p.id)[:80]
                dump_dir.mkdir(parents=True, exist_ok=True)
                (dump_dir / f"{safe}.json").write_text(body, encoding="utf-8")
    finally:
        eg.close()
    return responses


def load_offline(directory: Path) -> dict[str, tuple[int, str]]:
    """offline 模式：把目录里的响应当成本次探测的真实回包（零发包）。

    两种约定：
    1. 目录内有 ``manifest.json``：``{probe_id: 文件名主干}`` —— 推荐（真实回包的文件名往往
       比 probe_id 更可读，例如 ``checkOnlyUser_exists``）；
    2. 否则：文件名主干 == probe_id。
    状态码取 ``<主干>.status``，缺省 200。
    """
    responses: dict[str, tuple[int, str]] = {}
    if not directory.exists():
        return responses

    def _load(stem: str, key: str) -> None:
        p = directory / f"{stem}.json"
        if not p.exists():
            return
        status = 200
        sp = directory / f"{stem}.status"
        if sp.exists():
            try:
                status = int(sp.read_text(encoding="utf-8").strip())
            except ValueError:
                pass
        responses[key] = (status, p.read_text(encoding="utf-8", errors="replace"))

    manifest = directory / "manifest.json"
    if manifest.exists():
        try:
            mapping = json.loads(manifest.read_text(encoding="utf-8"))
        except ValueError:
            mapping = {}
        for probe_id, stem in (mapping or {}).items():
            _load(str(stem), str(probe_id))
        if responses:
            return responses
    for p in sorted(directory.glob("*.json")):
        if p.name == "manifest.json":
            continue
        _load(p.stem, p.stem)
    return responses


def render_markdown(result: ProbeResult) -> str:
    lines = [f"# auth logic probe: {result.url}", ""]
    lines.append("## 探测结果")
    for v in result.verdicts:
        tag = {
            "unauthenticated_reachable": "未认证可达",
            "auth_required": "需鉴权",
            "not_found": "不存在",
            "backend_down": "后端不可用",
            "rejected_input": "输入被拒",
            "skipped": "已跳过",
            "unknown": "未知",
        }.get(v["kind"], v["kind"])
        lines.append(f"- [{tag}] {v['probe']}  HTTP {v['status']}  {v.get('message') or ''}")
        if v["kind"] == "skipped":
            lines.append(f"  - 原因：{v['note']}")
    if result.findings:
        lines.append("\n## 发现")
        for f in result.findings:
            lines.append(f"- **[{f.severity}] {f.rule}** {f.summary}")
            lines.append(f"  - 证据：`{f.evidence}`")
            lines.append(f"  - 下一步：{f.next_action}")
    if result.coverage_warnings:
        lines.append("\n### 覆盖告警")
        for w in result.coverage_warnings:
            lines.append(f"  - {w}")
    return "\n".join(lines)


def force_utf8_stdout() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]  # 非常规流可能没有 reconfigure，外层已 catch AttributeError
        except (AttributeError, ValueError):  # pragma: no cover
            pass


def main(argv: list[str] | None = None) -> int:
    force_utf8_stdout()
    ap = argparse.ArgumentParser(description="认证逻辑面探测：未认证可达性 / 枚举 oracle / 缺失鉴权")
    ap.add_argument("--target", help="目标名（出口身份与台账）")
    ap.add_argument("--url", required=True, help="站点根 URL")
    ap.add_argument("--endpoint", action="append", default=[], help="显式端点（可多次）")
    ap.add_argument("--from-auth-surface", help="读取 auth_surface 输出的 JSON，取其 endpoints")
    ap.add_argument("--max-probes", type=int, default=20)
    ap.add_argument("--offline-dir", help="offline 模式：读该目录的响应，零发包")
    ap.add_argument("--i-approve-state-change", action="store_true", help="允许状态改变类探测（注册/短信/改密等，操作员门控）")
    ap.add_argument("--dump-dir", help="响应落盘目录（默认 tmp/auth_logic/<host>）")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--out", help="JSON 报告输出路径")
    args = ap.parse_args(argv)

    slug = re.sub(r"[^a-z0-9]+", "-", (urlsplit(args.url).netloc or "target").lower()).strip("-")
    dump_dir = Path(args.dump_dir) if args.dump_dir else _TOOLS_DIR.parent / "tmp" / "auth_logic" / slug

    endpoints = load_endpoints(
        endpoint=args.endpoint,
        from_auth_surface=Path(args.from_auth_surface) if args.from_auth_surface else None,
    )
    probes = plan_probes(endpoints, approve_state_change=args.i_approve_state_change, max_probes=args.max_probes)

    warnings: list[str] = []
    skipped = [p for p in probes if p.skipped]
    if skipped:
        warnings.append(f"{len(skipped)} 个探测被跳过（状态改变类或超预算）：" + ", ".join(p.kind for p in skipped))
    if not [p for p in probes if not p.skipped]:
        warnings.append("没有任何可执行的探测：端点为空或全被门控跳过")

    if args.offline_dir:
        responses = load_offline(Path(args.offline_dir))
    else:
        responses = run_probes(args.url, probes, target=args.target, dump_dir=dump_dir)

    result = ProbeResult(url=args.url, coverage_warnings=warnings)
    result.probes = [asdict(p) for p in probes]
    result.verdicts = summarize(probes, responses)
    result.findings = analyze(probes, responses)

    if args.json:
        print(json.dumps(result.to_json(), ensure_ascii=False, indent=2))
    else:
        print(render_markdown(result))
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(json.dumps(result.to_json(), ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\n[json] {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
