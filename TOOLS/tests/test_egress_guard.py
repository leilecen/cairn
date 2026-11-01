#!/usr/bin/env python3
"""出口形态治理守卫测试（防退化守卫）。

设计文档：`docs/modules/egress-traffic-shaping.md`；被守卫的运行时实现：`TOOLS/utils/egress.py`。

本文件把「形态治理」从口头约定变成可自动验证的静态约束。它**只读源码，不发包**，
扫描 `TOOLS/**/*.py` 与两个台账文件，命中即 pytest 失败，输出 `文件:行号 [规则] 违反了什么 → 该怎么改`。

六条规则：
  R1 禁止自报名号 UA —— UA 相关字符串字面量含 `utils.egress.TOOL_UA_MARKERS` 里的任何标记即违规。
  R2 禁止随机 UA —— `--random-agent` 之类开关，以及每请求变化的 User-Agent 构造。
  R3 禁止重复定义代理常量 —— 模块级 BURP/SQLMAP 代理字面量常量必须收敛到 `utils.egress`；
     legacy 尚未收敛的文件走显式例外清单（每条带理由）。
  R4 直连目标的文件必须显式声明受众 —— `import requests/httpx/aiohttp/urllib.request` 的文件
     必须属于第三方情报白名单（目标侧看不到）或本地控制面白名单；否则必须改走 `utils.egress`。
  R5 API 冻结 —— `utils.egress` 公开符号 + `egress_log` 表（schema.sql 与 migration 042）。
  R6 守卫自检 —— 假源码必须被判违规、干净源码不得误报（用 tmp_path 夹具，不往 TOOLS/ 写坏文件）。

直接运行可当报告工具用：`.venv\\Scripts\\python.exe TOOLS\\tests\\test_egress_guard.py`
"""

from __future__ import annotations

import ast
import re
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

_TOOLS_DIR = Path(__file__).resolve().parent.parent
if str(_TOOLS_DIR) not in sys.path:  # 直接运行时（非 pytest）也能 import utils
    sys.path.insert(0, str(_TOOLS_DIR))

from utils import egress as eg  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]  # TOOLS/tests/ → TOOLS/ → 仓库根
TOOLS = ROOT / "TOOLS"

# 所有规则共用的排除目录：vendored 第三方工具、测试自身（R6 的坏样例就写在临时文件里）。
GLOBAL_EXCLUDED_DIRS = frozenset({"codeql", "tests", "js-tools", "node_modules", "__pycache__", ".mypy_cache", ".ruff_cache", ".venv"})

# 无法用 Python 3 解析的文件（vendored / 历史脚本）单独记录，避免扫描器整体崩掉。
UNPARSABLE_SOURCES: list[str] = []

# 允许直连的第三方情报 / 通知客户端与本地控制面：目标侧看不到这些请求，因此不构成形态痕迹。
# 每条必须带一行中文理由；新增条目要能说清「为什么目标侧看不到这个请求」。
INTEL_CLIENT_ALLOWLIST: dict[str, str] = {
    # 第三方情报 API（audience=intel）
    "recon/fofa_relay.py": "FOFA relay 情报 API 客户端，请求只到 api.fofa.info，目标侧不可见",
    "recon/zoomeye_query.py": "ZoomEye 情报 API 客户端，请求只到 api.zoomeye.org，目标侧不可见",
    "recon/ct_search.py": "crt.sh / SSLMate CT 日志客户端，第三方公共数据源，目标侧不可见",
    "recon/recon_intel.py": "第三方情报 API 客户端（FOFA relay / SecurityTrails / uncover），请求只到情报服务商，目标侧不可见",
    "utils/feishu_notify.py": "飞书 webhook 通知客户端，出站只到 open.feishu.cn，不接触目标",
    # 本地控制面（127.0.0.1），非目标侧
    "auth/chrome_manager.py": "Chrome CDP 本地控制面（127.0.0.1:9222），只与本机浏览器通信",
    "utils/yakit_mcp.py": "Yakit MCP JSON-RPC 客户端（127.0.0.1:11432）；它本身就是 Egress 的 yakit 传输，只与本机 Yakit 引擎通信",
}

# R4 额外排除：底层 fetcher（唯一传输后端，由 Egress 调用）与治理层自身。
DIRECT_SCAN_EXCLUDED_FILES = frozenset({"utils/egress.py", "utils/http_fetcher.py"})
# R4 额外排除目录：历史扫描器（不再作为默认命令，收敛另行安排）。
DIRECT_SCAN_EXCLUDED_DIRS = frozenset({"legacy"})

# R3 显式例外：尚未收敛的 legacy 模块级代理常量。**只允许历史上已存在的文件**，
# 新代码不得模仿；例外清单一经收敛必须删除对应条目（`test_proxy_constant_exceptions_are_alive` 会检查）。
PROXY_CONSTANT_EXCEPTIONS: dict[str, str] = {}

UA_CONTEXT_RE = re.compile(r"user[-_]?agent|^ua$|_ua$|^ua_", re.I)
RANDOM_UA_LITERAL_RE = re.compile(
    r"random[-_]?(?:user[-_]?)?agent|fake[-_]?user[-_]?agent|rotate[-_]?agent|random[-_]?ua",
    re.I,
)
PER_REQUEST_UA_RE = re.compile(r"random|choice|uuid|nonce|randint|token_hex", re.I)
PROXY_CONST_NAME_RE = re.compile(r"PROXY|PROXIES", re.I)
DIRECT_CLIENT_NAMES = frozenset({"requests", "httpx", "aiohttp"})


@dataclass(frozen=True)
class Violation:
    """一处违规：文件、行号、规则、违反了什么、该怎么改。"""

    path: Path
    line: int
    rule: str
    detail: str
    fix: str

    def render(self) -> str:
        try:
            shown = self.path.relative_to(ROOT).as_posix()
        except ValueError:
            shown = self.path.as_posix()
        return f"{shown}:{self.line} [{self.rule}] {self.detail} → {self.fix}"

    def __str__(self) -> str:  # 便于 pytest 断言里直接打印
        return self.render()


RULE_UA = "R1 自报名号 UA"
RULE_RANDOM = "R2 随机 UA"
RULE_PROXY_CONST = "R3 代理常量重复定义"
RULE_DIRECT = "R4 直连未声明受众"

FIX_UA = "删除脚本自带的 UA/header 字面量，改用 utils.egress 的固定身份（target_egress(...).get/post 或 Identity.headers()）"
FIX_RANDOM = "删除随机 UA 开关，身份在委托内固定（utils.egress.Identity 单一 UA，禁止 --random-agent）"
FIX_PROXY_CONST = "删除该字面量，改用 utils.egress.proxy_map() / Egress.proxy_kwargs() 取出口"
FIX_DIRECT = "目标侧请求改走 utils.egress（Egress.request/get/post/navigate）；确属第三方情报 API 才可登记进 INTEL_CLIENT_ALLOWLIST"


def _rel(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def iter_sources(root: Path, *, extra_excluded_dirs: frozenset[str] = frozenset()) -> list[Path]:
    """枚举 root 下的 .py 源文件（跳过全局排除目录 + 规则自定义排除目录）。"""
    excluded = GLOBAL_EXCLUDED_DIRS | extra_excluded_dirs
    found: list[Path] = []
    for path in sorted(root.rglob("*.py")):
        parts = path.relative_to(root).parts
        if any(part in excluded for part in parts[:-1]):
            continue
        found.append(path)
    return found


def _parse(path: Path) -> ast.Module | None:
    """解析源码；无法解析（非 Python 3 语法）时不炸整个守卫，登记后跳过。"""
    try:
        return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (SyntaxError, UnicodeDecodeError) as exc:
        note = f"{path}: {type(exc).__name__}: {exc}"
        if note not in UNPARSABLE_SOURCES:
            UNPARSABLE_SOURCES.append(note)
        return None


def _ua_context_nodes(tree: ast.AST) -> list[tuple[ast.AST, tuple[str, ...]]]:
    """返回「处于 UA 上下文」的节点及其上下文名（dict 键 / 赋值名 / 关键字参数名）。

    上下文识别而非全文匹配，避免把普通字符串（如 `"claude-monitoring"` 这类模块名）误判成 UA。
    """
    found: list[tuple[ast.AST, tuple[str, ...]]] = []

    def record(node: ast.AST, ctx: tuple[str, ...]) -> None:
        if ctx:
            found.append((node, ctx))

    def visit(node: ast.AST, ctx: tuple[str, ...]) -> None:
        if isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values, strict=True):
                child = ctx
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    child = ctx + (key.value,)
                visit(value, child)
            return
        if isinstance(node, ast.Assign):
            names = list(ctx)
            for target in node.targets:
                if isinstance(target, ast.Name):
                    names.append(target.id)
                elif isinstance(target, ast.Attribute):
                    names.append(target.attr)
                elif isinstance(target, ast.Subscript) and isinstance(target.slice, ast.Constant) and isinstance(target.slice.value, str):
                    names.append(target.slice.value)
            visit(node.value, tuple(names))
            return
        if isinstance(node, ast.AnnAssign) and node.value is not None:
            if isinstance(node.target, ast.Name):
                visit(node.value, ctx + (node.target.id,))
            else:
                visit(node.value, ctx)
            return
        if isinstance(node, ast.Call):
            visit(node.func, ctx)
            for arg in node.args:
                visit(arg, ctx)
            for keyword in node.keywords:
                visit(keyword.value, ctx + ((keyword.arg,) if keyword.arg else ()))
            return
        if isinstance(node, ast.keyword):
            visit(node.value, ctx + ((node.arg,) if node.arg else ()))
            return
        if isinstance(node, ast.Constant):
            if isinstance(node.value, str) and any(UA_CONTEXT_RE.search(name) for name in ctx):
                record(node, ctx)
            return
        if isinstance(node, (ast.JoinedStr, ast.BinOp)) and any(UA_CONTEXT_RE.search(name) for name in ctx):
            record(node, ctx)
            return
        for sub in ast.iter_child_nodes(node):
            visit(sub, ctx)

    visit(tree, ())
    return found


# ── R1 自报名号 UA ─────────────────────────────────────────────────────────────


def scan_self_naming_ua(root: Path = TOOLS, markers: tuple[str, ...] = eg.TOOL_UA_MARKERS) -> list[Violation]:
    """UA 上下文里的字符串字面量含工具/自报名号标记 → 违规（清单直接复用 utils.egress）。"""
    violations: list[Violation] = []
    for path in iter_sources(root):
        tree = _parse(path)
        if tree is None:
            continue
        for node, _ctx in _ua_context_nodes(tree):
            if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                continue
            lowered = node.value.lower()
            hits = sorted({marker for marker in markers if marker in lowered})
            if hits:
                violations.append(Violation(path, node.lineno, RULE_UA, f"User-Agent 字面量 {node.value!r} 含工具标记 {hits}", FIX_UA))
    return violations


# ── R2 随机 UA ────────────────────────────────────────────────────────────────


def scan_random_ua(root: Path = TOOLS) -> list[Violation]:
    """随机 UA 开关字面量 + 每请求变化的 User-Agent 构造 → 违规。"""
    violations: list[Violation] = []
    for path in iter_sources(root):
        source = path.read_text(encoding="utf-8")
        for lineno, line in enumerate(source.splitlines(), start=1):
            for match in RANDOM_UA_LITERAL_RE.finditer(line):
                violations.append(Violation(path, lineno, RULE_RANDOM, f"出现随机 UA 开关字面量 {match.group(0)!r}", FIX_RANDOM))
        try:
            tree = ast.parse(source, filename=str(path))
        except SyntaxError:
            continue
        for node, _ctx in _ua_context_nodes(tree):
            if not isinstance(node, (ast.JoinedStr, ast.BinOp)):
                continue
            segment = ast.get_source_segment(source, node) or ""
            if PER_REQUEST_UA_RE.search(segment):
                violations.append(
                    Violation(
                        path,
                        node.lineno,
                        RULE_RANDOM,
                        f"User-Agent 每请求变化（{segment.strip()[:60]}）；同会话 UA 变化本身就是工具特征",
                        FIX_RANDOM,
                    )
                )
    return violations


# ── R3 代理常量重复定义 ───────────────────────────────────────────────────────


def _proxy_url_literals(node: ast.AST) -> list[tuple[int, str]]:
    """取字面量里的代理 URL：字符串常量或字符串常量字典的值。"""
    urls: list[tuple[int, str]] = []
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        urls.append((node.lineno, node.value))
    elif isinstance(node, ast.Dict):
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                urls.append((value.lineno, value.value))
    return urls


def scan_duplicate_proxy_constants(root: Path = TOOLS, *, honour_exceptions: bool = True) -> list[Violation]:
    """模块级 BURP/SQLMAP 代理字面量常量 → 违规（legacy 走显式例外清单）。

    判定边界：`CLASH_PROXY = "http://127.0.0.1:9870"` 这类本机 Clash 常量不算违规
    （它不是目标侧出口，也没有被 egress 取代的语义）；命中范围是 `:8080` 或名字含 BURP/SQLMAP。
    `honour_exceptions=False` 用于例外清单自检（例外文件本身仍要被扫出违规，否则条目该删了）。
    """
    violations: list[Violation] = []
    for path in iter_sources(root):
        rel = _rel(path, root)
        if rel in DIRECT_SCAN_EXCLUDED_FILES:
            continue
        if honour_exceptions and rel in PROXY_CONSTANT_EXCEPTIONS:
            continue
        tree = _parse(path)
        if tree is None:
            continue
        for node in tree.body:
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            names = [t.id for t in targets if isinstance(t, ast.Name)]
            value = node.value
            if value is None:
                continue
            for name in names:
                if not PROXY_CONST_NAME_RE.search(name):
                    continue
                urls = _proxy_url_literals(value)
                if not urls or not any("://" in url for _line, url in urls):
                    continue
                is_burp_family = any(":8080" in url for _line, url in urls) or re.search(r"BURP|SQLMAP", name, re.I)
                if not is_burp_family:
                    continue
                violations.append(
                    Violation(
                        path,
                        node.lineno,
                        RULE_PROXY_CONST,
                        f"模块级代理常量 {name} 重复定义出口（{urls[0][1]}）",
                        FIX_PROXY_CONST,
                    )
                )
    return violations


# ── R4 直连目标的文件必须显式声明受众 ─────────────────────────────────────────


def _is_direct_client_module(name: str) -> bool:
    return name in DIRECT_CLIENT_NAMES or name == "urllib.request" or name.startswith("urllib.request.")


# 受治理的必要条件：仅「import 了 egress」不够（那可能只取了 UA，仍然直连目标），
# 还必须真的取出口配置（代理映射 / Egress 实例）。
EGRESS_GOVERNANCE_REFS = frozenset(
    {
        "Egress",
        "target_egress",
        "intel_egress",
        "proxy_kwargs",
        "target_proxy_map",
        "target_proxy_url",
        "proxy_map",
        "default_proxies",
        "default_proxy_url",
        "ProxyHandler",
        "burp_port_open",
    }
)


def egress_governance(tree: ast.AST) -> tuple[bool, bool]:
    """返回 (是否 import utils.egress, 是否引用了出口配置助手)。"""
    imports_egress = False
    refs_governance = False
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[-1] == "egress":
                imports_egress = True
        elif isinstance(node, ast.Import):
            if any(alias.name.split(".")[-1] == "egress" for alias in node.names):
                imports_egress = True
        elif isinstance(node, ast.Name) and node.id in EGRESS_GOVERNANCE_REFS:
            refs_governance = True
        elif isinstance(node, ast.Attribute) and node.attr in EGRESS_GOVERNANCE_REFS:
            refs_governance = True
    return imports_egress, refs_governance


def direct_client_imports(tree: ast.AST) -> list[tuple[int, str]]:
    """返回文件里所有直连 HTTP 客户端的 import（含函数内延迟 import）。"""
    hits: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if _is_direct_client_module(alias.name):
                    hits.append((node.lineno, alias.name))
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if node.level == 0 and _is_direct_client_module(module):
                hits.append((node.lineno, module))
    return hits


def scan_direct_clients(root: Path = TOOLS) -> list[Violation]:
    """扫描直连客户端 import。

    合规路径只有两条：
    1. 在情报/本地控制面白名单内（目标侧看不到该请求）；
    2. import `utils.egress` **且**取出口配置（proxy_kwargs / target_proxy_map / Egress ...）
       —— 只取 UA 不算受治理，那正是「UA 声称浏览器、TLS 是 Python」的自相矛盾形态。
    """
    excluded_dirs = DIRECT_SCAN_EXCLUDED_DIRS
    violations: list[Violation] = []
    for path in iter_sources(root, extra_excluded_dirs=excluded_dirs):
        rel = _rel(path, root)
        if rel in DIRECT_SCAN_EXCLUDED_FILES:
            continue
        tree = _parse(path)
        if tree is None:
            continue
        imports = direct_client_imports(tree)
        if not imports or rel in INTEL_CLIENT_ALLOWLIST:
            continue
        imports_egress, refs_governance = egress_governance(tree)
        if imports_egress and refs_governance:
            continue
        detail_tail = (
            "只 import 了 egress 但没取出口配置（proxy_kwargs/target_proxy_map/Egress）"
            if imports_egress
            else "既没 import utils.egress，也没取出口配置"
        )
        for lineno, module in imports:
            violations.append(
                Violation(
                    path,
                    lineno,
                    RULE_DIRECT,
                    f"import {module} 直连 HTTP，{detail_tail}（目标侧请求必须经 utils.egress 取身份与出口）",
                    FIX_DIRECT,
                )
            )
    return violations


def collect_violations(root: Path = TOOLS) -> list[Violation]:
    """汇总全部静态规则结果（R5/R6 不走这里，它们是自检而非扫描）。"""
    return scan_self_naming_ua(root) + scan_random_ua(root) + scan_duplicate_proxy_constants(root) + scan_direct_clients(root)


def _fail(rule: str, violations: list[Violation]) -> None:
    if not violations:
        return
    lines = [f"{rule}: 检出 {len(violations)} 处违规（每行给出 文件:行号 + 违反内容 → 修法）"]
    lines += [f"  {item.render()}" for item in violations]
    pytest.fail("\n".join(lines), pytrace=False)


# ── 实时守卫（对当前工作树生效） ───────────────────────────────────────────────


def test_no_self_naming_user_agent():
    """R1：TOOLS 下不得再出现自报名号 / 工具 UA。"""
    _fail(RULE_UA, scan_self_naming_ua())


def test_no_random_user_agent():
    """R2：TOOLS 下不得出现随机 UA 开关或每请求变化的 UA。"""
    _fail(RULE_RANDOM, scan_random_ua())


def test_no_duplicate_proxy_constants():
    """R3：模块级 Burp/sqlmap 代理字面量常量必须收敛（legacy 例外清单除外）。"""
    _fail(RULE_PROXY_CONST, scan_duplicate_proxy_constants())


def test_direct_target_clients_are_declared():
    """R4：直连 HTTP 的文件必须在情报/本地控制面白名单内。"""
    _fail(RULE_DIRECT, scan_direct_clients())


def test_intel_allowlist_entries_carry_reasons_and_exist():
    """白名单不是免责清单：条目必须存在、必须写清理由，且确实还在直连。"""
    problems: list[str] = []
    for rel, reason in INTEL_CLIENT_ALLOWLIST.items():
        path = TOOLS / rel
        if not path.is_file():
            problems.append(f"{rel}: 文件不存在，白名单条目已过期 → 删除该条")
            continue
        if len(reason.strip()) < 10 or not re.search(r"[\u4e00-\u9fff]", reason):
            problems.append(f"{rel}: 缺失中文理由 → 补一行说明「目标侧为何看不到这个请求」")
            continue
        tree = _parse(path)
        if tree is None:
            problems.append(f"{rel}: 源码无法解析，白名单无法验证 → 修正或从白名单移除")
            continue
        if not direct_client_imports(tree):
            problems.append(f"{rel}: 已不再直接 import 直连客户端 → 从 INTEL_CLIENT_ALLOWLIST 移除")
    assert not problems, "白名单自检失败:\n  " + "\n  ".join(problems)


def test_proxy_constant_exceptions_are_alive():
    """R3 例外清单同样要收敛：文件消失、或已无违规时必须删除条目（否则例外会烂在清单里）。"""
    problems: list[str] = []
    raw = {item.path for item in scan_duplicate_proxy_constants(honour_exceptions=False)}
    for rel, reason in PROXY_CONSTANT_EXCEPTIONS.items():
        path = TOOLS / rel
        if not path.is_file():
            problems.append(f"{rel}: 文件不存在 → 删除例外条目")
            continue
        if not re.search(r"[\u4e00-\u9fff]", reason):
            problems.append(f"{rel}: 例外必须写明中文理由")
            continue
        if path not in raw:
            problems.append(f"{rel}: 已无代理常量违规 → 删除例外条目（收敛完成）")
    assert not problems, "代理常量例外清单自检失败:\n  " + "\n  ".join(problems)


def test_current_violations_are_reported_with_locations():
    """扫描器自身可观测：命中项必须带 文件:行号，便于 Lead 直接派活。"""
    for item in collect_violations():
        assert re.match(r"^TOOLS/[^\s]+:\d+ \[R\d", item.render()), item.render()


def test_all_scanned_sources_are_parsable():
    """守卫盲区检查：解析失败的文件会被静默跳过，等于规则失效，必须显式暴露。"""
    collect_violations()  # 触发全量扫描，填充 UNPARSABLE_SOURCES
    assert not UNPARSABLE_SOURCES, "以下 TOOLS 源码无法解析，守卫规则对其失效（修语法或移出扫描范围）:\n  " + "\n  ".join(
        UNPARSABLE_SOURCES
    )


# ── R5 API 冻结 ───────────────────────────────────────────────────────────────

REQUIRED_EGRESS_API = (
    "TOOL_UA_MARKERS",
    "Egress",
    "target_egress",
    "intel_egress",
    "EgressUnavailable",
    "classify_response",
    "PacingPolicy",
    "CircuitBreaker",
)


@pytest.mark.parametrize("name", REQUIRED_EGRESS_API)
def test_egress_public_api_is_frozen(name):
    """R5：utils.egress 的公开符号是其他模块的依赖面，不得改名/删除。"""
    assert hasattr(eg, name), f"utils.egress 缺少公开符号 {name}：其他模块依赖它，改名/删除会静默退化"
    assert name in eg.__all__, f"{name} 必须在 utils.egress.__all__ 中声明"


def test_tool_ua_markers_are_usable():
    """R5：R1 直接复用这份清单，它必须非空且已小写（比较时按小写匹配）。"""
    assert isinstance(eg.TOOL_UA_MARKERS, tuple) and len(eg.TOOL_UA_MARKERS) >= 10
    assert all(marker == marker.lower() for marker in eg.TOOL_UA_MARKERS)


def test_egress_log_table_is_declared():
    """R5：台账表必须在 schema.sql 与 migration 042 同时存在（否则合规证据无处落库）。"""
    schema = (TOOLS / "db" / "schema.sql").read_text(encoding="utf-8")
    migration = ROOT / "migrations" / "042_egress_log.sql"
    assert "CREATE TABLE IF NOT EXISTS egress_log" in schema, "TOOLS/db/schema.sql 缺少 egress_log 表"
    assert migration.is_file(), "migrations/042_egress_log.sql 不存在"
    assert "CREATE TABLE IF NOT EXISTS egress_log" in migration.read_text(encoding="utf-8")


def test_no_trace_clearing_code_paths():
    """R5 附带约束：不做目标侧日志/痕迹清除（破坏性且摧毁授权证据链）。"""
    forbidden = re.compile(r"(?i)clear[-_ ]?(?:access[-_ ]?)?log|rm .*access\.log|unlink.*\.log|wipe[-_ ]?logs")
    hits: list[str] = []
    for path in iter_sources(TOOLS):
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if forbidden.search(line):
                hits.append(f"{_rel(path, TOOLS)}:{lineno} {line.strip()[:80]}")
    assert not hits, "检出痕迹清除式写法（属破坏性操作，禁止）:\n  " + "\n  ".join(hits)


# ── R6 守卫自检（假源码必须被判违规，不往 TOOLS/ 写坏文件） ────────────────────


def test_guard_detects_self_naming_ua(tmp_path: Path):
    bad = tmp_path / "bad_probe.py"
    bad.write_text(
        "from urllib.request import Request\ndef probe(url):\n    return Request(url, headers={'User-Agent': 'SRC-preauth-probe/1.0'})\n",
        encoding="utf-8",
    )
    violations = scan_self_naming_ua(tmp_path)
    assert len(violations) == 1, [str(v) for v in violations]
    assert violations[0].line == 3
    assert "preauth-probe" in violations[0].render()
    assert RULE_UA in violations[0].render()


def test_guard_accepts_clean_ua_fixture(tmp_path: Path):
    good = tmp_path / "good_probe.py"
    good.write_text(
        "from utils.egress import target_egress\ndef probe(url):\n    client = target_egress('demo')\n    return client.get(url)\n",
        encoding="utf-8",
    )
    assert scan_self_naming_ua(tmp_path) == []


def test_guard_detects_random_agent_switch(tmp_path: Path):
    bad = tmp_path / "bad_sqli.py"
    bad.write_text("CMD = ['sqlmap', '--random-agent']\n", encoding="utf-8")
    violations = scan_random_ua(tmp_path)
    assert violations and "random-agent" in violations[0].render()


def test_guard_detects_per_request_ua_mutation(tmp_path: Path):
    bad = tmp_path / "bad_rotate.py"
    bad.write_text(
        "import random\n"
        "POOL = ['Mozilla/5.0 (A)', 'Mozilla/5.0 (B)']\n"
        "def headers():\n"
        "    return {'User-Agent': f'Mozilla/5.0 {random.choice(POOL)}'}\n",
        encoding="utf-8",
    )
    violations = scan_random_ua(tmp_path)
    assert violations, "每请求变化的 UA 必须被判违规"


def test_guard_detects_duplicate_burp_proxy_constant(tmp_path: Path):
    bad = tmp_path / "bad_scan.py"
    bad.write_text(
        "BURP_PROXY = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}\n",
        encoding="utf-8",
    )
    violations = scan_duplicate_proxy_constants(tmp_path)
    assert violations and "BURP_PROXY" in violations[0].render()


def test_guard_allows_local_clash_constant(tmp_path: Path):
    """边界：本机 Clash 常量不是目标侧出口，不属 R3 违规（避免误报）。"""
    ok = tmp_path / "clash_like.py"
    ok.write_text("CLASH_PROXY = 'http://127.0.0.1:9870'\n", encoding="utf-8")
    assert scan_duplicate_proxy_constants(tmp_path) == []


def test_guard_detects_undeclared_direct_client(tmp_path: Path):
    bad = tmp_path / "bad_direct.py"
    bad.write_text(
        "import requests\ndef check(url):\n    return requests.get(url, verify=False)\n",
        encoding="utf-8",
    )
    violations = scan_direct_clients(tmp_path)
    assert violations and RULE_DIRECT in violations[0].render()
    assert "requests" in violations[0].render()


def test_guard_ignores_urllib_parse_only(tmp_path: Path):
    """边界：只 import urllib.parse（纯字符串处理）不算直连客户端。"""
    ok = tmp_path / "parse_only.py"
    ok.write_text("from urllib.parse import urlparse\n\ndef host(u):\n    return urlparse(u).hostname\n", encoding="utf-8")
    assert scan_direct_clients(tmp_path) == []


def test_guard_rejects_ua_only_egress_import(tmp_path: Path):
    """只 import egress 取 UA、仍直连目标的文件必须被判违规（自相矛盾形态）。"""
    bad = tmp_path / "ua_only.py"
    bad.write_text(
        "import urllib.request\n"
        "from utils.egress import load_identity\n"
        "def probe(url):\n"
        "    req = urllib.request.Request(url, headers={'User-Agent': load_identity().user_agent})\n"
        "    return urllib.request.urlopen(req)\n",
        encoding="utf-8",
    )
    violations = scan_direct_clients(tmp_path)
    assert violations, "只取 UA 不算受治理"
    assert "没取出口配置" in violations[0].render()


def test_guard_accepts_governed_direct_client(tmp_path: Path):
    """正向验证：import egress + 取出口配置（ProxyHandler）即视为受治理。"""
    ok = tmp_path / "governed.py"
    ok.write_text(
        "import urllib.request\n"
        "from utils.egress import target_proxy_map\n"
        "def probe(url):\n"
        "    proxies = target_proxy_map()\n"
        "    opener = urllib.request.build_opener(urllib.request.ProxyHandler(proxies))\n"
        "    return opener.open(url)\n",
        encoding="utf-8",
    )
    assert scan_direct_clients(tmp_path) == []


def test_guard_allowlists_declared_intel_client(tmp_path: Path):
    """正向验证白名单机制本身有效：已登记的情报客户端 import requests 不报违规。"""
    intel_dir = tmp_path / "recon"
    intel_dir.mkdir()
    (intel_dir / "fofa_relay.py").write_text("import requests\n", encoding="utf-8")
    target_dir = tmp_path / "pipeline"
    target_dir.mkdir()
    (target_dir / "probe.py").write_text("import requests\n", encoding="utf-8")
    violations = scan_direct_clients(tmp_path)
    assert [Path(v.path).name for v in violations] == ["probe.py"], [str(v) for v in violations]


if __name__ == "__main__":  # 报告模式：列出当前工作树的直连清单与全部静态违规
    print("== 直连 HTTP 客户端清单（R4） ==")
    for path in iter_sources(TOOLS, extra_excluded_dirs=DIRECT_SCAN_EXCLUDED_DIRS):
        rel = _rel(path, TOOLS)
        if rel in DIRECT_SCAN_EXCLUDED_FILES:
            continue
        tree = _parse(path)
        if tree is None:
            continue
        imports = direct_client_imports(tree)
        if not imports:
            continue
        tag = "白名单(情报/本地控制面)" if rel in INTEL_CLIENT_ALLOWLIST else "违规(目标侧未收敛)"
        print(f"  [{tag}] {rel}: " + ", ".join(f"L{line} {mod}" for line, mod in imports))
    if UNPARSABLE_SOURCES:
        print("== 无法解析（已跳过） ==")
        for note in UNPARSABLE_SOURCES:
            print(f"  {note}")
    found = collect_violations()
    print(f"\n== 静态违规 {len(found)} 处 ==")
    for item in found:
        print("  " + item.render())
    raise SystemExit(1 if found else 0)
