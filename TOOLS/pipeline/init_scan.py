"""初始化扫描：httpx 批量验活 + 技术指纹 + 写 DB。

用法:
  python3 TOOLS/init_scan.py --target "目标名"
  python3 TOOLS/init_scan.py --target "目标名" --urls "https://a.com,https://b.com"
  python3 TOOLS/init_scan.py --urls-file /tmp/urls.txt

输出:
  - 更新 targets.tech_stack / title / ip / server
  - 新发现的 URL 写入 pages 表 (status='queued', depth=0)
  - 打印 httpx 扫描摘要

依赖: httpx (projectdiscovery) 安装在 PATH 中

说明:
  - 本脚本保留对外部 ProjectDiscovery `httpx` CLI 的调用，用于批量验活/指纹探测。
  - 它不走 `TOOLS/utils/http_fetcher.py`，这是有意保留的工具级例外，不属于 Python 内部轻量 fetch 统一层。
  - 接口**身份**仍必须统一：基线入口探测的 UA 取自 `utils.egress` 的固定身份，
    不再自报 `src-recon-*` 名号（自报名号等于给防御方一份工具清单）。节拍不在此文件接入。
"""

import argparse
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta
from functools import lru_cache
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent  # pipeline/ → TOOLS/ → SRC/

_TOOLS_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_TOOLS_DIR))
from db.db_utils import connect, find_db, session  # noqa: E402
from recon.baseline_entries import run_baseline_entry_probe  # noqa: E402
from recon.recon_runtime import begin_recon_run, update_recon_run  # noqa: E402
from utils.egress import PacingPolicy, load_identity, target_proxy_url  # noqa: E402

LOGIN_KEYWORDS = re.compile(r"(login|signin|sign-in|auth|passport|sso|oauth|账号|登录|验证|portal)", re.IGNORECASE)
REGISTER_KEYWORDS = re.compile(r"(register|signup|sign-up|registration|join|注册|开户|加入)", re.IGNORECASE)
AUTH_STATUS_CODES = {302, 401, 403}
AUTH_KEYWORDS = re.compile(
    r"(login|signin|sign-in|auth|passport|sso|oauth|账号|登录|验证|portal|请先登录|会话过期)",
    re.IGNORECASE,
)
LIVE_STATUS_CODES = set(range(200, 400)) | {401, 403}
_BASELINE_ENTRY_TIMEOUT = 10


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


@lru_cache(maxsize=1)
def _baseline_identity_ua() -> str:
    """统一固定身份 UA（与 `utils.egress` 共用同一份身份文件，含 EGRESS_UA 覆盖）。

    只统一身份、不接入 Egress 节拍：本脚本的 httpx CLI 调用是有意保留的工具级例外
    （见文件头说明）。
    """
    return load_identity().user_agent


@lru_cache(maxsize=1)
def _egress_proxy_url() -> str | None:
    """目标侧出口（默认 Burp）：httpx CLI 的 `-proxy`。Burp 不可达时 fail-closed 抛错。"""
    return target_proxy_url()


@lru_cache(maxsize=1)
def _egress_rate_limit() -> str:
    """httpx `-rl`：由 egress 节拍策略推导的每秒请求上限（默认 1 rps）。"""
    policy = PacingPolicy.from_env()
    if not policy.enabled:
        return "0"
    return str(max(1, int(round(policy.max_rps))))


def _httpx_egress_args() -> list[str]:
    """身份 + 出口 + 限速：避免 httpx 自报 UA、避免绕过 Burp、避免默认 10 并发猛打。"""
    args = ["-H", f"User-Agent: {_baseline_identity_ua()}"]
    proxy = _egress_proxy_url()
    if proxy:
        args += ["-proxy", proxy]
    rate_limit = _egress_rate_limit()
    if rate_limit != "0":
        args += ["-rl", rate_limit]
    return args


def _baseline_entry_fetcher(url: str, method: str) -> dict:
    """Fetch only compact response metadata for the bounded entry probe."""
    request = Request(url, method=method, headers={"User-Agent": _baseline_identity_ua()})  # noqa: S310
    proxy = _egress_proxy_url()
    # 显式 ProxyHandler：有代理走 Burp；没有也传 {} 以屏蔽环境代理（HTTP_PROXY→Clash）
    mapping = {"http": proxy, "https": proxy} if proxy else {}
    opener = build_opener(ProxyHandler(mapping), _NoRedirectHandler)
    try:
        with opener.open(request, timeout=_BASELINE_ENTRY_TIMEOUT) as response:
            body_hint = response.read(500).decode("utf-8", errors="replace")
            return {
                "status_code": int(response.getcode() or 0),
                "location": response.headers.get("Location", ""),
                "body_hint": body_hint[:500],
            }
    except HTTPError as exc:
        body_hint = exc.read(500).decode("utf-8", errors="replace") if exc.fp else ""
        return {
            "status_code": int(exc.code or 0),
            "location": exc.headers.get("Location", "") if exc.headers else "",
            "body_hint": body_hint[:500],
        }
    except (TimeoutError, URLError, OSError) as exc:
        return {"status_code": 0, "body_hint": type(exc).__name__}


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table,),
    ).fetchone()
    return row is not None


def ensure_asset_verification_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS target_assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_name TEXT NOT NULL,
            asset_type TEXT DEFAULT 'domain',
            asset_value TEXT NOT NULL,
            port INTEGER,
            protocol TEXT DEFAULT 'https',
            source TEXT DEFAULT 'manual',
            tech_stack TEXT,
            requires_auth INTEGER DEFAULT 0,
            status TEXT DEFAULT 'new',
            priority INTEGER DEFAULT 0,
            notes TEXT,
            created_at TEXT DEFAULT (datetime('now','localtime')),
            validated_at TEXT
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_target_assets_identity
            ON target_assets(target_name, asset_value, COALESCE(port, 443));
        CREATE TABLE IF NOT EXISTS asset_auth_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_name TEXT NOT NULL,
            asset_id INTEGER,
            url TEXT NOT NULL,
            entry_type TEXT NOT NULL CHECK(entry_type IN ('login','register')),
            source TEXT NOT NULL,
            confidence TEXT DEFAULT 'medium',
            status TEXT DEFAULT 'observed',
            notes TEXT,
            discovered_at TEXT DEFAULT (datetime('now','localtime')),
            UNIQUE(target_name, asset_id, url, entry_type, source)
        );
        """
    )
    additions = {
        "live_status": "TEXT DEFAULT 'unknown'",
        "last_status_code": "INTEGER",
        "last_title": "TEXT",
        "resolved_ip": "TEXT",
        "last_tech_stack": "TEXT",
        "last_verified_at": "TEXT",
        "last_verify_status": "TEXT",
        "auth_required": "INTEGER DEFAULT 0",
        "auth_entry_found": "INTEGER DEFAULT 0",
        "login_urls": "TEXT DEFAULT '[]'",
        "register_urls": "TEXT DEFAULT '[]'",
        "auth_blocker": "TEXT DEFAULT 'unknown'",
        "scope_status": "TEXT DEFAULT 'needs_review'",
        "scope_reason": "TEXT",
        "scope_class": "TEXT DEFAULT 'unknown'",
        "authorization_state": "TEXT DEFAULT 'unknown'",
        "relation_to_target": "TEXT",
    }
    existing = _columns(conn, "target_assets")
    for name, ddl in additions.items():
        if name not in existing:
            conn.execute(f"ALTER TABLE target_assets ADD COLUMN {name} {ddl}")
    conn.commit()


def _build_asset_url(asset_value: str, protocol: str | None = None, port: int | None = None) -> str:
    value = (asset_value or "").strip()
    if not value:
        return ""
    if value.startswith(("http://", "https://")):
        return value.rstrip("/")

    scheme = (protocol or "").strip().lower() or ("http" if port == 80 else "https")
    host = value.rstrip("/")
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443) or re.search(r":\d+$", host)):
        host = f"{host}:{port}"
    return f"{scheme}://{host}"


def get_target_urls(conn: sqlite3.Connection, target_name: str | None = None) -> list[str]:
    seen: set[str] = set()
    urls: list[str] = []

    def add(url: str) -> None:
        if url and url not in seen:
            seen.add(url)
            urls.append(url)

    if _table_exists(conn, "target_assets"):
        query = """
            SELECT asset_value, protocol, port
            FROM target_assets
            WHERE asset_value IS NOT NULL AND asset_value != ''
        """
        params: tuple[str, ...] = ()
        if target_name:
            query += " AND target_name=?"
            params = (target_name,)
        query += " ORDER BY id"
        for row in conn.execute(query, params).fetchall():
            add(_build_asset_url(row["asset_value"], row["protocol"], row["port"]))

    query = "SELECT domain FROM targets WHERE domain IS NOT NULL AND domain != ''"
    params = ()
    if target_name:
        query += " AND target_name=?"
        params = (target_name,)
    for row in conn.execute(query, params).fetchall():
        add(_build_asset_url(row["domain"]))

    return urls


def get_baseline_urls(conn: sqlite3.Connection, target_name: str) -> list[str]:
    """Return only explicitly authorized, in-scope asset URLs for L0."""
    if not _table_exists(conn, "target_assets"):
        return []
    rows = conn.execute(
        """SELECT asset_value, protocol, port FROM target_assets
           WHERE target_name=? AND asset_value IS NOT NULL AND asset_value != ''
             AND scope_status='in_scope'
             AND scope_class IN ('owned', 'authorized_vendor')
           ORDER BY id""",
        (target_name,),
    ).fetchall()
    seen: set[str] = set()
    urls: list[str] = []
    for row in rows:
        url = _build_asset_url(row["asset_value"], row["protocol"], row["port"])
        if url and url not in seen:
            seen.add(url)
            urls.append(url)
    return urls


def _resolve_target_db(target_name: str, db_value: str | None) -> Path:
    """Use an explicitly supplied DB when present and fail closed on mismatch."""
    path = Path(db_value) if db_value else find_db(target_name)
    if not path.is_file():
        raise ValueError(f"database file not found: {path}")
    with session(path, read_only=True) as check:
        row = check.execute("SELECT 1 FROM targets WHERE target_name=? LIMIT 1", (target_name,)).fetchone()
    if row is None:
        raise ValueError("target is not present in the explicit database")
    return path


def resolve_httpx_binary() -> str:
    """Prefer ProjectDiscovery httpx over the Python package's homonymous CLI."""
    candidates: list[str] = []

    go_bin = shutil.which("httpx")
    if go_bin:
        candidates.append(go_bin)

    for path_dir in os.environ.get("PATH", "").split(os.pathsep):
        if not path_dir:
            continue
        candidate = Path(path_dir) / "httpx.exe"
        if candidate.exists():
            candidate_str = str(candidate)
            if candidate_str not in candidates:
                candidates.append(candidate_str)

    for candidate_bin in candidates:
        try:
            result = subprocess.run(
                [candidate_bin, "-version"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except OSError:
            continue
        output = f"{result.stdout}\n{result.stderr}".lower()
        if "projectdiscovery" in output:
            return str(candidate_bin)

    sys.exit("[error] 未找到 ProjectDiscovery httpx，可用命令被同名 Python CLI 覆盖")


def run_httpx(urls: list[str]) -> list[dict]:
    httpx_bin = resolve_httpx_binary()

    # stdin 模式（2026-10-27 Lenovo 测绘实测）：Windows 下 httpx v1.12 的 `-l <file>`
    # 偶发在写完 banner 后长时间阻塞（进程 idle、无 CPU、不退出），导致 100-host 批次
    # 卡死 20+ 分钟；同一批 URL 走 stdin 立即返回。与 run_httpx_baseline 保持一致。
    # 同时显式 capture_output，避免子进程继承上层 stdout 管道后被管道背压卡住。
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("# stdin-mode marker\n")
        input_file = f.name

    out_file = input_file + ".json"
    cmd = [
        httpx_bin,
        "-sc",  # status code
        "-title",  # page title
        "-tech-detect",  # tech detection (Wappalyzer-based)
        "-server",  # Server header
        "-ip",  # resolved IP
        "-fr",  # follow redirects
        "-timeout",
        "10",
        "-threads",
        os.environ.get("INIT_SCAN_THREADS", "30"),
        "-json",
        "-o",
        out_file,
        "-silent",
        *_httpx_egress_args(),
    ]
    print(f"[httpx] 扫描 {len(urls)} 个 URL...")
    try:
        subprocess.run(cmd, check=False, timeout=240, capture_output=True, text=True,
                       input="\n".join(urls) + "\n")
    except subprocess.TimeoutExpired:
        print("[warn] httpx 超时")
    finally:
        os.unlink(input_file)

    results = []
    if os.path.exists(out_file):
        with open(out_file, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        results.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        os.unlink(out_file)
    return results


def run_httpx_baseline(urls: list[str], *, start_index: int = 0, budget: dict | None = None) -> dict:
    """Run one bounded L0 batch and expose subprocess state to the ledger.

    The legacy ``run_httpx`` contract intentionally remains unchanged.  This
    helper is only for baseline mode, where an empty result must not hide a
    failed/partial subprocess and a cursor must be resumable.
    """
    budget = budget or {}
    max_assets = max(1, int(budget.get("max_assets", len(urls) or 1)))
    start_index = max(0, min(int(start_index), len(urls)))
    batch = urls[start_index : start_index + max_assets]
    if not batch:
        return {"status": "succeeded", "results": [], "next_index": start_index}

    httpx_bin = resolve_httpx_binary()
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        # Filename is only used to derive the -o JSONL path; the URL list itself
        # is fed via stdin below.  On httpx v1.12.0 (Windows) the ``-l <file>``
        # argument mode hangs before printing its banner in some shell hosts,
        # while stdin mode returns immediately, so stdin is the reliable path.
        f.write("# stdin-mode marker\n")
        input_file = f.name
    out_file = input_file + ".json"
    cmd = [
        httpx_bin,
        "-sc",
        "-title",
        "-tech-detect",
        "-server",
        "-ip",
        "-fr",
        "-timeout",
        "10",
        "-threads",
        "10",
        "-json",
        "-o",
        out_file,
        "-silent",
        *_httpx_egress_args(),
    ]
    returncode = 0
    error: str | None = None
    try:
        try:
            completed = subprocess.run(
                cmd,
                check=False,
                timeout=int(budget.get("timeout_seconds", 120)),
                capture_output=True,
                text=True,
                input="\n".join(batch) + "\n",
            )
            returncode = int(getattr(completed, "returncode", 0) or 0)
            if returncode:
                error = f"httpx_exit_{returncode}"
        except subprocess.TimeoutExpired:
            error = "httpx_timeout"

        results: list[dict] = []
        if os.path.exists(out_file):
            with open(out_file, encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        results.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        else:
            error = error or "missing_jsonl"

        if error and results:
            status = "partial"
        elif error:
            status = "failed"
        else:
            status = "succeeded"
        return {
            "status": status,
            "results": results,
            # httpx emits only observed rows, so result count cannot identify
            # which input assets were skipped after a partial subprocess.
            # Re-run the same bounded batch on resume rather than lose assets.
            "next_index": start_index if error else start_index + len(batch),
            **({"error": error} if error else {}),
        }
    finally:
        for path in (input_file, out_file):
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass


def _strip_scheme(url: str) -> str:
    return url.replace("https://", "").replace("http://", "").rstrip("/")


def _asset_value(url: str) -> str:
    parsed = urlparse(url)
    if parsed.hostname:
        return parsed.hostname
    return _strip_scheme(url).split("/", 1)[0].split(":", 1)[0]


def _asset_port(url: str) -> int:
    parsed = urlparse(url)
    if parsed.port:
        return parsed.port
    if parsed.scheme == "http":
        return 80
    return 443


def _entry_urls(result: dict, pattern: re.Pattern[str]) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for field in ("url", "input", "final_url", "location", "redirect"):
        value = result.get(field)
        if isinstance(value, str) and pattern.search(value):
            found.append((value, field))
    title = result.get("title") or ""
    if isinstance(title, str) and pattern.search(title):
        found.append((result.get("url") or result.get("input") or "", "title"))
    for field in ("links", "a", "extracts"):
        values = result.get(field) or []
        if isinstance(values, str):
            values = [values]
        if isinstance(values, list):
            for value in values:
                if isinstance(value, str) and pattern.search(value):
                    found.append((value, field))
    dedup: dict[str, str] = {}
    for url, source in found:
        if url:
            dedup[url] = source
    return [(url, source) for url, source in dedup.items()]


def _json_list(values: list[str]) -> str:
    return json.dumps(sorted(set(values)), ensure_ascii=False)


def _live_status(status_code: int) -> str:
    if status_code in LIVE_STATUS_CODES:
        return "live"
    if status_code:
        return "dead"
    return "unknown"


def update_target(conn: sqlite3.Connection, result: dict, *, enqueue_pages: bool = True) -> dict:
    url = result.get("url", result.get("input", ""))
    status_code = result.get("status_code", 0)
    title = result.get("title", "")
    ip = result.get("host", "")
    tech_list: list = result.get("tech", []) or []
    tech_stack = ", ".join(tech_list) if tech_list else ""
    live_status = _live_status(int(status_code or 0))
    login_entries = _entry_urls(result, LOGIN_KEYWORDS)
    register_entries = _entry_urls(result, REGISTER_KEYWORDS)
    auth_entry_found = bool(login_entries or register_entries)

    # targets schema: id, target_name, domain, ip, tech_stack, requires_auth, auth_status, discovered_at, notes
    # match on full URL OR bare hostname (domain may be stored either way)
    hostname = _strip_scheme(url)
    rows_updated = conn.execute(
        "UPDATE targets SET tech_stack=?, ip=? WHERE domain=? OR domain=?",
        (tech_stack, ip, url, hostname),
    ).rowcount
    conn.commit()

    if rows_updated == 0:
        print(f"  [warn] targets 中未找到匹配域名: {hostname}（跳过更新）")

    needs_login = bool(LOGIN_KEYWORDS.search(title or "") or LOGIN_KEYWORDS.search(url or ""))
    if needs_login:
        print(f"  [!] 疑似登录页: {url} — {title}")

    needs_auth = status_code in AUTH_STATUS_CODES or bool(AUTH_KEYWORDS.search(title or "")) or bool(AUTH_KEYWORDS.search(url or ""))
    if needs_auth:
        print(f"  [!] 疑似需要认证: {url} (HTTP {status_code}) — {title}")

    if enqueue_pages and status_code in (200, 301, 302):
        conn.execute(
            "INSERT INTO pages (url, depth, status) VALUES (?, 0, 'queued') ON CONFLICT(url) DO NOTHING",
            (url,),
        )
        conn.commit()

    target_row = conn.execute(
        "SELECT target_name FROM targets WHERE domain=? OR domain=? LIMIT 1",
        (url, hostname),
    ).fetchone()
    if target_row is None and _table_exists(conn, "target_assets"):
        asset_value = _asset_value(url)
        asset_port = _asset_port(url)
        target_row = conn.execute(
            "SELECT target_name FROM target_assets WHERE asset_value=? AND COALESCE(port, 443)=? LIMIT 1",
            (asset_value, asset_port),
        ).fetchone()
    target_name = target_row["target_name"] if target_row else ""
    if target_name:
        asset_value = _asset_value(url)
        asset_port = _asset_port(url)
        protocol = "http" if str(url).startswith("http://") else "https"
        target_domain_row = conn.execute("SELECT domain FROM targets WHERE target_name=? LIMIT 1", (target_name,)).fetchone()
        target_domain = str(target_domain_row["domain"] or "").lower().rstrip(".") if target_domain_row else ""
        # hostname still carries ":port" for non-standard ports, which made the suffix
        # test fail and silently demote in-scope assets to needs_review/intel_only on
        # every baseline run.  asset_value is the port-free hostname from the same URL.
        asset_host = str(asset_value).lower().rstrip(".")
        is_owned = bool(target_domain and (asset_host == target_domain or asset_host.endswith("." + target_domain)))
        scope_status = "in_scope" if is_owned else "needs_review"
        scope_class = "owned" if is_owned else "intel_only"
        conn.execute(
            """
            INSERT INTO target_assets (
                target_name, asset_type, asset_value, port, protocol, source, tech_stack,
                status, validated_at, live_status, last_status_code, last_title,
                resolved_ip, last_tech_stack, last_verified_at, last_verify_status,
                auth_required, auth_entry_found, login_urls, register_urls, auth_blocker,
                scope_status, scope_reason, scope_class, authorization_state
            )
            VALUES (?, 'subdomain', ?, ?, ?, 'other', ?, 'validated', datetime('now','localtime'),
                    ?, ?, ?, ?, ?, datetime('now','localtime'), ?,
                    ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(target_name, asset_value, COALESCE(port, 443)) DO UPDATE SET
                port=excluded.port,
                protocol=excluded.protocol,
                tech_stack=excluded.tech_stack,
                status='validated',
                validated_at=datetime('now','localtime'),
                live_status=excluded.live_status,
                last_status_code=excluded.last_status_code,
                last_title=excluded.last_title,
                resolved_ip=excluded.resolved_ip,
                last_tech_stack=excluded.last_tech_stack,
                last_verified_at=datetime('now','localtime'),
                last_verify_status=excluded.last_verify_status,
                auth_required=excluded.auth_required,
                auth_entry_found=excluded.auth_entry_found,
                login_urls=excluded.login_urls,
                register_urls=excluded.register_urls,
                auth_blocker=excluded.auth_blocker,
                -- Scope fields: 基线验活只更新验证字段，不改动授权状态。
                -- 既有资产的 scope 由操作员清单/授权根域决定（targets.domain 只含
                -- init 单根域，旧逻辑会把多根域授权资产每次运行都降为
                -- needs_review/intel_only）。新插入资产走 VALUES 分支的默认值。
                scope_status=target_assets.scope_status,
                scope_reason=target_assets.scope_reason,
                scope_class=target_assets.scope_class,
                authorization_state=target_assets.authorization_state
            """,
            (
                target_name,
                asset_value,
                asset_port,
                protocol,
                tech_stack,
                live_status,
                status_code,
                title,
                ip,
                tech_stack,
                live_status,
                1 if needs_auth else 0,
                1 if auth_entry_found else 0,
                _json_list([u for u, _ in login_entries]),
                _json_list([u for u, _ in register_entries]),
                "login_required" if needs_auth else "none" if auth_entry_found else "unknown",
                scope_status,
                "same target root domain" if is_owned else "outside target root; passive intelligence only",
                scope_class,
                "inherited_target_scope" if is_owned else "unknown",
            ),
        )
        asset_id = conn.execute(
            "SELECT id FROM target_assets WHERE target_name=? AND asset_value=? AND COALESCE(port, 443)=?",
            (target_name, asset_value, asset_port),
        ).fetchone()["id"]
        for entry_type, entries in (("login", login_entries), ("register", register_entries)):
            for entry_url, source in entries:
                conn.execute(
                    """
                    INSERT INTO asset_auth_entries (
                        target_name, asset_id, url, entry_type, source, confidence, status, notes
                    )
                    VALUES (?, ?, ?, ?, ?, 'medium', 'observed', 'passive GET/HEAD/httpx signal only')
                    ON CONFLICT(target_name, asset_id, url, entry_type, source) DO UPDATE SET
                        discovered_at=datetime('now','localtime'),
                        status='observed'
                    """,
                    (target_name, asset_id, entry_url, entry_type, source),
                )
        conn.commit()

    return {"url": url, "needs_auth": needs_auth, "status_code": status_code}


def print_summary(results: list[dict]) -> None:
    print("\n=== init_scan 完成 ===")
    print(f"扫描: {len(results)} 个")
    live = [r for r in results if r.get("status_code", 0) in (200, 301, 302)]
    print(f"存活: {len(live)} 个")
    for r in live:
        tech = ", ".join(r.get("tech", []) or [])
        print(f"  {r.get('status_code')} {r.get('url')} [{tech or r.get('webserver', '')}]")


def main() -> None:
    parser = argparse.ArgumentParser(description="httpx 批量验活 + 技术指纹")
    parser.add_argument("--target", help="显式目标名")
    parser.add_argument("--db", help="显式 DB 路径；与 --target 一起锁定本次运行")
    parser.add_argument("--urls", help="逗号分隔的 URL 列表")
    parser.add_argument("--urls-file", help="URL 列表文件路径")
    parser.add_argument("--baseline", action="store_true", help="运行无队列副作用的 L0 广度验活")
    args = parser.parse_args()

    if args.baseline and (not args.target or not args.db):
        parser.error("--baseline requires both --target and --db")

    if args.baseline:
        db_path = _resolve_target_db(args.target, args.db)
        conn = connect(db_path)
        ensure_asset_verification_schema(conn)
        urls = get_baseline_urls(conn, args.target)
        budget = {"max_assets": 100, "timeout_seconds": 120, "max_results": 100}
        run = begin_recon_run(
            conn,
            target_name=args.target,
            source="init_scan_httpx_baseline",
            # Keep the run identity compact and stable: the asset set is
            # represented by the persisted cursor, not by every URL.
            input_data={"mode": "baseline", "adapter": "httpx", "version": 1},
            budget=budget,
        )
        prior_cursor = json.loads(run["cursor_json"] or "{}")
        start_index = int(prior_cursor.get("next_index", 0) or 0)
        if start_index >= len(urls):
            start_index = 0
        if not urls:
            update_recon_run(
                conn,
                run_id=int(run["id"]),
                status="blocked",
                cursor={"next_index": 0, "total": 0},
                budget=budget,
                summary={"requested": 0, "observed": 0, "reason": "no_authorized_assets"},
                next_retry_at=None,
            )
            conn.close()
            print_summary([])
            return
        try:
            outcome = run_httpx_baseline(urls, start_index=start_index, budget=budget)
            results = outcome["results"]
            for result in results:
                update_target(conn, result, enqueue_pages=False)
            next_index = min(int(outcome.get("next_index", start_index)), len(urls))
            status = str(outcome.get("status", "failed"))
            if status == "succeeded" and next_index < len(urls):
                status = "partial"
            retry_at = None
            if status in {"partial", "failed"}:
                retry_at = (datetime.now().astimezone().replace(microsecond=0) + timedelta(minutes=5)).isoformat()
            update_recon_run(
                conn,
                run_id=int(run["id"]),
                status=status,
                cursor={"next_index": next_index, "total": len(urls)},
                budget=budget,
                summary={
                    "requested": min(len(urls) - start_index, int(budget["max_assets"])),
                    "observed": len(results),
                    **({"error": outcome["error"]} if outcome.get("error") else {}),
                },
                last_success_at=(datetime.now().astimezone().isoformat(timespec="seconds") if status == "succeeded" else None),
                next_retry_at=retry_at,
            )
            if status == "succeeded":
                # Breadth over depth: 6 root-level candidates per asset covers
                # login+admin+api for every live asset (31 live x 6 = 186 < 200),
                # instead of spending the whole budget on the first 5 assets.
                entry_budget = {"per_asset_cap": 6, "total_cap": 200}
                entry_run = begin_recon_run(
                    conn,
                    target_name=args.target,
                    source="init_scan_baseline_entries",
                    input_data={"mode": "baseline", "adapter": "entry_probe", "version": 1},
                    budget=entry_budget,
                )
                try:
                    entry_result = run_baseline_entry_probe(
                        conn,
                        target_name=args.target,
                        fetcher=_baseline_entry_fetcher,
                        per_asset_cap=entry_budget["per_asset_cap"],
                        total_cap=entry_budget["total_cap"],
                    )
                    entry_status = (
                        "succeeded"
                        if entry_result.get("status") == "done"
                        else "blocked"
                        if entry_result.get("status") == "blocked"
                        else "failed"
                    )
                    entry_retry = None
                    if entry_status in {"blocked", "failed"}:
                        entry_retry = (datetime.now().astimezone().replace(microsecond=0) + timedelta(minutes=5)).isoformat()
                    update_recon_run(
                        conn,
                        run_id=int(entry_run["id"]),
                        status=entry_status,
                        cursor={"stage": "entries", "complete": entry_status == "succeeded"},
                        budget=entry_budget,
                        summary={
                            key: entry_result[key]
                            for key in ("assets_processed", "requests", "observations", "stop_reason")
                            if key in entry_result
                        },
                        last_success_at=(
                            datetime.now().astimezone().isoformat(timespec="seconds") if entry_status == "succeeded" else None
                        ),
                        next_retry_at=entry_retry,
                    )
                except Exception as exc:
                    update_recon_run(
                        conn,
                        run_id=int(entry_run["id"]),
                        status="failed",
                        cursor={"stage": "entries", "complete": False},
                        budget=entry_budget,
                        summary={"error": type(exc).__name__},
                        next_retry_at=(datetime.now().astimezone().replace(microsecond=0) + timedelta(minutes=5)).isoformat(),
                    )
        except Exception as exc:
            update_recon_run(
                conn,
                run_id=int(run["id"]),
                status="failed",
                cursor={"next_index": start_index, "total": len(urls)},
                budget=budget,
                summary={"requested": len(urls), "observed": 0, "error": type(exc).__name__},
                next_retry_at=(datetime.now().astimezone().replace(microsecond=0) + timedelta(minutes=5)).isoformat(),
            )
            conn.close()
            raise
        conn.close()
        print_summary(results)
        return

    urls: list[str] = []  # type: ignore[no-redef]  # 与函数前半段的分支变量同名，类型一致

    if args.urls:
        urls = [u.strip() for u in args.urls.split(",") if u.strip()]
    elif args.urls_file:
        with open(args.urls_file) as f:
            urls = [line.strip() for line in f if line.strip()]
    elif args.target:
        db_path = _resolve_target_db(args.target, args.db)
        conn = connect(db_path)
        ensure_asset_verification_schema(conn)
        urls = get_target_urls(conn, args.target)
        conn.close()
    else:
        parser.print_help()
        sys.exit(1)

    if not urls:
        sys.exit("[error] 无可扫描的 URL")

    results = run_httpx(urls)

    if args.target:
        db_path = _resolve_target_db(args.target, args.db)
        conn = connect(db_path)
        ensure_asset_verification_schema(conn)
        for r in results:
            update_target(conn, r)
        # seed_url 迁移: 旧 run_scan 链(唯一写入者)已归档, 由本脚本在验活后
        # 幂等回填 scan_state.seed_url, 保证 sqli_scan/ssrf_scan/xss_scan/race_scan
        # 等专项扫描器有种子 URL(它们都读 scan_state.seed_url, 为空直接退出)。
        seed_candidates = [r.get("url") for r in results if r.get("live")]
        seed_candidates = seed_candidates or [u for u in urls if u.startswith("http")]
        if seed_candidates:
            # 防御: scan_state 表在 schema.sql 中定义, 此处确保存在(旧 DB 可能缺失)
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_state (
                    id INTEGER PRIMARY KEY,
                    seed_url TEXT,
                    phase TEXT DEFAULT 'init'
                )
                """
            )
            scan_state_columns = _columns(conn, "scan_state")
            for column, ddl in (
                ("seed_url", "TEXT"),
                ("phase", "TEXT DEFAULT 'init'"),
                ("started_at", "TEXT"),
            ):
                if column not in scan_state_columns:
                    conn.execute(f"ALTER TABLE scan_state ADD COLUMN {column} {ddl}")
            conn.execute(
                """
                INSERT INTO scan_state (id, seed_url, phase, started_at)
                VALUES (1, ?, 'init', datetime('now','localtime'))
                ON CONFLICT(id) DO UPDATE SET
                    seed_url=CASE WHEN scan_state.seed_url IS NULL OR scan_state.seed_url=''
                                  THEN excluded.seed_url ELSE scan_state.seed_url END,
                    phase=CASE WHEN scan_state.phase IS NULL OR scan_state.phase=''
                               THEN 'init' ELSE scan_state.phase END
                """,
                (seed_candidates[0],),
            )
            conn.commit()
        conn.close()
        print(f"[db] 已更新 targets 表，DB: {db_path.name}")

    print_summary(results)


if __name__ == "__main__":
    main()
