"""Bounded, unauthenticated pre-auth probe adapter.

The adapter is intentionally small: it probes only one explicitly authorized
asset, never sends credentials, and stores compact response facts only.

身份与节拍（`docs/modules/egress-traffic-shaping.md`）：身份 UA 取自 `utils.egress`
的固定身份（不再自报名号），默认最小间隔也由 egress 节拍策略推导。本模块保持
「纯函数 + 注入 fetcher」的结构，因此不直接接入 Egress 的请求路径与台账。
"""

from __future__ import annotations

import hashlib
import sys
import time
import urllib.error
import urllib.request
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable

TOOLS_DIR = Path(__file__).resolve().parent.parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from entry_probe import generate_candidates  # noqa: E402 -- 必须排在 sys.path bootstrap 之后
from recon.preauth import ProbeBudget, classify_response  # noqa: E402 -- 必须排在 sys.path bootstrap 之后
from recon.recon_store import ensure_recon_schema, record_entry  # noqa: E402 -- 必须排在 sys.path bootstrap 之后
from recon.scope import is_active_scope  # noqa: E402 -- 必须排在 sys.path bootstrap 之后
from utils.egress import PacingPolicy, load_identity, target_proxy_map  # noqa: E402 -- 必须排在 sys.path bootstrap 之后

FetchResult = dict[str, Any]
Fetcher = Callable[[str, str], FetchResult]


@lru_cache(maxsize=1)
def identity_headers() -> tuple[tuple[str, str], ...]:
    """固定身份头：UA 取 `utils.egress` 统一身份，不再自报工具名号。

    返回元组以便 lru_cache 缓存（避免每个候选都读盘）。
    """
    return (
        ("User-Agent", load_identity().user_agent),
        ("Accept", "text/html,application/json,*/*;q=0.1"),
    )


def default_min_interval_seconds(policy: PacingPolicy | None = None) -> float:
    """从 egress 节拍策略推导默认探测间隔（秒）：不再写死均匀 2s。

    默认策略下（max_rps=0.5 → 2s、min_gap_ms=900）结果仍是 2.0s，但改
    `EGRESS_MAX_RPS` / `EGRESS_MIN_GAP_MS` 即可整体调节，且与其它出口同源。
    """
    pacing = policy or PacingPolicy.from_env()
    if not pacing.enabled:
        return 0.0
    return max(1.0 / max(pacing.max_rps, 1e-6), pacing.min_gap_ms / 1000.0)


def _fetch(url: str, method: str) -> FetchResult:
    request = urllib.request.Request(  # noqa: S310 - URL 来自已授权资产清单
        url, method=method, headers=dict(identity_headers())
    )
    # 目标侧出口与治理层一致（默认 Burp）；Burp 不可达时 target_proxy_map 抛 EgressUnavailable（fail-closed）。
    # 非 Burp 模式下一律用 ProxyHandler({})：显式关掉环境代理（本机 HTTP_PROXY 指向 Clash 9870）。
    proxies = target_proxy_map()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler(proxies or {}))
    try:
        with opener.open(request, timeout=10) as response:  # noqa: S310 - URL 来自已授权资产清单
            body = response.read(4096).decode("utf-8", errors="replace") if method != "HEAD" else ""
            return {
                "status_code": int(response.status),
                "location": response.headers.get("Location", ""),
                "final_url": response.geturl(),
                "content_type": response.headers.get("Content-Type", ""),
                "body": body,
            }
    except urllib.error.HTTPError as exc:
        body = exc.read(4096).decode("utf-8", errors="replace")
        return {
            "status_code": int(exc.code),
            "location": exc.headers.get("Location", ""),
            "final_url": url,
            "content_type": exc.headers.get("Content-Type", ""),
            "body": body,
        }
    except (OSError, ValueError) as exc:
        return {"status_code": 0, "location": "", "final_url": url, "content_type": "", "body": "", "error": str(exc)}


def _fingerprint(body: str) -> str:
    return hashlib.sha256((body or "")[:4096].encode("utf-8", errors="replace")).hexdigest()[:16]


def run_preauth_probe(
    conn,
    *,
    target_name: str,
    asset_id: int,
    base_url: str,
    known_urls: list[str] | tuple[str, ...] = (),
    tech_stack: list[str] | tuple[str, ...] = (),
    methods: tuple[str, ...] = ("HEAD", "GET"),
    max_requests: int = 30,
    min_interval_seconds: float | None = None,
    fetcher: Fetcher | None = None,
) -> dict[str, Any]:
    ensure_recon_schema(conn)
    if min_interval_seconds is None:
        # 未显式指定时由 egress 节拍策略给出（默认仍是 2.0s），避免散落魔法数。
        min_interval_seconds = default_min_interval_seconds()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS preauth_probe_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT, target_name TEXT NOT NULL,
            asset_id INTEGER, endpoint_group TEXT, max_requests INTEGER NOT NULL DEFAULT 30,
            request_count INTEGER NOT NULL DEFAULT 0, min_interval_seconds REAL NOT NULL DEFAULT 2,
            status TEXT NOT NULL DEFAULT 'running', stop_reason TEXT,
            evidence_refs_json TEXT NOT NULL DEFAULT '[]',
            started_at TEXT DEFAULT (datetime('now','localtime')), finished_at TEXT
        );
        CREATE TABLE IF NOT EXISTS operator_inbox (
            id INTEGER PRIMARY KEY AUTOINCREMENT, target_name TEXT NOT NULL,
            related_work_item_id INTEGER, kind TEXT NOT NULL, title TEXT NOT NULL,
            detail TEXT, suggested_action TEXT, url TEXT, status TEXT NOT NULL DEFAULT 'open'
        );
        """
    )
    asset = conn.execute(
        "SELECT asset_value,scope_status,scope_class,authorization_state,live_status FROM target_assets WHERE id=? AND target_name=?",
        (asset_id, target_name),
    ).fetchone()
    if asset is None:
        raise ValueError("asset not found")
    if not is_active_scope(asset["scope_class"], asset["scope_status"]):
        raise PermissionError("preauth probe requires an active owned or explicitly authorized vendor asset")
    conn.execute(
        """INSERT INTO preauth_probe_runs(target_name,asset_id,endpoint_group,max_requests,min_interval_seconds,status)
           VALUES(?,?,?,?,?,'running')""",
        (target_name, asset_id, base_url, max_requests, min_interval_seconds),
    )
    run_id = int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])
    conn.commit()
    budget = ProbeBudget(max_requests=max_requests, min_interval_seconds=min_interval_seconds)
    fetch = fetcher or _fetch
    candidates = generate_candidates(base_url, known_urls=known_urls, tech_stack=tech_stack)
    observations: list[dict[str, Any]] = []
    waf_blocked = False
    try:
        for candidate in candidates:
            for method in methods:
                method = method.upper()
                if method not in {"GET", "HEAD", "OPTIONS"}:
                    continue
                now = time.monotonic()
                if not budget.allow(now=now):
                    break
                budget.record(now=now)
                result = fetch(candidate.url, method)
                body = str(result.get("body", ""))
                response_class = classify_response(
                    int(result.get("status_code", 0) or 0),
                    location=str(result.get("location", "")),
                    body=body,
                )
                record_entry(
                    conn,
                    target_name=target_name,
                    asset_id=asset_id,
                    url=candidate.url,
                    entry_type=candidate.entry_type,
                    source=f"preauth_probe:{method}",
                    status="observed",
                    status_code=int(result.get("status_code", 0) or 0),
                    confidence=candidate.confidence,
                    response_class=response_class,
                    notes="bounded unauthenticated probe",
                )
                observations.append(
                    {
                        "url": candidate.url,
                        "entry_type": candidate.entry_type,
                        "method": method,
                        "status_code": int(result.get("status_code", 0) or 0),
                        "response_class": response_class,
                        "content_type": str(result.get("content_type", ""))[:120],
                        "fingerprint": _fingerprint(body),
                    }
                )
                if response_class == "waf_blocked":
                    budget.stop("waf_blocked")
                    waf_blocked = True
                    break
                if min_interval_seconds:
                    time.sleep(min_interval_seconds)
            if budget.stop_reason or budget.request_count >= budget.max_requests:
                break
        status = "blocked" if waf_blocked else "done"
        stop_reason = budget.stop_reason or ("budget_exhausted" if budget.request_count >= max_requests else None)
        conn.execute(
            """UPDATE preauth_probe_runs SET request_count=?,status=?,stop_reason=?,finished_at=datetime('now','localtime') WHERE id=?""",
            (budget.request_count, status, stop_reason, run_id),
        )
        if waf_blocked:
            conn.execute(
                """INSERT INTO operator_inbox(target_name,related_work_item_id,kind,title,detail,suggested_action,url,status)
                   VALUES(?,?,?,?,?,?,?,'open')""",
                (
                    target_name,
                    None,
                    "manual_review",
                    f"Pre-auth probe stopped for {asset['asset_value']}",
                    "WAF/rate-limit response stopped the bounded probe; no automatic retry or proxy rotation.",
                    "Wait for operator decision or cooldown",
                    base_url,
                ),
            )
        conn.commit()
        return {
            "status": status,
            "summary": f"pre-auth probe observed={len(observations)} requests={budget.request_count}",
            "observations": observations[:30],
            "waf_blocked": waf_blocked,
            "stop_reason": stop_reason,
            "next_action": "review public/auth boundary facts" if not waf_blocked else "operator_gate",
        }
    except Exception:
        conn.execute(
            "UPDATE preauth_probe_runs SET request_count=?,status='failed',stop_reason='adapter_error',finished_at=datetime('now','localtime') WHERE id=?",
            (budget.request_count, run_id),
        )
        conn.commit()
        raise
