"""竞态条件（Race Condition）扫描器。

从 hunt_queue 中识别竞态风险端点（支付/优惠券/积分/注册等），
用 HTTP/2 多路复用或 gate 同步发送并发请求，检测并记录竞态漏洞。

出口（`docs/modules/egress-traffic-shaping.md`）：身份与代理取自 `utils.egress`；
并发扇出**刻意**在一个显式的 unpaced 窗口（`egress.unpaced("race-window")`）里进行——
竞态复现依赖同时性，抖动节拍会直接破坏它。窗口内每个请求都用 `note_external()`
补台账，因此 egress_log 仍能暴露这段峰值 RPS 供强度声明使用。

用法:
  uv run python TOOLS/pipeline/race_scan.py --target "目标名"

写入:
  - findings (type='race_condition', risk='High') — 确认漏洞
  - suspicious_points (test_type='race_condition', risk='Medium') — 低置信度
"""

import argparse
import asyncio
import sqlite3
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from db.cookie_helper import get_auth_cookie_header  # noqa: E402
from db.db_utils import connect, find_db  # noqa: E402
from utils.egress import (  # noqa: E402
    Egress,
    EgressBlocked,
    EgressUnavailable,
    PacingPolicy,
    target_egress,
)
from utils.http_fetcher import async_fetch  # noqa: E402

RACE_N = 15
REQUEST_DELAY = 1.5  # 候选端点之间的冷却（在竞态窗口之外）

# 出口不可用时的可操作提示（fail-closed：宁可停下也不静默直连）。
EGRESS_HINT = "启动 Burp 监听 127.0.0.1:8080，或显式设置 EGRESS_MODE=direct EGRESS_ALLOW_DIRECT=1"


def build_egress(target: str, db_path: str | Path | None = None) -> Egress:
    """构造目标侧唯一出口（固定身份 + 节拍 + 熔断 + 台账）。"""
    return target_egress(target, db_path=db_path, policy=PacingPolicy.from_env())


def report_egress_unavailable(exc: Exception) -> None:
    """统一的 fail-closed 提示（stderr），调用方随后以非零码退出。"""
    print(f"[race_scan] 出口不可用，按 fail-closed 停止发包: {exc}", file=sys.stderr)
    print(f"[race_scan] {EGRESS_HINT}", file=sys.stderr)


def candidate_cooldown_s(egress: Egress) -> float:
    """候选端点之间的冷却：不短于 egress 节拍下限，也不短于原 REQUEST_DELAY。"""
    pacing = egress.preflight()["pacing"]
    return max(REQUEST_DELAY, float(pacing.get("min_gap_ms", 0) or 0) / 1000.0)


def single_proxy(egress: Egress) -> str | None:
    """async 出口需要一个单值代理：从 egress 取（burp 模式 = 127.0.0.1:8080）。"""
    proxies = egress.proxy_kwargs() or {}
    return proxies.get("http") or proxies.get("https")


RACE_KEYWORDS = frozenset(
    {
        "coupon",
        "redeem",
        "use",
        "apply",
        "voucher",
        "discount",
        "order",
        "pay",
        "deduct",
        "consume",
        "transfer",
        "withdraw",
        "register",
        "signup",
        "verify",
        "otp",
        "stock",
        "inventory",
        "limit",
        "quota",
        "balance",
        "point",
        "ticket",
        "charge",
        "refund",
        "exchange",
        "prize",
        "reward",
        "gift",
    }
)

SUCCESS_SIGNALS = frozenset(
    {
        '"code":0',
        '"code": 0',
        '"status":"ok"',
        '"status": "ok"',
        '"result":true',
        '"result": true',
        '"success":true',
        '"success": true',
        '"msg":"success"',
        '"msg": "success"',
        '"message":"ok"',
    }
)

ERROR_SIGNALS = frozenset(
    {
        '"error"',
        '"fail"',
        '"failed"',
        '"invalid"',
        '"expired"',
        '"already',
        '"duplicate"',
        "already used",
        '"consumed"',
    }
)


def _url_kw_cond(kw: str) -> str:
    """生成 URL 路径段精确匹配条件（防止 /use 误匹配 /user）。"""
    # 匹配：/kw/ 或 /kw? 或 /kw 结尾
    return f"(LOWER(url) LIKE '%/{kw}/%' OR LOWER(url) LIKE '%/{kw}?%' OR LOWER(url) LIKE '%/{kw}')"


def find_race_candidates(conn: sqlite3.Connection) -> list[dict]:
    """找竞态风险端点。首选 hunt_queue(旧管线输入, 兼容); 空则回退
    endpoint_observations(新管线接口地图, entry_recursion/auth_explore 写入)。"""
    # business_intent: simple LIKE match (free-text field)
    # url: path-segment match to avoid e.g. "use" matching "user"
    intent_conds = " OR ".join(f"LOWER(business_intent) LIKE '%{kw}%'" for kw in sorted(RACE_KEYWORDS))
    url_conds = " OR ".join(_url_kw_cond(kw) for kw in sorted(RACE_KEYWORDS))
    # Keywords are hardcoded constants, not user input — S608 false positive
    where_clause = f"({intent_conds} OR {url_conds})"
    if _table_exists(conn, "hunt_queue"):
        sql = (
            "SELECT method, url, query_string, body, content_type,"  # noqa: S608
            " business_intent, notes, target_id FROM hunt_queue"
            f" WHERE status = 'queued' AND {where_clause} LIMIT 10"
        )
        rows = conn.execute(sql).fetchall()
        if rows:
            return [dict(r) for r in rows]

    # 回退: endpoint_observations(新管线), 匹配 canonical_url 路径段
    ep_url_conds = " OR ".join(_url_kw_cond(kw) for kw in sorted(RACE_KEYWORDS))
    if _table_exists(conn, "endpoint_observations"):
        ep_sql = (
            "SELECT method, canonical_url AS url, '' AS query_string, '' AS body,"  # noqa: S608
            " 'application/json' AS content_type, '' AS business_intent, '' AS notes,"
            " asset_id AS target_id FROM endpoint_observations"
            f" WHERE {ep_url_conds} LIMIT 10"
        )
        try:
            rows = conn.execute(ep_sql).fetchall()
        except sqlite3.Error:
            rows = []
        if rows:
            return [dict(r) for r in rows]
    return []


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
    return row is not None


def is_race_detected(responses: list) -> tuple[bool, str]:
    """分析并发响应，判断是否存在竞态条件。"""
    successes = 0
    total = len(responses)
    for r in responses:
        if isinstance(r, Exception):
            continue
        if r.status_code not in (200, 201, 204):
            continue
        body_sample = r.text[:500]
        body_lower = body_sample.lower()
        has_success = any(sig.lower() in body_lower for sig in SUCCESS_SIGNALS)
        has_error = any(sig.lower() in body_lower for sig in ERROR_SIGNALS)
        if has_success and not has_error:
            successes += 1
        elif r.status_code in (200, 201) and not has_error and not has_success:
            successes += 1
    if successes >= 2:
        return True, f"{successes}/{total} 并发请求均返回成功响应（预期仅 1 次成功）"
    return False, f"仅 {successes}/{total} 请求成功，未检测到竞态"


async def http2_race(
    url: str,
    method: str,
    headers: dict,
    body: bytes | None,
    proxy: str | None,
    n: int = RACE_N,
) -> list:
    """HTTP/2 多路复用并发 — 同一连接发送 N 个请求。"""
    try:
        tasks = [
            async_fetch(
                url,
                method=method,
                headers=headers,
                data=body,
                timeout=15.0,
                verify=False,
                proxy=proxy,
                http2=True,
            )
            for _ in range(n)
        ]
        return await asyncio.gather(*tasks, return_exceptions=True)
    except Exception as exc:
        return [exc] * n


async def gate_race(
    url: str,
    method: str,
    headers: dict,
    body: bytes | None,
    proxy: str | None,
    n: int = RACE_N,
) -> list:
    """Gate/last-byte sync — 所有连接同时释放。"""
    gate = asyncio.Event()

    async def _one():
        await gate.wait()
        return await async_fetch(
            url,
            method=method,
            headers=headers,
            data=body,
            timeout=15.0,
            verify=False,
            proxy=proxy,
            http2=False,
        )

    tasks = [asyncio.create_task(_one()) for _ in range(n)]
    await asyncio.sleep(0.05)
    gate.set()
    return await asyncio.gather(*tasks, return_exceptions=True)


def run_fanout(
    egress: Egress,
    url: str,
    method: str,
    headers: dict,
    body: bytes | None,
    n: int = RACE_N,
) -> tuple[list, str]:
    """在显式 unpaced 窗口里并发扇出，返回 (responses, kernel)。

    同时性语义保持不变：窗口内不做任何节拍等待，全部请求仍然共享同一固定身份与同一
    出口代理。扇出不经过 `egress.request()`，因此逐个用 `note_external()` 补台账。
    """
    proxy = single_proxy(egress)
    with egress.unpaced("race-window"):
        responses = asyncio.run(http2_race(url, method, headers, body, proxy, n))
        real_resps = [r for r in responses if not isinstance(r, Exception)]
        kernel = "http2"
        if len(real_resps) < n // 2:
            responses = asyncio.run(gate_race(url, method, headers, body, proxy, n))
            kernel = "gate"
    for response in responses:
        if isinstance(response, Exception):
            egress.note_external(url, method=method, status=0, note=f"async-race:{kernel}", decision="error")
        else:
            egress.note_external(url, method=method, status=int(response.status_code), note=f"async-race:{kernel}")
    return responses, kernel


def write_race_finding(
    conn: sqlite3.Connection,
    target_id: int,
    url: str,
    method: str,
    evidence: str,
    n_success: int,
) -> bool:
    """写入 findings 表，去重返回 False。"""
    existing = conn.execute("SELECT id FROM findings WHERE url=? AND type='race_condition'", (url,)).fetchone()
    if existing:
        return False
    finding_id = f"F-RACE-{uuid.uuid4().hex[:8]}"
    conn.execute(
        """INSERT INTO findings
           (id, target_id, type, url, method, payload, evidence, risk, cvss, remediation, confirmed_at)
           VALUES (?, ?, 'race_condition', ?, ?, ?, ?, 'High',
                   'CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N',
                   '使用幂等令牌（idempotency key）或数据库唯一约束防止重复操作',
                   datetime('now','localtime'))""",
        (finding_id, target_id, url, method, f"race_n_success={n_success}", evidence),
    )
    conn.commit()
    return True


def write_race_sp(
    conn: sqlite3.Connection,
    target_id: int,
    url: str,
    method: str,
    evidence: str,
) -> bool:
    """写入 suspicious_points，去重返回 False。"""
    existing = conn.execute(
        "SELECT id FROM suspicious_points WHERE url=? AND param=? AND test_type=?",
        (url, method, "race_condition"),
    ).fetchone()
    if existing:
        return False
    sp_id = f"SP-RACE-{uuid.uuid4().hex[:8]}"
    conn.execute(
        """INSERT INTO suspicious_points
           (id, url, param, method, test_type, evidence, source, risk, test_status, created_at)
           VALUES (?, ?, ?, ?, 'race_condition', ?, 'race_scan', 'Medium', 'untested',
                   datetime('now','localtime'))""",
        (sp_id, url, method, method, evidence),
    )
    conn.commit()
    return True


def _build_headers(candidate: dict, cookie_header: str | None, egress: Egress) -> dict:
    """身份（含 User-Agent）统一取自 egress 固定身份；脚本不再自带 UA 字面量。"""
    extra: dict[str, str] = {}
    if candidate.get("content_type"):
        extra["Content-Type"] = candidate["content_type"]
    if cookie_header:
        extra["Cookie"] = cookie_header
    return egress.identity.headers(profile="repeater", extra=extra)


def _build_body(candidate: dict) -> bytes | None:
    raw = candidate.get("body") or ""
    return raw.encode() if raw else None


def main() -> None:
    parser = argparse.ArgumentParser(description="竞态条件扫描器")
    parser.add_argument("--target", required=True)
    args = parser.parse_args()

    db_path = find_db(args.target)

    # 出口先于任何发包构造：Burp 不可达时 fail-closed 退出（竞态扇出绝不静默直连）。
    try:
        egress = build_egress(args.target, db_path)
    except EgressUnavailable as exc:
        report_egress_unavailable(exc)
        sys.exit(1)

    conn = connect(db_path)

    seed_row = conn.execute("SELECT seed_url FROM scan_state WHERE id=1").fetchone()
    seed_domain = seed_row[0] if seed_row and seed_row[0] else ""
    cookie_header = get_auth_cookie_header(str(db_path), seed_domain, role="primary")

    target_row = conn.execute("SELECT id FROM targets WHERE target_name=?", (args.target,)).fetchone()
    target_id = target_row[0] if target_row else 1

    candidates = find_race_candidates(conn)
    cooldown = candidate_cooldown_s(egress)
    print(f"[race_scan] 找到 {len(candidates)} 个竞态候选端点  并发 N={RACE_N}  候选冷却={cooldown:.1f}s")

    found_findings = 0
    found_sp = 0
    stop_reason = ""

    try:
        for cand in candidates:
            url = cand["url"]
            method = cand["method"]
            headers = _build_headers(cand, cookie_header, egress)
            body = _build_body(cand)

            print(f"  [*] 测试 {method} {url}")
            try:
                responses, kernel = run_fanout(egress, url, method, headers, body)
                if kernel == "gate":
                    print("    [!] HTTP/2 失败率高，降级为 gate sync")
            except (EgressUnavailable, EgressBlocked):
                raise
            except Exception as exc:
                print(f"    [!] 请求异常: {exc}")
                time.sleep(cooldown)
                continue

            detected, evidence = is_race_detected(responses)
            success_count = sum(1 for r in responses if not isinstance(r, Exception) and r.status_code in (200, 201, 204))

            if detected:
                ok = write_race_finding(conn, target_id, url, method, evidence, success_count)
                if ok:
                    found_findings += 1
                    print(f"    [+] RACE CONFIRMED: {evidence}")
            elif success_count >= 1:
                ok = write_race_sp(conn, target_id, url, method, evidence)
                if ok:
                    found_sp += 1
                    print(f"    [?] SP: {evidence}")

            time.sleep(cooldown)
    except EgressUnavailable as exc:
        report_egress_unavailable(exc)
        conn.close()
        sys.exit(1)
    except EgressBlocked as exc:
        stop_reason = exc.reason
        print(f"[race_scan] 出口熔断，停止发包（{stop_reason}）: {exc}", file=sys.stderr)

    conn.close()
    print(f"\n[RACE_SCAN] candidates={len(candidates)} findings={found_findings} sp={found_sp}")
    summary = egress.summary()
    print(f"[race_scan] egress: sent={summary['sent']} peak_rps={summary['peak_rps']} stop_reason={summary['stop_reason'] or 'none'}")
    if stop_reason:
        sys.exit(1)


if __name__ == "__main__":
    main()
