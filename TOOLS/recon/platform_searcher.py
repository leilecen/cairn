"""多平台公开情报搜索工具。
通过 Playwright CDP 连接已登录的 Chrome，在多个平台搜索关键词并保存结果。

用法:
  uv run python TOOLS/recon/platform_searcher.py --keyword "之江实验室" --target "目标名" --db path.db
  uv run python TOOLS/recon/platform_searcher.py --keyword "之江实验室" --platforms github,yuque
  uv run python TOOLS/recon/platform_searcher.py --keyword "target" --cdp-port 9222

依赖: playwright（browser-use 已自带）
"""

import argparse
import asyncio
import json
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from playwright.async_api import async_playwright

# ── 配置 ────────────────────────────────────────────────────────────────────
DEFAULT_CDP_PORT = 9222
RESULTS_DIR = Path(__file__).resolve().parent.parent.parent / "tmp"
KEYWORDS_CODE = ["password", "secret", "key", "config", "token", "access", "ak sk"]
KEYWORDS_SENSITIVE = [
    "password",
    "secret",
    "token",
    "api_key",
    "api-key",
    "apikey",
    "access_key",
    "secret_key",
    "private_key",
    "ssh-key",
    "-----begin",
    "ak=",
    "sk=",
    "endpoint",
    "bucket",
    "region",
    "username",
    "passwd",
    "redis://",
    "mysql://",
    "postgres://",
    "mongodb://",
    "conn_str",
    "connection_string",
    "jwt_secret",
    "session_secret",
    "auth_token",
    "bearer",
]


def now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ═══════════════════════════════════════════════════════════════════════════════
#  GitHub
# ═══════════════════════════════════════════════════════════════════════════════


async def search_github(page, keyword: str) -> list[dict]:
    """GitHub 代码搜索 + 仓库搜索"""
    results = []
    seen_urls = set()

    for suffix in [""] + [f" {kw}" for kw in KEYWORDS_CODE]:
        q = f'"{keyword}"{suffix}' if suffix else f'"{keyword}"'
        try:
            url = f"https://github.com/search?q={q.replace(' ', '+')}&type=code"
            await page.goto(url, wait_until="domcontentloaded", timeout=15_000)
            await asyncio.sleep(2)

            items = await page.evaluate("""
                () => {
                    const r = [];
                    document.querySelectorAll('[data-testid=\"results-list\"] > div').forEach(div => {
                        const link = div.querySelector('a');
                        if (link) r.push({title: link.textContent.trim(), href: link.href});
                    });
                    if (!r.length) {
                        document.querySelectorAll('.code-list-item .title a').forEach(a => {
                            r.push({title: a.textContent.trim(), href: a.href});
                        });
                    }
                    return r.slice(0, 5);
                }
            """)
            for item in items or []:
                h = item.get("href", "")
                if h and h not in seen_urls:
                    seen_urls.add(h)
                    results.append({"source": "github_code", "query": q, **item})
        except Exception as e:
            print(f"    [warn] GitHub code '{q[:30]}': {e}", file=sys.stderr)

    # ── 仓库搜索 ──
    try:
        url = f"https://github.com/search?q={keyword}&type=repositories"
        await page.goto(url, wait_until="domcontentloaded", timeout=15_000)
        await asyncio.sleep(2)
        items = await page.evaluate("""
            () => {
                const r = [];
                document.querySelectorAll('[data-testid=\"results-list\"] > div').forEach(div => {
                    const link = div.querySelector('a[href*=\"/\"]');
                    if (link && link.href.includes('github.com/')) r.push({title: link.textContent.trim(), href: link.href});
                });
                return r.slice(0, 10);
            }
        """)
        for item in items or []:
            h = item.get("href", "")
            if h and h not in seen_urls:
                seen_urls.add(h)
                results.append({"source": "github_repo", "query": f"repo:{keyword}", **item})
    except Exception as e:
        print(f"    [warn] GitHub repo: {e}", file=sys.stderr)

    return results


# ═══════════════════════════════════════════════════════════════════════════════
#  语雀
# ═══════════════════════════════════════════════════════════════════════════════


async def search_yuque(page, keyword: str) -> list[dict]:
    """语雀搜索"""
    try:
        url = f"https://www.yuque.com/search?q={keyword}&type=doc"
        await page.goto(url, wait_until="domcontentloaded", timeout=15_000)
        await asyncio.sleep(3)

        is_logged_in = await page.evaluate("!document.body.innerText.includes('快速注册')")
        if not is_logged_in:
            print("    [info] 语雀未登录", file=sys.stderr)

        items = await page.evaluate("""
            () => {
                const r = [];
                document.querySelectorAll('a').forEach(a => {
                    const text = a.textContent.trim();
                    const href = a.href;
                    if (text && text.length > 3 && href && !href.includes('/login') && !href.includes('/terms')) {
                        r.push({title: text.substring(0, 150), href: href});
                    }
                });
                return r;
            }
        """)
        # 去重 + 过滤导航类链接
        seen = set()
        filtered = []
        for it in items or []:
            h = it["href"]
            if h in seen or "/yuque/" in h or "yuque.com/terms" in h:
                continue
            seen.add(h)
            filtered.append({"source": "yuque", "query": keyword, **it})

        return filtered[:30]
    except Exception as e:
        print(f"    [warn] 语雀: {e}", file=sys.stderr)
        return []


# ═══════════════════════════════════════════════════════════════════════════════
#  Gitee
# ═══════════════════════════════════════════════════════════════════════════════


async def search_gitee(page, keyword: str) -> list[dict]:
    """Gitee 代码搜索 + 仓库搜索"""
    results = []
    seen_urls = set()

    for q in [keyword, keyword + " password", keyword + " secret", keyword + " config"]:
        try:
            url = f"https://search.gitee.com/?type=code&q={q.replace(' ', '+')}"
            await page.goto(url, wait_until="domcontentloaded", timeout=15_000)
            await asyncio.sleep(2)
            items = await page.evaluate("""
                () => {
                    const r = [];
                    document.querySelectorAll('a[href*=\"gitee.com/\"]').forEach(a => {
                        const t = a.textContent.trim();
                        if (t && t.length > 2 && t.length < 200) r.push({title: t, href: a.href});
                    });
                    return r;
                }
            """)
            for item in items or []:
                h = item.get("href", "")
                if h and h not in seen_urls:
                    seen_urls.add(h)
                    results.append({"source": "gitee_code", "query": q, **item})
        except Exception as e:
            print(f"    [warn] Gitee code '{q[:20]}': {e}", file=sys.stderr)

    for q in [keyword, keyword.replace("之江实验室", "zhejianglab")]:
        try:
            url = f"https://search.gitee.com/?type=repository&q={q}"
            await page.goto(url, wait_until="domcontentloaded", timeout=15_000)
            await asyncio.sleep(2)
            items = await page.evaluate("""
                () => {
                    const r = [];
                    document.querySelectorAll('.project-title a, a[href*=\"gitee.com/\"][title]').forEach(a => {
                        const t = a.textContent.trim();
                        if (t && t.length > 2 && t.length < 200) r.push({title: t, href: a.href});
                    });
                    return r;
                }
            """)
            for item in items or []:
                h = item.get("href", "")
                if h and h not in seen_urls:
                    seen_urls.add(h)
                    results.append({"source": "gitee_repo", "query": f"repo:{q}", **item})
        except Exception as e:
            print(f"    [warn] Gitee repo '{q[:20]}': {e}", file=sys.stderr)

    return results


# ═══════════════════════════════════════════════════════════════════════════════
#  凌风云盘 (lingfengyun.com)
# ═══════════════════════════════════════════════════════════════════════════════


async def search_lingfeng(page, keyword: str) -> list[dict]:
    """凌风云盘搜索"""
    try:
        url = f"https://www.lingfengyun.com/search?q={keyword}"
        await page.goto(url, wait_until="domcontentloaded", timeout=15_000)
        await asyncio.sleep(3)

        items = await page.evaluate("""
            () => {
                const r = [];
                document.querySelectorAll('.resource-item a, .search-result-item a, .list-group a, .panel a[href*=\"pan\"]').forEach(a => {
                    const t = a.textContent.trim();
                    const h = a.href;
                    if (t && t.length > 2) r.push({title: t.substring(0, 150), href: h});
                });
                // fallback: 所有有意义的链接
                if (!r.length) {
                    document.querySelectorAll('a[href]').forEach(a => {
                        const t = a.textContent.trim();
                        const h = a.href;
                        if (t && t.length > 3 && !h.includes('javascript')) r.push({title: t.substring(0, 150), href: h});
                    });
                }
                return r;
            }
        """)
        filtered = [{"source": "lingfengyun", "query": keyword, **it} for it in (items or [])]
        return filtered[:30]
    except Exception as e:
        print(f"    [warn] 凌风云盘: {e}", file=sys.stderr)
        return []


# ═══════════════════════════════════════════════════════════════════════════════
#  入口
# ═══════════════════════════════════════════════════════════════════════════════


async def run_searches(
    keyword: str,
    platforms: list[str],
    cdp_port: int = DEFAULT_CDP_PORT,
    output_file: Optional[str] = None,
    target_name: Optional[str] = None,
    db_path: Optional[str] = None,
) -> dict:
    """在所有指定平台搜索，返回结构化结果"""
    cdp_url = f"http://localhost:{cdp_port}"

    SEARCH_MAP = {
        "github": search_github,
        "yuque": search_yuque,
        "gitee": search_gitee,
        "lingfengyun": search_lingfeng,
    }

    # 值类型混合（platforms 是 dict[str, list]，total 是 int），显式 Any 让下游索引/累加可检查
    results: dict[str, Any] = {"keyword": keyword, "timestamp": now(), "platforms": {}}

    async with async_playwright() as p:
        browser = await p.chromium.connect_over_cdp(cdp_url)
        ctx = browser.contexts[0]
        n_cookies = len(await ctx.cookies())
        print(f"[OK] Chrome 已连接 (cookies: {n_cookies})", file=sys.stderr)

        for name in platforms:
            searcher = SEARCH_MAP.get(name)
            if not searcher:
                print(f"[skip] 未知平台: {name}", file=sys.stderr)
                continue

            print(f"\n=== {name} ===", file=sys.stderr)
            page = await ctx.new_page()
            try:
                t0 = time.time()
                data = await searcher(page, keyword)
                elapsed = time.time() - t0
                results["platforms"][name] = data
                print(f"  → {len(data)} 条 ({elapsed:.0f}s)", file=sys.stderr)
            finally:
                await page.close()

    # 汇总
    total = sum(len(v) for v in results["platforms"].values())
    results["total"] = total
    print(f"\n=== 汇总: {total} 条 ===", file=sys.stderr)

    if output_file:
        out_path = Path(output_file)
    else:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_kw = keyword.replace(" ", "_")[:20]
        out_path = RESULTS_DIR / f"{safe_kw}_search_{ts}.json"

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print(f"[OK] 结果保存: {out_path}", file=sys.stderr)

    if target_name and db_path:
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
        from db.db_utils import connect
        from recon.recon_store import record_source

        conn = connect(db_path)
        try:
            for platform, data in results["platforms"].items():
                record_source(
                    conn,
                    target_name=target_name,
                    source_kind=platform,
                    query=keyword,
                    result={"items": data[:50], "total": len(data)},
                )
        finally:
            conn.close()
        print(f"[OK] 结构化结果已写入 recon_sources: {target_name}", file=sys.stderr)

    return results


def main():
    parser = argparse.ArgumentParser(description="多平台公开情报搜索")
    parser.add_argument("--keyword", "-k", required=True, help="搜索关键词")
    parser.add_argument(
        "--platforms",
        "-p",
        default="github,yuque,gitee,lingfengyun",
        help="平台列表，逗号分隔 (默认: github,yuque,gitee,lingfengyun)",
    )
    parser.add_argument("--cdp-port", type=int, default=DEFAULT_CDP_PORT, help="Chrome CDP 端口")
    parser.add_argument("--output", "-o", help="输出文件路径")
    parser.add_argument("--target", help="目标名；与 --db 一起使用时写入 recon_sources")
    parser.add_argument("--db", help="SQLite DB 路径；需配合 --target")
    args = parser.parse_args()

    platforms = [p.strip() for p in args.platforms.split(",") if p.strip()]

    print(f"[开始] 关键词: {args.keyword}", file=sys.stderr)
    print(f"[开始] 平台: {', '.join(platforms)}", file=sys.stderr)
    print(f"[开始] CDP: localhost:{args.cdp_port}", file=sys.stderr)

    asyncio.run(
        run_searches(
            args.keyword,
            platforms,
            args.cdp_port,
            args.output,
            target_name=args.target,
            db_path=args.db,
        )
    )


if __name__ == "__main__":
    main()
