"""按站点自己声明的 chunk 清单抓取懒加载 JS，产出供 `js_recon.py` 消费的文件集。

边界（与 `js_chunk_manifest.py` 的分工）
----------------------------------------
- `js_chunk_manifest.py`：纯离线解析，不发包。
- 本模块：**发包**，因此必须受受管出口（`TOOLS/utils/egress.py`）串行低频约束，
  并自己再做三道硬门：

  1. **同源门**：默认只抓入口 URL 的同一 origin。跨域（CDN/微前端）必须在
     `--allow-host` 里显式列白名单——因为 CDN 上的 chunk 属于第三方资产，
     `AGENTS.md` 要求第三方资产不主动测试。
  2. **预算门**：`--max-chunks`（默认 60）与 `--max-bytes`（默认 24 MiB）双上限，
     到位即停并记录 `stop_reason`，不静默截断。
  3. **不猜门**：只抓解析出来的候选 URL，不做路径字典、不做后缀探测、不做目录列举。
     候选自带 `confidence`，`--min-confidence` 可只抓高置信。

为什么需要它
------------
SPA 的 chunk 按路由懒加载，未访问页面的 JS 永不请求，接口地图在那一块全空。
本模块把「站点自己声明存在的 chunk」拉回来，交给既有 `js_recon.py` 走采集+还原+落库，
不重复实现那套工具链。

用法
----
    # 先只解析不抓取，看会抓到什么（零风险）
    .venv/Scripts/python.exe TOOLS/pipeline/chunk_discover.py \
        --url "https://target.example/" --dry-run

    # 实际抓取（走受管出口，串行）
    .venv/Scripts/python.exe TOOLS/pipeline/chunk_discover.py \
        --url "https://target.example/" --out tmp/chunks/target --max-chunks 40

    # 微前端：CDN 上的 chunk 必须显式放行
    ... --allow-host cdn.example.com
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

TOOLS_DIR = Path(__file__).resolve().parent.parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from db.db_utils import force_utf8_stdout  # noqa: E402
from utils.js_chunk_manifest import (  # noqa: E402
    extract_declared_chunks,
    extract_entry_scripts,
    parse_chunk_manifest,
)

DEFAULT_MAX_CHUNKS = 60
DEFAULT_MAX_BYTES = 24 * 1024 * 1024
DEFAULT_MAX_BYTES_PER_FILE = 4 * 1024 * 1024
CONFIDENCE_ORDER = {"high": 0, "medium": 1, "low": 2}


class ScopeViolation(RuntimeError):
    """候选 URL 的 host 不在允许范围内。"""


def _host(url: str) -> str:
    return (urlparse(url).netloc or "").lower()


def _same_site(url: str, entry_url: str) -> bool:
    """同源判定：host 完全一致。端口不同视为不同（避免误抓管理端口）。"""
    return _host(url) == _host(entry_url)


def check_scope(url: str, *, entry_url: str, allow_hosts: set[str]) -> None:
    """候选 URL 必须落在同源或显式白名单里，否则抛 ScopeViolation。"""
    host = _host(url)
    if _same_site(url, entry_url):
        return
    if host in allow_hosts:
        return
    raise ScopeViolation(f"跨域候选需显式 --allow-host 放行：{host} ({url})")


def _safe_name(url: str) -> str:
    """把 URL 变成稳定、无路径穿越风险的文件名。"""
    path = urlparse(url).path
    name = path.rsplit("/", 1)[-1] or "index.js"
    # 同名不同目录时用 host+path 的哈希后缀区分，避免互相覆盖
    import hashlib

    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:8]
    stem = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in name)[:80]
    return f"{digest}_{stem}"


def _fetch_text(egress: Any, url: str) -> tuple[str, int, str]:
    """经受管出口取文本。返回 (text, status, error)。

    必须用 `recon.auth_surface.fetch_asset` 而不是裸 `egress.get`：
    Yakit 文本通道对 >10KB 的响应会截断并附
    `... (truncated; set save-packet=true ...)`。真机实测该目标入口页
    （20,443 B）在 9,923 字符处被截断，`</html>` 都拿不到——而 SPA 的入口
    `<script>` 往往在文件末尾，截断会让「入口脚本数 = 0」，后续推导全落空。
    `fetch_asset` 会识别截断标记并自动改用 save-packet 全量重取。
    """
    try:
        from recon.auth_surface import fetch_asset  # 与本项目的既有实现复用，不重写
    except Exception:  # 兜底：导入失败时退回裸取，但记录
        fetch_asset = None  # type: ignore[assignment]

    if fetch_asset is not None:
        try:
            text, meta = fetch_asset(egress, url, timeout=15.0, note=f"chunk-discover:{url}"[:120])
        except Exception as exc:
            return "", 0, f"{type(exc).__name__}: {exc}"
        status = int(meta.get("status", 0) or 0)
        if status == 0:
            return "", 0, "no status"
        if meta.get("truncated"):
            return text, status, "响应被出口通道截断且 save-packet 重取失败（结果不完整）"
        return text, status, ""

    try:
        result = egress.get(url)
    except Exception as exc:
        return "", 0, f"{type(exc).__name__}: {exc}"
    status = int(getattr(result, "status_code", 0) or 0)
    if status == 0:
        return "", 0, str(getattr(result, "error", "") or "no status")
    text = str(result.text or "")
    if "(truncated" in text:
        return text, status, "响应被出口通道截断（save-packet 重取不可用，结果不完整）"
    return text, status, ""


def discover(
    entry_url: str,
    *,
    out_dir: Path,
    egress: Any,
    allow_hosts: set[str] | None = None,
    max_chunks: int = DEFAULT_MAX_CHUNKS,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_bytes_per_file: int = DEFAULT_MAX_BYTES_PER_FILE,
    min_confidence: str = "low",
    dry_run: bool = False,
    max_rounds: int = 2,
) -> dict[str, Any]:
    """抓取入口 HTML → 找 runtime → 解析 chunk 清单 → 抓 chunk。

    返回结构化结果（含 stop_reason 与逐条失败原因），不抛业务异常。
    """
    allow = {h.lower() for h in (allow_hosts or set())}
    min_rank = CONFIDENCE_ORDER.get(min_confidence, 2)

    report: dict[str, Any] = {
        "entry_url": entry_url,
        "out_dir": str(out_dir),
        "dry_run": dry_run,
        "entry_scripts": [],
        "declared_chunks": [],
        "declared_chunk_count": 0,
        "rounds": [],
        "fetched": [],
        "skipped": [],
        "failed": [],
        "warnings": [],
        "stop_reason": None,
        "total_bytes": 0,
    }

    html, status, error = _fetch_text(egress, entry_url)
    if not html:
        report["stop_reason"] = f"入口页抓取失败 status={status} error={error}"
        return report
    report["entry_status"] = status

    scripts = extract_entry_scripts(html, base_url=entry_url)
    declared = extract_declared_chunks(html, base_url=entry_url)
    report["entry_scripts"] = scripts
    report["declared_chunks"] = [item["url"] for item in declared]
    report["declared_chunk_count"] = len(declared)

    # 入口脚本要抓回来才能读出 webpack 运行时清单（通常只几个）；
    # HTML 里 rel=prefetch/preload 已声明的 chunk 不需要再"发现"，直接进候选。
    pending: list[dict[str, Any]] = [{"url": u, "chunk_id": "", "confidence": "high", "via": "entry-script"} for u in scripts]
    pending.extend({"url": item["url"], "chunk_id": item["chunk_id"], "confidence": "high", "via": item["via"]} for item in declared)
    seen_urls: set[str] = set()
    budgets_exhausted = False
    # 「未识别出清单」只在**所有**文件都没解析出清单时才成立。chunk 文件本身不含
    # 清单是正常的，逐文件收集会把这条警告误报出来（实测踩过）。
    manifests_found = 0
    deferred_no_manifest_warning: str | None = None

    for round_index in range(max_rounds):
        if not pending:
            break
        round_info: dict[str, Any] = {"round": round_index + 1, "scanned": len(pending), "new_candidates": 0}
        next_pending: list[dict[str, Any]] = []

        for item in pending:
            url = item["url"]
            if url in seen_urls:
                continue
            seen_urls.add(url)

            # ---- 同源/白名单门 ----
            try:
                check_scope(url, entry_url=entry_url, allow_hosts=allow)
            except ScopeViolation as exc:
                report["skipped"].append({"url": url, "reason": str(exc), "gate": "scope"})
                continue

            # ---- 预算门 ----
            if len(report["fetched"]) >= max_chunks:
                report["stop_reason"] = f"已达 --max-chunks={max_chunks}"
                budgets_exhausted = True
                break
            if report["total_bytes"] >= max_bytes:
                report["stop_reason"] = f"已达 --max-bytes={max_bytes}"
                budgets_exhausted = True
                break

            if dry_run and item.get("via") != "entry-script":
                # 预演模式：入口/入口脚本已真实抓取（否则算不出计划），
                # 只对「由清单推导出来的 chunk」不抓，报告里标为 planned。
                report["fetched"].append(
                    {
                        "url": url,
                        "chunk_id": item.get("chunk_id", ""),
                        "confidence": item.get("confidence", "low"),
                        "via": item.get("via", ""),
                        "planned_only": True,
                    }
                )
                continue

            text, st, err = _fetch_text(egress, url)
            if not text:
                report["failed"].append({"url": url, "status": st, "error": err})
                continue
            if len(text.encode("utf-8", errors="ignore")) > max_bytes_per_file:
                report["skipped"].append({"url": url, "reason": "超过单文件上限", "gate": "size"})
                continue

            saved = _write_js(out_dir, url, text)
            report["total_bytes"] += len(text.encode("utf-8", errors="ignore"))
            report["fetched"].append(
                {
                    "url": url,
                    "chunk_id": item.get("chunk_id", ""),
                    "confidence": item.get("confidence", "high"),
                    "via": item.get("via", ""),
                    "status": st,
                    "saved": str(saved),
                    "bytes": len(text.encode("utf-8", errors="ignore")),
                }
            )

            # ---- 从已抓到的文件里继续找下一层 chunk 清单 ----
            parsed = parse_chunk_manifest(text, base_url=entry_url)
            if parsed["candidates"]:
                manifests_found += 1
            for warning in parsed["warnings"]:
                if warning.startswith("未识别出"):
                    # 暂存：只有全部文件都没清单时才需要这条
                    deferred_no_manifest_warning = warning
                elif warning not in report["warnings"]:
                    report["warnings"].append(warning)
            for cand in parsed["candidates"]:
                if CONFIDENCE_ORDER.get(cand["confidence"], 2) > min_rank:
                    continue
                if cand["url"] in seen_urls:
                    continue
                next_pending.append(cand)
            round_info["new_candidates"] += len(next_pending)

        report["rounds"].append(round_info)
        if budgets_exhausted:
            break
        pending = next_pending

    if manifests_found == 0 and deferred_no_manifest_warning:
        report["warnings"].append(deferred_no_manifest_warning)
        report["manifests_found"] = 0
    else:
        report["manifests_found"] = manifests_found

    if report["stop_reason"] is None:
        report["stop_reason"] = "清单已走完（无更多候选）"
    return report


def _write_js(out_dir: Path, url: str, text: str) -> Path:
    js_dir = out_dir / "js"
    js_dir.mkdir(parents=True, exist_ok=True)
    path = js_dir / _safe_name(url)
    path.write_text(text, encoding="utf-8", newline="\n")
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="按站点声明的 chunk 清单抓取懒加载 JS")
    parser.add_argument("--url", required=True, help="入口 URL（必须已授权）")
    parser.add_argument("--out", help="输出目录（默认 tmp/chunks/<host>）")
    parser.add_argument("--allow-host", action="append", default=[], help="额外放行的 host（CDN/微前端）")
    parser.add_argument("--max-chunks", type=int, default=DEFAULT_MAX_CHUNKS)
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    parser.add_argument("--min-confidence", choices=["high", "medium", "low"], default="low")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="预演：抓入口页与入口脚本（否则算不出计划），但不抓由清单推导出的 chunk",
    )
    parser.add_argument("--json", action="store_true", help="输出 JSON")
    args = parser.parse_args(argv)

    force_utf8_stdout()

    from utils.egress import target_egress  # 延迟导入：--dry-run 也仍然要发包取入口页

    out_dir = Path(args.out) if args.out else Path("tmp") / "chunks" / (_host(args.url) or "target")

    try:
        egress = target_egress(args.url)
    except Exception as exc:
        print(f"[FAIL] 受管出口不可用：{type(exc).__name__}: {exc}", file=sys.stderr)
        print("       本工具 fail-closed，不降级直连。检查 EGRESS_MODE / Yakit / Burp。", file=sys.stderr)
        return 2

    report = discover(
        args.url,
        out_dir=out_dir,
        egress=egress,
        allow_hosts=set(args.allow_host),
        max_chunks=args.max_chunks,
        max_bytes=args.max_bytes,
        min_confidence=args.min_confidence,
        dry_run=args.dry_run,
    )

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(f"入口: {report['entry_url']}  (status={report.get('entry_status')})")
        print(f"入口脚本: {len(report['entry_scripts'])} 个 | HTML 已声明 chunk: {report.get('declared_chunk_count', 0)} 个")
        print(f"抓取: {len(report['fetched'])} 个 | 跳过: {len(report['skipped'])} | 失败: {len(report['failed'])}")
        print(f"总字节: {report['total_bytes']}")
        print(f"停止原因: {report['stop_reason']}")
        for warning in report["warnings"]:
            print(f"  warn: {warning}")
        for failed in report["failed"][:10]:
            print(f"  fail: {failed['url']} status={failed['status']} {failed['error'][:80]}")
        if not args.dry_run:
            print(f"产物目录: {out_dir / 'js'}")
            print("下一步: 用 js_recon.py 逐个消费这些文件（本工具不落库）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
