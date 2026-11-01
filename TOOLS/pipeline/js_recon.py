"""单文件 JS 分析入口：把已观测脚本串过采集层与还原层，落库为 js_signals / js_signal_clusters。

设计原则（`docs/modules/js-analysis-toolchain.md`）：
- **只消费已观测/已加载脚本**：输入是本地 `local_path`（浏览器/`js_files` 已落盘的 JS 或 source map），
  本工具不向目标发任何请求（唯一来源是已落盘文件）。
- **工具链先于 AI 精读**：采集层 jsluice → 还原层 webcrack / gitleaks / Retire.js → 落库；
  契约层复用 `TOOLS/recon/phase_a_adapters.py`（命令构造 + 输出归一化），不自己拼命令行。
- **密钥绝不留原文**：jsluice secrets 的 `data`、gitleaks 的 `Secret/Match` 一律丢弃，
  只保留 rule/kind + 位置。
- **每步失败都记 blocker，不中断**：单个工具炸了不影响其余步骤与落库。

用法:
  .venv\\Scripts\\python.exe TOOLS/pipeline/js_recon.py --target "example-client" --js-id 123
  .venv\\Scripts\\python.exe TOOLS/pipeline/js_recon.py --file tmp/recon/case/app.js --case case
  .venv\\Scripts\\python.exe TOOLS/pipeline/js_recon.py --target "X" --js-id 1 --promote --min-score 70
"""

from __future__ import annotations

import argparse
import json
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent  # pipeline/ → TOOLS/ → SRC/
TOOLS_DIR = Path(__file__).resolve().parent.parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from db.db_utils import connect, find_db, force_utf8_stdout  # noqa: E402
from recon import phase_a_adapters as adapters  # noqa: E402
from utils.js_signal_store import insert_js_signal, promote_js_candidates, upsert_js_cluster  # noqa: E402

BIN_DIR = TOOLS_DIR / "bin"
JS_TOOLS_DIR = TOOLS_DIR / "js-tools"
REVERSE_ROOT = PROJECT_ROOT / "tmp" / "js_reverse"
DEFAULT_TIMEOUT = 120

# 路径关键词 → 风险加权（命中说明更值得人工看一眼，不代表漏洞）
RISK_KEYWORDS = {
    "admin": 25,
    "manage": 20,
    "internal": 25,
    "debug": 20,
    "upload": 20,
    "export": 15,
    "download": 15,
    "token": 25,
    "secret": 25,
    "user": 10,
    "order": 10,
    "pay": 15,
    "sql": 25,
    "query": 10,
    "exec": 25,
    "file": 15,
    "path": 15,
    "url": 10,
}


def _tool_path(name: str) -> str | None:
    """解析工具可执行文件：Go 二进制在 TOOLS/bin，npm 工具在 js-tools/node_modules/.bin。"""
    if name in {"urlfinder", "jsluice", "x8", "gitleaks"}:
        candidate = BIN_DIR / f"{name}.exe"
        return str(candidate) if candidate.is_file() else None
    shim_dir = JS_TOOLS_DIR / "node_modules" / ".bin"
    for suffix in (".cmd", ".ps1", ""):
        candidate = shim_dir / f"{name}{suffix}"
        if candidate.is_file():
            return str(candidate)
    return None


def _run(command: list[str], *, timeout: int = DEFAULT_TIMEOUT, input_text: str | None = None, cwd: Path | None = None) -> dict[str, Any]:
    """执行外部工具；返回 {returncode, stdout, stderr, error}。不抛异常。"""
    try:
        completed = subprocess.run(  # noqa: S603 - 命令由 build_* 契约构造，非用户拼接
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
            input=input_text,
            cwd=str(cwd) if cwd else None,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"returncode": -1, "stdout": "", "stderr": "", "error": f"{type(exc).__name__}: {exc}"}
    return {
        "returncode": completed.returncode,
        "stdout": completed.stdout or "",
        "stderr": completed.stderr or "",
        "error": None,
    }


# ── 输出解析（密钥只留类型与位置） ────────────────────────────────────────────


def jsluice_url_rows(payload: str) -> list[dict[str, Any]]:
    """逐行解析 jsluice urls 的 NDJSON，保留 url/参数/方法/触发类型。"""
    rows: list[dict[str, Any]] = []
    for line in payload.splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict):
            continue
        url = str(row.get("url") or "").strip()
        if not url:
            continue
        rows.append(
            {
                "url": url,
                "params": [str(value) for value in (row.get("queryParams") or [])],
                "body_params": [str(value) for value in (row.get("bodyParams") or [])],
                "method": str(row.get("method") or "").strip().upper() or "GET",
                "kind": str(row.get("type") or "unknown"),
            }
        )
    return rows


def jsluice_secret_rows(payload: str) -> list[dict[str, Any]]:
    """解析 jsluice secrets：**丢弃 data/context**（含密钥原文），只留类型/严重度/文件。"""
    rows: list[dict[str, Any]] = []
    for line in payload.splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict):
            continue
        kind = str(row.get("kind") or row.get("rule") or "").strip()
        if not kind:
            continue
        rows.append(
            {
                "kind": kind,
                "severity": str(row.get("severity") or "unknown").strip().lower(),
                "file": str(row.get("filename") or "?").strip() or "?",
            }
        )
    return rows


def risk_for_path(path: str) -> int:
    lowered = (path or "").lower()
    return min(90, sum(weight for keyword, weight in RISK_KEYWORDS.items() if keyword in lowered))


# ── 流水线 ────────────────────────────────────────────────────────────────────


def _signals_from_jsluice(rows: list[dict[str, Any]], *, js_file_id: int | None, page_route: str) -> list[dict[str, Any]]:
    signals: list[dict[str, Any]] = []
    for row in rows:
        signals.append(
            {
                "signal_type": "js_endpoint",
                "method": row["method"],
                "url": row["url"],
                "params": row["params"] + row["body_params"],
                "caller_hint": row["kind"],
                "page_route": page_route,
                "evidence_location": f"jsluice:urls:{row['kind']}",
                "evidence_snippet": row["url"][:180],
                "confidence": 70,
                "risk_score": risk_for_path(row["url"]),
            }
        )
    return signals


def _signals_from_secrets(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    weight = {"critical": 85, "high": 75, "medium": 60, "low": 45}
    return [
        {
            "signal_type": "secret_candidate",
            "business_hint": row["kind"],
            "evidence_location": f"jsluice:secrets:{row['file']}",
            "evidence_snippet": f"{row['kind']} ({row['severity']})",
            "confidence": weight.get(row["severity"], 50),
            "risk_score": weight.get(row["severity"], 50),
        }
        for row in rows
    ]


def _signals_from_retire(items: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    signals = []
    for item in items:
        severity = str(item.get("severity") or "unknown").lower()
        signals.append(
            {
                "signal_type": "vulnerable_lib",
                "business_hint": f"{item.get('component')}@{item.get('version')}",
                "signature_hint": str(item.get("cve") or ""),
                "evidence_location": "retirejs",
                "evidence_snippet": f"{item.get('component')} {item.get('version')} {item.get('cve')} ({severity})",
                "confidence": 80 if severity in {"high", "critical"} else 60,
                "risk_score": 85 if severity in {"high", "critical"} else 65,
            }
        )
    return signals


def _signals_from_gitleaks(items: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "signal_type": "secret_candidate",
            "business_hint": str(item.get("rule") or ""),
            "evidence_location": f"gitleaks:{item.get('file')}:{item.get('line')}",
            "evidence_snippet": f"gitleaks rule={item.get('rule')} line={item.get('line')}",
            "confidence": 60,
            "risk_score": 60,
        }
        for item in items
    ]


def find_source_map_url(js_text: str) -> str:
    """从文件尾注释里取 sourceMappingURL（不抓取，只登记线索）。"""
    for line in reversed(js_text.splitlines()[-5:]):
        stripped = line.strip()
        for marker in ("//# sourceMappingURL=", "//@ sourceMappingURL=", "/*# sourceMappingURL="):
            if marker in stripped:
                value = stripped.split(marker, 1)[1].strip().rstrip("*/").strip()
                return value
    return ""


def analyze_js_file(
    js_path: Path,
    *,
    case: str,
    target_name: str = "",
    js_file_id: int | None = None,
    page_route: str = "",
    skip: frozenset[str] = frozenset(),
    timeout: int = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """跑完单文件流水线，返回 compact 摘要（含 signals，供落库）。"""
    out_dir = REVERSE_ROOT / case
    out_dir.mkdir(parents=True, exist_ok=True)
    blockers: list[dict[str, str]] = []
    warnings: list[str] = []
    tools_used: dict[str, str] = {}
    signals: list[dict[str, Any]] = []
    restored: list[dict[str, Any]] = []

    js_text = ""
    try:
        js_text = js_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        blockers.append({"tool": "read", "reason": f"{type(exc).__name__}: {exc}"})

    # 1) 采集层：jsluice urls / secrets
    jsluice = _tool_path("jsluice")
    if jsluice and "jsluice" not in skip:
        tools_used["jsluice"] = jsluice
        url_run = _run(adapters.build_jsluice_command(jsluice, js_path), timeout=timeout)
        if url_run["error"] or url_run["returncode"] != 0:
            blockers.append({"tool": "jsluice", "reason": url_run["error"] or f"exit_{url_run['returncode']}"})
        else:
            rows = jsluice_url_rows(url_run["stdout"])
            compact = adapters.parse_jsluice_fixture(url_run["stdout"])
            (out_dir / "jsluice_urls.ndjson").write_text(url_run["stdout"], encoding="utf-8")
            signals += _signals_from_jsluice(rows, js_file_id=js_file_id, page_route=page_route)
            if compact.get("status") == "blocked" and rows:
                warnings.append("jsluice_contract_parse_failed")
        secret_run = _run([jsluice, "secrets", str(js_path)], timeout=timeout)
        if secret_run["returncode"] == 0:
            secret_rows = jsluice_secret_rows(secret_run["stdout"])
            (out_dir / "jsluice_secrets.json").write_text(json.dumps(secret_rows, ensure_ascii=False, indent=1), encoding="utf-8")
            signals += _signals_from_secrets(secret_rows)
        else:
            warnings.append("jsluice_secrets_failed")
    elif not jsluice:
        blockers.append({"tool": "jsluice", "reason": "binary_missing"})

    # 2) 还原层：webcrack 反混淆（产物目录随后一起送 gitleaks/Retire.js）
    webcrack = _tool_path("webcrack")
    restore_dir = out_dir / "webcrack"
    if webcrack and "webcrack" not in skip:
        tools_used["webcrack"] = webcrack
        # webcrack 对已存在的非空输出目录会直接失败（exit 1），重跑前先清掉自己的产物目录
        if restore_dir.exists():
            shutil.rmtree(restore_dir, ignore_errors=True)
        run = _run(adapters.build_webcrack_command(webcrack, js_path, restore_dir), timeout=timeout)
        if run["returncode"] != 0:
            blockers.append({"tool": "webcrack", "reason": run["error"] or f"exit_{run['returncode']}"})
        else:
            restored_files = sorted(str(path.relative_to(restore_dir).as_posix()) for path in restore_dir.rglob("*") if path.is_file())
            manifest = json.dumps({"files": [{"path": name, "bytes": 0} for name in restored_files]})
            parsed = adapters.parse_webcrack_fixture(manifest)
            if parsed.get("status") == "blocked":
                warnings.append("webcrack_manifest_unparsed")
    elif not webcrack:
        blockers.append({"tool": "webcrack", "reason": "binary_missing"})

    scan_dir = restore_dir if restored else js_path.parent

    # 3) gitleaks（必须 detect --source --no-git）
    gitleaks = _tool_path("gitleaks")
    if gitleaks and "gitleaks" not in skip:
        tools_used["gitleaks"] = gitleaks
        report = out_dir / "gitleaks.json"
        run = _run(adapters.build_gitleaks_command(gitleaks, scan_dir, report), timeout=timeout)
        # 有命中时 exit=1 属正常；解析不依赖退出码
        if not report.is_file():
            blockers.append({"tool": "gitleaks", "reason": run["error"] or f"exit_{run['returncode']}"})
        else:
            parsed = adapters.parse_gitleaks_fixture(report.read_text(encoding="utf-8"))
            if parsed.get("status") == "blocked":
                blockers.append({"tool": "gitleaks", "reason": "parse_failed"})
            else:
                items = parsed.get("items") or []
                signals += _signals_from_gitleaks(items)
                if not items:
                    # 实测结论：本机 8.30.1 对 AWS key/PEM/ghp_ 全部 0 命中，
                    # 0 命中不能当成「没有密钥」——显式警告，改看 jsluice secrets。
                    warnings.append("gitleaks_zero_findings(may_under_report; 以 jsluice secrets 为准)")
    elif not gitleaks:
        blockers.append({"tool": "gitleaks", "reason": "binary_missing"})

    # 4) Retire.js（已知漏洞库）
    retire = _tool_path("retire")
    if retire and "retire" not in skip:
        tools_used["retire"] = retire
        run = _run(adapters.build_retirejs_command(retire, scan_dir), timeout=timeout)
        if run["stdout"].strip():
            parsed = adapters.parse_retirejs_fixture(run["stdout"])
            (out_dir / "retire.json").write_text(run["stdout"], encoding="utf-8")
            if parsed.get("status") == "blocked":
                blockers.append({"tool": "retirejs", "reason": "parse_failed"})
            else:
                signals += _signals_from_retire(parsed.get("items") or [])
        else:
            blockers.append({"tool": "retirejs", "reason": run["error"] or f"exit_{run['returncode']}"})
    elif not retire:
        blockers.append({"tool": "retirejs", "reason": "binary_missing"})

    # 5) source map 线索（只登记 URL，不抓取：抓取属于新的目标侧请求，须经 Egress）
    source_map_url = find_source_map_url(js_text)
    if source_map_url:
        signals.append(
            {
                "signal_type": "source_map",
                "url": source_map_url,
                "evidence_location": "sourceMappingURL",
                "evidence_snippet": source_map_url[:180],
                "confidence": 60,
                "risk_score": 20,
            }
        )

    summary = {
        "case": case,
        "target": target_name,
        "js_file_id": js_file_id,
        "js_path": str(js_path),
        "scan_dir": str(scan_dir),
        "out_dir": str(out_dir),
        "tools": tools_used,
        "signals": signals,
        "signal_count": len(signals),
        "restored_files": restored[:50],
        "restored_count": len(restored),
        "source_map_url": source_map_url,
        "blockers": blockers,
        "warnings": warnings,
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=1), encoding="utf-8")
    return summary


# ── 落库 ──────────────────────────────────────────────────────────────────────


def store_signals(db_path: Path, summary: Mapping[str, Any], *, promote: bool = False, min_score: int = 70) -> dict[str, Any]:
    """把 signals 写进 js_signals，并聚成 js_signal_clusters；可选按分数晋级。"""
    conn = connect(db_path)
    result = {"inserted": 0, "duplicates": 0, "clusters": 0, "promoted": 0}
    try:
        row = conn.execute("SELECT id FROM targets WHERE target_name=?", (summary.get("target") or "",)).fetchone()
        target_id = row[0] if row else None
        js_file_id = summary.get("js_file_id")
        # 计数以事实表为准：底层可能用 INSERT OR IGNORE，调用方拿不到「是否真的写入」，
        # 所以用插入前后的实际行数差来报告，避免把去重当成功计数（也曾把 signal_count 写虚）。
        before_total = (
            conn.execute("SELECT COUNT(*) FROM js_signals WHERE js_file_id=?", (js_file_id,)).fetchone()[0] if js_file_id is not None else 0
        )
        before_clusters = conn.execute("SELECT COUNT(*) FROM js_signal_clusters").fetchone()[0]
        for signal in summary.get("signals") or []:
            try:
                signal_id = insert_js_signal(
                    conn,
                    target_id,
                    js_file_id,
                    signal,
                    source_kind="toolchain",
                    commit=False,
                )
            except sqlite3.IntegrityError:
                result["duplicates"] += 1
                continue
            try:
                upsert_js_cluster(conn, target_id, signal_id, commit=False)
                result["clusters"] += 1
            except (sqlite3.Error, ValueError):
                pass
        if js_file_id is not None:
            actual = conn.execute("SELECT COUNT(*) FROM js_signals WHERE js_file_id=?", (js_file_id,)).fetchone()[0]
            result["inserted"] = max(0, actual - before_total)
            result["duplicates"] = max(result["duplicates"], len(summary.get("signals") or []) - result["inserted"])
            result["clusters"] = max(0, conn.execute("SELECT COUNT(*) FROM js_signal_clusters").fetchone()[0] - before_clusters)
            conn.execute(
                "UPDATE js_files SET extraction_status='extracted', analyzed_at=datetime('now','localtime'),"
                " signal_count=?, source_map_url=COALESCE(NULLIF(?,''), source_map_url)"
                " WHERE id=?",
                (actual, summary.get("source_map_url") or "", js_file_id),
            )
        else:
            result["inserted"] = len(summary.get("signals") or [])
        if promote:
            result["promoted"] = int(promote_js_candidates(conn, min_score=min_score, target_id=target_id))
        conn.commit()
    finally:
        conn.close()
    return result


def resolve_js_file(db_path: Path, js_id: int) -> dict[str, Any]:
    conn = connect(db_path)
    try:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM js_files WHERE id=?", (js_id,)).fetchone()
    finally:
        conn.close()
    if row is None:
        raise ValueError(f"js_files 无此 id: {js_id}")
    return dict(row)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="单文件 JS 分析入口（工具链 → js_signals/clusters，不发目标请求）")
    parser.add_argument("--target", help="目标名（落库必需；与 --db 二选一）")
    parser.add_argument("--db", help="直接指定 DB 路径")
    parser.add_argument("--js-id", type=int, help="js_files.id（本地路径从 DB 解析）")
    parser.add_argument("--file", help="直接指定本地 JS 文件（不落库时可用）")
    parser.add_argument("--case", help="tmp/js_reverse/<case> 目录名（默认 js-<id> 或文件名）")
    parser.add_argument("--skip", default="", help="跳过的工具，逗号分隔：jsluice,webcrack,gitleaks,retire")
    parser.add_argument("--promote", action="store_true", help="按分数晋级到 suspicious_points（默认关闭，需先过 coverage_guard）")
    parser.add_argument("--min-score", type=int, default=70)
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("--json", action="store_true", help="输出完整摘要 JSON")
    args = parser.parse_args(argv)
    force_utf8_stdout()

    db_path: Path | None = Path(args.db) if args.db else (find_db(args.target) if args.target else None)
    js_row: dict[str, Any] = {}
    if args.js_id is not None:
        if db_path is None:
            print(json.dumps({"error": "--js-id 需要 --target 或 --db"}, ensure_ascii=False), file=sys.stderr)
            return 2
        js_row = resolve_js_file(db_path, args.js_id)
    local_path = args.file or js_row.get("local_path") or ""
    if not local_path:
        print(
            json.dumps({"error": "无法解析本地 JS 路径：请给 --file 或用 --js-id 指向已有 local_path"}, ensure_ascii=False),
            file=sys.stderr,
        )
        return 2
    js_path = Path(local_path)
    if not js_path.is_file():
        print(json.dumps({"error": f"本地 JS 不存在: {js_path}"}, ensure_ascii=False), file=sys.stderr)
        return 1

    case = args.case or (f"js-{args.js_id}" if args.js_id is not None else js_path.stem)
    skip = frozenset(part.strip() for part in args.skip.split(",") if part.strip())
    summary = analyze_js_file(
        js_path,
        case=case,
        target_name=args.target or "",
        js_file_id=args.js_id,
        page_route=str(js_row.get("page_url") or ""),
        skip=skip,
        timeout=args.timeout,
    )
    store_result: dict[str, Any] = {}
    if db_path is not None:
        try:
            store_result = store_signals(db_path, summary, promote=args.promote, min_score=args.min_score)
        except (sqlite3.Error, ValueError) as exc:
            summary["blockers"].append({"tool": "store", "reason": f"{type(exc).__name__}: {exc}"})
    summary["store"] = store_result

    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=1))
    else:
        print(
            json.dumps(
                {
                    "case": summary["case"],
                    "js_path": summary["js_path"],
                    "signals": summary["signal_count"],
                    "restored_files": summary["restored_count"],
                    "store": store_result,
                    "warnings": summary["warnings"],
                    "blockers": summary["blockers"],
                    "out_dir": summary["out_dir"],
                },
                ensure_ascii=False,
            )
        )
    return 0 if not summary["blockers"] else 4


if __name__ == "__main__":
    raise SystemExit(main())
