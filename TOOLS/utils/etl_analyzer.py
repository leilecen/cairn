"""
ETL Adapter: LLM-backed text analysis for SRC vulnerability hunting.
Primary text ETL engine for the project.

Supports two backends (select via SRC_ETL_BACKEND env var):
  - "deepseek" (default): DeepSeek Chat – set DEEPSEEK_API
  - "openai": OpenAI GPT – set SRC_OPENAI_API_KEY (+ optional
    SRC_OPENAI_BASE_URL, SRC_OPENAI_MODEL; defaults to gpt-4o)

Usage (Python):
    from utils.etl_analyzer import analyze
    result = analyze("filter_burp", raw_json_text)

Usage (CLI):
    uv run python TOOLS/utils/etl_analyzer.py --task filter_burp < data.json
    uv run python TOOLS/utils/etl_analyzer.py --task analyze_js --data "$(cat file.js)"

# Switch to GPT:
    SRC_ETL_BACKEND=openai SRC_OPENAI_API_KEY=sk-... uv run python ... --task analyze_js
"""

import argparse
import hashlib
import json
import os
import sqlite3
import sys
import time
from pathlib import Path

from openai import OpenAI

DEEPSEEK_BASE_URL = "https://api.deepseek.com"
DEEPSEEK_MODEL = "deepseek-chat"
DEFAULT_METRICS_FILE = Path("tmp") / "etl_metrics.jsonl"

# ── Backend selector ─────────────────────────────────────────────────────
# Set SRC_ETL_BACKEND=openai to use GPT; default is deepseek.
# OpenAI-specific env vars:
#   SRC_OPENAI_API_KEY   – OpenAI API key
#   SRC_OPENAI_BASE_URL  – custom base URL (optional, for proxies/azure)
#   SRC_OPENAI_MODEL     – model name (default: gpt-4o)
_SRC_ETL_BACKEND = os.environ.get("SRC_ETL_BACKEND", "deepseek").lower()
_OPENAI_API_KEY = os.environ.get("SRC_OPENAI_API_KEY")
_OPENAI_BASE_URL = os.environ.get("SRC_OPENAI_BASE_URL")
_OPENAI_MODEL = os.environ.get("SRC_OPENAI_MODEL", "gpt-4o")

_SYSTEM_PROMPTS: dict[str, str] = {
    "filter_burp": (
        "从以下Burp代理历史中提取所有API端点（路径+参数名），"
        "JSON格式，字段：url(string), params(array of string)。"
        "排除第三方CDN/统计/广告。返回纯JSON数组，无markdown围栏。"
    ),
    "analyze_js": (
        "从以下JS代码提取：1.API端点 2.硬编码密钥/token 3.内部路由 4.鉴权模式 5.签名线索。"
        "JSON输出，字段："
        "api_endpoints(数组，每项含 path/method/params), "
        "hardcoded_secrets(数组，每项含 type/name/value), "
        "internal_routes(数组), auth_patterns(数组), signature_hints(数组)。"
        "兼容旧字段时也请尽量映射到上述字段。返回纯JSON，无markdown围栏。"
    ),
    "filter_db": (
        "以下是数据库查询结果，请标出其中测试状态异常、风险等级High、"
        "或参数名可疑（含file/path/uid/cmd/role等）的记录，"
        "只输出可疑行，保留原始格式。"
    ),
    "extract_endpoints": (
        "从以下HTML提取：1.所有表单（action, method, 字段名）"
        "2.外链API URL 3.注释中的敏感信息。"
        "JSON输出，字段：forms(数组), api_urls(数组), sensitive_comments(数组)。"
        "返回纯JSON，无markdown围栏。"
    ),
    "classify_business": (
        "你是SRC渗透测试助手，从Burp HTTP历史列表筛选业务接口。"
        '输出JSON数组，每条: {"burp_history_id":<int>,"method":"POST",'
        '"url":"...","endpoint_type":"business_api|auth_login|auth_register'
        '|auth_reset_password|auth_verify_code","business_intent":"一句话业务含义",'
        '"risk_hint":"High|Medium|Low","flow_step":<int>,"auth_required":true|false}\n'
        "判定: auth_*: URL含login/register/reset/sms/captcha; "
        "business_api: /api/或.do/.action且非登录; "
        "risk=High: 含id/uid/oid参数或DELETE/PUT; Low: 字典/枚举无参数\n"
        "排除: 第三方CDN/统计/广告; 同URL去重保留risk最高; health check/version端点\n"
        "返回纯JSON，无markdown围栏。"
    ),
    "analyze_flow": (
        "分析以下HTTP请求序列，识别业务流程链，输出JSON:\n"
        '{"flow_chains":[{"chain_id":1,"steps":[1,2,3],"flow_name":"创建订单流程",'
        '"state_params":{"order_id":"请求2响应→请求3请求"},"auth_context":"primary"}],'
        '"cross_request_params":[{"param_name":"token",'
        '"source_request_id":1,"target_request_id":2}]}\n'
        "规则: flow_chains 识别 flow_step>0 的连续请求链; "
        "state_params 标注跨请求传递参数。返回纯JSON，无markdown围栏。"
    ),
    "generate_variants": (
        "给定HTTP请求及业务意图，生成安全测试变种，输出JSON数组（5-15条）:\n"
        '[{"test_type":"idor|unauth|param_logic|user_enum|captcha_reuse'
        '|password_reset_takeover|info_leak",'
        '"target_param":"参数名","original_value":"原始值",'
        '"replacement_value":"替换值",'
        '"modification":"replace_param|remove_auth|replace_cookie|remove_param|add_param",'
        '"description":"变种说明"}]\n'
        "业务意图→变种映射: 订单创建/查询→idor+unauth+param_logic; "
        "登录→user_enum; 验证码→captcha_reuse; "
        "密码重置→password_reset_takeover; 用户信息→idor+info_leak\n"
        "返回纯JSON，无markdown围栏。"
    ),
    "diff_responses": (
        "对比以下两个HTTP响应，判断是否存在安全漏洞（如IDOR/注入/信息泄露），"
        '说明差异和判断依据。输出格式：{"has_vuln": true|false, '
        '"vuln_type": "类型或null", "evidence": "差异说明", '
        '"confidence": "High|Medium|Low"}'
    ),
}


def normalize_js_findings(data: dict) -> dict:
    """Normalize legacy/new analyze_js payloads to a stable schema."""
    api_endpoints = data.get("api_endpoints")
    if not isinstance(api_endpoints, list):
        legacy_apis = data.get("apis", [])
        api_endpoints = []
        if isinstance(legacy_apis, list):
            for item in legacy_apis:
                if isinstance(item, dict):
                    api_endpoints.append(
                        {
                            "path": item.get("path") or item.get("url") or "",
                            "method": item.get("method", "GET"),
                            "params": item.get("params", []),
                        }
                    )
                elif isinstance(item, str):
                    api_endpoints.append({"path": item, "method": "GET", "params": []})

    hardcoded_secrets = data.get("hardcoded_secrets")
    if not isinstance(hardcoded_secrets, list):
        legacy_secrets = data.get("secrets", [])
        hardcoded_secrets = []
        if isinstance(legacy_secrets, list):
            for item in legacy_secrets:
                if isinstance(item, dict):
                    hardcoded_secrets.append(
                        {
                            "type": item.get("type", "secret"),
                            "name": item.get("name") or item.get("key") or "",
                            "value": item.get("value") or item.get("secret") or "",
                        }
                    )
                elif isinstance(item, str):
                    hardcoded_secrets.append({"type": "secret", "name": "", "value": item})

    internal_routes = data.get("internal_routes", [])
    if not isinstance(internal_routes, list):
        internal_routes = []

    auth_patterns = data.get("auth_patterns", [])
    if not isinstance(auth_patterns, list):
        auth_patterns = []

    signature_hints = data.get("signature_hints", [])
    if not isinstance(signature_hints, list):
        signature_hints = []

    sensitive_params = data.get("sensitive_params", [])
    if isinstance(sensitive_params, list) and sensitive_params:
        api_endpoints.append(
            {
                "path": "",
                "method": "UNKNOWN",
                "params": [str(param) for param in sensitive_params],
            }
        )

    return {
        "api_endpoints": api_endpoints,
        "hardcoded_secrets": hardcoded_secrets,
        "internal_routes": internal_routes,
        "auth_patterns": auth_patterns,
        "signature_hints": signature_hints,
    }


def _connect_cache_db(cache_db: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(cache_db))
    conn.row_factory = sqlite3.Row
    conn.execute(
        """CREATE TABLE IF NOT EXISTS etl_cache (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task TEXT NOT NULL,
            instruction_hash TEXT NOT NULL,
            data_hash TEXT NOT NULL,
            result TEXT NOT NULL,
            model TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now', 'localtime')),
            hit_count INTEGER DEFAULT 0,
            UNIQUE(task, instruction_hash, data_hash)
        )"""
    )
    conn.commit()
    return conn


def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _load_cached_result(
    conn: sqlite3.Connection,
    task: str,
    instruction: str,
    data: str,
) -> str | None:
    instruction_hash = _hash_text(instruction)
    data_hash = _hash_text(data)
    row = conn.execute(
        """SELECT result
        FROM etl_cache
        WHERE task = ? AND instruction_hash = ? AND data_hash = ?""",
        (task, instruction_hash, data_hash),
    ).fetchone()
    if row is None:
        return None

    conn.execute(
        """UPDATE etl_cache
        SET hit_count = hit_count + 1
        WHERE task = ? AND instruction_hash = ? AND data_hash = ?""",
        (task, instruction_hash, data_hash),
    )
    conn.commit()
    return row["result"]


def _store_cached_result(
    conn: sqlite3.Connection,
    task: str,
    instruction: str,
    data: str,
    result: str,
) -> None:
    backend, _, _ = _resolve_backend()
    conn.execute(
        """INSERT INTO etl_cache (
            task, instruction_hash, data_hash, result, model
        ) VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(task, instruction_hash, data_hash)
        DO UPDATE SET result = excluded.result, model = excluded.model""",
        (task, _hash_text(instruction), _hash_text(data), result, _active_model(backend)),
    )
    conn.commit()


def _metrics_path() -> Path:
    return Path(os.environ.get("SRC_ETL_METRICS_FILE") or DEFAULT_METRICS_FILE)


def _extract_usage(response: object) -> dict[str, int]:
    usage = getattr(response, "usage", None)
    if usage is None:
        return {}
    fields = ("prompt_tokens", "completion_tokens", "total_tokens")
    result = {}
    for field in fields:
        value = getattr(usage, field, None)
        if isinstance(value, int):
            result[field] = value
    return result


def _write_metrics(record: dict) -> None:
    try:
        path = _metrics_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
    except Exception:
        return


def _build_metrics_record(
    *,
    task: str,
    model: str,
    caller: str,
    data: str,
    instruction: str,
    output: str,
    elapsed_ms: int,
    status: str,
    cache_db_present: bool,
    cache_hit: bool,
    response: object | None = None,
) -> dict:
    record = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "task": task,
        "model": model,
        "caller": caller,
        "input_chars": len(data),
        "instruction_chars": len(instruction),
        "output_chars": len(output),
        "elapsed_ms": elapsed_ms,
        "status": status,
        "cache_db_present": cache_db_present,
        "cache_hit": cache_hit,
    }
    if response is not None:
        record.update(_extract_usage(response))
    return record


def _resolve_backend() -> tuple[str, str, str | None]:
    """Return (backend, api_key, base_url) from environment."""
    backend = _SRC_ETL_BACKEND
    if backend == "openai":
        if not _OPENAI_API_KEY:
            raise RuntimeError("SRC_OPENAI_API_KEY env var required when SRC_ETL_BACKEND=openai")
        return "openai", _OPENAI_API_KEY, _OPENAI_BASE_URL
    # default: deepseek
    api_key = os.environ.get("DEEPSEEK_API")
    if not api_key:
        raise RuntimeError("DEEPSEEK_API environment variable not set")
    return "deepseek", api_key, DEEPSEEK_BASE_URL


def _active_model(backend: str) -> str:
    if backend == "openai":
        return _OPENAI_MODEL
    return DEEPSEEK_MODEL


def analyze(
    task: str,
    data: str,
    instruction: str = "",
    cache_db: str | Path | None = None,
    bypass_cache: bool = False,
    caller: str = "unknown",
) -> str:
    """Call the configured LLM backend to perform ETL analysis on data.

    The backend is selected via the SRC_ETL_BACKEND env var:
      - "deepseek" (default): uses DeepSeek Chat API.
      - "openai": uses OpenAI GPT models (set SRC_OPENAI_API_KEY).

    Args:
        task: One of the keys in _SYSTEM_PROMPTS.
        data: Raw text to analyze (JSON, JS, HTML, SQL output, etc.).
        instruction: Optional extra instruction prepended to data.
        cache_db: Optional SQLite DB path used for ETL response caching.
        bypass_cache: If True, skip cache reads and force a fresh model call.
        caller: Short sanitized caller label for metrics.

    Returns:
        LLM response text (typically JSON).

    Raises:
        RuntimeError: If the required API key env var is not set.
        ValueError: If task is not a recognized task name.
    """
    backend, api_key, base_url = _resolve_backend()
    active_model = _active_model(backend)

    system_prompt = _SYSTEM_PROMPTS.get(task)
    if not system_prompt:
        valid = list(_SYSTEM_PROMPTS.keys())
        raise ValueError(f"Unknown task: {task!r}. Valid tasks: {valid}")

    started = time.perf_counter()
    cache_conn = _connect_cache_db(cache_db) if cache_db else None
    cache_db_present = cache_db is not None
    cache_hit = False
    response = None
    status = "success"
    result = ""

    try:
        if cache_conn and not bypass_cache:
            cached = _load_cached_result(cache_conn, task, instruction, data)
            if cached is not None:
                cache_hit = True
                result = cached
                status = "cache_hit"
                return cached

        client = OpenAI(api_key=api_key, base_url=base_url)
        user_content = f"{instruction}\n{data}" if instruction else data

        response = client.chat.completions.create(
            model=active_model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content},
            ],
            temperature=0.1,
            max_tokens=4096,
        )
        result = response.choices[0].message.content or ""
        if cache_conn:
            _store_cached_result(cache_conn, task, instruction, data, result)
        return result
    except Exception:
        status = "error"
        raise
    finally:
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        _write_metrics(
            _build_metrics_record(
                task=task,
                model=active_model,
                caller=caller,
                data=data,
                instruction=instruction,
                output=result,
                elapsed_ms=elapsed_ms,
                status=status,
                cache_db_present=cache_db_present,
                cache_hit=cache_hit,
                response=response,
            )
        )
        if cache_conn:
            cache_conn.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ETL text analyzer (DeepSeek / OpenAI GPT)")
    parser.add_argument(
        "--task",
        required=True,
        choices=list(_SYSTEM_PROMPTS.keys()),
        help="Analysis task type",
    )
    parser.add_argument("--instruction", default="", help="Additional instruction")
    parser.add_argument("--data", default=None, help="Data to analyze (or stdin)")
    parser.add_argument("--cache-db", default=None, help="Optional SQLite DB path for ETL cache")
    parser.add_argument("--bypass-cache", action="store_true", help="Ignore cache and force a fresh model call")
    parser.add_argument("--caller", default="etl_analyzer_cli", help="Sanitized caller label for metrics")
    args = parser.parse_args()

    raw_data = args.data if args.data is not None else sys.stdin.read()
    print(
        analyze(
            args.task,
            raw_data,
            args.instruction,
            cache_db=args.cache_db,
            bypass_cache=args.bypass_cache,
            caller=args.caller,
        )
    )
