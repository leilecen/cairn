"""Best-effort JS value-flow folding for URLs and request params."""

from __future__ import annotations

import re
from typing import Any

CONST_RE = re.compile(r"\bconst\s+([A-Za-z_$][\w$]*)\s*=\s*(['\"`])(.+?)\2\s*;?")
OBJECT_RE = re.compile(r"\bconst\s+([A-Za-z_$][\w$]*)\s*=\s*\{(?P<body>.*?)\}\s*;?", re.DOTALL)
MEMBER_RE = re.compile(r"([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+)")
KEY_VALUE_RE = re.compile(r"([A-Za-z_$][\w$]*)\s*:\s*([^,\n}]+)")
TEMPLATE_TOKEN_RE = re.compile(r"\$\{([^}]+)\}")
STRING_LITERAL_RE = re.compile(r"^\s*(['\"`])(.+?)\1\s*$", re.DOTALL)
STORAGE_RE = re.compile(r"(wx\.getStorageSync|localStorage\.getItem)\(\s*['\"]([^'\"]+)['\"]\s*\)")


def _line_number(content: str, index: int) -> int:
    return content.count("\n", 0, max(index, 0)) + 1


def _extract_context(content: str) -> dict[str, Any]:
    values: dict[str, dict[str, Any]] = {}
    for match in CONST_RE.finditer(content):
        values[match.group(1)] = {
            "value": match.group(3),
            "source": "literal",
            "line": _line_number(content, match.start()),
        }
    for match in OBJECT_RE.finditer(content):
        body = match.group("body")
        obj_name = match.group(1)
        for item in KEY_VALUE_RE.finditer(body):
            raw = item.group(2).strip()
            key = f"{obj_name}.{item.group(1)}"
            resolved = _resolve_expr(raw, values)
            values[key] = {
                "value": resolved["value"],
                "source": "object_member",
                "line": _line_number(content, match.start()),
            }
    return values


def _resolve_expr(expr: str, context: dict[str, Any]) -> dict[str, Any]:
    expr = expr.strip().rstrip(",")
    storage_match = STORAGE_RE.search(expr)
    if storage_match:
        key = storage_match.group(2)
        return {"value": "{dynamic}", "source": f"storage:{key}", "expr": expr}
    if expr.startswith("`") and expr.endswith("`"):

        def repl(match: re.Match[str]) -> str:
            inner = _resolve_expr(match.group(1), context)
            return inner["value"] if inner["value"] else "{dynamic}"

        value = TEMPLATE_TOKEN_RE.sub(repl, expr.strip("`"))
        return {"value": value, "source": "template", "expr": expr}
    literal = STRING_LITERAL_RE.match(expr)
    if literal:
        return {"value": literal.group(2), "source": "literal", "expr": expr}
    if expr in context:
        item = context[expr]
        return {"value": item["value"], "source": item["source"], "expr": expr}
    member_match = MEMBER_RE.fullmatch(expr)
    if member_match and expr in context:
        item = context[expr]
        return {"value": item["value"], "source": item["source"], "expr": expr}
    if expr.startswith("this.globalData.") or expr.startswith("app.globalData."):
        return {"value": "{dynamic}", "source": "globalData", "expr": expr}
    if "+" in expr:
        parts = [part.strip() for part in expr.split("+")]
        folded: list[str] = []
        dynamic = False
        for part in parts:
            resolved = _resolve_expr(part, context)
            folded.append(resolved["value"])
            dynamic = dynamic or resolved["value"] == "{dynamic}"
        return {
            "value": "".join("{dynamic}" if item == "{dynamic}" else item for item in folded),
            "source": "concat" if not dynamic else "mixed",
            "expr": expr,
        }
    return {"value": "{dynamic}", "source": "function_param", "expr": expr}


def fold_request_value_flow(
    content: str,
    url_expr: str,
    data_expr: str = "",
    *,
    file_path: str = "<memory>",
    line: int = 1,
) -> dict[str, Any]:
    context = _extract_context(content)
    resolved_url = _resolve_expr(url_expr, context)
    url_sources = []
    for name, item in context.items():
        if name in url_expr:
            url_sources.append({"expr": name, "value": item["value"], "file": file_path, "line": item["line"]})
    if not url_sources:
        url_sources.append(
            {
                "expr": url_expr,
                "value": resolved_url["value"],
                "file": file_path,
                "line": line,
                "source": resolved_url["source"],
            }
        )

    params = []
    if data_expr:
        for item in KEY_VALUE_RE.finditer(data_expr):
            name = item.group(1)
            resolved = _resolve_expr(item.group(2), context)
            params.append({"name": name, "source": resolved["source"], "value": resolved["value"]})
        bare_keys = re.findall(r"\b([A-Za-z_$][\w$]*)\b", data_expr)
        seen = {item["name"] for item in params}
        for key in bare_keys:
            if key in {"data", "url", "method"} or key in seen:
                continue
            params.append({"name": key, "source": "function_param", "value": "{dynamic}"})
    return {"url": resolved_url["value"], "url_sources": url_sources, "params": params}
