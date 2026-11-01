"""Helpers for source map discovery and safe parsing."""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urljoin, urlparse

SOURCEMAP_COMMENT_RE = re.compile(r"(?://#|/\*#)\s*sourceMappingURL=(?P<url>[^\s*]+)")


def detect_source_map_url(content: str, script_url: str, headers: dict[str, str] | None = None) -> str | None:
    headers = headers or {}
    for key in ("SourceMap", "X-SourceMap"):
        if headers.get(key):
            return urljoin(script_url, headers[key])
    match = SOURCEMAP_COMMENT_RE.search(content)
    if not match:
        return None
    return urljoin(script_url, match.group("url"))


def is_same_origin_or_scope(script_url: str, candidate_url: str) -> bool:
    script = urlparse(script_url)
    candidate = urlparse(candidate_url)
    return (script.scheme, script.netloc) == (candidate.scheme, candidate.netloc)


def parse_source_map_text(raw_text: str) -> list[dict]:
    try:
        payload = json.loads(raw_text)
    except json.JSONDecodeError:
        return []
    sources = payload.get("sources") or []
    contents = payload.get("sourcesContent") or []
    results = []
    for idx, source in enumerate(sources):
        results.append(
            {
                "source": source,
                "content": contents[idx] if idx < len(contents) and contents[idx] is not None else "",
            }
        )
    return results


def build_source_cache_path(target: str, content_hash: str, suffix: str = ".map") -> Path:
    return Path("tmp") / "js_cache" / target / f"{content_hash}{suffix}"
