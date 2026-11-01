from __future__ import annotations

from utils.js_callgraph import build_js_callgraph


def test_callgraph_accepts_non_string_content():
    result = build_js_callgraph(None)  # type: ignore[arg-type]
    assert result["nodes"] == []
    assert result["edges"] == []
    assert result["request_calls"] == []


def test_callgraph_handles_large_minified_input_without_process_failure():
    content = "function load(){fetch('/api/ping')}" + ";" * 100_000
    result = build_js_callgraph(content, "large.js")
    assert any(item["url_expr"] == "/api/ping" for item in result["request_calls"])
