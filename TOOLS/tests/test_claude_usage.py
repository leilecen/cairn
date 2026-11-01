from __future__ import annotations

import io
import json
import sys

from db import claude_usage


def test_normalize_event_extracts_usage_without_body_fields(tmp_path):
    transcript = tmp_path / "transcript.jsonl"
    transcript.write_text(
        json.dumps(
            {
                "type": "assistant",
                "message": {
                    "model": "claude-sonnet-4",
                    "usage": {
                        "input_tokens": 10,
                        "output_tokens": 5,
                        "cache_creation_input_tokens": 2,
                        "cache_read_input_tokens": 3,
                    },
                    "content": "secret response body must not be saved",
                },
            },
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    payload = {
        "hook_event_name": "Stop",
        "session_id": "s-1",
        "project": "SRC",
        "target": "demo",
        "agent_id": "demo:worker:1",
        "lane": "logic_probe",
        "work_item_id": "42",
        "transcript_path": str(transcript),
        "prompt": "do not store this",
        "Authorization": "Bearer token",
    }

    event = claude_usage.normalize_event(payload)

    assert event["session"] == "s-1"
    assert event["target"] == "demo"
    assert event["agent"] == "demo:worker:1"
    assert event["lane"] == "logic_probe"
    assert event["work_item"] == "42"
    assert event["model"] == "claude-sonnet-4"
    assert event["input_tokens"] == 10
    assert event["output_tokens"] == 5
    assert event["cache_creation_input_tokens"] == 2
    assert event["cache_read_input_tokens"] == 3
    assert event["total_tokens"] == 20
    assert "prompt" not in event
    assert "content" not in event
    assert "Authorization" not in event


def test_record_and_summary_groups_by_target_lane_agent_model(tmp_path, monkeypatch):
    store = tmp_path / "costs.jsonl"
    payload = {
        "hook_event_name": "SubagentStop",
        "session_id": "s-1",
        "target_name": "demo",
        "agent": "agent-a",
        "lane": "quick_scout",
        "model": "claude-haiku",
        "reasoning_effort": "low",
        "usage": {"input_tokens": 7, "output_tokens": 8, "total_tokens": 15, "cost_usd": 0.001},
    }
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(payload)))

    event = claude_usage.record_from_stdin(store)
    rows = claude_usage.summarize([event], target="demo")

    assert store.exists()
    saved = json.loads(store.read_text(encoding="utf-8").strip())
    assert saved["input_tokens"] == 7
    assert rows[0]["target"] == "demo"
    assert rows[0]["lane"] == "quick_scout"
    assert rows[0]["agent"] == "agent-a"
    assert rows[0]["model"] == "claude-haiku"
    assert rows[0]["reasoning_effort"] == "low"
    assert rows[0]["total_tokens"] == 15
    assert rows[0]["cost_usd"] == 0.001


def test_missing_fields_remain_unknown_or_none():
    event = claude_usage.normalize_event({"hook_event_name": "Stop"})

    assert event["agent"] == "main"
    assert event["lane"] == "main"
    assert event["model"] == "unknown"
    assert event["target"] is None
    assert event["reasoning_effort"] is None
    assert event["input_tokens"] is None
    assert event["output_tokens"] is None
    assert event["cost_usd"] is None


def test_exact_subagent_mirror_after_stop_is_not_counted_twice(tmp_path):
    store = tmp_path / "costs.jsonl"
    stop = {
        "schema": "claude_usage.v1",
        "event_name": "Stop",
        "session": "s-1",
        "model": "deepseek-v4-pro",
        "input_tokens": 100,
        "output_tokens": 20,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": 500,
        "total_tokens": 620,
    }
    mirror = {**stop, "event_name": "SubagentStop", "agent": "worker-1"}
    claude_usage.append_event(stop, store)
    claude_usage.append_event(mirror, store)
    assert len(store.read_text(encoding="utf-8").splitlines()) == 1


def test_different_subagent_usage_is_preserved(tmp_path):
    store = tmp_path / "costs.jsonl"
    stop = {
        "schema": "claude_usage.v1",
        "event_name": "Stop",
        "session": "s-1",
        "model": "deepseek-v4-pro",
        "input_tokens": 100,
        "output_tokens": 20,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": 500,
        "total_tokens": 620,
    }
    worker = {**stop, "event_name": "SubagentStop", "total_tokens": 621, "agent": "worker-1"}
    claude_usage.append_event(stop, store)
    claude_usage.append_event(worker, store)
    assert len(store.read_text(encoding="utf-8").splitlines()) == 2


def test_record_codex_event_keeps_only_compact_allowlist(tmp_path, monkeypatch):
    store = tmp_path / "costs.jsonl"
    payload = {
        "event_name": "worker_stop",
        "target": "demo",
        "session": "codex-session-1",
        "agent": "demo:param-fuzzer:1",
        "lane": "logic_probe",
        "work_item": "123",
        "model": "gpt-5.4",
        "reasoning_effort": "low",
        "usage": {"input_tokens": 11, "output_tokens": 12, "total_tokens": 23, "cost_usd": 0.002},
        "prompt": "secret prompt",
        "response": "secret response",
        "html": "<html>secret</html>",
        "js": "secret js",
        "burp": "secret burp",
        "headers": {"Authorization": "Bearer token", "Cookie": "sid=secret"},
        "Authorization": "Bearer token",
        "Cookie": "sid=secret",
    }
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(payload)))

    event = claude_usage.record_event_from_stdin(store, source="codex_explicit")

    saved = json.loads(store.read_text(encoding="utf-8").strip())
    assert event == saved
    assert saved["source"] == "codex_explicit"
    assert saved["event_name"] == "worker_stop"
    assert saved["agent"] == "demo:param-fuzzer:1"
    assert saved["lane"] == "logic_probe"
    assert saved["work_item"] == "123"
    assert saved["model"] == "gpt-5.4"
    assert saved["reasoning_effort"] == "low"
    assert saved["total_tokens"] == 23
    forbidden = {
        "prompt",
        "response",
        "html",
        "js",
        "burp",
        "headers",
        "Authorization",
        "Cookie",
    }
    assert forbidden.isdisjoint(saved)
