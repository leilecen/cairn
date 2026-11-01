from __future__ import annotations

import io
import json
import sys
from pathlib import Path

from db import claude_monitor



def test_write_hook_keeps_only_workspace_relative_path() -> None:
    payload = {
        "hook_event_name": "PostToolUse",
        "session_id": "session-1",
        "cwd": str(claude_monitor.PROJECT_ROOT),
        "tool_name": "Write",
        "tool_input": {
            "file_path": str(claude_monitor.PROJECT_ROOT / "TOOLS" / "demo.py"),
            "content": "Authorization: Bearer super-secret-token",
        },
        "tool_response": {"success": True, "content": "secret response"},
        "duration_ms": 12,
    }

    event = claude_monitor.normalize_hook_event(payload)

    assert event["schema"] == "claude_monitor.v1"
    assert event["session_id"] == "session-1"
    assert event["tool_name"] == "Write"
    assert event["tool_category"] == "write"
    assert event["status"] == "success"
    assert event["files"] == ["TOOLS/demo.py"]
    assert event["duration_ms"] == 12
    serialized = json.dumps(event, ensure_ascii=False)
    assert "super-secret-token" not in serialized
    assert "secret response" not in serialized
    assert "tool_input" not in event
    assert "tool_response" not in event


def test_relative_write_path_falls_back_to_project_root_when_cwd_is_unusable() -> None:
    event = claude_monitor.normalize_hook_event(
        {
            "hook_event_name": "PostToolUse",
            "session_id": "session-relative",
            "cwd": "?:/unusable",
            "tool_name": "Edit",
            "tool_input": {"file_path": "TOOLS/demo.py", "new_string": "private"},
            "tool_response": {"success": True},
        }
    )

    assert event["files"] == ["TOOLS/demo.py"]


def test_bash_hook_classifies_test_and_extracts_counts_without_command_or_output() -> None:
    payload = {
        "hook_event_name": "PostToolUse",
        "session_id": "session-2",
        "cwd": str(claude_monitor.PROJECT_ROOT),
        "tool_name": "Bash",
        "tool_input": {"command": "uv run pytest TOOLS/tests/ -q --token secret-value"},
        "tool_response": {"stdout": "611 passed, 2 skipped in 9.12s\nsecret-value", "stderr": ""},
    }

    event = claude_monitor.normalize_hook_event(payload)

    assert event["command_kind"] == "test"
    assert event["test_result"] == {"passed": 611, "failed": 0, "errors": 0, "skipped": 2}
    assert event["output_bytes"] > 0
    serialized = json.dumps(event, ensure_ascii=False)
    assert "pytest TOOLS" not in serialized
    assert "secret-value" not in serialized
    assert "stdout" not in event


def test_failure_is_categorized_and_secret_fields_are_counted_not_copied() -> None:
    payload = {
        "hook_event_name": "PostToolUseFailure",
        "session_id": "session-3",
        "tool_name": "Bash",
        "tool_input": {
            "command": "uv run pytest TOOLS/tests/test_demo.py",
            "headers": {"Authorization": "Bearer abc", "Cookie": "sid=xyz"},
        },
        "error": "Command exited with non-zero status code 1: 2 failed, 10 passed",
        "duration_ms": 500,
    }

    event = claude_monitor.normalize_hook_event(payload)

    assert event["status"] == "failure"
    assert event["error_type"] == "test_failure"
    assert event["sensitive_field_count"] == 2
    assert event["test_result"] == {"passed": 10, "failed": 2, "errors": 0, "skipped": 0}
    serialized = json.dumps(event, ensure_ascii=False)
    assert "Bearer abc" not in serialized
    assert "sid=xyz" not in serialized


def test_session_note_is_compact_and_redacts_sensitive_material() -> None:
    note = claude_monitor.normalize_session_note(
        {
            "session_id": "session-4",
            "target": "example-client",
            "summary": "完成接口归属修复。 Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456",
            "decisions": ["保留历史证据", "访问 https://example.test/a?token=secret"],
            "blockers": ["缺少账号"],
            "next_actions": ["运行定向测试"],
            "work_items": [123, "124"],
            "prompt": "must never survive",
        }
    )

    assert note["event_name"] == "SessionNote"
    assert note["target"] == "example-client"
    assert note["work_items"] == ["123", "124"]
    serialized = json.dumps(note, ensure_ascii=False)
    assert "must never survive" not in serialized
    assert "abcdefghijklmnopqrstuvwxyz" not in serialized
    assert "token=secret" not in serialized
    assert "[redacted]" in serialized


def test_handoff_surfaces_repeated_failure_missing_test_and_missing_note() -> None:
    events = [
        {
            "schema": "claude_monitor.v1",
            "recorded_at": "2026-08-01T10:00:00+08:00",
            "event_name": "SessionStart",
            "session_id": "session-5",
            "model": "claude-sonnet",
            "status": "started",
        },
        {
            "schema": "claude_monitor.v1",
            "recorded_at": "2026-08-01T10:01:00+08:00",
            "event_name": "PostToolUse",
            "session_id": "session-5",
            "tool_name": "Edit",
            "tool_category": "write",
            "status": "success",
            "files": ["TOOLS/demo.py"],
            "duration_ms": 10,
            "output_bytes": 20,
        },
        *[
            {
                "schema": "claude_monitor.v1",
                "recorded_at": f"2026-08-01T10:0{index}:30+08:00",
                "event_name": "PostToolUseFailure",
                "session_id": "session-5",
                "tool_name": "Bash",
                "tool_category": "shell",
                "command_kind": "shell",
                "status": "failure",
                "error_type": "command_failure",
                "duration_ms": 50,
                "output_bytes": 0,
            }
            for index in (2, 3)
        ],
        {
            "schema": "claude_monitor.v1",
            "recorded_at": "2026-08-01T10:04:00+08:00",
            "event_name": "SessionEnd",
            "session_id": "session-5",
            "status": "ended",
            "reason": "prompt_input_exit",
        },
    ]

    handoff = claude_monitor.build_handoff(events, "session-5")

    assert handoff["files_changed"] == ["TOOLS/demo.py"]
    assert handoff["tool_summary"]["failures"] == 2
    assert handoff["verification"]["tests_run"] == 0
    rule_ids = {item["rule_id"] for item in handoff["feedback"]}
    assert {"missing_session_note", "repeated_tool_failure", "changes_without_tests"} <= rule_ids


def test_cognitive_feedback_preserves_structured_delta_and_pivot_flags() -> None:
    note = claude_monitor.normalize_session_note(
        {
            "session_id": "cognitive-1",
            "work_items": ["42"],
            "cognitive_summary": {
                "pivot_recommended": True,
                "broad_queue_dominance": True,
                "unknown_delta": {"before": 3, "after": 3, "delta": 0},
            },
            "decision_notes": [],
        }
    )
    handoff = claude_monitor.build_handoff([note], "cognitive-1")
    rule_ids = {item["rule_id"] for item in handoff["feedback"]}
    assert {"missed_pivot", "unknown_not_reduced", "broad_queue_dominance"} <= rule_ids


def test_cognitive_feedback_covers_repetition_evidence_and_lane_consumption() -> None:
    note = claude_monitor.normalize_session_note(
        {
            "session_id": "cognitive-2",
            "cognitive_summary": {
                "repeated_inconclusive_direction": True,
                "observation_without_evidence": True,
                "experiment_without_expected_observation": True,
                "new_lane_not_consumed": True,
            },
        }
    )
    rule_ids = {item["rule_id"] for item in claude_monitor.build_handoff([note], "cognitive-2")["feedback"]}
    assert {
        "repeated_inconclusive_direction",
        "observation_without_evidence",
        "experiment_without_expected_observation",
        "new_lane_not_consumed",
    } <= rule_ids


def test_record_hook_and_latest_handoff_are_end_to_end(tmp_path: Path, monkeypatch) -> None:
    store = tmp_path / "sessions.jsonl"
    handoff_dir = tmp_path / "handoffs"
    payloads = [
        {"hook_event_name": "SessionStart", "session_id": "session-6", "model": "claude-sonnet"},
        {
            "hook_event_name": "PostToolUse",
            "session_id": "session-6",
            "tool_name": "Bash",
            "tool_input": {"command": "uv run pytest -q"},
            "tool_response": {"stdout": "4 passed in 0.2s"},
        },
        {"hook_event_name": "SessionEnd", "session_id": "session-6", "reason": "other"},
    ]
    for payload in payloads:
        monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(payload)))
        claude_monitor.record_hook_from_stdin(store=store, handoff_dir=handoff_dir)

    saved = claude_monitor.load_latest_handoff(handoff_dir)

    assert saved is not None
    assert saved["session_id"] == "session-6"
    assert saved["verification"]["tests_run"] == 1
    assert saved["verification"]["passed"] == 4
    assert (handoff_dir / "session-6.json").exists()
    assert (handoff_dir / "latest.json").exists()


def test_monitor_never_opens_claude_transcript() -> None:
    content = (claude_monitor.PROJECT_ROOT / "TOOLS" / "db" / "claude_monitor.py").read_text(encoding="utf-8")

    assert "transcript_path" not in content


def test_note_cli_accepts_compact_arguments(tmp_path: Path) -> None:
    store = tmp_path / "sessions.jsonl"
    handoff_dir = tmp_path / "handoffs"

    exit_code = claude_monitor.main(
        [
            "note",
            "--store",
            str(store),
            "--handoff-dir",
            str(handoff_dir),
            "--session",
            "session-cli",
            "--target",
            "demo",
            "--summary",
            "完成监控接入",
            "--decision",
            "保留成本日志",
            "--next-action",
            "运行全量测试",
            "--work-item",
            "42",
        ]
    )

    assert exit_code == 0
    saved = claude_monitor.load_latest_handoff(handoff_dir)
    assert saved is not None
    assert saved["target"] == "demo"
    assert saved["summary"] == "完成监控接入"
    assert saved["decisions"] == ["保留成本日志"]
    assert saved["next_actions"] == ["运行全量测试"]
    assert saved["work_items"] == ["42"]
