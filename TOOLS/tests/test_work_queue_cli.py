from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from pathlib import Path

from db.work_queue import create_work_item

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = PROJECT_ROOT / "TOOLS" / "db" / "schema.sql"
WORK_QUEUE_SCRIPT = PROJECT_ROOT / "TOOLS" / "db" / "work_queue.py"


def _db_path(tmp_path: Path) -> Path:
    path = tmp_path / "work_queue_cli.db"
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    create_work_item(
        conn,
        target_name="demo",
        lane="quick_scout",
        subject_table="pages",
        subject_id="1",
        priority=80,
    )
    create_work_item(
        conn,
        target_name="demo",
        lane="js_reverse",
        subject_table="js_files",
        subject_id="2",
        priority=20,
    )
    conn.close()
    return path


def _empty_db_path(tmp_path: Path) -> Path:
    path = tmp_path / "work_queue_cli_empty.db"
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    conn.close()
    return path


def _run_cli(db_path: Path, *args: str) -> subprocess.CompletedProcess[str]:
    # 用当前解释器的绝对路径：本机没有全局 `uv`（AGENTS.md 硬约束 4），
    # 绝对 argv[0] 同时满足 Bandit S607（partial executable path）。
    return subprocess.run(  # noqa: S603 -- 测试用 sys.executable 绝对路径起本仓库脚本
        [sys.executable, str(WORK_QUEUE_SCRIPT), *args, "--db", str(db_path)],
        capture_output=True,
        text=True,
        cwd=PROJECT_ROOT,
        check=False,
    )


def _json(stdout: str) -> dict:
    return json.loads(stdout)


def test_cli_create_then_claim_heartbeat_partial_complete(tmp_path):
    db_path = _empty_db_path(tmp_path)

    created = _run_cli(
        db_path,
        "create",
        "--target",
        "demo",
        "--lane",
        "quick_scout",
        "--subject-table",
        "pages",
        "--subject-id",
        "42",
        "--title",
        "Scout landing page",
        "--objective",
        "collect routes",
        "--priority",
        "90",
    )
    assert created.returncode == 0
    created_payload = _json(created.stdout)
    assert created_payload["ok"] is True
    work_item_id = created_payload["work_item_id"]

    claimed = _run_cli(db_path, "claim", "--target", "demo", "--agent-id", "agent-a")
    assert claimed.returncode == 0
    claimed_payload = _json(claimed.stdout)
    assert claimed_payload["ok"] is True
    assert claimed_payload["items"][0]["id"] == work_item_id
    assert claimed_payload["items"][0]["lane"] == "quick_scout"
    assert claimed_payload["items"][0]["title"] == "Scout landing page"

    heartbeat = _run_cli(db_path, "heartbeat", "--work-item-id", str(work_item_id), "--agent-id", "agent-a")
    assert heartbeat.returncode == 0
    assert _json(heartbeat.stdout)["ok"] is True

    partial = _run_cli(
        db_path,
        "partial",
        "--work-item-id",
        str(work_item_id),
        "--agent-id",
        "agent-a",
        "--summary",
        "found route",
    )
    assert partial.returncode == 0
    assert _json(partial.stdout)["ok"] is True

    complete = _run_cli(
        db_path,
        "complete",
        "--work-item-id",
        str(work_item_id),
        "--agent-id",
        "agent-a",
        "--summary",
        "done",
    )
    assert complete.returncode == 0
    assert _json(complete.stdout)["ok"] is True

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT status, target_name, lane, subject_table, subject_id, priority, summary FROM work_items WHERE id = ?",
        (work_item_id,),
    ).fetchone()
    events = conn.execute("SELECT event_type FROM agent_events WHERE work_item_id = ? ORDER BY id", (work_item_id,)).fetchall()
    conn.close()
    assert dict(row) == {
        "status": "done",
        "target_name": "demo",
        "lane": "quick_scout",
        "subject_table": "pages",
        "subject_id": "42",
        "priority": 90,
        "summary": "done",
    }
    assert [event["event_type"] for event in events] == ["heartbeat", "partial_result", "done"]


def test_cli_claim_next_then_heartbeat_partial_complete(tmp_path):
    db_path = _db_path(tmp_path)

    claimed = _run_cli(db_path, "claim", "--target", "demo", "--agent-id", "agent-a")
    assert claimed.returncode == 0
    claimed_payload = _json(claimed.stdout)
    assert claimed_payload["ok"] is True
    work_item_id = claimed_payload["items"][0]["id"]
    assert claimed_payload["items"][0]["lane"] == "quick_scout"

    heartbeat = _run_cli(db_path, "heartbeat", "--work-item-id", str(work_item_id), "--agent-id", "agent-a")
    assert heartbeat.returncode == 0
    assert _json(heartbeat.stdout)["ok"] is True

    partial = _run_cli(
        db_path,
        "partial",
        "--work-item-id",
        str(work_item_id),
        "--agent-id",
        "agent-a",
        "--summary",
        "found route",
        "--payload",
        '{"route": "/app"}',
    )
    assert partial.returncode == 0
    assert _json(partial.stdout)["ok"] is True

    complete = _run_cli(
        db_path,
        "complete",
        "--work-item-id",
        str(work_item_id),
        "--agent-id",
        "agent-a",
        "--summary",
        "done",
        "--next-action",
        "review",
    )
    assert complete.returncode == 0
    assert _json(complete.stdout)["ok"] is True

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT status, summary, next_action, claimed_by FROM work_items WHERE id = ?", (work_item_id,)).fetchone()
    events = conn.execute("SELECT event_type FROM agent_events WHERE work_item_id = ? ORDER BY id", (work_item_id,)).fetchall()
    conn.close()
    assert dict(row) == {"status": "done", "summary": "done", "next_action": "review", "claimed_by": None}
    assert [event["event_type"] for event in events] == ["heartbeat", "partial_result", "done"]


def test_cli_claim_by_id_and_block_creates_operator_inbox(tmp_path):
    db_path = _db_path(tmp_path)

    claimed = _run_cli(
        db_path,
        "claim",
        "--target",
        "demo",
        "--agent-id",
        "agent-b",
        "--work-item-id",
        "2",
    )
    assert claimed.returncode == 0
    payload = _json(claimed.stdout)
    assert payload["ok"] is True
    assert payload["items"][0]["id"] == 2

    blocked = _run_cli(
        db_path,
        "block",
        "--work-item-id",
        "2",
        "--agent-id",
        "agent-b",
        "--reason",
        "need login",
        "--blocker-class",
        "auth_barrier",
        "--operator-kind",
        "login_required",
        "--operator-title",
        "Login required",
        "--operator-detail",
        "refresh session",
        "--operator-url",
        "https://example.com/login",
    )
    assert blocked.returncode == 0
    assert _json(blocked.stdout)["ok"] is True

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    item = conn.execute("SELECT status, blocker_reason FROM work_items WHERE id = 2").fetchone()
    inbox = conn.execute("SELECT kind, title, detail, url FROM operator_inbox WHERE related_work_item_id = 2").fetchone()
    conn.close()
    assert dict(item) == {"status": "blocked", "blocker_reason": "need login"}
    assert dict(inbox) == {
        "kind": "login_required",
        "title": "Login required",
        "detail": "refresh session",
        "url": "https://example.com/login",
    }


def test_cli_errors_are_json_and_exit_1(tmp_path):
    db_path = _db_path(tmp_path)

    bad = _run_cli(db_path, "heartbeat", "--work-item-id", "999", "--agent-id", "agent-a")

    assert bad.returncode == 1
    payload = _json(bad.stdout)
    assert payload["ok"] is False
    assert "work_item not found" in payload["error"]
