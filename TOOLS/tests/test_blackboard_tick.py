import json
import sqlite3
import subprocess
import sys
from pathlib import Path

from db.blackboard_tick import run_blackboard_tick
from db.work_queue import claim_next, create_work_item, partial_result

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = PROJECT_ROOT / "TOOLS" / "db" / "schema.sql"
TICK_SCRIPT = PROJECT_ROOT / "TOOLS" / "db" / "blackboard_tick.py"


def _conn():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    return conn


def _seed_tick_fixture(conn: sqlite3.Connection) -> int:
    conn.execute("INSERT INTO targets (id, target_name, domain) VALUES (1, 'demo', 'example.com')")
    conn.execute(
        """
        INSERT INTO pages (
            id, url, depth, status, title, js_files_json, api_calls_json, crawled_at, source,
            canonical_url, endpoint_fingerprint, signal_value, signal_reason
        ) VALUES (
            1, 'https://example.com/dashboard', 0, 'queued', 'Dashboard',
            '[]', '[]', '2026-07-14 09:00:00', 'crawl',
            'https://example.com/dashboard', 'page-1', 'high_value', 'auth_surface'
        )
        """
    )
    expired_id = create_work_item(
        conn,
        target_name="demo",
        lane="js_reverse",
        subject_table="pages",
        subject_id="99",
        priority=90,
        heartbeat_minutes=5,
    )
    claim_next(conn, target_name="demo", agent_id="agent-a", lanes=["js_reverse"])
    partial_result(conn, work_item_id=expired_id, agent_id="agent-a", payload={"summary": "half done"})
    conn.execute(
        """
        UPDATE work_items
        SET claimed_at='2026-07-14 09:00:00',
            lease_until='2026-07-14 09:05:00',
            heartbeat_at='2026-07-14 09:00:00'
        WHERE id = ?
        """,
        (expired_id,),
    )
    conn.commit()
    return expired_id


def test_run_blackboard_tick_seeds_reclaims_and_returns_view():
    conn = _conn()
    expired_id = _seed_tick_fixture(conn)

    payload = run_blackboard_tick(conn, target_name="demo")

    expired = conn.execute(
        "SELECT status, claimed_by FROM work_items WHERE id = ?",
        (expired_id,),
    ).fetchone()
    assert payload["seed"]["created"] == 2
    assert payload["reclaim"] == {"requeued": 0, "partial_released": 1, "total": 1}
    assert expired["status"] == "partial"
    assert expired["claimed_by"] is None
    assert payload["view"]["work_summary"]["queued"] == 2
    assert payload["view"]["work_summary"]["partial"] == 1
    assert payload["view"]["active_agents"] == []
    assert any("claim next work_item" in item for item in payload["view"]["next_recommended_actions"])


def test_blackboard_tick_cli_supports_json(tmp_path):
    db_path = tmp_path / "tick_demo.db"
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    _seed_tick_fixture(conn)
    conn.close()

    cmd = [
        sys.executable,
        str(TICK_SCRIPT),
        "--db",
        str(db_path),
        "--target",
        "demo",
        "--json",
    ]
    completed = subprocess.run(cmd, capture_output=True, text=True, check=True, cwd=PROJECT_ROOT)  # noqa: S603 -- 测试用 sys.executable 起本仓库脚本
    payload = json.loads(completed.stdout)

    assert payload["target"] == "demo"
    assert payload["seed"]["created"] == 2
    assert payload["reclaim"]["partial_released"] == 1
    assert payload["view"]["work_summary"]["partial"] == 1
