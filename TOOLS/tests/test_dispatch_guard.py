from __future__ import annotations

import sqlite3

from db.dispatch_guard import check_payload, queued_dispatchable_items


def create_db(path):
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE work_items (
            id INTEGER PRIMARY KEY, target_name TEXT, lane TEXT, title TEXT,
            priority INTEGER DEFAULT 50, status TEXT DEFAULT 'queued',
            claimed_by TEXT, attempt_count INTEGER DEFAULT 0, max_attempts INTEGER DEFAULT 3,
            timebox_minutes INTEGER DEFAULT 10, heartbeat_minutes INTEGER DEFAULT 5,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        """
    )
    conn.commit()
    return conn


def test_queued_worker_item_is_a_stop_blocker(tmp_path):
    db_path = tmp_path / "demo.db"
    conn = create_db(db_path)
    conn.execute("INSERT INTO work_items (target_name,lane,title) VALUES ('demo','quick_scout','page')")
    conn.commit()
    conn.close()
    assert check_payload({"target_name": "demo"}, db_path=db_path)


def test_claimed_or_decision_items_do_not_block(tmp_path):
    db_path = tmp_path / "demo.db"
    conn = create_db(db_path)
    conn.execute("INSERT INTO work_items (target_name,lane,claimed_by) VALUES ('demo','quick_scout','w1')")
    conn.execute("INSERT INTO work_items (target_name,lane) VALUES ('demo','asset_triage')")
    conn.commit()
    assert queued_dispatchable_items(conn, target_name="demo") == []
    conn.close()
    assert check_payload({"target_name": "demo"}, db_path=db_path) is None


def test_stop_hook_active_does_not_loop(tmp_path):
    db_path = tmp_path / "demo.db"
    conn = create_db(db_path)
    conn.execute("INSERT INTO work_items (target_name,lane) VALUES ('demo','quick_scout')")
    conn.commit()
    conn.close()
    assert check_payload({"target_name": "demo", "stop_hook_active": True}, db_path=db_path) is None
