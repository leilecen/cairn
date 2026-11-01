import sqlite3

import pytest
from db.hunt_sessions import create_session, get_active_session, set_status


def db():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    c.executescript("""
    CREATE TABLE hunt_sessions(id INTEGER PRIMARY KEY AUTOINCREMENT,target_name TEXT,soft_target_id INTEGER,focus_subject_table TEXT,focus_subject_id TEXT,goal TEXT,success_criteria_json TEXT,stop_conditions_json TEXT,status TEXT,selected_by TEXT,started_at TEXT,ended_at TEXT,summary TEXT,created_at TEXT,updated_at TEXT);
    CREATE UNIQUE INDEX uq ON hunt_sessions(target_name) WHERE status='active';
    """)
    return c


def test_one_active_session_and_activation_gate():
    c = db()
    a = create_session(
        c,
        target_name="demo",
        focus_subject_table="soft_targets",
        focus_subject_id="1",
        goal="map boundary",
        selected_by="operator",
    )
    b = create_session(
        c,
        target_name="demo",
        focus_subject_table="soft_targets",
        focus_subject_id="2",
        goal="map api",
        selected_by="operator",
    )
    with pytest.raises(PermissionError):
        set_status(c, a, "active", actor="worker")
    set_status(c, a, "active", actor="operator")
    assert get_active_session(c, target_name="demo")["id"] == a
    with pytest.raises(ValueError):
        set_status(c, b, "active", actor="main")
