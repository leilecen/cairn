import sqlite3

from db.experiment_planner import materialize_approved_experiments, plan_experiments


def test_offline_focus_candidates_rank_and_limit():
    c = sqlite3.connect(":memory:")
    c.executescript("CREATE TABLE experiments(id INTEGER,hunt_session_id INTEGER,experiment_key TEXT);")
    out = plan_experiments(
        c,
        hunt_session_id=1,
        candidates=[
            {"experiment_key": "b", "method_class": "offline", "information_gain": 3, "focus_alignment": 3},
            {"experiment_key": "a", "method_class": "active_low", "information_gain": 9},
            {"experiment_key": "c", "method_class": "passive", "information_gain": 1},
        ],
        limit=2,
    )
    assert [x["experiment_key"] for x in out] == ["b", "c"]


def test_approved_experiment_materializes_work_item():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    c.executescript("""
    CREATE TABLE experiments(id INTEGER PRIMARY KEY,hunt_session_id INTEGER,attack_thread_id INTEGER,work_item_id INTEGER,experiment_key TEXT,question TEXT,method_class TEXT,status TEXT,priority INTEGER DEFAULT 50);
    CREATE TABLE work_items(id INTEGER PRIMARY KEY AUTOINCREMENT,target_name TEXT,lane TEXT,subtype TEXT,subject_table TEXT,subject_id TEXT,attack_thread_id INTEGER,title TEXT,objective TEXT,priority INTEGER,model_tier TEXT,reasoning_tier TEXT,auth_requirement TEXT,risk_class TEXT,timebox_minutes INTEGER,heartbeat_minutes INTEGER,status TEXT DEFAULT 'queued');
    INSERT INTO experiments VALUES(1,7,8,NULL,'x','q','offline','approved',90);
    """)
    created = materialize_approved_experiments(c, target_name="demo", hunt_session_id=7)
    assert created == [1]
    assert c.execute("SELECT subtype FROM work_items").fetchone()[0] == "experiment:1"


def test_active_low_approved_experiment_never_materializes():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    c.executescript("""
    CREATE TABLE experiments(id INTEGER PRIMARY KEY,hunt_session_id INTEGER,attack_thread_id INTEGER,work_item_id INTEGER,experiment_key TEXT,question TEXT,method_class TEXT,status TEXT);
    CREATE TABLE work_items(id INTEGER PRIMARY KEY AUTOINCREMENT,target_name TEXT,lane TEXT,subtype TEXT,subject_table TEXT,subject_id TEXT,attack_thread_id INTEGER,title TEXT,objective TEXT,priority INTEGER,model_tier TEXT,reasoning_tier TEXT,auth_requirement TEXT,risk_class TEXT,timebox_minutes INTEGER,heartbeat_minutes INTEGER,status TEXT DEFAULT 'queued');
    INSERT INTO experiments VALUES(1,7,8,NULL,'active','q','active_low','approved');
    """)
    assert materialize_approved_experiments(c, target_name="demo", hunt_session_id=7) == []
    assert c.execute("SELECT COUNT(*) FROM work_items").fetchone()[0] == 0
