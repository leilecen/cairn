import sqlite3

from db.cognitive_view import build_cognitive_view


def test_no_active_session_is_explicit_blocker():
    c = sqlite3.connect(":memory:")
    c.executescript("CREATE TABLE hunt_sessions(id INTEGER,target_name TEXT,status TEXT);")
    view = build_cognitive_view(c, target_name="demo")
    assert view["active_session"] is None and "blocker" in view


def test_unknown_delta_uses_experiment_snapshots():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    c.executescript("""
    CREATE TABLE hunt_sessions(id INTEGER,target_name TEXT,status TEXT,focus_subject_table TEXT,focus_subject_id TEXT,soft_target_id INTEGER,goal TEXT,selected_by TEXT);
    CREATE TABLE attack_threads(id INTEGER,hunt_session_id INTEGER,evaluation_status TEXT);
    CREATE TABLE experiments(id INTEGER,hunt_session_id INTEGER,attack_thread_id INTEGER,status TEXT,outcome TEXT,unknown_items_before_json TEXT,unknown_items_after_json TEXT);
    CREATE TABLE endpoint_observations(target_name TEXT,auth_state TEXT); CREATE TABLE coverage_ledger(target_name TEXT,status TEXT); CREATE TABLE work_items(target_name TEXT,status TEXT,lane TEXT);
    INSERT INTO hunt_sessions VALUES(1,'demo','active','soft_targets','1',1,'goal','operator');
    INSERT INTO attack_threads VALUES(1,1,'supported');
    INSERT INTO experiments VALUES(1,1,1,'observed','supports','[\"endpoint:a\",\"coverage:x\"]','[\"coverage:x\"]');
    """)
    view = build_cognitive_view(c, target_name="demo")
    assert view["unknown_delta"] == {"before": 2, "after": 1, "delta": -1}


def test_unknown_delta_uses_first_before_and_last_after():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    c.executescript("""
    CREATE TABLE hunt_sessions(id INTEGER,target_name TEXT,status TEXT,focus_subject_table TEXT,focus_subject_id TEXT,soft_target_id INTEGER,goal TEXT,selected_by TEXT);
    CREATE TABLE attack_threads(id INTEGER,hunt_session_id INTEGER,status TEXT,evaluation_status TEXT);
    CREATE TABLE experiments(id INTEGER,hunt_session_id INTEGER,attack_thread_id INTEGER,status TEXT,outcome TEXT,unknown_items_before_json TEXT,unknown_items_after_json TEXT,evidence_refs_json TEXT);
    CREATE TABLE endpoint_observations(target_name TEXT,auth_state TEXT); CREATE TABLE coverage_ledger(target_name TEXT,status TEXT); CREATE TABLE work_items(target_name TEXT,status TEXT,lane TEXT);
    INSERT INTO hunt_sessions VALUES(1,'demo','active','soft_targets','1',1,'goal','operator'); INSERT INTO attack_threads VALUES(1,1,'active','supported');
    INSERT INTO experiments VALUES(1,1,1,'observed','inconclusive','[\"a\",\"b\"]','[\"b\"]','[]');
    INSERT INTO experiments VALUES(2,1,1,'observed','inconclusive','[\"b\"]','[]','[]');
    """)
    assert build_cognitive_view(c, target_name="demo")["unknown_delta"] == {"before": 2, "after": 0, "delta": -2}


def test_inconclusive_streak_is_per_attack_thread():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    c.executescript("""
    CREATE TABLE hunt_sessions(id INTEGER,target_name TEXT,status TEXT,focus_subject_table TEXT,focus_subject_id TEXT,soft_target_id INTEGER,goal TEXT,selected_by TEXT);
    CREATE TABLE attack_threads(id INTEGER,hunt_session_id INTEGER,status TEXT,evaluation_status TEXT);
    CREATE TABLE experiments(id INTEGER,hunt_session_id INTEGER,attack_thread_id INTEGER,status TEXT,outcome TEXT,unknown_items_before_json TEXT,unknown_items_after_json TEXT,evidence_refs_json TEXT,expected_observation TEXT);
    CREATE TABLE endpoint_observations(target_name TEXT,auth_state TEXT); CREATE TABLE coverage_ledger(target_name TEXT,status TEXT); CREATE TABLE work_items(target_name TEXT,status TEXT,lane TEXT);
    INSERT INTO hunt_sessions VALUES(1,'demo','active','soft_targets','1',1,'goal','operator');
    INSERT INTO attack_threads VALUES(1,1,'active','supported'); INSERT INTO attack_threads VALUES(2,1,'active','supported'); INSERT INTO attack_threads VALUES(3,1,'active','supported');
    INSERT INTO experiments VALUES(1,1,1,'observed','inconclusive','[]','[]','[]','expected');
    INSERT INTO experiments VALUES(2,1,2,'observed','inconclusive','[]','[]','[]','expected');
    INSERT INTO experiments VALUES(3,1,3,'observed','inconclusive','[]','[]','[]','expected');
    """)
    view = build_cognitive_view(c, target_name="demo")
    assert view["experiment_summary"]["inconclusive_streak"] == 1
    assert view["repeated_inconclusive_direction"] is False
    assert view["pivot_recommended"] is False
