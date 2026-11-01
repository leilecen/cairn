import sqlite3

import pytest
from db.experiments import observe_experiment, propose_experiment


def db():
    c = sqlite3.connect(":memory:")
    c.executescript("""
    CREATE TABLE hunt_sessions(id INTEGER PRIMARY KEY,target_name TEXT);
    CREATE TABLE attack_threads(id INTEGER PRIMARY KEY);
    CREATE TABLE experiments(id INTEGER PRIMARY KEY AUTOINCREMENT,hunt_session_id INTEGER,attack_thread_id INTEGER,work_item_id INTEGER UNIQUE,experiment_key TEXT,question TEXT,method_class TEXT,expected_observation TEXT,control_description TEXT,budget_json TEXT,stop_conditions_json TEXT,risk_class TEXT,status TEXT,outcome TEXT,observation_summary TEXT,alternative_explanation TEXT,evidence_refs_json TEXT,confidence_before TEXT,confidence_after TEXT,unknown_items_before_json TEXT,unknown_items_after_json TEXT,surprise_score INTEGER,created_at TEXT,updated_at TEXT,finished_at TEXT,UNIQUE(hunt_session_id,experiment_key));
    INSERT INTO hunt_sessions VALUES(1,'demo'); INSERT INTO attack_threads VALUES(2);
    """)
    return c


def test_experiment_contract_and_evidence_downgrade():
    c = db()
    with pytest.raises(ValueError):
        propose_experiment(
            c,
            hunt_session_id=1,
            attack_thread_id=2,
            experiment_key="x",
            question="q",
            expected_observation="e",
            control_description="c",
            stop_conditions=[],
        )
    eid = propose_experiment(
        c,
        hunt_session_id=1,
        attack_thread_id=2,
        experiment_key="x",
        question="q",
        expected_observation="e",
        control_description="c",
        stop_conditions=["one"],
    )
    row = observe_experiment(c, eid, outcome="supports", observation_summary="no ref", evidence_refs=[])
    assert row["outcome"] == "inconclusive"
