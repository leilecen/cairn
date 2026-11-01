import json
import sqlite3
from pathlib import Path

# ruff: noqa: E501
from db.attack_threads import update_attack_thread
from db.claude_monitor import build_handoff, normalize_session_note
from db.experiments import approve_experiment, propose_experiment
from db.hunt_sessions import create_session, set_status
from db.sprint_tick import run_sprint_tick
from db.work_queue import claim_by_id, complete_work_item


def test_focused_loop_is_driven_by_sprint_tick_and_dispatcher():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    c.executescript((Path(__file__).parents[2] / "TOOLS/db/schema.sql").read_text(encoding="utf-8"))
    # This fixture intentionally exercises the pre-system cognitive contract.
    c.execute("DELETE FROM schema_version")
    c.execute("INSERT INTO schema_version(version,description) VALUES(32,'legacy-cognitive-fixture')")
    c.execute("INSERT INTO soft_targets(target_name,asset_value,tier,status,total_score) VALUES('demo','demo.invalid','A','focused',90)")
    soft_id = c.execute("SELECT last_insert_rowid()").fetchone()[0]
    sid = create_session(
        c,
        target_name="demo",
        focus_subject_table="soft_targets",
        focus_subject_id=str(soft_id),
        goal="reduce auth unknown",
        selected_by="operator",
        soft_target_id=soft_id,
    )
    set_status(c, sid, "active", actor="operator")
    c.execute(
        "INSERT INTO attack_surface_profiles(target_name,soft_target_id,subject_table,subject_id,flows_json,status) VALUES(?,?,?,?,?,?)",
        (
            "demo",
            soft_id,
            "soft_targets",
            str(soft_id),
            json.dumps([{"key": "boundary", "unknowns": ["anonymous access state"]}]),
            "active",
        ),
    )
    c.execute(
        "INSERT INTO endpoint_observations(target_name,canonical_url,method,source,auth_state) VALUES('demo','https://demo.invalid/api','GET','fixture','unknown')"
    )
    c.commit()

    first = run_sprint_tick(c, target_name="demo", seed=False, reclaim=False)
    assert first["seeded_hypotheses"]
    thread_id = first["seeded_hypotheses"][0]
    update_attack_thread(c, attack_thread_id=thread_id, status="active", commit=True)
    experiment_id = propose_experiment(
        c,
        hunt_session_id=sid,
        attack_thread_id=thread_id,
        experiment_key="offline-boundary",
        question="Does stored evidence distinguish anonymous access?",
        expected_observation="stored evidence has an explicit public/auth state",
        control_description="compare the stored endpoint state with the profile unknown",
        stop_conditions=["do not make a network request"],
    )
    approve_experiment(c, experiment_id, actor="main")

    dispatched = run_sprint_tick(c, target_name="demo", seed=False, reclaim=False)
    assert dispatched["materialized_experiments"] == [experiment_id]
    tasks = dispatched["dispatch_plan"]["tasks"]
    assert len(tasks) == 1 and tasks[0]["lane"] == "cognitive_experiment"
    work_item_id = tasks[0]["work_item_id"]
    assert claim_by_id(c, work_item_id=work_item_id, agent_id="worker", target_name="demo")

    c.execute("UPDATE endpoint_observations SET auth_state='public' WHERE target_name='demo'")
    complete_work_item(
        c,
        work_item_id=work_item_id,
        agent_id="worker",
        summary="stored evidence reduced the unknown",
        result_payload={
            "outcome": "supports",
            "evidence_refs": ["ev-1"],
            "confidence": "medium",
            "observation_summary": "state is now explicit",
        },
    )
    finished = run_sprint_tick(c, target_name="demo", seed=False, reclaim=False)
    assert finished["cognitive_loop"]["unknown_delta"]["delta"] < 0
    assert c.execute("SELECT outcome FROM experiments WHERE id=?", (experiment_id,)).fetchone()[0] == "supports"

    note = normalize_session_note(
        {
            "session_id": "s1",
            "target": "demo",
            "work_items": [str(work_item_id)],
            "cognitive_summary": finished["cognitive_loop"],
            "decision_notes": [
                {
                    "decision_type": "dispatch",
                    "chosen_action": "dispatch experiment",
                    "rationale": "highest information gain",
                    "experiment_id": experiment_id,
                }
            ],
        }
    )
    handoff = build_handoff([note], "s1")
    assert handoff["cognitive_summary"]["unknown_delta"]["delta"] < 0
