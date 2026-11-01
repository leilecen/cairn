from __future__ import annotations

# ruff: noqa: E501
import json
import sqlite3

from db.claude_monitor import build_handoff, normalize_session_note, record_note
from db.db_query import init_db
from db.dispatcher import build_dispatch_plan
from db.focus_control import accept_switch, activate_focus, propose_switch
from db.human_brief import build_human_brief
from db.operator_actions import complete_action_card, create_action_card
from db.recon_readiness import RECON_KEYS, evaluate_readiness
from db.sprint_tick import run_sprint_tick
from db.system_registry import link_asset, register_system
from db.system_scorer import score_systems
from db.work_queue import create_work_item


def test_human_focus_real_sqlite_chain_mapping_switch_and_db_handoff(tmp_path):
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    c.executescript("""
    CREATE TABLE schema_version(version INTEGER PRIMARY KEY,description TEXT); INSERT INTO schema_version VALUES(33,'033');
    CREATE TABLE target_assets(id INTEGER PRIMARY KEY,target_name TEXT,asset_value TEXT,scope_class TEXT,scope_status TEXT,authorization_state TEXT);
    CREATE TABLE target_systems(id INTEGER PRIMARY KEY AUTOINCREMENT,target_name TEXT,system_key TEXT,display_name TEXT,canonical_url TEXT,description TEXT,scope_class TEXT,lifecycle_state TEXT,created_by TEXT,created_at TEXT,updated_at TEXT,UNIQUE(target_name,system_key));
    CREATE TABLE system_asset_links(id INTEGER PRIMARY KEY AUTOINCREMENT,target_name TEXT,system_id INTEGER,asset_id INTEGER,relationship TEXT,confidence TEXT,evidence_refs_json TEXT,updated_at TEXT,UNIQUE(system_id,asset_id,relationship));
    CREATE TABLE hunt_sessions(id INTEGER PRIMARY KEY AUTOINCREMENT,target_name TEXT,focus_subject_table TEXT,focus_subject_id TEXT,goal TEXT,success_criteria_json TEXT,stop_conditions_json TEXT,status TEXT,selected_by TEXT,started_at TEXT,ended_at TEXT,system_id INTEGER,recon_readiness_snapshot_json TEXT,operator_acknowledged_at TEXT,updated_at TEXT);
    CREATE TABLE work_items(id INTEGER PRIMARY KEY AUTOINCREMENT,target_name TEXT,lane TEXT,subtype TEXT,subject_table TEXT,subject_id TEXT,attack_thread_id INTEGER,title TEXT,objective TEXT,priority INTEGER,model_tier TEXT,reasoning_tier TEXT,auth_requirement TEXT,risk_class TEXT,timebox_minutes INTEGER,heartbeat_minutes INTEGER,status TEXT DEFAULT 'queued',dispatch_state TEXT DEFAULT 'active',system_id INTEGER,park_reason TEXT,claimed_by TEXT,heartbeat_at TEXT,lease_until TEXT,attempt_count INTEGER DEFAULT 0,max_attempts INTEGER DEFAULT 3,summary TEXT,created_at TEXT,updated_at TEXT);
    CREATE TABLE soft_targets(id INTEGER PRIMARY KEY,target_name TEXT,asset_id INTEGER,status TEXT,updated_at TEXT);
    CREATE TABLE decision_events(id INTEGER PRIMARY KEY AUTOINCREMENT,target_name TEXT,hunt_session_id INTEGER,actor TEXT,decision_type TEXT,compact_snapshot_json TEXT,candidate_actions_json TEXT DEFAULT '[]',chosen_action TEXT,rationale TEXT,expected_change TEXT,actual_change TEXT DEFAULT '',created_at TEXT);
    CREATE TABLE coverage_ledger(id INTEGER PRIMARY KEY AUTOINCREMENT,target_name TEXT,item_key TEXT,status TEXT);
    CREATE TABLE operator_inbox(id INTEGER PRIMARY KEY,target_name TEXT,status TEXT,blocking INTEGER,system_id INTEGER);
    CREATE TABLE endpoint_observations(id INTEGER PRIMARY KEY,target_name TEXT,resolution_status TEXT,business_hint TEXT);
    CREATE TABLE agent_events(id INTEGER PRIMARY KEY,target_name TEXT,work_item_id INTEGER,agent_id TEXT,event_type TEXT,severity TEXT,payload_json TEXT,created_at TEXT);
        INSERT INTO target_assets VALUES(1,'T','blog.example','owned','in_scope','active');
        INSERT INTO target_assets VALUES(2,'T','portal.example','owned','in_scope','active');
    """)
    blog = register_system(
        c,
        target_name="T",
        system_key="blog",
        display_name="官方博客",
        canonical_url="https://blog.example",
        scope_class="owned",
    )
    portal = register_system(
        c,
        target_name="T",
        system_key="portal",
        display_name="开发者门户",
        canonical_url="https://portal.example",
        scope_class="owned",
    )
    link_asset(c, target_name="T", system_id=blog["id"], asset_id=1, relationship="primary", confidence="high")
    link_asset(c, target_name="T", system_id=portal["id"], asset_id=2, relationship="primary", confidence="high")
    activate_focus(c, target_name="T", system_id=blog["id"], goal="mapping", operator_acknowledged=True)
    wid = create_work_item(
        c,
        target_name="T",
        system_id=blog["id"],
        lane="entry_probe",
        subject_table="target_assets",
        subject_id="1",
        title="map blog",
        objective="map entry",
    )
    assert build_dispatch_plan(c, target_name="T")["tasks"][0]["work_item_id"] == wid
    for key in RECON_KEYS:
        c.execute("INSERT INTO coverage_ledger(target_name,item_key,status) VALUES('T',?,'covered')", (key,))
    c.commit()
    assert evaluate_readiness(c, target_name="T", system_id=blog["id"])["state"] == "ready"
    propose_switch(c, target_name="T", from_system_id=blog["id"], to_system_id=portal["id"], reason="切换")
    assert c.execute("SELECT system_id FROM hunt_sessions WHERE status='active'").fetchone()[0] == blog["id"]
    accept_switch(c, target_name="T", to_system_id=portal["id"], goal="portal mapping")
    assert c.execute("SELECT system_id FROM hunt_sessions WHERE status='active'").fetchone()[0] == portal["id"]
    brief = build_human_brief(c, target_name="T")
    assert brief["current_system"]["display_name"] == "开发者门户"
    note = normalize_session_note({"session_id": "s", "target": "T", "current_system": brief["current_system"]})
    db = tmp_path / "handoff.db"
    c.commit()
    backup = sqlite3.connect(db)
    c.backup(backup)
    backup.close()
    handoff = build_handoff([note], "s", db_path=db)
    assert handoff["current_system"]["display_name"] == "开发者门户"


def test_fresh_init_to_tick_action_card_and_db_first_handoff(tmp_path):
    db_path = tmp_path / "fresh.db"
    init_db(str(db_path), "Fresh Target")
    c = sqlite3.connect(db_path)
    c.row_factory = sqlite3.Row
    c.execute(
        "INSERT INTO target_assets(target_name,asset_value,protocol,scope_status,scope_class,authorization_state,status) VALUES('Fresh Target','portal.example','https','in_scope','owned','authorized','new')"
    )
    asset_id = c.execute("SELECT last_insert_rowid()").fetchone()[0]
    c.commit()
    system = register_system(
        c,
        target_name="Fresh Target",
        system_key="portal",
        display_name="Portal",
        canonical_url="https://portal.example",
        scope_class="owned",
    )
    link_asset(
        c,
        target_name="Fresh Target",
        system_id=system["id"],
        asset_id=asset_id,
        relationship="primary",
        confidence="high",
    )
    score_systems(c, "Fresh Target", apply=True)
    activate_focus(c, target_name="Fresh Target", system_id=system["id"], goal="map portal", operator_acknowledged=True)
    wid = create_work_item(
        c,
        target_name="Fresh Target",
        system_id=system["id"],
        lane="entry_probe",
        subject_table="target_assets",
        subject_id=str(asset_id),
        title="map portal",
        objective="identify entry",
    )
    tick = run_sprint_tick(c, target_name="Fresh Target", seed=False, reclaim=False)
    assert any(item["work_item_id"] == wid for item in tick["dispatch_plan"]["tasks"])
    card = create_action_card(
        c,
        target_name="Fresh Target",
        system_id=system["id"],
        kind="evidence_capture",
        action_key="portal-result",
        action_label="回填入口观察",
        why_needed="需要操作员确认入口",
        steps=["确认入口"],
        expected_observation="入口可见或明确 blocker",
        report_back_format="结果=...",
        url="https://portal.example",
    )
    complete_action_card(c, card_id=card["id"], report="入口已确认")
    store = tmp_path / "events.jsonl"
    handoff_dir = tmp_path / "handoff"
    record_note(
        {
            "session_id": "fresh-s1",
            "target": "Fresh Target",
            "summary": "fresh db-first handoff",
            "decision_notes": [{"decision_type": "focus", "chosen_action": "portal", "rationale": "operator confirmed"}],
        },
        store=store,
        handoff_dir=handoff_dir,
        db_path=db_path,
    )
    events = [json.loads(line) for line in store.read_text(encoding="utf-8").splitlines()]
    handoff = build_handoff(events, "fresh-s1", db_path=db_path)
    assert handoff["human_brief"]["current_system"]["id"] == system["id"]
    assert handoff["decision_notes"]
