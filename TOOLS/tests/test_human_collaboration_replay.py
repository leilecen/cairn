from __future__ import annotations

import sqlite3

from db.focus_control import activate_focus, pause_focus
from db.human_collaboration_replay import apply, preview


def _schema32_fixture(path):
    """A pre-033 DB with realistic focus, asset, queue, and legacy-card fields."""
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE schema_version(version INTEGER PRIMARY KEY, description TEXT);
        INSERT INTO schema_version VALUES(32, '032_cognitive_hunt_loop');
        CREATE TABLE targets(id INTEGER PRIMARY KEY, target_name TEXT, domain TEXT);
        CREATE TABLE target_assets(
            id INTEGER PRIMARY KEY, target_name TEXT, asset_value TEXT, protocol TEXT,
            port INTEGER, scope_class TEXT, scope_status TEXT, authorization_state TEXT
        );
        CREATE TABLE soft_targets(
            id INTEGER PRIMARY KEY, target_name TEXT, asset_id INTEGER, asset_value TEXT,
            status TEXT, rank INTEGER
        );
        CREATE TABLE work_items(
            id INTEGER PRIMARY KEY, target_name TEXT, lane TEXT, subject_table TEXT,
            subject_id TEXT, title TEXT, objective TEXT, status TEXT, dispatch_state TEXT
        );
        CREATE TABLE hunt_sessions(
            id INTEGER PRIMARY KEY, target_name TEXT, soft_target_id INTEGER,
            focus_subject_table TEXT, focus_subject_id TEXT, goal TEXT,
            success_criteria_json TEXT, stop_conditions_json TEXT, status TEXT,
            selected_by TEXT, started_at TEXT, ended_at TEXT, summary TEXT,
            created_at TEXT, updated_at TEXT
        );
        CREATE TABLE operator_inbox(
            id INTEGER PRIMARY KEY, target_name TEXT, related_work_item_id INTEGER,
            kind TEXT, title TEXT, detail TEXT, suggested_action TEXT, url TEXT,
            burp_action_id INTEGER, evidence_ref_id INTEGER, status TEXT,
            created_at TEXT, resolved_at TEXT
        );
        CREATE TABLE facts(id INTEGER);
        CREATE TABLE findings(id INTEGER);
        CREATE TABLE evidence_packs(id INTEGER);
        CREATE TABLE agent_events(id INTEGER);
        CREATE TABLE decision_events(
            id INTEGER PRIMARY KEY AUTOINCREMENT, target_name TEXT, hunt_session_id INTEGER,
            actor TEXT, decision_type TEXT, compact_snapshot_json TEXT,
            candidate_actions_json TEXT DEFAULT '[]', chosen_action TEXT, rationale TEXT,
            expected_change TEXT, actual_change TEXT DEFAULT '', created_at TEXT
        );
        CREATE TABLE attack_threads(id INTEGER PRIMARY KEY, target_name TEXT);
        CREATE TABLE endpoint_observations(id INTEGER PRIMARY KEY, target_name TEXT);
        CREATE TABLE entry_observations(id INTEGER PRIMARY KEY, target_name TEXT);
        CREATE TABLE evidence_refs(id INTEGER PRIMARY KEY, target_name TEXT);
        CREATE TABLE burp_actions(id INTEGER PRIMARY KEY, target_name TEXT);
        CREATE TABLE pages(id INTEGER PRIMARY KEY);
        CREATE TABLE js_files(id INTEGER PRIMARY KEY);
        """
    )
    conn.execute("INSERT INTO targets VALUES(1, 'T', 'example.com')")
    conn.executemany(
        "INSERT INTO target_assets VALUES(?,?,?,?,?,?,?,?)",
        [
            (1, "T", "main.example.com", "https", 443, "owned", "in_scope", "authorized"),
            (2, "T", "blog.example.com", "https", 443, "owned", "in_scope", "authorized"),
            (3, "T", "blog-pre.example.com", "https", 443, "owned", "in_scope", "authorized"),
        ],
    )
    conn.executemany(
        "INSERT INTO soft_targets VALUES(?,?,?,?,?,?)",
        [
            (1, "T", 1, "main.example.com", "ranked", 1),
            (2, "T", 2, "blog.example.com", "focused", 2),
            (3, "T", 3, "blog-pre.example.com", "ranked", 3),
        ],
    )
    conn.execute(
        "INSERT INTO work_items VALUES(1, 'T', 'operator_task', 'targets', '1', 'legacy task', 'capture evidence', 'queued', 'active')"
    )
    conn.execute(
        "INSERT INTO operator_inbox VALUES(7, 'T', NULL, 'manual_review', 'legacy card', 'old details', 'old action', 'https://old.example', NULL, NULL, 'open', '2026-08-01 00:00:00', NULL)"
    )
    conn.commit()
    conn.close()


def _assert_zero_reconciliation(result):
    reconciliation = result["reconciliation"]
    assert reconciliation["reconciliation_mutations"] == 0
    assert all(value == 0 for value in reconciliation.values()), reconciliation


def test_human_focus_replay_keeps_primary_url_and_cards_stable_after_focus_lifecycle(tmp_path):
    db = tmp_path / "schema32_focus.db"
    _schema32_fixture(db)

    first = apply(db, target_name="T", backup_dir=tmp_path / "backups")
    assert first["schema_before"] == 32
    assert first["schema_after"] == 33
    assert first["reconciliation"]["incomplete_action_cards_created"] == 1
    assert first["reconciliation"]["legacy_action_cards_normalized"] == 1

    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    historical_system = conn.execute(
        "SELECT id FROM target_systems WHERE target_name='T' AND system_key='proposal-example-com-blog'"
    ).fetchone()["id"]
    core_system = conn.execute("SELECT id FROM target_systems WHERE target_name='T' AND system_key='proposal-example-com-core'").fetchone()[
        "id"
    ]
    legacy_card = conn.execute("SELECT * FROM operator_inbox WHERE id=7").fetchone()
    assert legacy_card["action_key"] == "legacy-card:7"
    assert legacy_card["blocking"] == 0
    assert (
        conn.execute("SELECT canonical_url FROM target_systems WHERE id=?", (historical_system,)).fetchone()[0]
        == "https://blog.example.com"
    )
    created_card = conn.execute("SELECT suggested_action FROM operator_inbox WHERE related_work_item_id=1").fetchone()
    assert created_card["suggested_action"] is None

    # Production-shaped lifecycle: activation parks the formerly focused blog
    # target, a tick advances a same-system work item, then the operator pauses
    # core.  Replay must not reinterpret that lifecycle as a URL/card change.
    conn.execute(
        "INSERT INTO work_items(target_name,lane,subject_table,subject_id,title,objective,status,dispatch_state,system_id) VALUES('T','entry_probe','target_assets','1','core mapping','map core','queued','active',?)",
        (core_system,),
    )
    conn.commit()
    activation = activate_focus(conn, target_name="T", system_id=core_system, goal="map core", operator_acknowledged=True)
    conn.execute(
        "UPDATE work_items SET status='partial' WHERE id=?",
        (conn.execute("SELECT MAX(id) FROM work_items").fetchone()[0],),
    )
    pause_focus(conn, target_name="T", session_id=activation["session_id"])
    conn.commit()
    conn.close()

    second = apply(db, target_name="T", backup_dir=tmp_path / "backups")
    third = apply(db, target_name="T", backup_dir=tmp_path / "backups")
    _assert_zero_reconciliation(second)
    _assert_zero_reconciliation(third)

    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    assert (
        conn.execute("SELECT canonical_url FROM target_systems WHERE id=?", (historical_system,)).fetchone()[0]
        == "https://blog.example.com"
    )
    assert conn.execute("SELECT suggested_action FROM operator_inbox WHERE related_work_item_id=1").fetchone()[0] is None
    conn.close()


def test_human_focus_replay_preview_is_read_only_and_apply_is_idempotent(tmp_path):
    db = tmp_path / "focus.db"
    c = sqlite3.connect(db)
    c.executescript(
        "CREATE TABLE schema_version(version INTEGER PRIMARY KEY,description TEXT); INSERT INTO schema_version VALUES(32,'032'); CREATE TABLE work_items(id INTEGER PRIMARY KEY,target_name TEXT); CREATE TABLE operator_inbox(id INTEGER PRIMARY KEY,target_name TEXT,related_work_item_id INTEGER,kind TEXT,title TEXT,detail TEXT,suggested_action TEXT,url TEXT,burp_action_id INTEGER,evidence_ref_id INTEGER,status TEXT,created_at TEXT,resolved_at TEXT); CREATE TABLE target_assets(id INTEGER PRIMARY KEY,target_name TEXT); CREATE TABLE facts(id INTEGER); CREATE TABLE findings(id INTEGER); CREATE TABLE evidence_packs(id INTEGER); CREATE TABLE agent_events(id INTEGER); CREATE TABLE soft_targets(id INTEGER PRIMARY KEY,target_name TEXT,asset_value TEXT,rank INTEGER); CREATE TABLE targets(target_name TEXT); CREATE TABLE hunt_sessions(id INTEGER PRIMARY KEY,target_name TEXT,status TEXT); CREATE TABLE decision_events(id INTEGER PRIMARY KEY,target_name TEXT); CREATE TABLE attack_threads(id INTEGER PRIMARY KEY,target_name TEXT); CREATE TABLE endpoint_observations(id INTEGER PRIMARY KEY,target_name TEXT); CREATE TABLE entry_observations(id INTEGER PRIMARY KEY,target_name TEXT); CREATE TABLE evidence_refs(id INTEGER PRIMARY KEY,target_name TEXT); CREATE TABLE burp_actions(id INTEGER PRIMARY KEY,target_name TEXT); CREATE TABLE pages(id INTEGER PRIMARY KEY); CREATE TABLE js_files(id INTEGER PRIMARY KEY); CREATE TABLE suspicious_points(id INTEGER PRIMARY KEY); CREATE TABLE work_items_extra(id INTEGER PRIMARY KEY);"
    )
    c.execute("INSERT INTO soft_targets VALUES(1,'T','blog.example',1)")
    c.commit()
    c.close()
    before = preview(db, target_name="T")
    assert before["apply_mutations"] is False and before["proposed_systems"]
    first = apply(db, target_name="T", backup_dir=tmp_path / "backups")
    second = apply(db, target_name="T", backup_dir=tmp_path / "backups")
    assert first["schema_after"] == 33 and second["schema_after"] == 33
