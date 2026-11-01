from __future__ import annotations

import sqlite3
from pathlib import Path

from db.blackboard_seed import apply_seed
from db.db_admin import init_target_db
from db.dispatcher import build_dispatch_plan
from db.human_brief import build_human_brief
from db.v3_chain import run_v3_chain_facts
from pipeline import init_scan
from recon import recon_doctor


def _seed_assets(path: Path) -> None:
    with sqlite3.connect(path) as conn:
        conn.executemany(
            """INSERT INTO target_assets(
                   target_name,asset_type,asset_value,protocol,scope_status,scope_class,authorization_state
               ) VALUES('Demo','domain',?,'https','in_scope','owned','authorized')""",
            [("a.demo.test",), ("b.demo.test",)],
        )
        conn.commit()


def _run_baseline(path: Path, monkeypatch) -> None:
    monkeypatch.setattr(init_scan, "find_db", lambda _target: path)
    monkeypatch.setattr(
        init_scan,
        "run_httpx_baseline",
        lambda urls, **_: {
            "status": "succeeded",
            "results": [
                {
                    "url": url,
                    "status_code": 200,
                    "title": "Admin Console",
                    "tech": ["Admin"],
                    "live": True,
                }
                for url in urls
            ],
            "next_index": len(urls),
        },
    )
    monkeypatch.setattr(
        init_scan,
        "run_baseline_entry_probe",
        lambda *args, **kwargs: {
            "status": "done",
            "assets_processed": 2,
            "requests": 0,
            "observations": 0,
        },
    )
    monkeypatch.setattr(init_scan.sys, "argv", ["init_scan", "--target", "Demo", "--db", str(path), "--baseline"])
    init_scan.main()


def test_v45_progressive_recon_broad_then_explicit_focus(tmp_path, monkeypatch):
    initialized = init_target_db(target_name="Demo", slug="demo", domain="demo.test", db_dir=tmp_path)
    db_path = Path(initialized["db_path"])
    _seed_assets(db_path)

    network_calls = []
    monkeypatch.setattr(recon_doctor.subprocess, "run", lambda *args, **kwargs: network_calls.append(args))
    manifest = recon_doctor.build_manifest(
        target="Demo",
        db_path=db_path,
        environ={"PATH": "", "FOFA_RELAY_KEY": "relay-present"},
        path_entries=[],
    )
    assert manifest["target"] == "Demo"
    assert manifest["network"] == "not_used"
    assert network_calls == []

    _run_baseline(db_path, monkeypatch)
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        assert conn.execute("SELECT COUNT(*) FROM pages WHERE status='queued'").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM work_items").fetchone()[0] == 0
        facts = run_v3_chain_facts(conn, target_name="Demo", apply=True)
        # Explicit init now contributes the authorized root-domain baseline
        # asset alongside the two review fixtures.
        assert facts["types"]["observed"] == 3
        brief = build_human_brief(conn, target_name="Demo")
        assert brief["candidate_systems"]
        assert all(card["type_labels"] == ["admin_portal"] for card in brief["candidate_systems"])

        conn.execute(
            """INSERT INTO target_systems(
                   target_name,system_key,display_name,canonical_url,scope_class,lifecycle_state,created_by
               ) VALUES('Demo','operator-a','A','https://a.demo.test/','owned','mapping','operator')"""
        )
        system_a = conn.execute("SELECT id FROM target_systems WHERE system_key='operator-a'").fetchone()[0]
        assets = {row["asset_value"]: row["id"] for row in conn.execute("SELECT id,asset_value FROM target_assets")}
        asset_a, asset_b = assets["a.demo.test"], assets["b.demo.test"]
        conn.execute(
            """INSERT INTO system_asset_links(
                   target_name,system_id,asset_id,relationship,confidence,evidence_refs_json
               ) VALUES('Demo',?,?, 'primary','high','["ev:a"]')""",
            (system_a, asset_a),
        )
        conn.execute(
            """INSERT INTO hunt_sessions(
                   target_name,focus_subject_table,focus_subject_id,goal,status,selected_by,system_id
               ) VALUES('Demo','target_systems',?,'bounded A','active','operator',?)""",
            (str(system_a), system_a),
        )
        conn.execute(
            """INSERT INTO system_soft_targets(
                   target_name,system_id,eligibility_status,status,total_score,timebox_until
               ) VALUES('Demo',?,'eligible','focused',90,datetime('now','localtime','+30 minutes'))""",
            (system_a,),
        )
        conn.commit()

        _run_baseline(db_path, monkeypatch)
        facts = run_v3_chain_facts(conn, target_name="Demo", apply=True)
        assert facts["types"]["observed"] == 3
        assert (
            conn.execute(
                "SELECT label FROM system_type_observations WHERE target_name='Demo' AND asset_id=?",
                (asset_b,),
            ).fetchone()[0]
            == "admin_portal"
        )
        seeded = apply_seed(conn, target_name="Demo", dry_run=False)
        assert seeded["created"] >= 0
        plan = build_dispatch_plan(conn, target_name="Demo", limit=10)
        assert len(plan["tasks"]) <= 2
        assert all(item["system_id"] == system_a for item in plan["tasks"])
        assert not conn.execute(
            "SELECT 1 FROM work_items WHERE target_name='Demo' AND system_id=? AND subject_id=?",
            (system_a, str(asset_b)),
        ).fetchone()

        assert conn.execute("SELECT COUNT(*) FROM targets WHERE target_name='Demo'").fetchone()[0] == 1
