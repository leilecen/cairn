"""Fresh-DB proof for the v4.6 L0-to-L3 closure contract."""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

import pytest
from db import experience_store, insight_capture
from db.db_admin import init_target_db
from db.focus_control import activate_focus
from db.human_brief import build_human_brief
from db.system_registry import link_asset, register_system
from db.system_scorer import score_systems
from db.v3_chain import run_v3_chain_facts
from db.work_queue import create_work_item
from pipeline import init_scan
from recon import recon_doctor, recon_intel


def _run_mocked_baseline(db_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Use the real L0 CLI while replacing its only network-facing boundary."""
    monkeypatch.setattr(
        init_scan,
        "run_httpx_baseline",
        lambda urls, **_: {
            "status": "succeeded",
            "results": [
                {
                    "url": url,
                    "status_code": 200,
                    "title": "Portal login",
                    "tech": ["nginx"],
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
            "assets_processed": 1,
            "requests": 0,
            "observations": 0,
        },
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["init_scan", "--target", "Closure", "--db", str(db_path), "--baseline"],
    )
    init_scan.main()


def _proposal_event(conn: sqlite3.Connection, work_item_id: int, asset_id: int) -> None:
    conn.execute(
        """INSERT INTO agent_events(work_item_id,agent_id,event_type,severity,payload_json)
           VALUES(?, 'v46-worker', 'partial_result', 'info', ?)""",
        (
            work_item_id,
            json.dumps(
                {
                    "worker_result": {
                        "insight_proposals": [
                            {
                                "summary": "登录入口的重定向分支需要复核",
                                "trigger": "login observed",
                                "asset_id": asset_id,
                                "evidence_refs": ["evidence:login"],
                                "next_action": "compare the public redirect response",
                            }
                        ]
                    }
                }
            ),
        ),
    )
    conn.commit()


def test_v46_fresh_db_closure_and_cross_system_proposal_gate(tmp_path, monkeypatch):
    # L0: explicit initialization, local doctor, mocked baseline, a single source
    # adapter, v3 facts, and the compact read model.  No queue or inspiration exists.
    initialized = init_target_db(target_name="Closure", slug="closure", domain="closure.example", db_dir=tmp_path)
    db_path = Path(initialized["db_path"])
    network_calls: list[object] = []
    monkeypatch.setattr(recon_doctor.subprocess, "run", lambda *args, **kwargs: network_calls.append(args))
    doctor = recon_doctor.build_manifest(target="Closure", db_path=db_path, environ={"PATH": ""}, path_entries=[])
    assert doctor["network"] == "not_used"
    assert network_calls == []
    _run_mocked_baseline(db_path, monkeypatch)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    source = recon_intel.run_source_adapter(
        conn,
        target_name="Closure",
        source_kind="fixture_passive",
        adapter="fixture",
        input_data={"domain": "closure.example"},
        budget={"items": 1},
        runner=lambda: {"status": "observed", "items": [{"host": "review.closure.example"}]},
    )
    assert source["status"] == "observed"
    assert (
        conn.execute("SELECT status FROM recon_runs WHERE target_name='Closure' AND source='fixture_passive'").fetchone()[0] == "succeeded"
    )
    facts = run_v3_chain_facts(conn, target_name="Closure", apply=True)
    assert facts["types"]["observed"] == 1
    brief = build_human_brief(conn, target_name="Closure")
    assert brief["candidate_systems"]
    assert conn.execute("SELECT COUNT(*) FROM work_items").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM inspirations").fetchone()[0] == 0

    # The operator upgrades the explicitly seeded root into one manual system A.
    root_asset_id = conn.execute("SELECT id FROM target_assets WHERE target_name='Closure' AND asset_value='closure.example'").fetchone()[0]
    conn.execute("UPDATE target_assets SET authorization_state='authorized' WHERE id=?", (root_asset_id,))
    system_a = register_system(
        conn,
        target_name="Closure",
        system_key="portal-a",
        display_name="Portal A",
        canonical_url="https://closure.example/",
        scope_class="owned",
    )
    link_asset(conn, target_name="Closure", system_id=system_a["id"], asset_id=root_asset_id, relationship="primary")
    score_systems(conn, "Closure", apply=True)
    activate_focus(
        conn,
        target_name="Closure",
        system_id=system_a["id"],
        goal="operator selected portal A",
        operator_acknowledged=True,
    )
    source_work_item_id = create_work_item(
        conn,
        target_name="Closure",
        system_id=system_a["id"],
        lane="entry_explore",
        subject_table="target_assets",
        subject_id=str(root_asset_id),
        title="map portal A",
        objective="map the chosen system",
    )
    _proposal_event(conn, source_work_item_id, root_asset_id)

    # L3 main-session acceptance -> terminal evidence-backed outcome -> operator harvest.
    accepted = insight_capture.accept_proposal(conn, "Closure", source_work_item_id)
    validation_id = accepted["validation_work_item_id"]
    conn.execute("UPDATE work_items SET status='done' WHERE id=?", (validation_id,))
    conn.execute(
        """INSERT INTO agent_events(work_item_id,agent_id,event_type,severity,payload_json)
           VALUES(?, 'v46-validator', 'done', 'info', ?)""",
        (validation_id, json.dumps({"worker_result": {"status": "done", "evidence_refs": ["evidence:validation"]}})),
    )
    conn.commit()
    insight_capture.transit(conn, "Closure", accepted["inspiration_id"], "verified")
    harvested = experience_store.harvest_insight(
        conn,
        target_name="Closure",
        insight_id=accepted["inspiration_id"],
        category="auth",
        title="login redirect branch",
        body="operator-reviewed compact validation result",
        trigger_signal="login observed",
    )

    # A later, explicit L3 work item is the only place where reuse may occur.
    reuse_work_item_id = create_work_item(
        conn,
        target_name="Closure",
        system_id=system_a["id"],
        lane="entry_explore",
        subject_table="target_assets",
        subject_id=str(root_asset_id),
        title="reuse auth lesson",
        objective="apply the operator-harvested lesson",
    )
    candidates = experience_store.l3_candidates(conn, target_name="Closure", work_item_id=reuse_work_item_id, trigger="login")
    assert [entry["id"] for entry in candidates] == [harvested["experience_id"]]
    experience_store.adopt_for_l3(
        conn,
        target_name="Closure",
        work_item_id=reuse_work_item_id,
        experience_id=harvested["experience_id"],
    )
    assert conn.execute("SELECT reuse_count FROM experience_entries WHERE id=?", (harvested["experience_id"],)).fetchone()[0] == 1

    # A proposal from system B cannot cross the active A focus and must leave no
    # extra insight or validation work item behind.
    conn.execute(
        """INSERT INTO target_assets(target_name,asset_type,asset_value,protocol,scope_status,scope_class,authorization_state)
           VALUES('Closure','domain','other.closure.example','https','in_scope','owned','authorized')"""
    )
    asset_b_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    system_b = register_system(
        conn,
        target_name="Closure",
        system_key="portal-b",
        display_name="Portal B",
        canonical_url="https://other.closure.example/",
        scope_class="owned",
    )
    link_asset(conn, target_name="Closure", system_id=system_b["id"], asset_id=asset_b_id, relationship="primary")
    work_item_b = create_work_item(
        conn,
        target_name="Closure",
        system_id=system_b["id"],
        lane="entry_explore",
        subject_table="target_assets",
        subject_id=str(asset_b_id),
        title="map portal B",
        objective="must not cross active focus A",
    )
    _proposal_event(conn, work_item_b, asset_b_id)
    before = (
        conn.execute("SELECT COUNT(*) FROM inspirations").fetchone()[0],
        conn.execute("SELECT COUNT(*) FROM work_items").fetchone()[0],
    )
    with pytest.raises(PermissionError, match="different system"):
        insight_capture.accept_proposal(conn, "Closure", work_item_b)
    after = (
        conn.execute("SELECT COUNT(*) FROM inspirations").fetchone()[0],
        conn.execute("SELECT COUNT(*) FROM work_items").fetchone()[0],
    )
    assert after == before
