from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from db import v3_chain
from db.db_query import init_db
from db.v3_chain import run_v3_chain_facts

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "TOOLS" / "db" / "schema.sql"


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA.read_text(encoding="utf-8"))
    return conn


def _ready_focused_system(conn: sqlite3.Connection) -> None:
    """One eligible focused ready system (reuses the M9 focus contract)."""
    conn.execute("INSERT INTO targets(target_name,domain) VALUES('T','hcm.example.test')")
    conn.execute(
        """INSERT INTO target_assets(
               target_name,asset_type,asset_value,port,scope_status,scope_class,authorization_state,live_status)
           VALUES('T','domain','hcm.example.test',443,'in_scope','owned','authorized','live')"""
    )
    conn.execute(
        """INSERT INTO target_systems(target_name,system_key,display_name,canonical_url,scope_class,lifecycle_state)
           VALUES('T','hcm','HCM','https://hcm.example.test/Mobile/','owned','mapping')"""
    )
    conn.execute(
        """INSERT INTO system_asset_links(target_name,system_id,asset_id,relationship,confidence,evidence_refs_json)
           VALUES('T',1,1,'primary','high','["pages:mobile-1"]')"""
    )
    conn.execute(
        """INSERT INTO hunt_sessions(
               target_name,focus_subject_table,focus_subject_id,goal,status,selected_by,system_id,
               operator_acknowledged_at)
           VALUES('T','target_systems','1','offline M9','active','operator',1,datetime('now','localtime'))"""
    )
    conn.execute(
        """INSERT INTO system_soft_targets(
               target_name,system_id,eligibility_status,status,timebox_until)
           VALUES('T',1,'eligible','focused',datetime('now','localtime','+30 minutes'))"""
    )
    conn.execute(
        """INSERT INTO soft_targets(target_name,asset_id,asset_value,tier,status)
           VALUES('T',1,'hcm.example.test','B','focused')"""
    )
    conn.execute(
        """INSERT INTO attack_surface_profiles(target_name,soft_target_id,subject_table,subject_id,status)
           VALUES('T',1,'soft_targets','1','active')"""
    )
    for key in (
        "recon.identity",
        "recon.scope",
        "recon.asset_membership",
        "recon.network_edge",
        "recon.technology",
        "recon.entry_auth",
        "recon.api_ownership",
        "recon.business_flows",
        "recon.trust_boundaries",
        "recon.critical_unknowns",
    ):
        conn.execute(
            """INSERT INTO coverage_ledger(target_name,profile_id,item_key,category,status,confidence)
               VALUES('T',1,?,'recon','covered','high')""",
            (key,),
        )
    conn.execute(
        """INSERT INTO recon_sources(target_name,source_kind,query,result_json,status)
           VALUES('T','entry_recursion_observed','https://hcm.example.test/Mobile/',?, 'needs_review')""",
        (
            json.dumps(
                {"url": "https://hcm.example.test/Mobile/", "evidence_refs": ["pages:mobile-1"]},
                ensure_ascii=False,
            ),
        ),
    )
    conn.execute(
        """INSERT INTO js_files(url,page_url,source_kind,extraction_status)
           VALUES('https://hcm.example.test/Mobile/js/app.js','https://hcm.example.test/Mobile/','browser_script','pending')"""
    )
    conn.execute(
        """INSERT INTO endpoint_observations(
               target_name,asset_id,canonical_url,host,path,method,source,auth_state,
               parameter_names_json,evidence_refs_json,resolution_status)
           VALUES('T',1,'https://hcm.example.test/Mobile/AppBaseApi/GetBMData?TableName=',
                  'hcm.example.test','/Mobile/AppBaseApi/GetBMData','GET','auth_passive','public',
                  '["TableName"]','["ev:hcm"]','resolved')"""
    )
    conn.commit()


def test_v3_chain_empty_database_is_a_safe_noop():
    conn = _conn()
    conn.execute("INSERT INTO targets(target_name,domain) VALUES('T','example.test')")
    conn.commit()
    result = run_v3_chain_facts(conn, target_name="T", apply=True)
    assert result["cluster"]["systems"] == 0
    assert result["score"]["systems"] == 0
    assert result["linkage"]["planned"] == 0
    assert result["entry_recursion"] == [] and result["param_semantics"] == []
    assert result["pending_intel"] == [] and result["errors"] == []
    assert result["types"]["observed"] == 0


def test_v3_chain_cli_uses_explicit_db_and_echoes_it(tmp_path, monkeypatch, capsys):
    db_path = tmp_path / "demo.db"
    init_db(str(db_path), "Demo", "demo.test")
    monkeypatch.setattr(
        v3_chain.sys,
        "argv",
        ["v3_chain", "--target", "Demo", "--db", str(db_path), "--preview"],
    )

    assert v3_chain.main() == 0

    output = json.loads(capsys.readouterr().out)
    assert output["db"] == str(db_path)


def test_v3_chain_persists_cluster_score_and_linkage_facts():
    conn = _conn()
    conn.execute("INSERT INTO targets(target_name,domain) VALUES('T','example.test')")
    conn.execute(
        """INSERT INTO target_assets(
               target_name,asset_type,asset_value,port,scope_status,scope_class,authorization_state)
           VALUES('T','domain','app-a.example.test',443,'in_scope','owned','authorized'),
                 ('T','domain','unrelated.example.net',443,'needs_review','intel_only','unknown')"""
    )
    conn.execute(
        """INSERT INTO network_observations(
               target_name,asset_id,host,ip,port,protocol,service,http_json,source,evidence_refs_json,observed_at)
           VALUES('T',1,'app-a.example.test','203.0.113.33',443,'https','https','{}','dns','["ev:dns"]','2026-08-13'),
                 ('T',2,'unrelated.example.net','198.51.100.9',443,'https','https','{}','passive_dns','["ev:other"]','2026-08-13')"""
    )
    conn.commit()

    result = run_v3_chain_facts(conn, target_name="T", apply=True)

    assert result["errors"] == []
    assert result["cluster"] is not None and result["cluster"]["systems"] >= 1
    assert conn.execute("SELECT COUNT(*) FROM system_asset_links").fetchone()[0] >= 1
    assert result["score"]["systems"] >= 1
    rows = conn.execute("SELECT eligibility_status FROM system_soft_targets ORDER BY system_id").fetchall()
    assert {"eligible", "scope_blocked"} <= {row[0] for row in rows}
    assert result["linkage"]["planned"] >= 1 and result["linkage"]["inserted"] >= 1
    assert conn.execute("SELECT COUNT(*) FROM recon_sources WHERE source_kind='domain_ip_service_linkage'").fetchone()[0] >= 1
    assert any(item["source_kind"] == "domain_ip_service_linkage" for item in result["pending_intel"])
    assert result["types"]["observed"] == 2
    assert conn.execute("SELECT COUNT(*) FROM system_type_observations WHERE target_name='T'").fetchone()[0] == 2


def test_v3_chain_refreshes_types_without_focus_and_keeps_same_label_assets_separate():
    conn = _conn()
    conn.execute("INSERT INTO targets(target_name,domain) VALUES('T','example.test')")
    conn.executemany(
        """INSERT INTO target_assets(target_name,asset_type,asset_value,scope_status,scope_class,last_title,tech_stack)
           VALUES('T','domain',?,'in_scope','owned',?,?)""",
        [("a.example.test", "Admin Console", ""), ("b.example.test", "Admin Console", "")],
    )
    conn.commit()
    result = run_v3_chain_facts(conn, target_name="T", apply=True)
    assert result["types"]["observed"] == 2
    assert conn.execute("SELECT COUNT(*) FROM system_type_observations WHERE label='admin_portal'").fetchone()[0] == 2
    assert conn.execute("SELECT COUNT(*) FROM target_systems").fetchone()[0] == 2


def test_v3_chain_focused_system_consumes_entry_recursion_and_param_semantics():
    conn = _conn()
    _ready_focused_system(conn)

    result = run_v3_chain_facts(conn, target_name="T", apply=True)

    assert result["errors"] == []
    assert result["types"]["observed"] == 1
    assert conn.execute("SELECT COUNT(*) FROM system_type_observations WHERE target_name='T'").fetchone()[0] == 1
    assert result["entry_recursion"] and result["entry_recursion"][0]["system_id"] == 1
    assert any(
        row["lane"] == "js_reverse" and str(row["subtype"]).startswith("entry_recursion:")
        for row in conn.execute("SELECT lane,subtype FROM work_items WHERE system_id=1").fetchall()
    )
    assert conn.execute("SELECT COUNT(*) FROM entry_observations WHERE target_name='T'").fetchone()[0] >= 1
    assert result["param_semantics"] and result["param_semantics"][0]["families"]
    probe = conn.execute(
        """SELECT lane,subtype,subject_table,subject_id FROM work_items
           WHERE system_id=1 AND lane='logic_probe' ORDER BY id"""
    ).fetchall()
    assert probe and probe[0]["subtype"] == "generic_probe:input_error_diff"
    coverage = dict(
        conn.execute("SELECT item_key,status FROM coverage_ledger WHERE target_name='T' AND category='entry_recursion'").fetchall()
    )
    assert coverage["endpoint:param_semantic_classification"] == "covered"


def test_v3_chain_is_idempotent_across_ticks():
    conn = _conn()
    _ready_focused_system(conn)
    first = run_v3_chain_facts(conn, target_name="T", apply=True)
    second = run_v3_chain_facts(conn, target_name="T", apply=True)
    assert first["errors"] == [] and second["errors"] == []
    assert second["entry_recursion"][0]["queued"] == 0
    assert second["param_semantics"] == []
    assert conn.execute("SELECT COUNT(*) FROM work_items WHERE system_id=1").fetchone()[0] >= 2
