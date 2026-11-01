from __future__ import annotations

import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from db.coverage_backfill import M9_COVERAGE_KEYS, backfill_coverage
from db.dispatcher import build_dispatch_plan
from db.param_semantics import classify_parameter_names, reconcile_param_semantics

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "TOOLS" / "db" / "schema.sql"
SCRIPT = ROOT / "TOOLS" / "db" / "param_semantics.py"


def _conn(*, ready: bool = False) -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA.read_text(encoding="utf-8"))
    conn.execute("INSERT INTO targets(target_name,domain) VALUES('T','hcm.example.test')")
    conn.execute(
        """INSERT INTO target_assets(
               target_name,asset_type,asset_value,port,scope_status,scope_class,authorization_state)
           VALUES('T','domain','hcm.example.test',443,'in_scope','owned','authorized')"""
    )
    conn.execute(
        """INSERT INTO system_soft_targets(
               target_name,system_id,eligibility_status,status,timebox_until)
           VALUES('T',1,'eligible','focused',datetime('now','localtime','+30 minutes'))"""
    )
    conn.execute(
        """INSERT INTO target_systems(target_name,system_key,display_name,canonical_url,scope_class,lifecycle_state)
           VALUES('T','hcm','HCM','https://hcm.example.test/Mobile/','owned','ready')"""
    )
    conn.execute(
        """INSERT INTO system_asset_links(target_name,system_id,asset_id,relationship,confidence,evidence_refs_json)
           VALUES('T',1,1,'primary','high','["ev:system"]')"""
    )
    conn.execute(
        """INSERT INTO endpoint_observations(
               target_name,asset_id,canonical_url,host,path,method,source,auth_state,
               parameter_names_json,evidence_refs_json,resolution_status,scope_class)
           VALUES('T',1,'https://hcm.example.test/Mobile/AppBaseApi/GetBMData?TableName=',
                  'hcm.example.test','/Mobile/AppBaseApi/GetBMData','GET','fixture','public',
                  '["TableName","Action","FileName","Token"]','["js_signals:hcm"]','resolved','owned')"""
    )
    conn.execute(
        """INSERT INTO hunt_sessions(
               target_name,focus_subject_table,focus_subject_id,goal,status,selected_by,system_id,
               operator_acknowledged_at)
           VALUES('T','target_systems','1','offline M9','active','operator',1,datetime('now','localtime'))"""
    )
    if True:
        conn.execute(
            """INSERT INTO soft_targets(target_name,asset_id,asset_value,tier,status)
               VALUES('T',1,'hcm.example.test','B','focused')"""
        )
        conn.execute(
            """INSERT INTO attack_surface_profiles(
                   target_name,soft_target_id,subject_table,subject_id,status)
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
    conn.commit()
    return conn


def test_parameter_families_and_only_input_error_diff_route():
    classified = classify_parameter_names(["TableName", "filter", "Action", "FileName", "Token"])
    assert set(classified) == {"db_structure", "query_filter", "data_action", "file_flow", "auth_flow"}
    conn = _conn()
    result = reconcile_param_semantics(
        conn,
        target_name="T",
        system_id=1,
        endpoint_id=1,
        evidence_refs=["js_signals:hcm"],
        public_confirmed=True,
        state_change=False,
        apply=True,
    )
    assert result["probe_subtype"] == "generic_probe:input_error_diff"
    row = conn.execute("SELECT lane,subtype,risk_class,system_id,objective FROM work_items").fetchone()
    assert (row["lane"], row["subtype"], row["risk_class"], row["system_id"]) == (
        "logic_probe",
        "generic_probe:input_error_diff",
        "safe_replay",
        1,
    )
    assert "sqli" not in row["objective"].lower() and "payload" not in row["objective"].lower()
    assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 0


@pytest.mark.parametrize(("public", "state_change"), [(False, False), (True, True), (False, True)])
def test_only_confirmed_public_stateless_endpoint_gets_l0_l1(public: bool, state_change: bool):
    conn = _conn()
    result = reconcile_param_semantics(
        conn,
        target_name="T",
        system_id=1,
        endpoint_id=1,
        evidence_refs=["js_signals:hcm"],
        public_confirmed=public,
        state_change=state_change,
        apply=True,
    )
    assert result["auto_plan_level"] is None
    assert conn.execute("SELECT COUNT(*) FROM work_items").fetchone()[0] == 0
    coverage = conn.execute(
        """SELECT status FROM coverage_ledger
           WHERE item_key='endpoint:param_semantic_classification' ORDER BY id DESC LIMIT 1"""
    ).fetchone()
    assert coverage is not None and coverage[0] != "covered"


def test_unclassified_or_blocked_outcome_does_not_mark_coverage_covered():
    conn = _conn()
    conn.execute("UPDATE endpoint_observations SET parameter_names_json='[\"opaque\"]'")
    conn.commit()
    result = reconcile_param_semantics(
        conn,
        target_name="T",
        system_id=1,
        endpoint_id=1,
        evidence_refs=["js_signals:hcm"],
        public_confirmed=True,
        state_change=False,
        outcome="blocked",
        apply=True,
    )
    assert not result["families"]
    status = conn.execute(
        """SELECT status FROM coverage_ledger
           WHERE item_key='endpoint:param_semantic_classification' ORDER BY id DESC LIMIT 1"""
    ).fetchone()[0]
    assert status in {"unknown", "blocked"}


def test_no_difference_is_not_reported_as_safe_or_no_injection():
    conn = _conn()
    result = reconcile_param_semantics(
        conn,
        target_name="T",
        system_id=1,
        endpoint_id=1,
        evidence_refs=["js_signals:hcm"],
        public_confirmed=True,
        state_change=False,
        outcome="no_difference",
        apply=False,
    )
    text = str(result).lower()
    assert "no_observed_difference" in text
    assert "no injection" not in text and "safe" not in text and "无注入" not in text


def test_preview_idempotency_savepoint_and_schema34_dispatch_readiness():
    conn = _conn(ready=True)
    before = conn.total_changes
    preview = reconcile_param_semantics(
        conn,
        target_name="T",
        system_id=1,
        endpoint_id=1,
        evidence_refs=["js_signals:hcm"],
        public_confirmed=True,
        state_change=False,
        apply=False,
    )
    assert conn.total_changes == before and preview["network_request_count"] == 0
    conn.execute("INSERT INTO targets(target_name,domain) VALUES('caller','caller.test')")
    first = reconcile_param_semantics(
        conn,
        target_name="T",
        system_id=1,
        endpoint_id=1,
        evidence_refs=["js_signals:hcm"],
        public_confirmed=True,
        state_change=False,
        apply=True,
    )
    second = reconcile_param_semantics(
        conn,
        target_name="T",
        system_id=1,
        endpoint_id=1,
        evidence_refs=["js_signals:hcm"],
        public_confirmed=True,
        state_change=False,
        apply=True,
    )
    assert first["work_items_inserted"] == 1 and second["work_items_inserted"] == 0
    task = build_dispatch_plan(conn, target_name="T", limit=1)["tasks"][0]
    assert task["system_id"] == 1 and task["readiness"]["state"] == "ready"
    conn.rollback()
    assert conn.execute("SELECT COUNT(*) FROM targets WHERE target_name='caller'").fetchone()[0] == 0


def test_invalid_ref_secret_and_cross_system_are_rejected():
    conn = _conn()
    with pytest.raises(ValueError):
        reconcile_param_semantics(
            conn,
            target_name="T",
            system_id=1,
            endpoint_id=1,
            evidence_refs=["Authorization: Bearer x"],
            public_confirmed=True,
            state_change=False,
        )
    with pytest.raises(ValueError, match="system"):
        reconcile_param_semantics(
            conn,
            target_name="T",
            system_id=999,
            endpoint_id=1,
            evidence_refs=["js_signals:hcm"],
            public_confirmed=True,
            state_change=False,
        )


def test_param_failure_rolls_back_coverage_but_preserves_caller_write():
    conn = _conn()
    baseline = conn.execute("SELECT COUNT(*) FROM coverage_ledger").fetchone()[0]
    conn.execute("INSERT INTO targets(target_name,domain) VALUES('caller','caller.test')")
    conn.execute(
        """CREATE TRIGGER fail_m9_param BEFORE INSERT ON work_items
           BEGIN SELECT RAISE(ABORT,'fixture failure'); END"""
    )
    with pytest.raises(sqlite3.IntegrityError):
        reconcile_param_semantics(
            conn,
            target_name="T",
            system_id=1,
            endpoint_id=1,
            evidence_refs=["js_signals:hcm"],
            public_confirmed=True,
            state_change=False,
            apply=True,
        )
    assert conn.execute("SELECT COUNT(*) FROM targets WHERE target_name='caller'").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM coverage_ledger").fetchone()[0] == baseline
    conn.rollback()


def test_four_m9_coverage_keys_seed_unknown_without_downgrade():
    conn = _conn()
    conn.execute("UPDATE system_soft_targets SET total_score=80")
    conn.execute(
        """INSERT INTO coverage_ledger(target_name,item_key,category,status,confidence)
           VALUES('T','entry:mobile_h5_discovery','m9_recursive_recon','blocked','high')"""
    )
    conn.commit()
    backfill_coverage(conn, target_name="T", apply=True)
    rows = dict(
        conn.execute(
            "SELECT item_key,status FROM coverage_ledger WHERE item_key IN (?,?,?,?)",
            M9_COVERAGE_KEYS,
        ).fetchall()
    )
    assert set(rows) == set(M9_COVERAGE_KEYS)
    assert rows["entry:mobile_h5_discovery"] == "blocked"
    assert all(rows[key] == "unknown" for key in M9_COVERAGE_KEYS[1:])


def test_param_cli_default_is_compact(tmp_path):
    path = tmp_path / "param.db"
    source = _conn()
    disk = sqlite3.connect(path)
    source.backup(disk)
    disk.close()
    source.close()
    run = subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(SCRIPT),
            "--file",
            str(path),
            "--target",
            "T",
            "--system-id",
            "1",
            "--endpoint-id",
            "1",
            "--evidence-ref",
            "js_signals:hcm",
            "--public-confirmed",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert run.returncode == 0 and len(run.stdout.encode()) < 1199
