from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from db.dispatcher import build_dispatch_plan
from db.entry_recursion import normalize_observed_url, plan_entry_recursion, reconcile_entry_recursion

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "TOOLS" / "db" / "schema.sql"
HCM = ROOT / "TOOLS" / "tests" / "fixtures" / "hcm_mobile_recursion.json"
SCRIPT = ROOT / "TOOLS" / "db" / "entry_recursion.py"


def _conn() -> sqlite3.Connection:
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
        """INSERT INTO target_systems(target_name,system_key,display_name,canonical_url,scope_class,lifecycle_state)
           VALUES('T','hcm','HCM','https://hcm.example.test/Mobile/','owned','mapping')"""
    )
    conn.execute(
        """INSERT INTO system_asset_links(target_name,system_id,asset_id,relationship,confidence,evidence_refs_json)
           VALUES('T',1,1,'primary','high','["pages:mobile-1"]')"""
    )
    conn.commit()
    return conn


def _fixture() -> dict:
    return json.loads(HCM.read_text(encoding="utf-8"))


def test_hcm_observed_mobile_chain_recovers_endpoint_without_network():
    conn = _conn()
    before = conn.total_changes
    preview = reconcile_entry_recursion(conn, target_name="T", system_id=1, fixture=_fixture(), apply=False, include_items=True)
    assert conn.total_changes == before
    assert preview["network_request_count"] == 0
    assert any(x["normalized_url"].endswith("/Mobile/AppBaseApi/GetBMData?TableName=") for x in preview["items"])
    assert not any("not-found" in x.get("normalized_url", "") and x["auto_queue"] for x in preview["items"])
    assert not any("chunk-987" in x.get("normalized_url", "") and x["auto_queue"] for x in preview["items"])
    applied = reconcile_entry_recursion(conn, target_name="T", system_id=1, fixture=_fixture(), apply=True)
    assert applied["endpoints_inserted"] == 1
    endpoint = conn.execute("SELECT canonical_url,parameter_names_json FROM endpoint_observations").fetchone()
    assert endpoint["canonical_url"].endswith("/Mobile/AppBaseApi/GetBMData?TableName=")
    assert json.loads(endpoint["parameter_names_json"]) == ["TableName"]
    works = conn.execute("SELECT lane,subject_table,system_id FROM work_items ORDER BY id").fetchall()
    assert all(row["system_id"] == 1 and row["subject_table"] == "recon_sources" for row in works)
    assert {row["lane"] for row in works} == {"js_reverse"}
    assert conn.execute("SELECT COUNT(*) FROM entry_observations").fetchone()[0] >= 1
    assert conn.execute("SELECT COUNT(*) FROM pages").fetchone()[0] >= 1
    assert conn.execute("SELECT COUNT(*) FROM js_files").fetchone()[0] >= 1
    coverage = dict(conn.execute("SELECT item_key,status FROM coverage_ledger WHERE category='entry_recursion'").fetchall())
    assert set(coverage) == {
        "entry:mobile_h5_discovery",
        "entry:recursive_js_expansion",
        "entry:lazy_chunk_coverage",
        "endpoint:param_semantic_classification",
    }
    assert coverage["endpoint:param_semantic_classification"] == "unknown"
    dispatch = build_dispatch_plan(conn, target_name="T", limit=10)
    assert dispatch["tasks"] and all(task["system_id"] == 1 for task in dispatch["tasks"])


@pytest.mark.parametrize("depth,eligible", [(0, True), (2, True), (3, False)])
def test_depth_boundary(depth: int, eligible: bool):
    fixture = _fixture()
    fixture["observations"] = [fixture["observations"][0] | {"depth": depth}]
    item = plan_entry_recursion(fixture)["items"][0]
    assert item["auto_queue"] is eligible


@pytest.mark.parametrize("budget", [0, 1, 20, 21, 50, 51])
def test_fixed_budget_boundaries_never_exceed_caps(budget: int):
    fixture = _fixture()
    base = fixture["observations"][0]
    fixture["observations"] = [base | {"url": f"https://hcm.example.test/Mobile/js/{i}.js"} for i in range(60)]
    plan = plan_entry_recursion(fixture, per_entry_budget=budget, per_system_budget=budget)
    assert plan["queued_count"] <= min(budget, 20, 50)
    if budget in {0, 21, 51}:
        assert plan["status"] in {"partial", "blocked"}
        assert plan["coverage_status"] != "covered"


def test_cycle_url_normalization_ports_fragments_and_source_map():
    assert normalize_observed_url("HTTPS://HCM.EXAMPLE.TEST:443/a?b=2&a=1#x") == ("https://hcm.example.test/a?a=1&b=2")
    fixture = _fixture()
    fixture["observations"] = [
        fixture["observations"][0],
        fixture["observations"][0] | {"url": "https://hcm.example.test:443/Mobile/js/app.bundle.js"},
        fixture["observations"][0] | {"url": "https://hcm.example.test:8443/a.js"},
        fixture["observations"][0] | {"url": "https://hcm.example.test/Mobile/js/app.bundle.js.map", "kind": "source_map", "depth": 2},
    ]
    plan = plan_entry_recursion(fixture)
    assert plan["queued_count"] == 2
    blocked = {x["blocker"] for x in plan["items"] if not x["auto_queue"]}
    assert "duplicate_or_cycle" in blocked and "cross_origin" in blocked


@pytest.mark.parametrize("response_class", ["auth_blocked", "captcha", "download"])
def test_blockers_are_not_queued(response_class: str):
    fixture = _fixture()
    fixture["observations"] = [fixture["observations"][0] | {"response_class": response_class}]
    item = plan_entry_recursion(fixture)["items"][0]
    assert not item["auto_queue"] and item["blocker"] == response_class


def test_seed_must_belong_to_system_and_blocked_endpoint_is_not_persisted():
    conn = _conn()
    fixture = _fixture()
    fixture["seed"]["url"] = "https://other.test/Mobile/"
    with pytest.raises(ValueError, match="seed origin"):
        reconcile_entry_recursion(conn, target_name="T", system_id=1, fixture=fixture, apply=True)
    fixture = _fixture()
    fixture["observations"] = [fixture["observations"][-1] | {"response_class": "soft_404", "kind": "endpoint"}]
    result = reconcile_entry_recursion(conn, target_name="T", system_id=1, fixture=fixture, apply=True)
    assert result["endpoints_inserted"] == 0
    assert conn.execute("SELECT COUNT(*) FROM endpoint_observations").fetchone()[0] == 0


@pytest.mark.parametrize("mutation", ["no_session", "no_ack", "unfocused", "ineligible", "null_timebox", "expired", "mapping"])
def test_schema34_requires_exact_operator_focus_ready_and_live_timebox(mutation: str):
    conn = _conn()
    if mutation == "no_session":
        conn.execute("DELETE FROM hunt_sessions")
    elif mutation == "no_ack":
        conn.execute("UPDATE hunt_sessions SET operator_acknowledged_at=NULL")
    elif mutation == "unfocused":
        conn.execute("UPDATE system_soft_targets SET status='ranked'")
    elif mutation == "ineligible":
        conn.execute("UPDATE system_soft_targets SET eligibility_status='needs_review'")
    elif mutation == "null_timebox":
        conn.execute("UPDATE system_soft_targets SET timebox_until=NULL")
    elif mutation == "expired":
        conn.execute("UPDATE system_soft_targets SET timebox_until=datetime('now','localtime','-1 minute')")
    else:
        conn.execute("UPDATE target_systems SET lifecycle_state='mapping'")
        conn.execute("UPDATE coverage_ledger SET status='unknown' WHERE item_key='recon.critical_unknowns'")
    conn.commit()
    before = conn.total_changes
    with pytest.raises(ValueError):
        reconcile_entry_recursion(conn, target_name="T", system_id=1, fixture=_fixture(), apply=True)
    assert conn.total_changes == before
    assert conn.execute("SELECT COUNT(*) FROM recon_sources").fetchone()[0] == 0


def test_budget_exhaustion_never_settles_m9_coverage_as_covered():
    conn = _conn()
    result = reconcile_entry_recursion(conn, target_name="T", system_id=1, fixture=_fixture(), apply=True, per_entry_budget=0)
    assert result["status"] in {"partial", "blocked"}
    assert result["next_action"]
    assert not conn.execute("SELECT 1 FROM coverage_ledger WHERE category='entry_recursion' AND status='covered'").fetchone()


def test_target_mismatch_and_multiple_seed_shape_are_zero_write():
    conn = _conn()
    before = conn.total_changes
    with pytest.raises(ValueError, match="target_name|system"):
        reconcile_entry_recursion(conn, target_name="Other", system_id=1, fixture=_fixture(), apply=True)
    assert conn.total_changes == before
    fixture = _fixture()
    fixture["seed"] = [fixture["seed"], fixture["seed"]]
    with pytest.raises(ValueError, match="one seed"):
        reconcile_entry_recursion(conn, target_name="T", system_id=1, fixture=fixture, apply=True)
    assert conn.total_changes == before


def test_schema33_keeps_explicit_operator_session_compatibility_without_timebox():
    conn = _conn()
    conn.execute("DELETE FROM schema_version")
    conn.execute("INSERT INTO schema_version(version,description) VALUES(33,'legacy focus')")
    conn.execute("UPDATE hunt_sessions SET operator_acknowledged_at=NULL")
    conn.execute("DELETE FROM system_soft_targets")
    conn.commit()
    result = reconcile_entry_recursion(conn, target_name="T", system_id=1, fixture=_fixture(), apply=False)
    assert result["network_request_count"] == 0 and result["status"] == "done"


def test_dns_or_ip_cannot_authorize_cross_hostname_and_secrets_are_rejected():
    fixture = _fixture()
    fixture["observations"] = [fixture["observations"][0] | {"url": "https://other.test/a.js", "source_kind": "dns"}]
    with pytest.raises(ValueError, match="trusted"):
        plan_entry_recursion(fixture)
    fixture = _fixture()
    fixture["seed"]["url"] = "https://hcm.example.test/Mobile/?Authorization=Bearer-secret"
    with pytest.raises(ValueError, match="raw HTTP or credential"):
        plan_entry_recursion(fixture)


@pytest.mark.parametrize("field", ["observed", "guessed"])
def test_seed_must_be_an_observed_non_guessed_fact(field: str):
    fixture = _fixture()
    fixture["seed"][field] = False if field == "observed" else True
    with pytest.raises(ValueError, match="observed"):
        plan_entry_recursion(fixture)


def test_apply_is_idempotent_and_savepoint_preserves_outer_transaction():
    conn = _conn()
    conn.execute("INSERT INTO targets(target_name,domain) VALUES('caller','caller.test')")
    first = reconcile_entry_recursion(conn, target_name="T", system_id=1, fixture=_fixture(), apply=True)
    second = reconcile_entry_recursion(conn, target_name="T", system_id=1, fixture=_fixture(), apply=True)
    assert first["sources_inserted"] > 0 and second["sources_inserted"] == 0
    assert conn.in_transaction
    conn.rollback()
    assert conn.execute("SELECT COUNT(*) FROM targets WHERE target_name='caller'").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM recon_sources").fetchone()[0] == 0


def test_entry_failure_rolls_back_only_function_savepoint():
    conn = _conn()
    conn.execute("INSERT INTO targets(target_name,domain) VALUES('caller','caller.test')")
    conn.execute(
        """CREATE TRIGGER fail_m9_entry BEFORE INSERT ON recon_sources
           BEGIN SELECT RAISE(ABORT,'fixture failure'); END"""
    )
    with pytest.raises(sqlite3.IntegrityError):
        reconcile_entry_recursion(conn, target_name="T", system_id=1, fixture=_fixture(), apply=True)
    assert conn.execute("SELECT COUNT(*) FROM targets WHERE target_name='caller'").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM recon_sources").fetchone()[0] == 0
    conn.rollback()


def test_entry_cli_is_compact_and_missing_file_is_not_created(tmp_path):
    path = tmp_path / "entry.db"
    source = _conn()
    disk = sqlite3.connect(path)
    source.backup(disk)
    disk.close()
    source.close()
    run = subprocess.run(  # noqa: S603
        [sys.executable, str(SCRIPT), "--file", str(path), "--target", "T", "--system-id", "1", "--fixture", str(HCM)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert run.returncode == 0 and len(run.stdout.encode()) < 1199
    missing = tmp_path / "missing.db"
    failed = subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(SCRIPT),
            "--file",
            str(missing),
            "--target",
            "T",
            "--system-id",
            "1",
            "--fixture",
            str(HCM),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert failed.returncode == 1 and not missing.exists()
