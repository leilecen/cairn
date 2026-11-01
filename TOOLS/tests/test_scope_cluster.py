from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from db.scope_cluster import apply_cluster_decision, cluster_assets, rollback_cluster_decision, write_cluster_card

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "TOOLS" / "db" / "schema.sql"
SCRIPT = ROOT / "TOOLS" / "db" / "scope_cluster.py"


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA.read_text(encoding="utf-8"))
    # B2 requires the S3 action kind. Mirror the migrated table contract without
    # coupling this unit test to the migration runner.
    conn.execute("DROP TABLE operator_inbox")
    conn.execute(
        """CREATE TABLE operator_inbox(
               id INTEGER PRIMARY KEY AUTOINCREMENT,target_name TEXT NOT NULL,
               related_work_item_id INTEGER,kind TEXT NOT NULL,title TEXT NOT NULL,
               detail TEXT,suggested_action TEXT,url TEXT,burp_action_id INTEGER,
               evidence_ref_id INTEGER,system_id INTEGER,action_key TEXT,action_label TEXT,
               why_needed TEXT,steps_json TEXT NOT NULL DEFAULT '[]',expected_observation TEXT,
               report_back_format TEXT,blocking INTEGER NOT NULL DEFAULT 1,status TEXT DEFAULT 'open',
               created_at TEXT DEFAULT CURRENT_TIMESTAMP,resolved_at TEXT)"""
    )
    conn.execute("INSERT INTO targets(target_name,domain) VALUES(?,?)", ("Acme's 目标", "example.com"))
    conn.commit()
    return conn


def _asset(conn: sqlite3.Connection, value: str, *, ip: str = "", tech: str = "") -> int:
    cur = conn.execute(
        """INSERT INTO target_assets(
               target_name,asset_type,asset_value,resolved_ip,last_tech_stack,status,
               scope_status,scope_class,authorization_state
           ) VALUES(?,?,?,?,?,'validated','needs_review','unknown','unknown')""",
        ("Acme's 目标", "subdomain", value, ip or None, tech or None),
    )
    # lastrowid 是 int | None（DDL 语句没有 rowid），这里紧跟 INSERT，用 or 0 兜底
    return int(cur.lastrowid or 0)


def test_cluster_preview_is_zero_write_and_shared_ip_does_not_merge_vhosts():
    conn = _conn()
    first = _asset(conn, "app.example.com", ip="203.0.113.8", tech="nginx")
    second = _asset(conn, "portal.other.test", ip="203.0.113.8", tech="nginx")
    before = conn.total_changes

    result = cluster_assets(conn, target_name="Acme's 目标")

    assert conn.total_changes == before
    assert len(result["clusters"]) == 2
    by_asset = {member: cluster for cluster in result["clusters"] for member in cluster["asset_ids"]}
    assert by_asset[first]["cluster_id"] != by_asset[second]["cluster_id"]
    assert by_asset[first]["recommended_decision"] == "confirm"
    assert by_asset[second]["recommended_decision"] == "reject"
    assert all("shared IP" in warning for warning in by_asset[first]["risk_warnings"])


def test_write_card_is_explicit_and_idempotent():
    conn = _conn()
    _asset(conn, "app.example.com")
    for index in range(12):
        _asset(conn, f"portal{index}.foreign{index}.test")
    assert conn.execute("SELECT count(*) FROM operator_inbox").fetchone()[0] == 0

    first = write_cluster_card(conn, target_name="Acme's 目标")
    second = write_cluster_card(conn, target_name="Acme's 目标")

    assert first["id"] == second["id"]
    assert conn.execute("SELECT count(*) FROM operator_inbox").fetchone()[0] == 1
    assert first["kind"] == "scope_cluster_confirm"
    why = json.loads(first["why_needed"])
    assert len(first["why_needed"]) <= 1000
    assert why["summary"]["cluster_count"] == 13
    assert len(why["summary"]["sample"]) <= 5
    assert why["summary"]["omitted"] >= 8
    assert all("assets" not in item and "asset_ids" not in item for item in why["summary"]["sample"])


def test_apply_is_audited_idempotent_and_rollback_restores_every_field():
    conn = _conn()
    asset_id = _asset(conn, "app.example.com")
    conn.commit()
    cluster_id = cluster_assets(conn, target_name="Acme's 目标")["clusters"][0]["cluster_id"]

    first = apply_cluster_decision(conn, target_name="Acme's 目标", cluster_id=cluster_id, decision="confirm")
    second = apply_cluster_decision(conn, target_name="Acme's 目标", cluster_id=cluster_id, decision="confirm")

    assert first["audit_id"] == second["audit_id"]
    row = conn.execute("SELECT * FROM target_assets WHERE id=?", (asset_id,)).fetchone()
    assert (row["scope_status"], row["scope_class"], row["authorization_state"]) == (
        "in_scope",
        "owned",
        "authorized",
    )
    audit = conn.execute("SELECT result_json FROM recon_sources WHERE id=?", (first["audit_id"],)).fetchone()
    payload = json.loads(audit[0])
    assert payload["assets"][0]["before"]["scope_status"] == "needs_review"
    assert payload["assets"][0]["after"]["scope_status"] == "in_scope"

    rolled_back = rollback_cluster_decision(conn, target_name="Acme's 目标", audit_id=first["audit_id"])
    assert rolled_back["restored"] == 1
    restored = conn.execute("SELECT * FROM target_assets WHERE id=?", (asset_id,)).fetchone()
    assert (restored["scope_status"], restored["scope_class"], restored["authorization_state"]) == (
        "needs_review",
        "unknown",
        "unknown",
    )


def test_exclude_marks_asset_but_never_consumes_another_target():
    conn = _conn()
    own_id = _asset(conn, "foreign.vendor.test")
    conn.execute("INSERT INTO targets(target_name,domain) VALUES('other','other.test')")
    conn.execute(
        """INSERT INTO target_assets(target_name,asset_value,status,scope_status)
           VALUES('other','other.test','validated','needs_review')"""
    )
    conn.commit()
    cluster_id = cluster_assets(conn, target_name="Acme's 目标")["clusters"][0]["cluster_id"]

    apply_cluster_decision(conn, target_name="Acme's 目标", cluster_id=cluster_id, decision="exclude")

    own = conn.execute("SELECT status,scope_reason FROM target_assets WHERE id=?", (own_id,)).fetchone()
    assert own["status"] == "excluded"
    assert "operator:exclude" in own["scope_reason"]
    assert conn.execute("SELECT scope_status FROM target_assets WHERE target_name='other'").fetchone()[0] == "needs_review"


def test_write_paths_validate_exact_target_and_leave_zero_writes():
    conn = _conn()
    _asset(conn, "app.example.com")
    conn.commit()

    with pytest.raises(ValueError, match="exactly match"):
        write_cluster_card(conn, target_name="Acme")
    with pytest.raises(ValueError, match="exactly match"):
        apply_cluster_decision(conn, target_name="Acme", cluster_id="scope-missing", decision="confirm")
    with pytest.raises(ValueError, match="exactly match"):
        rollback_cluster_decision(conn, target_name="Acme", audit_id=1)

    assert conn.execute("SELECT count(*) FROM recon_sources").fetchone()[0] == 0
    assert conn.execute("SELECT count(*) FROM operator_inbox").fetchone()[0] == 0


def test_apply_and_rollback_read_mutable_facts_only_after_immediate_lock():
    conn = _conn()
    _asset(conn, "app.example.com")
    conn.commit()
    cluster_id = cluster_assets(conn, target_name="Acme's 目标")["clusters"][0]["cluster_id"]
    trace: list[str] = []
    conn.set_trace_callback(trace.append)

    applied = apply_cluster_decision(conn, target_name="Acme's 目标", cluster_id=cluster_id, decision="confirm")
    begin = next(index for index, sql in enumerate(trace) if sql.upper().startswith("BEGIN IMMEDIATE"))
    mutable_reads = [
        index
        for index, sql in enumerate(trace)
        if sql.lstrip().upper().startswith("SELECT") and ("TARGET_ASSETS" in sql.upper() or "RECON_SOURCES" in sql.upper())
    ]
    assert mutable_reads and min(mutable_reads) > begin

    trace.clear()
    rollback_cluster_decision(conn, target_name="Acme's 目标", audit_id=applied["audit_id"])
    begin = next(index for index, sql in enumerate(trace) if sql.upper().startswith("BEGIN IMMEDIATE"))
    mutable_reads = [
        index
        for index, sql in enumerate(trace)
        if sql.lstrip().upper().startswith("SELECT") and ("TARGET_ASSETS" in sql.upper() or "RECON_SOURCES" in sql.upper())
    ]
    assert mutable_reads and min(mutable_reads) > begin


def test_scope_cluster_cli_file_target_mismatch_is_compact_exit_one_and_zero_write(tmp_path):
    path = tmp_path / "scope.db"
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA.read_text(encoding="utf-8"))
    conn.execute("INSERT INTO targets(target_name,domain) VALUES('real','example.test')")
    conn.commit()
    conn.close()

    completed = subprocess.run(  # noqa: S603 -- fixed interpreter and repository script
        [sys.executable, str(SCRIPT), "--file", str(path), "--target", "wrong", "cluster", "--write-card"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 1
    assert json.loads(completed.stdout) == {
        "ok": False,
        "error": "target_name does not exactly match the database targets",
    }
    with sqlite3.connect(path) as verify:
        assert verify.execute("SELECT count(*) FROM operator_inbox").fetchone()[0] == 0
        assert verify.execute("SELECT count(*) FROM recon_sources").fetchone()[0] == 0


def test_scope_cluster_cli_defaults_compact_and_requires_explicit_full_clusters(tmp_path):
    path = tmp_path / "scope-compact.db"
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA.read_text(encoding="utf-8"))
    conn.execute("INSERT INTO targets(target_name,domain) VALUES('real','example.test')")
    for index in range(12):
        conn.execute(
            """INSERT INTO target_assets(
                   target_name,asset_value,status,scope_status,scope_class,authorization_state
               ) VALUES('real',?,'validated','needs_review','unknown','unknown')""",
            (f"portal{index}.foreign{index}.test",),
        )
    conn.commit()
    conn.close()

    base = [sys.executable, str(SCRIPT), "--file", str(path), "--target", "real", "cluster"]
    compact_run = subprocess.run(  # noqa: S603 -- fixed interpreter and repository script
        base,
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    compact = json.loads(compact_run.stdout)
    assert compact_run.returncode == 0
    assert "clusters" not in compact
    assert compact["cluster_count"] == 12
    assert len(compact["sample"]) == 10
    assert compact["omitted"] == 2
    assert compact["counts"]["by_recommendation"] == {"reject": 12}
    assert compact["counts"]["by_basis"] == {"registered_domain": 12}
    assert all("assets" not in item and "asset_ids" not in item for item in compact["sample"])

    card_run = subprocess.run(  # noqa: S603 -- fixed interpreter and repository script
        [*base, "--write-card"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    card_payload = json.loads(card_run.stdout)
    assert card_run.returncode == 0
    assert "clusters" not in card_payload
    why = json.loads(card_payload["action_card"]["why_needed"])
    assert why["summary"]["cluster_count"] == 12

    full_run = subprocess.run(  # noqa: S603 -- fixed interpreter and repository script
        [*base, "--include-clusters"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    full = json.loads(full_run.stdout)
    assert full_run.returncode == 0
    assert len(full["clusters"]) == 12
    assert all("assets" in item and "asset_ids" in item for item in full["clusters"])
