from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from db.coverage_backfill import backfill_coverage, category_for_key

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "TOOLS" / "db" / "schema.sql"
SCRIPT = ROOT / "TOOLS" / "db" / "coverage_backfill.py"


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA.read_text(encoding="utf-8"))
    conn.execute("INSERT INTO targets(id,target_name,domain) VALUES(1,'T[1]?','example.test')")
    conn.execute("INSERT INTO targets(id,target_name,domain) VALUES(2,'other','other.test')")
    conn.execute(
        """INSERT INTO target_assets(target_name,asset_value,status,live_status)
           VALUES('T[1]?','app.example.test','validated','live'),('other','other.test','validated','live')"""
    )
    conn.execute(
        """INSERT INTO endpoint_observations(target_name,canonical_url,method,source,source_id,evidence_refs_json)
           VALUES('T[1]?','HTTPS://APP.EXAMPLE.TEST:443/api?b=2&a=1#frag','GET','fixture','1','["ep:1"]'),
                 ('other','https://other.test/api','GET','fixture','2','[]')"""
    )
    conn.execute("""INSERT INTO suspicious_points(id,url,test_status) VALUES('SP-1','https://app.example.test/x','untested')""")
    conn.execute(
        """INSERT INTO work_items(target_name,lane,subject_table,subject_id,status)
           VALUES('T[1]?','quick_scout','pages','1','done')"""
    )
    conn.execute(
        """INSERT INTO attack_surface_profiles(target_name,subject_table,subject_id,status,evidence_refs_json)
           VALUES('T[1]?','soft_targets','1','active','["profile:1"]')"""
    )
    conn.commit()
    return conn


def test_backfill_twice_is_idempotent_with_null_profile_and_target_isolation():
    conn = _conn()

    first = backfill_coverage(conn, target_name="T[1]?", apply=True)
    keys_first = {row[0] for row in conn.execute("SELECT item_key FROM coverage_ledger WHERE target_name='T[1]?' ")}
    second = backfill_coverage(conn, target_name="T[1]?", apply=True)
    keys_second = {row[0] for row in conn.execute("SELECT item_key FROM coverage_ledger WHERE target_name='T[1]?' ")}

    assert first["inserted"] == 5
    assert second["inserted"] == 0
    assert keys_first == keys_second
    assert len(keys_second) == 5
    assert conn.execute("SELECT count(*) FROM coverage_ledger WHERE target_name='other'").fetchone()[0] == 0
    assert "endpoint:https://app.example.test:443/api?a=1&b=2" in keys_second


def test_category_is_deterministic_and_matches_every_written_key():
    conn = _conn()
    backfill_coverage(conn, target_name="T[1]?", apply=True)

    rows = conn.execute("SELECT item_key,category FROM coverage_ledger WHERE target_name=?", ("T[1]?",)).fetchall()
    work_lanes = {1: "quick_scout"}
    assert all(category_for_key(row["item_key"], work_lanes=work_lanes) == row["category"] for row in rows)


def test_empty_suspicious_point_id_is_a_hard_failure_and_writes_nothing():
    conn = _conn()
    conn.execute("DROP TABLE suspicious_points")
    conn.execute(
        """CREATE TABLE suspicious_points(
               id TEXT PRIMARY KEY,url TEXT,page_url TEXT,test_status TEXT)"""
    )
    conn.execute("INSERT INTO suspicious_points(id,url,test_status) VALUES(NULL,'https://example.test/y','untested')")
    conn.commit()

    with pytest.raises(ValueError, match="empty suspicious_points.id"):
        backfill_coverage(conn, target_name="T[1]?", apply=True)

    assert conn.execute("SELECT count(*) FROM coverage_ledger").fetchone()[0] == 0


def test_empty_suspicious_point_id_fails_closed_even_when_url_is_not_target_scoped():
    conn = _conn()
    conn.execute("DROP TABLE suspicious_points")
    conn.execute("CREATE TABLE suspicious_points(id TEXT PRIMARY KEY,url TEXT,page_url TEXT,test_status TEXT)")
    conn.execute("INSERT INTO suspicious_points(id,url,test_status) VALUES(NULL,'https://other.test/y','untested')")
    conn.commit()

    with pytest.raises(ValueError, match="empty suspicious_points.id"):
        backfill_coverage(conn, target_name="T[1]?", apply=True)

    assert conn.execute("SELECT count(*) FROM coverage_ledger").fetchone()[0] == 0


def test_preview_does_not_write_and_preserves_unknown_as_unknown():
    conn = _conn()
    result = backfill_coverage(conn, target_name="T[1]?", apply=False, include_items=True)
    assert result["planned"] == 5
    assert conn.execute("SELECT count(*) FROM coverage_ledger").fetchone()[0] == 0
    sp = next(row for row in result["items"] if row["item_key"] == "sp:SP-1")
    assert sp["status"] == "unknown"


def test_apply_validates_target_and_reads_facts_only_after_immediate_lock():
    conn = _conn()
    before = conn.execute("SELECT count(*) FROM coverage_ledger").fetchone()[0]
    with pytest.raises(ValueError, match="exactly match"):
        backfill_coverage(conn, target_name="T[1]", apply=True)
    assert conn.execute("SELECT count(*) FROM coverage_ledger").fetchone()[0] == before

    trace: list[str] = []
    conn.set_trace_callback(trace.append)
    backfill_coverage(conn, target_name="T[1]?", apply=True)
    begin = next(index for index, sql in enumerate(trace) if sql.upper().startswith("BEGIN IMMEDIATE"))
    fact_reads = [
        index
        for index, sql in enumerate(trace)
        if sql.lstrip().upper().startswith("SELECT")
        and any(
            table in sql.upper()
            for table in (
                "TARGET_ASSETS",
                "ENDPOINT_OBSERVATIONS",
                "SUSPICIOUS_POINTS",
                "WORK_ITEMS",
                "ATTACK_SURFACE_PROFILES",
            )
        )
    ]
    assert fact_reads and min(fact_reads) > begin


def test_cli_output_is_compact_and_target_mismatch_is_zero_write(tmp_path):
    path = tmp_path / "coverage.db"
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA.read_text(encoding="utf-8"))
    conn.execute("INSERT INTO targets(target_name,domain) VALUES('real','example.test')")
    for index in range(15):
        conn.execute(
            """INSERT INTO target_assets(target_name,asset_value,status,live_status)
               VALUES('real',?,'validated','live')""",
            (f"a{index}.example.test",),
        )
    conn.commit()
    conn.close()

    preview = subprocess.run(  # noqa: S603 -- fixed interpreter and repository script
        [sys.executable, str(SCRIPT), "--file", str(path), "--target", "real"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert preview.returncode == 0
    payload = json.loads(preview.stdout)
    assert "items" not in payload
    assert len(payload["sample"]) == 10
    assert payload["omitted"] == 5
    one_path = tmp_path / "coverage-one.db"
    one = sqlite3.connect(one_path)
    one.executescript(SCHEMA.read_text(encoding="utf-8"))
    one.execute("INSERT INTO targets(target_name,domain) VALUES('one','one.test')")
    one.execute(
        """INSERT INTO target_assets(target_name,asset_value,status,live_status)
           VALUES('one','one.test','validated','live')"""
    )
    one.commit()
    one.close()
    compact = subprocess.run(  # noqa: S603
        [sys.executable, str(SCRIPT), "--file", str(one_path), "--target", "one"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert compact.returncode == 0 and len(compact.stdout.encode()) < 1199

    mismatch = subprocess.run(  # noqa: S603 -- fixed interpreter and repository script
        [sys.executable, str(SCRIPT), "--file", str(path), "--target", "wrong", "--apply"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert mismatch.returncode == 1
    assert json.loads(mismatch.stdout) == {
        "ok": False,
        "error": "target_name does not exactly match the database targets",
    }
    with sqlite3.connect(path) as verify:
        assert verify.execute("SELECT count(*) FROM coverage_ledger").fetchone()[0] == 0


def test_m8_focused_system_seeds_exactly_eight_unknown_coverage_items():
    conn = _conn()
    conn.execute(
        """INSERT INTO target_systems(target_name,system_key,display_name,canonical_url,scope_class,lifecycle_state)
           VALUES('T[1]?','app','App','https://app.example.test','owned','ready')"""
    )
    conn.execute(
        """INSERT INTO system_soft_targets(target_name,system_id,eligibility_status,status)
           VALUES('T[1]?',1,'eligible','focused')"""
    )
    conn.commit()

    result = backfill_coverage(conn, target_name="T[1]?", apply=False, include_items=True)
    m8 = [item for item in result["items"] if item["category"] == "m8_control"]
    assert {item["item_key"] for item in m8} == {
        "identity:product_discrimination",
        "identity:domain_ip_service_linkage",
        "vendor_family:public_advisory_paths",
        "generic_probe:input_error_diff",
        "auth_boundary:public_endpoints",
        "js:login_page_decode",
        "intel:passive_neighbor_index",
        "external_intel:document_reconciliation",
    }
    assert all(item["status"] == "unknown" and not item["evidence_refs"] for item in m8)


def test_m8_seed_requires_focused_eligible_system_and_is_target_isolated():
    conn = _conn()
    conn.executemany(
        """INSERT INTO target_systems(target_name,system_key,display_name,canonical_url,scope_class,lifecycle_state)
           VALUES(?,?,?,?,?,?)""",
        [
            ("T[1]?", "blocked", "Blocked", "https://blocked.example.test", "unknown", "ready"),
            ("other", "eligible", "Other", "https://other.test", "owned", "ready"),
        ],
    )
    conn.executemany(
        """INSERT INTO system_soft_targets(target_name,system_id,eligibility_status,status)
           VALUES(?,?,?,?)""",
        [("T[1]?", 1, "scope_blocked", "focused"), ("other", 2, "eligible", "focused")],
    )
    conn.commit()

    result = backfill_coverage(conn, target_name="T[1]?", apply=False, include_items=True)
    assert not any(item["category"] == "m8_control" for item in result["items"])


@pytest.mark.parametrize("existing_status", ["covered", "blocked"])
def test_m8_seed_never_downgrades_an_existing_terminal_status(existing_status):
    conn = _conn()
    conn.execute(
        """INSERT INTO target_systems(target_name,system_key,display_name,canonical_url,scope_class,lifecycle_state)
           VALUES('T[1]?','app','App','https://app.example.test','owned','ready')"""
    )
    conn.execute(
        """INSERT INTO system_soft_targets(target_name,system_id,eligibility_status,status)
           VALUES('T[1]?',1,'eligible','focused')"""
    )
    conn.execute(
        """INSERT INTO coverage_ledger(
               target_name,profile_id,item_key,category,status,confidence,evidence_refs_json,summary
           ) VALUES(
               'T[1]?',NULL,'identity:product_discrimination','m8_control',?,'high','["ev:existing"]','existing'
           )""",
        (existing_status,),
    )
    conn.commit()

    backfill_coverage(conn, target_name="T[1]?", apply=True)
    row = conn.execute(
        """SELECT status,confidence,evidence_refs_json,summary FROM coverage_ledger
           WHERE target_name='T[1]?' AND item_key='identity:product_discrimination'"""
    ).fetchone()
    assert tuple(row) == (existing_status, "high", '["ev:existing"]', "existing")


def test_coverage_apply_uses_savepoint_and_does_not_swallow_caller_transaction():
    conn = _conn()
    conn.execute("INSERT INTO targets(target_name,domain) VALUES('caller','caller.test')")
    backfill_coverage(conn, target_name="T[1]?", apply=True)
    assert conn.in_transaction
    conn.rollback()
    assert conn.execute("SELECT COUNT(*) FROM targets WHERE target_name='caller'").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM coverage_ledger").fetchone()[0] == 0

    conn.execute("INSERT INTO targets(target_name,domain) VALUES('caller','caller.test')")
    conn.execute(
        """CREATE TRIGGER fail_coverage_nested BEFORE INSERT ON coverage_ledger
           BEGIN SELECT RAISE(ABORT,'nested failure'); END"""
    )
    with pytest.raises(sqlite3.IntegrityError):
        backfill_coverage(conn, target_name="T[1]?", apply=True)
    assert conn.execute("SELECT COUNT(*) FROM targets WHERE target_name='caller'").fetchone()[0] == 1
    conn.rollback()
