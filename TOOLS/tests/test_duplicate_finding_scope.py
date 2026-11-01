from __future__ import annotations

import sqlite3
import subprocess
import sys
from pathlib import Path

from db.duplicate_finding_scope import finding_scope_key, reconcile_duplicate_finding

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "TOOLS" / "db" / "schema.sql"
SCRIPT = ROOT / "TOOLS" / "db" / "duplicate_finding_scope.py"


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA.read_text(encoding="utf-8"))
    conn.execute("INSERT INTO targets(id,target_name,domain) VALUES(1,'T','hcm.example.test')")
    conn.execute(
        """INSERT INTO target_assets(
               target_name,asset_type,asset_value,port,scope_status,scope_class,authorization_state)
           VALUES('T','domain','hcm.example.test',443,'in_scope','owned','authorized')"""
    )
    conn.execute(
        """INSERT INTO target_systems(target_name,system_key,display_name,canonical_url,scope_class)
           VALUES('T','hcm','HCM','https://hcm.example.test','owned')"""
    )
    conn.execute(
        """INSERT INTO system_asset_links(target_name,system_id,asset_id,relationship,confidence,evidence_refs_json)
           VALUES('T',1,1,'primary','high','["ev:system"]')"""
    )
    rows = [
        (
            "F1",
            "sqli",
            "https://hcm.example.test:443/api/a?id=1#x",
            '{"system_id":1,"root_cause":"unsafe_query_concat","evidence_refs":["ev:f1"]}',
        ),
        (
            "F2",
            "sqli",
            "https://hcm.example.test/api/a?id=2",
            '{"system_id":1,"root_cause":"unsafe_query_concat","evidence_refs":["ev:f2"]}',
        ),
        (
            "F3",
            "sqli",
            "https://hcm.example.test/api/b?id=1",
            '{"system_id":1,"root_cause":"unsafe_query_concat","evidence_refs":["ev:f3"]}',
        ),
        (
            "F4",
            "idor",
            "https://hcm.example.test/api/a?id=1",
            '{"system_id":1,"root_cause":"missing_object_authz","evidence_refs":["ev:f4"]}',
        ),
    ]
    conn.executemany("INSERT INTO findings(id,target_id,type,url,evidence,review_status) VALUES(?,1,?,?,?, 'candidate')", rows)
    conn.commit()
    return conn


def test_scope_key_normalizes_default_port_fragment_and_ignores_query_values():
    one = finding_scope_key("https://HCM.example.test:443/api/a?id=1#x", "sqli")
    two = finding_scope_key("https://hcm.example.test/api/a?id=2", "SQLI")
    assert one == two


def test_only_exact_asset_endpoint_and_class_is_suppressed():
    conn = _conn()
    preview = reconcile_duplicate_finding(conn, target_name="T", system_id=1, finding_id="F2", apply=False)
    assert preview["duplicate_of"] == "F1"
    applied = reconcile_duplicate_finding(conn, target_name="T", system_id=1, finding_id="F2", apply=True)
    assert applied["updated"] == 1
    assert conn.execute("SELECT review_status FROM findings WHERE id='F2'").fetchone()[0] == "duplicate"
    notes = conn.execute("SELECT review_notes FROM findings WHERE id='F2'").fetchone()[0]
    assert "duplicate_of:F1" in notes and "ev:f1" in notes and "ev:f2" in notes
    assert reconcile_duplicate_finding(conn, target_name="T", system_id=1, finding_id="F3", apply=False)["duplicate_of"] is None


def test_same_path_class_but_different_root_cause_or_system_is_not_duplicate():
    conn = _conn()
    conn.execute(
        """INSERT INTO target_assets(
               target_name,asset_type,asset_value,port,scope_status,scope_class,authorization_state)
           VALUES('T','domain','other.example.test',443,'in_scope','owned','authorized')"""
    )
    conn.execute(
        """INSERT INTO target_systems(target_name,system_key,display_name,canonical_url,scope_class)
           VALUES('T','other','Other','https://other.example.test','owned')"""
    )
    conn.execute("INSERT INTO system_asset_links(target_name,system_id,asset_id,relationship) VALUES('T',2,2,'primary')")
    conn.execute(
        """INSERT INTO findings(id,target_id,type,url,evidence,review_status)
           VALUES('F5',1,'sqli','https://hcm.example.test/api/a','{"system_id":1,"root_cause":"unsafe_orm_filter","evidence_refs":["ev:f5"]}','candidate')"""
    )
    conn.execute(
        """INSERT INTO findings(id,target_id,type,url,evidence,review_status)
           VALUES('F6',1,'sqli','https://hcm.example.test/api/a','{"system_id":2,"root_cause":"unsafe_query_concat","evidence_refs":["ev:f6"]}','candidate')"""
    )
    conn.commit()
    assert reconcile_duplicate_finding(conn, target_name="T", system_id=1, finding_id="F5")["duplicate_of"] is None
    # Candidate F2 must not match the explicit other-system record F6.
    assert reconcile_duplicate_finding(conn, target_name="T", system_id=1, finding_id="F2")["duplicate_of"] == "F1"


def test_missing_root_cause_fails_closed_without_suppression():
    conn = _conn()
    conn.execute("UPDATE findings SET evidence='{}' WHERE id IN ('F1','F2')")
    conn.commit()
    result = reconcile_duplicate_finding(conn, target_name="T", system_id=1, finding_id="F2", apply=True)
    assert result["duplicate_of"] is None and result["updated"] == 0
    assert reconcile_duplicate_finding(conn, target_name="T", system_id=1, finding_id="F4", apply=False)["duplicate_of"] is None


def test_duplicate_apply_is_idempotent_and_preserves_outer_transaction():
    conn = _conn()
    conn.execute("INSERT INTO targets(target_name,domain) VALUES('caller','caller.test')")
    first = reconcile_duplicate_finding(conn, target_name="T", system_id=1, finding_id="F2", apply=True)
    second = reconcile_duplicate_finding(conn, target_name="T", system_id=1, finding_id="F2", apply=True)
    assert first["updated"] == 1 and second["updated"] == 0
    conn.rollback()
    assert conn.execute("SELECT review_status FROM findings WHERE id='F2'").fetchone()[0] == "candidate"
    assert conn.execute("SELECT COUNT(*) FROM targets WHERE target_name='caller'").fetchone()[0] == 0


def test_duplicate_failure_rolls_back_only_function_and_cli_is_compact(tmp_path):
    conn = _conn()
    conn.execute("INSERT INTO targets(target_name,domain) VALUES('caller','caller.test')")
    conn.execute(
        """CREATE TRIGGER fail_m9_duplicate BEFORE UPDATE ON findings
           BEGIN SELECT RAISE(ABORT,'fixture failure'); END"""
    )
    import pytest

    with pytest.raises(sqlite3.IntegrityError):
        reconcile_duplicate_finding(conn, target_name="T", system_id=1, finding_id="F2", apply=True)
    assert conn.execute("SELECT COUNT(*) FROM targets WHERE target_name='caller'").fetchone()[0] == 1
    conn.rollback()

    path = tmp_path / "duplicate.db"
    source = _conn()
    disk = sqlite3.connect(path)
    source.backup(disk)
    disk.close()
    source.close()
    run = subprocess.run(  # noqa: S603
        [sys.executable, str(SCRIPT), "--file", str(path), "--target", "T", "--system-id", "1", "--finding-id", "F2"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert run.returncode == 0 and len(run.stdout.encode()) < 1199
