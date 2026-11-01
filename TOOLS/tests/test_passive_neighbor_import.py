from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from db.passive_neighbor_import import import_passive_neighbors

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "TOOLS" / "db" / "schema.sql"
SCRIPT = ROOT / "TOOLS" / "db" / "passive_neighbor_import.py"


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA.read_text(encoding="utf-8"))
    conn.execute("INSERT INTO targets(target_name,domain) VALUES('T','example.test')")
    conn.commit()
    return conn


def _fixture():
    return {
        "provider": "fofa-fixture",
        "query": "ip=203.0.113.33",
        "observed_at": "2026-08-13T00:00:00Z",
        "evidence_refs": ["ev:provider:1"],
        "results": [{"host": "outside.example.net", "ip": "203.0.113.33", "port": 8443, "title": "Portal", "product": "Acme"}],
    }


def test_fixture_import_is_zero_network_needs_review_idempotent_and_compact():
    conn = _conn()
    before = conn.total_changes
    preview = import_passive_neighbors(conn, target_name="T", payload=_fixture(), apply=False, include_items=True)
    assert conn.total_changes == before and preview["network_requests"] == 0
    first = import_passive_neighbors(conn, target_name="T", payload=_fixture(), apply=True)
    second = import_passive_neighbors(conn, target_name="T", payload=_fixture(), apply=True)
    assert first["inserted"] == 1 and second["inserted"] == 0
    row = conn.execute("SELECT status,result_json FROM recon_sources").fetchone()
    assert row["status"] == "needs_review"
    assert len(row["result_json"]) < 1199
    assert conn.execute("SELECT COUNT(*) FROM target_assets").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM work_items").fetchone()[0] == 0
    assert first["network_requests"] == 0
    coverage = conn.execute(
        """SELECT status,evidence_refs_json FROM coverage_ledger
           WHERE target_name='T' AND profile_id IS NULL AND item_key='intel:passive_neighbor_index'"""
    ).fetchall()
    assert [tuple(row) for row in coverage] == [("covered", '["ev:provider:1"]')]


def test_invalid_fixture_rolls_back_and_cli_missing_db_does_not_create(tmp_path):
    conn = _conn()
    bad = _fixture()
    bad["results"][0]["password"] = "not-allowed"  # noqa: S105 -- rejection fixture
    with pytest.raises(ValueError, match="raw HTTP or credential"):
        import_passive_neighbors(conn, target_name="T", payload=bad, apply=True)
    conn.execute(
        """CREATE TRIGGER fail_neighbor BEFORE INSERT ON recon_sources
           BEGIN SELECT RAISE(ABORT,'fixture failure'); END"""
    )
    with pytest.raises(sqlite3.IntegrityError):
        import_passive_neighbors(conn, target_name="T", payload=_fixture(), apply=True)
    assert conn.execute("SELECT COUNT(*) FROM recon_sources").fetchone()[0] == 0

    missing = tmp_path / "missing.db"
    fixture = tmp_path / "neighbors.json"
    fixture.write_text(json.dumps(_fixture()), encoding="utf-8")
    result = subprocess.run(  # noqa: S603
        [sys.executable, str(SCRIPT), "--target", "T", "--file", str(missing), "--fixture", str(fixture), "--apply"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert json.loads(result.stdout)["ok"] is False
    assert not missing.exists()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("provider", "Authorization: Bearer x"),
        ("query", "Cookie: sid=x"),
        ("observed_at", "not-a-time"),
        ("evidence_refs", ["GET / HTTP/1.1"]),
    ],
)
def test_passive_top_level_metadata_requires_safe_compact_values(field, value):
    conn = _conn()
    payload = _fixture()
    payload[field] = value
    with pytest.raises(ValueError):
        import_passive_neighbors(conn, target_name="T", payload=payload, apply=False)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("host", "bad host"),
        ("ip", "999.1.1.1"),
        ("port", 0),
        ("port", 443.5),
        ("title", "Authorization: Bearer x"),
        ("product", "Cookie: sid=x"),
    ],
)
def test_passive_result_fields_reject_invalid_or_sensitive_values(field, value):
    conn = _conn()
    payload = _fixture()
    payload["results"][0][field] = value
    with pytest.raises(ValueError):
        import_passive_neighbors(conn, target_name="T", payload=payload, apply=False)


def test_passive_apply_uses_savepoint_preserves_terminal_coverage_and_caller_write():
    conn = _conn()
    conn.execute(
        """INSERT INTO coverage_ledger(target_name,item_key,category,status)
           VALUES('T','intel:passive_neighbor_index','m8_control','blocked')"""
    )
    conn.execute("INSERT INTO targets(target_name,domain) VALUES('caller','caller.test')")
    import_passive_neighbors(conn, target_name="T", payload=_fixture(), apply=True)
    assert conn.in_transaction
    assert conn.execute("SELECT status FROM coverage_ledger WHERE item_key='intel:passive_neighbor_index'").fetchone()[0] == "blocked"
    conn.rollback()
    assert conn.execute("SELECT COUNT(*) FROM targets WHERE target_name='caller'").fetchone()[0] == 0

    conn.execute("INSERT INTO targets(target_name,domain) VALUES('caller','caller.test')")
    conn.execute(
        """CREATE TRIGGER fail_neighbor_nested BEFORE INSERT ON recon_sources
           BEGIN SELECT RAISE(ABORT,'nested failure'); END"""
    )
    with pytest.raises(sqlite3.IntegrityError):
        import_passive_neighbors(conn, target_name="T", payload=_fixture(), apply=True)
    assert conn.execute("SELECT COUNT(*) FROM targets WHERE target_name='caller'").fetchone()[0] == 1
    conn.rollback()


def test_passive_cli_default_is_compact_and_target_mismatch_zero_write(tmp_path):
    path = tmp_path / "passive.db"
    source = _conn()
    disk = sqlite3.connect(path)
    source.backup(disk)
    disk.close()
    source.close()
    fixture = tmp_path / "fixture.json"
    fixture.write_text(json.dumps(_fixture()), encoding="utf-8")

    preview = subprocess.run(  # noqa: S603
        [sys.executable, str(SCRIPT), "--file", str(path), "--target", "T", "--fixture", str(fixture)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert preview.returncode == 0 and len(preview.stdout.encode()) < 1199
    mismatch = subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(SCRIPT),
            "--file",
            str(path),
            "--target",
            "wrong",
            "--fixture",
            str(fixture),
            "--apply",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert mismatch.returncode == 1
    with sqlite3.connect(path) as verify:
        assert verify.execute("SELECT COUNT(*) FROM recon_sources").fetchone()[0] == 0
