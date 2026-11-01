from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import uuid
from pathlib import Path

import db.sp_id_backfill as sp_id_backfill
import pytest
from db.sp_id_backfill import backfill_sp_ids

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "TOOLS" / "db" / "sp_id_backfill.py"


def _db(tmp_path):
    path = tmp_path / "fixture.db"
    with sqlite3.connect(path) as conn:
        conn.executescript(
            """
            CREATE TABLE targets(id INTEGER PRIMARY KEY, target_name TEXT NOT NULL);
            INSERT INTO targets(target_name) VALUES('Fixture Target');
            CREATE TABLE suspicious_points(
              id TEXT PRIMARY KEY, url TEXT, param TEXT, method TEXT,
              test_type TEXT, source TEXT, evidence TEXT
            );
            """
        )
    return path


def _rows(path):
    with sqlite3.connect(path) as conn:
        return conn.execute("SELECT rowid,id FROM suspicious_points ORDER BY rowid").fetchall()


def test_preview_covers_null_empty_duplicates_and_writes_nothing(tmp_path):
    path = _db(tmp_path)
    with sqlite3.connect(path) as conn:
        conn.executemany(
            "INSERT INTO suspicious_points(id,url,param,method,test_type,source,evidence) VALUES(?,?,?,?,?,?,?)",
            [
                (None, "https://secret.example/a", "token", "GET", "SQL Injection", "fixture", "raw-a"),
                ("", "https://secret.example/a", "token", "GET", "SQL Injection", "fixture", "raw-b"),
                ("sp-existing", "https://example.test/ok", "x", "GET", "xss", "fixture", "raw-c"),
            ],
        )
    before = _rows(path)

    result = backfill_sp_ids(path, target_name="Fixture Target", apply=False)

    assert result["mode"] == "preview"
    assert result["count"] == 2
    assert len(result["candidate_ids"]) == 2
    assert len(set(result["candidate_ids"])) == 2
    assert all(value.startswith("sp-sql-injection-") for value in result["candidate_ids"])
    assert "secret.example" not in repr(result)
    assert "token" not in repr(result)
    assert "raw-a" not in repr(result)
    assert _rows(path) == before


def test_apply_is_collision_safe_transactional_and_stable_on_rerun(tmp_path):
    path = _db(tmp_path)
    with sqlite3.connect(path) as conn:
        conn.execute(
            "INSERT INTO suspicious_points(id,url,param,method,test_type,source) VALUES(NULL,?,?,?,?,?)",
            ("https://example.test/a", "id", "POST", "SQL Injection", "fixture"),
        )
        rowid = conn.execute("SELECT rowid FROM suspicious_points").fetchone()[0]
        digest = hashlib.sha256(f"https://example.test/a|id|POST|fixture|{rowid}".encode()).hexdigest()
        colliding_id = f"sp-sql-injection-{digest[:12]}"
        conn.execute(
            "INSERT INTO suspicious_points(id,url,param,method,test_type,source) VALUES(?,?,?,?,?,?)",
            (colliding_id, "https://example.test/other", "q", "GET", "other", "fixture"),
        )

    first = backfill_sp_ids(path, target_name="Fixture Target", apply=True)
    rows_after_first = _rows(path)
    second = backfill_sp_ids(path, target_name="Fixture Target", apply=True)

    assert first["count"] == 1
    assert first["collision_count"] == 1
    assert first["remaining_empty_ids"] == 0
    assert rows_after_first[0][1].startswith(f"sp-sql-injection-{digest[:13]}")
    assert second["count"] == 0
    assert second["candidate_ids"] == []
    assert _rows(path) == rows_after_first


def test_apply_acquires_immediate_lock_before_candidate_reads(tmp_path, monkeypatch):
    path = _db(tmp_path)
    with sqlite3.connect(path) as conn:
        conn.execute("INSERT INTO suspicious_points(id,url,param,method,test_type,source) VALUES(NULL,'u','p','GET','x','s')")
    statements = []
    original_connect = sqlite3.connect

    def traced_connect(*args, **kwargs):
        conn = original_connect(*args, **kwargs)
        conn.set_trace_callback(statements.append)
        return conn

    monkeypatch.setattr(sp_id_backfill.sqlite3, "connect", traced_connect)

    backfill_sp_ids(path, target_name="Fixture Target", apply=True)

    normalized = [statement.upper() for statement in statements]
    begin_index = next(i for i, statement in enumerate(normalized) if statement.startswith("BEGIN IMMEDIATE"))
    empty_read_index = next(
        i for i, statement in enumerate(normalized) if "FROM SUSPICIOUS_POINTS" in statement and "ID IS NULL OR TRIM(ID)=''" in statement
    )
    assert begin_index < empty_read_index


def test_target_must_match_targets_table_exactly(tmp_path):
    path = _db(tmp_path)
    with pytest.raises(ValueError, match="target_name does not exactly match"):
        backfill_sp_ids(path, target_name="fixture target", apply=False)


def test_cli_preview_is_json_success_and_does_not_write(tmp_path):
    path = _db(tmp_path)
    with sqlite3.connect(path) as conn:
        conn.execute("INSERT INTO suspicious_points(id,url,param,method,test_type,source) VALUES(NULL,'u','p','GET','x','s')")
    before = _rows(path)

    completed = subprocess.run(  # noqa: S603 -- fixed interpreter and repository script
        [sys.executable, str(SCRIPT), "--file", str(path)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env={**os.environ, "PYTHONUTF8": "1"},
        check=False,
    )

    assert completed.returncode == 0
    assert json.loads(completed.stdout)["mode"] == "preview"
    assert completed.stderr == ""
    assert _rows(path) == before


@pytest.mark.parametrize("selection", ["missing_file", "missing_target"])
def test_cli_selection_errors_are_compact_json_without_traceback(tmp_path, selection):
    if selection == "missing_file":
        args = ["--file", str(tmp_path / "absent.db")]
    else:
        args = ["--target", f"b1-no-such-target-{uuid.uuid4().hex}"]

    completed = subprocess.run(  # noqa: S603 -- fixed interpreter and repository script
        [sys.executable, str(SCRIPT), *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env={**os.environ, "PYTHONUTF8": "1"},
        check=False,
    )

    assert completed.returncode != 0
    payload = json.loads(completed.stderr or completed.stdout)
    assert payload["error"]
    assert "Traceback" not in completed.stderr
