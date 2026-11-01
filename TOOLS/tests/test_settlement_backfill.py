from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import db.settlement_backfill as settlement_backfill
from db.settlement_backfill import apply_plan, build_plan

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = PROJECT_ROOT / "TOOLS" / "db" / "schema.sql"
SCRIPT_PATH = PROJECT_ROOT / "TOOLS" / "db" / "settlement_backfill.py"


def _fixture(path: Path) -> None:
    with sqlite3.connect(path) as conn:
        conn.row_factory = sqlite3.Row
        conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        conn.execute("INSERT INTO targets(id,target_name,domain) VALUES(1,'demo','example.com')")
        conn.execute("INSERT INTO targets(id,target_name,domain) VALUES(2,'other','other.example')")
        conn.execute(
            "INSERT INTO suspicious_points(id,url,test_type,risk,test_status) VALUES('SP-M','https://example.com/a','idor','Medium','confirmed')"
        )
        conn.execute(
            "INSERT INTO suspicious_points(id,url,test_type,risk,test_status) VALUES('SP-H','https://example.com/h','idor','High','confirmed')"
        )
        conn.execute(
            "INSERT INTO suspicious_points(id,url,test_type,risk,test_status) VALUES('SP-O','https://other.example/a','idor','Medium','confirmed')"
        )
        medium = conn.execute(
            """
            INSERT INTO work_items(target_name,lane,subtype,subject_table,subject_id,status)
            VALUES('demo','vuln_review','single_sp_review','suspicious_points','SP-M','done')
            """
        ).lastrowid
        payload = {
            "worker_result": {
                "status": "done",
                "summary": "compact diff",
                "confidence": "high",
                "evidence_refs": ["evidence_refs:7"],
                "sufficient_evidence": False,
            }
        }
        conn.execute(
            "INSERT INTO agent_events(work_item_id,agent_id,event_type,payload_json) VALUES(?,?,?,?)",
            (medium, "reviewer", "done", json.dumps(payload)),
        )
        conn.execute(
            """
            INSERT INTO work_items(target_name,lane,subtype,subject_table,subject_id,status)
            VALUES('demo','vuln_review','single_sp_review','suspicious_points','SP-H','done')
            """
        )
        conn.execute(
            """
            INSERT INTO work_items(target_name,lane,subtype,subject_table,subject_id,status)
            VALUES('other','vuln_review','single_sp_review','suspicious_points','SP-O','done')
            """
        )
        conn.execute(
            """
            INSERT INTO work_items(target_name,lane,subject_table,subject_id,status,blocker_reason)
            VALUES('demo','preauth_probe','target_assets','1','blocked','login unavailable')
            """
        )
        conn.execute(
            """
            INSERT INTO work_items(target_name,lane,subject_table,subject_id,status,blocker_reason)
            VALUES('other','preauth_probe','target_assets','2','blocked','unrelated')
            """
        )
        conn.commit()


def _conn(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def test_preview_is_zero_write_and_does_not_promote_high_confidence_false(tmp_path):
    path = tmp_path / "settlement.db"
    _fixture(path)
    before = path.read_bytes()
    with _conn(path) as conn:
        plan = build_plan(conn, "demo")

    assert path.read_bytes() == before
    dispositions = {item["sp_id"]: item["disposition"] for item in plan["confirmed"]}
    assert dispositions == {"SP-H": "operator_gate", "SP-M": "review_insufficient_evidence"}
    assert plan["blocked"] == [{"work_item_id": 4, "blocker_class": "other"}]


def test_historical_confirmed_needs_explicit_sufficient_evidence_not_confidence_alone(tmp_path):
    path = tmp_path / "settlement.confidence-only.db"
    _fixture(path)
    with _conn(path) as conn:
        conn.execute("INSERT INTO suspicious_points(id,risk,test_status) VALUES('SP-CONFIDENCE','Medium','confirmed')")
        work_id = conn.execute(
            """INSERT INTO work_items(target_name,lane,subtype,subject_table,subject_id,status)
               VALUES('demo','vuln_review','single_sp_review','suspicious_points','SP-CONFIDENCE','done')"""
        ).lastrowid
        conn.execute(
            "INSERT INTO agent_events(work_item_id,agent_id,event_type,payload_json) VALUES(?,?,?,?)",
            (
                work_id,
                "reviewer",
                "done",
                json.dumps(
                    {
                        "worker_result": {
                            "status": "done",
                            "summary": "compact evidence summary",
                            "confidence": "high",
                            "evidence_refs": ["evidence_refs:confidence-only"],
                        }
                    }
                ),
            ),
        )
        conn.commit()

        dispositions = {item["sp_id"]: item["disposition"] for item in build_plan(conn, "demo")["confirmed"]}

    assert dispositions["SP-CONFIDENCE"] == "review_insufficient_evidence"


def test_apply_settles_target_only_and_is_idempotent(tmp_path):
    path = tmp_path / "settlement.db"
    _fixture(path)
    with _conn(path) as conn:
        apply_plan(conn, "demo")
        snapshot = {
            "findings": conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0],
            "threads": conn.execute("SELECT COUNT(*) FROM attack_threads").fetchone()[0],
            "events": conn.execute("SELECT COUNT(*) FROM attack_thread_events WHERE event_type='parked'").fetchone()[0],
            "cards": conn.execute("SELECT COUNT(*) FROM operator_inbox").fetchone()[0],
        }
        apply_plan(conn, "demo")
        assert snapshot == {
            "findings": conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0],
            "threads": conn.execute("SELECT COUNT(*) FROM attack_threads").fetchone()[0],
            "events": conn.execute("SELECT COUNT(*) FROM attack_thread_events WHERE event_type='parked'").fetchone()[0],
            "cards": conn.execute("SELECT COUNT(*) FROM operator_inbox").fetchone()[0],
        }
        statuses = dict(conn.execute("SELECT id,test_status FROM suspicious_points"))
        assert statuses["SP-M"] == "review_insufficient_evidence"
        assert statuses["SP-H"] == "operator_required"
        assert statuses["SP-O"] == "confirmed"
        demo = conn.execute("SELECT blocker_class,attack_thread_id FROM work_items WHERE id=4").fetchone()
        other = conn.execute("SELECT blocker_class,attack_thread_id FROM work_items WHERE id=5").fetchone()
        assert demo["blocker_class"] == "other" and demo["attack_thread_id"] is not None
        assert other["blocker_class"] is None and other["attack_thread_id"] is None


def test_apply_acquires_write_lock_before_first_mutable_read(tmp_path):
    path = tmp_path / "settlement.db"
    _fixture(path)
    with _conn(path) as conn:
        statements = []
        conn.set_trace_callback(statements.append)
        apply_plan(conn, "demo")

    normalized = [statement.strip().upper() for statement in statements]
    begin_index = next(index for index, statement in enumerate(normalized) if statement.startswith("BEGIN IMMEDIATE"))
    first_select = next(index for index, statement in enumerate(normalized) if statement.startswith("SELECT"))
    assert begin_index < first_select


def test_cli_is_compact_and_returns_nonzero_for_null_confirmed_id(tmp_path):
    path = tmp_path / "bad.db"
    _fixture(path)
    with sqlite3.connect(path) as conn:
        # Rebuild a minimal malformed legacy table to exercise the hard stop.
        conn.execute("ALTER TABLE suspicious_points RENAME TO suspicious_points_good")
        conn.execute("CREATE TABLE suspicious_points(id TEXT, test_status TEXT, risk TEXT)")
        conn.execute("INSERT INTO suspicious_points VALUES(NULL,'confirmed','Medium')")
        conn.commit()
    run = subprocess.run(  # noqa: S603
        [sys.executable, str(SCRIPT_PATH), "--file", str(path), "--target-name", "demo"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    payload = json.loads(run.stdout)
    assert run.returncode == 1
    assert payload["status"] == "error"
    assert "NULL/empty id" in payload["error"]
    assert "\n" not in run.stdout.strip()


def test_cli_missing_file_fails_closed_without_creating_it(tmp_path):
    path = tmp_path / "does-not-exist.db"
    run = subprocess.run(  # noqa: S603
        [sys.executable, str(SCRIPT_PATH), "--file", str(path), "--target-name", "demo"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert run.returncode == 1
    assert json.loads(run.stdout)["status"] == "error"
    assert "does not exist" in run.stdout
    assert run.stderr == ""
    assert not path.exists()


def test_cli_default_is_bounded_and_include_items_is_explicit(tmp_path):
    path = tmp_path / "many.db"
    _fixture(path)
    with sqlite3.connect(path) as conn:
        for index in range(20):
            sp_id = f"SP-MANY-{index:02}"
            conn.execute(
                "INSERT INTO suspicious_points(id,risk,test_status) VALUES(?, 'Medium', 'confirmed')",
                (sp_id,),
            )
            conn.execute(
                """
                INSERT INTO work_items(target_name,lane,subtype,subject_table,subject_id,status)
                VALUES('demo','vuln_review','single_sp_review','suspicious_points',?,'done')
                """,
                (sp_id,),
            )
        conn.commit()

    default = subprocess.run(  # noqa: S603
        [sys.executable, str(SCRIPT_PATH), "--file", str(path), "--target-name", "demo"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    compact = json.loads(default.stdout)
    assert default.returncode == 0
    assert compact["confirmed"]["count"] == 22
    assert len(compact["confirmed"]["sample"]) == 10
    assert compact["confirmed"]["omitted"] == 12

    expanded = subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(SCRIPT_PATH),
            "--file",
            str(path),
            "--target-name",
            "demo",
            "--include-items",
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert len(json.loads(expanded.stdout)["confirmed"]) == 22


def test_cli_runtime_failure_is_compact_without_traceback(tmp_path, monkeypatch, capsys):
    path = tmp_path / "exists.db"
    path.touch()

    def fail_connect(_path):
        raise RuntimeError("forced apply failure")

    monkeypatch.setattr(settlement_backfill, "connect", fail_connect)
    monkeypatch.setattr(
        sys,
        "argv",
        [str(SCRIPT_PATH), "--file", str(path), "--target-name", "demo", "--apply"],
    )

    assert settlement_backfill.main() == 1
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {"status": "error", "error": "forced apply failure"}
    assert captured.err == ""
