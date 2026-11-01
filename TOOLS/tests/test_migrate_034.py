from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import db.db_admin as db_admin
import db.migrate as migrate
import pytest
from db.migrate import apply_migration, do_migrate
from db.operator_actions import create_action_card

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "TOOLS" / "db" / "schema.sql"
MIGRATION = ROOT / "migrations" / "034_chain_fix.sql"
DB_ADMIN = ROOT / "TOOLS" / "db" / "db_admin.py"
LATEST_SCHEMA_VERSION = max(int(path.name[:3]) for path in (ROOT / "migrations").glob("[0-9][0-9][0-9]_*.sql"))
OPERATOR_033_COLUMNS = {
    "id",
    "target_name",
    "related_work_item_id",
    "kind",
    "title",
    "detail",
    "suggested_action",
    "url",
    "burp_action_id",
    "evidence_ref_id",
    "status",
    "created_at",
    "resolved_at",
    "system_id",
    "action_key",
    "action_label",
    "why_needed",
    "steps_json",
    "expected_observation",
    "report_back_format",
    "blocking",
    "expires_at",
}


def _fixture(tmp_path):
    path = tmp_path / "schema33.db"
    with sqlite3.connect(path) as conn:
        schema33 = SCHEMA.read_text(encoding="utf-8")
        schema33 = schema33.replace("id TEXT PRIMARY KEY NOT NULL,", "id TEXT PRIMARY KEY,", 1)
        schema33 = schema33.replace(
            ",\n    blocker_class TEXT\n"
            "        CHECK(blocker_class IS NULL OR blocker_class IN (\n"
            "            'auth_barrier','network','scope','evidence','critical_found',"
            "'refuted','parked','other'\n"
            "        ))",
            "",
            1,
        )
        schema33 = schema33.replace(
            "'burp_action_required',\n            'scope_cluster_confirm',\n            'blocked_decision'",
            "'burp_action_required'",
            1,
        )
        schema33 = schema33.replace(
            "INSERT OR IGNORE INTO schema_version(version, description)\nVALUES(34, '034_chain_fix_fresh_baseline');",
            "",
            1,
        )
        schema33 = schema33.replace(
            "INSERT OR IGNORE INTO schema_version(version, description)\nVALUES(35, '035_business_state_machine');\n",
            "",
            1,
        )
        schema33 = schema33.replace(
            "INSERT OR IGNORE INTO schema_version(version, description)\nVALUES(36, '036_inspiration_base');\n",
            "",
            1,
        )
        schema33 = schema33.replace(
            "INSERT OR IGNORE INTO schema_version(version, description)\nVALUES(37, '037_experience_entries');\n",
            "",
            1,
        )
        conn.executescript(schema33)
        # Keep the recorded state at v33 even though the fresh schema contains
        # later DDL. This makes migration 034 (and its failure path) runnable.
        conn.execute("DELETE FROM schema_version WHERE version > 33")
        conn.execute("INSERT INTO schema_version(version,description) VALUES(33,'033')")
        conn.execute("INSERT INTO targets(target_name,domain) VALUES('Fixture Target','example.test')")
        conn.execute(
            """INSERT INTO operator_inbox(
            id,target_name,related_work_item_id,kind,title,detail,suggested_action,url,
            burp_action_id,evidence_ref_id,system_id,action_key,action_label,why_needed,
            steps_json,expected_observation,report_back_format,blocking,status,created_at,resolved_at,expires_at
            ) VALUES(7,'Fixture Target',NULL,'manual_review','title','detail','action',
            'https://example.test',NULL,NULL,NULL,'key','label','why','["step"]',
            'observe','report',0,'accepted','2026-08-13 01:02:03','2026-08-13 02:03:04',
            '2026-08-14 03:04:05')"""
        )
        conn.execute(
            """INSERT INTO suspicious_points(
            id,page_url,url,param,method,test_type,evidence,source,reasoning,risk,test_status,
            burp_request_id,created_at,notes,endpoint_fingerprint,response_summary,risk_score,
            canonical_url,auth_surface_type,signal_value,signal_reason,noise_reason
            ) VALUES(NULL,'page','url','param','POST','sqli','evidence','source','reason','High',
            'confirmed',9,'2026-08-13','notes','fp','summary',91,'canonical','preauth','value',
            'signal','noise')"""
        )
    return path


def test_migration_preserves_every_operator_and_sp_value_and_is_replayable(tmp_path):
    path = _fixture(tmp_path)
    with sqlite3.connect(path) as conn:
        conn.row_factory = sqlite3.Row
        operator_before = dict(conn.execute("SELECT * FROM operator_inbox WHERE id=7").fetchone())
        sp_rowid = conn.execute("SELECT rowid FROM suspicious_points").fetchone()[0]
        sp_before = dict(conn.execute("SELECT * FROM suspicious_points WHERE rowid=?", (sp_rowid,)).fetchone())

    result = do_migrate(str(path))

    assert result["current_version"] == LATEST_SCHEMA_VERSION
    assert result["pre_hooks"][0]["version"] == 34
    assert result["pre_hooks"][0]["result"]["count"] == 1
    with sqlite3.connect(path) as conn:
        conn.row_factory = sqlite3.Row
        operator_after = dict(conn.execute("SELECT * FROM operator_inbox WHERE id=7").fetchone())
        operator_columns = {row[1] for row in conn.execute("PRAGMA table_info(operator_inbox)")}
        sp_after = dict(conn.execute("SELECT * FROM suspicious_points").fetchone())
        generated_id = sp_after.pop("id")
        sp_before.pop("id")
        assert operator_after == operator_before
        assert OPERATOR_033_COLUMNS <= operator_columns
        assert operator_after["expires_at"] == "2026-08-14 03:04:05"
        assert sp_after == sp_before
        assert generated_id.startswith("sp-sqli-")
        empty_ids = conn.execute("SELECT COUNT(*) FROM suspicious_points WHERE id IS NULL OR trim(id)=''").fetchone()[0]
        assert empty_ids == 0
        assert conn.execute("SELECT COUNT(*) FROM pattern_guesses").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM system_soft_targets").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM review_candidates").fetchone()[0] == 0
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 0
        conn.commit()
        conn.execute("PRAGMA foreign_keys=ON")
        assert apply_migration(conn, 34, str(MIGRATION))
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM operator_inbox").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM suspicious_points").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM schema_version WHERE version=34").fetchone()[0] == 1


def test_migration_preserves_existing_indexes_and_triggers_on_rebuilt_tables(tmp_path):
    path = _fixture(tmp_path)
    with sqlite3.connect(path) as conn:
        conn.executescript(
            """
            CREATE INDEX idx_legacy_operator_title ON operator_inbox(target_name, title);
            CREATE TABLE suspicious_point_audit(point_id TEXT NOT NULL);
            CREATE TRIGGER trg_legacy_suspicious_point_audit
            AFTER INSERT ON suspicious_points
            BEGIN
                INSERT INTO suspicious_point_audit(point_id) VALUES(NEW.id);
            END;
            """
        )

    assert do_migrate(str(path))["current_version"] == LATEST_SCHEMA_VERSION

    with sqlite3.connect(path) as conn:
        objects = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type IN ('index', 'trigger')")}
        assert {"idx_legacy_operator_title", "trg_legacy_suspicious_point_audit"} <= objects
        conn.execute("INSERT INTO suspicious_points(id) VALUES('sp-trigger-check')")
        assert conn.execute("SELECT point_id FROM suspicious_point_audit").fetchall() == [("sp-trigger-check",)]


def test_fresh_schema_034_is_already_current_and_migration_is_a_noop(tmp_path):
    path = tmp_path / "fresh-034.db"
    with sqlite3.connect(path) as conn:
        conn.executescript(SCHEMA.read_text(encoding="utf-8"))

    result = do_migrate(str(path))

    assert result["current_version"] == LATEST_SCHEMA_VERSION
    assert [item["version"] for item in result["applied"]] == list(range(39, LATEST_SCHEMA_VERSION + 1))
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM schema_version WHERE version=34").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM schema_version WHERE version=35").fetchone()[0] == 1


def test_blocker_class_constraint_allows_null_and_rejects_invalid(tmp_path):
    path = _fixture(tmp_path)
    assert do_migrate(str(path))["current_version"] == LATEST_SCHEMA_VERSION
    with sqlite3.connect(path) as conn:
        conn.execute(
            """INSERT INTO work_items(target_name,lane,subject_table,subject_id,blocker_class)
               VALUES('T','logic_probe','x','1',NULL)"""
        )
        conn.execute(
            """INSERT INTO work_items(target_name,lane,subject_table,subject_id,blocker_class)
               VALUES('T','logic_probe','x','2','auth_barrier')"""
        )
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                """INSERT INTO work_items(target_name,lane,subject_table,subject_id,blocker_class)
                   VALUES('T','logic_probe','x','3','made_up')"""
            )


@pytest.mark.parametrize("kind", ["scope_cluster_confirm", "blocked_decision"])
def test_new_action_kinds_persist_through_formal_entrypoint(tmp_path, kind):
    path = _fixture(tmp_path)
    assert do_migrate(str(path))["current_version"] == LATEST_SCHEMA_VERSION
    with sqlite3.connect(path) as conn:
        conn.row_factory = sqlite3.Row
        card = create_action_card(
            conn,
            target_name="Fixture Target",
            system_id=None,
            kind=kind,
            action_key=f"test:{kind}",
            action_label="Operator decision",
            why_needed="A bounded decision is required",
            steps=["Review compact evidence"],
            expected_observation="A recorded decision",
            report_back_format="decision and reason",
            url="https://example.test/",
        )
        assert card["kind"] == kind
        assert conn.execute("SELECT kind FROM operator_inbox WHERE id=?", (card["id"],)).fetchone()[0] == kind


def test_failed_034_does_not_record_schema_version(tmp_path, monkeypatch):
    path = _fixture(tmp_path)
    migration_dir = tmp_path / "migrations"
    migration_dir.mkdir()
    (migration_dir / "034_broken.sql").write_text("CREATE TABLE partial_write(id INTEGER);\nSELECT * FROM absent_table;", encoding="utf-8")
    monkeypatch.setattr(migrate, "MIGRATIONS_DIR", migration_dir)

    result = do_migrate(str(path))

    assert "error" in result
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM schema_version WHERE version=34").fetchone()[0] == 0
        partial_tables = conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='partial_write'").fetchone()[0]
        assert partial_tables == 0


def test_db_admin_cli_migrates_schema33_fixture_to_34(tmp_path):
    path = _fixture(tmp_path)

    completed = subprocess.run(  # noqa: S603 -- fixed interpreter and repository script
        [sys.executable, str(DB_ADMIN), "--file", str(path), "migrate"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env={**os.environ, "PYTHONUTF8": "1"},
        check=False,
    )

    assert completed.returncode == 0
    assert json.loads(completed.stdout)["current_version"] == LATEST_SCHEMA_VERSION
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT max(version) FROM schema_version").fetchone()[0] == LATEST_SCHEMA_VERSION


def test_db_admin_main_returns_nonzero_for_migrate_error(tmp_path, monkeypatch, capsys):
    path = tmp_path / "fixture.db"
    path.touch()
    monkeypatch.setattr(sys, "argv", [str(DB_ADMIN), "--file", str(path), "migrate"])
    monkeypatch.setattr(db_admin, "do_migrate", lambda _path: {"error": "fixture failure"})

    return_code = db_admin.main()

    assert return_code == 1
    assert json.loads(capsys.readouterr().out)["error"] == "fixture failure"


@pytest.mark.parametrize("command", ["status", "verify"])
def test_db_admin_main_keeps_read_commands_successful(tmp_path, monkeypatch, capsys, command):
    path = tmp_path / "fixture.db"
    path.touch()
    monkeypatch.setattr(sys, "argv", [str(DB_ADMIN), "--file", str(path), command])
    monkeypatch.setattr(db_admin, "do_status", lambda _path: {"status": "ok"})
    monkeypatch.setattr(db_admin, "verify", lambda _path, _target: {"status": "ok"})

    return_code = db_admin.main()

    assert return_code == 0
    assert json.loads(capsys.readouterr().out) == {"status": "ok"}


def test_db_admin_main_keeps_rebuild_successful(tmp_path, monkeypatch, capsys):
    path = tmp_path / "fixture.db"
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE targets(id INTEGER PRIMARY KEY,target_name TEXT)")
        conn.execute("INSERT INTO targets(target_name) VALUES('Fixture Target')")
    monkeypatch.setattr(sys, "argv", [str(DB_ADMIN), "--file", str(path), "rebuild"])
    monkeypatch.setattr(db_admin, "rebuild", lambda _conn, target: {"status": "ok", "target": target})

    return_code = db_admin.main()

    assert return_code == 0
    assert json.loads(capsys.readouterr().out) == {"status": "ok", "target": "Fixture Target"}


def test_migrate_main_returns_nonzero_for_error_result(tmp_path, monkeypatch, capsys):
    path = tmp_path / "fixture.db"
    path.touch()
    monkeypatch.setattr(sys, "argv", ["migrate.py", "--file", str(path)])
    monkeypatch.setattr(migrate, "do_migrate", lambda _path: {"error": "fixture failure"})

    return_code = migrate.main()

    assert return_code == 1
    assert json.loads(capsys.readouterr().out)["error"] == "fixture failure"
