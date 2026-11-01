import json
import sqlite3
from pathlib import Path

from db.db_admin import verify
from db.db_query import init_db
from recon.recon_runtime import begin_recon_run, get_recon_run, update_recon_run

ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "migrations" / "039_recon_runs.sql"


def test_begin_recon_run_upserts_by_target_source_and_redacted_input_fingerprint():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row

    first = begin_recon_run(
        conn,
        target_name="T",
        source="sslmate_ct",
        input_data={"domain": "example.test", "api_key": "do-not-store"},
        budget={"max_items": 50},
    )
    second = begin_recon_run(
        conn,
        target_name="T",
        source="sslmate_ct",
        input_data={"api_key": "another-secret", "domain": "example.test"},
    )

    assert first["id"] == second["id"]
    assert second["attempt"] == 2
    assert conn.execute("SELECT COUNT(*) FROM recon_runs").fetchone()[0] == 1
    assert json.loads(second["budget_json"]) == {"max_items": 50}
    assert "secret" not in json.dumps(dict(second)).lower()


def test_update_recon_run_preserves_recovery_fields_without_recon_source_side_effects():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    run = begin_recon_run(
        conn,
        target_name="T",
        source="sslmate_ct",
        input_data={"domain": "example.test"},
    )

    updated = update_recon_run(
        conn,
        run_id=run["id"],
        status="limited",
        cursor={"after": "42", "authorization": "Bearer forbidden"},
        summary={"count": 20, "token": "forbidden"},
        next_retry_at="2026-08-23T23:00:00+08:00",
    )

    restored = get_recon_run(conn, run_id=run["id"])
    assert restored == updated
    assert json.loads(restored["cursor_json"]) == {"after": "42", "authorization": "[redacted]"}
    assert json.loads(restored["summary_json"]) == {"count": 20, "token": "[redacted]"}
    assert restored["next_retry_at"] == "2026-08-23T23:00:00+08:00"
    assert restored["last_success_at"] is None
    assert conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='recon_sources'").fetchone()[0] == 0


def test_update_recon_run_records_success_timestamp_without_bumping_attempt():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    run = begin_recon_run(conn, target_name="T", source="subfinder", input_data={"domain": "example.test"})

    updated = update_recon_run(
        conn,
        run_id=run["id"],
        status="observed",
        summary={"hosts": 3},
        last_success_at="2026-08-23T22:00:00+08:00",
    )

    assert updated["attempt"] == 1
    assert updated["last_success_at"] == "2026-08-23T22:00:00+08:00"


def test_recon_runs_migration_creates_ledger_and_resume_index():
    conn = sqlite3.connect(":memory:")

    conn.executescript(MIGRATION.read_text(encoding="utf-8"))

    assert conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='recon_runs'").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_recon_runs_ready'").fetchone()[0] == 1


def test_fresh_init_includes_recon_runs_and_verify_reports_it(tmp_path):
    db_path = tmp_path / "fresh.db"

    init_db(str(db_path), "Fresh Target")

    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM recon_runs").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM schema_version WHERE version=39").fetchone()[0] == 1
    assert verify(db_path, "Fresh Target")["required_tables"]["recon_runs"] == 1
