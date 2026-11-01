import sqlite3
from pathlib import Path

from db.cognitive_replay import apply, preview


def test_preview_is_offline_and_does_not_create_focus(tmp_path):
    p = tmp_path / "demo.db"
    c = sqlite3.connect(p)
    c.executescript("CREATE TABLE endpoint_observations(auth_state TEXT); INSERT INTO endpoint_observations VALUES('ok_unknown');")
    c.close()
    out = preview(p, target_name="demo")
    assert out["network_operation_count"] == 0
    assert out["focused_session_created"] is False
    assert out["auth_state_conversions"] == 1


def test_apply_distinguishes_response_evidence_and_parks_broad_queue(tmp_path):
    p = tmp_path / "demo.db"
    c = sqlite3.connect(p)
    c.executescript((Path(__file__).parent / "fixtures/cognitive_loop_minimal.sql").read_text(encoding="utf-8"))
    c.close()
    apply(p, target_name="demo", backup_dir=tmp_path / "backups")
    c = sqlite3.connect(p)
    assert c.execute("SELECT auth_state FROM endpoint_observations WHERE id=1").fetchone()[0] == "public"
    assert c.execute("SELECT auth_state FROM endpoint_observations WHERE id=2").fetchone()[0] == "unknown"
    assert c.execute("SELECT response_class FROM entry_observations WHERE id=1").fetchone()[0] == "auth_required"
    assert c.execute("SELECT response_class FROM entry_observations WHERE id=2").fetchone()[0] == "passive_hint"
    assert c.execute("SELECT dispatch_state FROM work_items WHERE id=1").fetchone()[0] == "parked"


def test_preview_handles_legacy_endpoint_check_without_writing(tmp_path):
    p = tmp_path / "legacy.db"
    c = sqlite3.connect(p)
    c.executescript((Path(__file__).parent / "fixtures/cognitive_loop_minimal.sql").read_text(encoding="utf-8"))
    c.execute("DROP TABLE endpoint_observations")
    c.execute(
        "CREATE TABLE endpoint_observations(id INTEGER PRIMARY KEY,target_name TEXT,auth_state TEXT NOT NULL CHECK(auth_state IN ('public','login_redirect','auth_required','token_required','role_required','unknown','blocked_by_waf','not_tested')),status_code INTEGER,evidence_refs_json TEXT)"
    )
    c.execute("INSERT INTO endpoint_observations VALUES(1,'demo','auth_required',NULL,'[]')")
    c.commit()
    c.close()
    out = preview(p, target_name="demo")
    assert out["legacy_endpoint_rebuild_required"] is True
    assert sqlite3.connect(p).execute("SELECT auth_state FROM endpoint_observations").fetchone()[0] == "auth_required"
