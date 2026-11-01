import sqlite3
from pathlib import Path

import pytest
from db import db_admin
from db.db_query import init_db


def test_fresh_explicit_init_creates_v45_schema_without_runtime_rows(tmp_path):
    result = db_admin.init_target_db(target_name="Demo Target", slug="demo-target", domain="demo.test", db_dir=tmp_path)
    path = Path(result["db_path"])
    assert path == tmp_path / "demo-target.db"
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT target_name,domain FROM targets").fetchall() == [("Demo Target", "demo.test")]
        assert conn.execute(
            "SELECT asset_type,asset_value,protocol,scope_status,scope_class,authorization_state,scope_reason FROM target_assets"
        ).fetchall() == [("domain", "demo.test", "https", "in_scope", "owned", "explicit_init", "explicit_init_domain")]
        assert conn.execute("SELECT COUNT(*) FROM recon_runs").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM system_type_observations").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM hunt_sessions").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM work_items").fetchone()[0] == 0
    verified = db_admin.verify(path, "Demo Target")
    assert verified["target"] == "Demo Target"
    assert verified["required_tables"]["recon_runs"] == 1
    assert verified["required_tables"]["cdn_observations"] == 1
    assert verified["required_tables"]["system_type_observations"] == 1


def test_repeat_init_is_idempotent_for_target_row(tmp_path):
    first = db_admin.init_target_db(target_name="Demo", slug="demo", db_dir=tmp_path)
    second = db_admin.init_target_db(target_name="Demo", slug="demo", domain="ignored.test", db_dir=tmp_path)
    assert first["db_path"] == second["db_path"]
    with sqlite3.connect(first["db_path"]) as conn:
        assert conn.execute("SELECT COUNT(*) FROM targets WHERE target_name='Demo'").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM target_assets WHERE target_name='Demo'").fetchone()[0] == 0


def test_repeat_init_is_idempotent_for_explicit_root_asset(tmp_path):
    first = db_admin.init_target_db(target_name="Demo", slug="demo", domain="demo.test", db_dir=tmp_path)
    db_admin.init_target_db(target_name="Demo", slug="demo", domain="demo.test", db_dir=tmp_path)
    with sqlite3.connect(first["db_path"]) as conn:
        assert conn.execute("SELECT COUNT(*) FROM target_assets WHERE target_name='Demo'").fetchone()[0] == 1


@pytest.mark.parametrize("slug", ["中文", "../escape", "a/b", "", ".", "..", "-bad"])
def test_init_rejects_non_ascii_or_unsafe_slug(tmp_path, slug):
    with pytest.raises(ValueError, match="slug"):
        db_admin.init_target_db(target_name="Demo", slug=slug, db_dir=tmp_path)


def test_db_query_init_uses_same_idempotent_helper(tmp_path, monkeypatch):
    monkeypatch.setattr("db.db_query.DBS_DIR", tmp_path)
    path = tmp_path / "Demo-Target_2026-08-23.db"
    init_db(str(path), "Demo Target")
    init_db(str(path), "Demo Target")
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM targets WHERE target_name='Demo Target'").fetchone()[0] == 1
