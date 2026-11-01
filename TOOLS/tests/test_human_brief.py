from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from pathlib import Path

from db import human_brief
from db.db_query import init_db
from db.human_brief import build_human_brief, render_markdown

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "TOOLS" / "db" / "human_brief.py"


def test_human_brief_without_focus_does_not_guess():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    c.executescript(
        "CREATE TABLE target_systems(id INTEGER PRIMARY KEY,target_name TEXT,system_key TEXT,display_name TEXT,canonical_url TEXT,scope_class TEXT,lifecycle_state TEXT); CREATE TABLE hunt_sessions(id INTEGER PRIMARY KEY,target_name TEXT,status TEXT,system_id INTEGER);"
    )
    brief = build_human_brief(c, target_name="T")
    assert brief["current_system"] is None and brief["phase"] == "unmapped"
    assert "操作员" in render_markdown(brief)


def test_unfocused_candidate_cards_include_compact_types_entries_evidence_and_score():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    c.executescript(
        """
        CREATE TABLE target_systems(
            id INTEGER PRIMARY KEY, target_name TEXT, system_key TEXT,
            display_name TEXT, canonical_url TEXT, scope_class TEXT, lifecycle_state TEXT
        );
        CREATE TABLE system_asset_links(
            id INTEGER PRIMARY KEY, target_name TEXT, system_id INTEGER, asset_id INTEGER,
            relationship TEXT, confidence TEXT, evidence_refs_json TEXT
        );
        CREATE TABLE target_assets(id INTEGER PRIMARY KEY, target_name TEXT, asset_value TEXT);
        CREATE TABLE system_type_observations(
            target_name TEXT, asset_id INTEGER, label TEXT, evidence_refs_json TEXT
        );
        CREATE TABLE entry_observations(
            target_name TEXT, asset_id INTEGER, entry_type TEXT, evidence_refs_json TEXT
        );
        CREATE TABLE system_soft_targets(
            target_name TEXT, system_id INTEGER, eligibility_status TEXT,
            total_score INTEGER, rank INTEGER
        );
        INSERT INTO target_systems VALUES(1,'T','admin','Admin','https://admin.test','owned','mapping');
        INSERT INTO target_assets VALUES(7,'T','admin.test');
        INSERT INTO system_asset_links VALUES(1,'T',1,7,'primary','high','["ev:link"]');
        INSERT INTO system_type_observations VALUES('T',7,'admin_portal','["ev:type"]');
        INSERT INTO entry_observations VALUES('T',7,'login','["ev:login"]');
        INSERT INTO entry_observations VALUES('T',7,'api','["ev:api"]');
        INSERT INTO system_soft_targets VALUES('T',1,'eligible',88,1);
        """
    )
    brief = build_human_brief(c, target_name="T")
    card = brief["candidate_systems"][0]
    assert card["type_labels"] == ["admin_portal"]
    assert card["entry_summary"] == {"api": 1, "login": 1}
    assert set(card["evidence_refs"]) >= {"ev:type", "ev:login", "ev:api"}
    assert card["eligibility_status"] == "eligible"
    assert card["total_score"] == 88


def test_human_brief_cli_is_read_only_and_echoes_explicit_db(tmp_path, monkeypatch, capsys):
    db_path = tmp_path / "demo.db"
    init_db(str(db_path), "Demo", "demo.test")
    monkeypatch.setattr(
        human_brief.sys,
        "argv",
        ["human_brief", "--target", "Demo", "--db", str(db_path), "--json"],
    )

    assert human_brief.main() == 0

    output = json.loads(capsys.readouterr().out)
    assert output["db"] == str(db_path)
    assert output["brief"]["current_system"] is None
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM work_items").fetchone()[0] == 0


def test_human_brief_direct_script_cli_loads_project_modules(tmp_path):
    db_path = tmp_path / "direct-cli.db"
    init_db(str(db_path), "Demo", "demo.test")

    result = subprocess.run(  # noqa: S603 -- 测试用 sys.executable 起本仓库脚本
        [sys.executable, str(SCRIPT), "--target", "Demo", "--db", str(db_path), "--json"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert json.loads(result.stdout)["db"] == str(db_path)


def test_human_brief_direct_cli_requires_explicit_database():
    result = subprocess.run(  # noqa: S603 -- 测试用 sys.executable 起本仓库脚本
        [sys.executable, str(SCRIPT), "--target", "Demo", "--json"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "--db" in result.stderr


def test_human_brief_recon_overview_is_compact_and_read_only():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    c.executescript(
        """
        CREATE TABLE target_systems(id INTEGER PRIMARY KEY,target_name TEXT,system_key TEXT,display_name TEXT,canonical_url TEXT,scope_class TEXT,lifecycle_state TEXT);
        CREATE TABLE recon_runs(id INTEGER PRIMARY KEY,target_name TEXT,source TEXT,status TEXT,attempt INTEGER,next_retry_at TEXT,updated_at TEXT);
        CREATE TABLE target_assets(id INTEGER PRIMARY KEY,target_name TEXT,scope_status TEXT);
        CREATE TABLE origin_candidates(id INTEGER PRIMARY KEY,target_name TEXT,verification_status TEXT);
        CREATE TABLE cdn_observations(id INTEGER PRIMARY KEY,target_name TEXT,classification TEXT);
        CREATE TABLE coverage_ledger(id INTEGER PRIMARY KEY,target_name TEXT,category TEXT,status TEXT);
        INSERT INTO recon_runs VALUES(1,'T','sslmate_ct','observed',1,NULL,'2026-08-23 10:00:00');
        INSERT INTO recon_runs VALUES(2,'T','subfinder_passive','rate_limited',2,'2026-08-23 11:00:00','2026-08-23 10:01:00');
        INSERT INTO target_assets VALUES(1,'T','needs_review');
        INSERT INTO origin_candidates VALUES(1,'T','candidate_ready_for_review');
        INSERT INTO origin_candidates VALUES(2,'T','evidence_insufficient');
        INSERT INTO cdn_observations VALUES(1,'T','cdn');
        INSERT INTO coverage_ledger VALUES(1,'T','public_exposure','covered');
        """
    )
    overview = build_human_brief(c, target_name="T")["recon_overview"]
    assert overview["source_health"]["by_status"] == {"observed": 1, "rate_limited": 1}
    assert overview["review_assets"] == 1
    assert overview["origin_candidates"] == {"total": 2, "ready_for_review": 1, "evidence_insufficient": 1}
    assert overview["cdn_observations"] == {"total": 1, "cdn": 1, "non_cdn": 0, "unknown": 0}
    assert overview["public_exposure"] == {"items": 1, "by_status": {"covered": 1}}
