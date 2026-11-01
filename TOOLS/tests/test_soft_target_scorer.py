# ruff: noqa: E501

import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from db.migrate import apply_migration, ensure_schema_version
from db.soft_target_scorer import (
    _matches_any,
    ensure_soft_target_schema,
    focus_soft_target,
    list_soft_targets,
    run_scorer,
    score_asset,
    score_negative,
    transition_soft_target,
    update_soft_target_status,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
MIGRATION_PATH = PROJECT_ROOT / "migrations" / "025_soft_targets.sql"
SCHEMA_PATH = PROJECT_ROOT / "TOOLS" / "db" / "schema.sql"
SCRIPT_PATH = PROJECT_ROOT / "TOOLS" / "db" / "soft_target_scorer.py"


def _conn():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    return conn


def _table_names(conn):
    return {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}


def _index_names(conn):
    return {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='index'").fetchall()}


def _seed_scoring_schema(conn):
    conn.executescript(
        """
        CREATE TABLE targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_name TEXT NOT NULL,
            domain TEXT
        );
        CREATE TABLE target_assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_name TEXT NOT NULL,
            asset_type TEXT DEFAULT 'domain',
            asset_value TEXT NOT NULL,
            port INTEGER,
            protocol TEXT DEFAULT 'https',
            source TEXT DEFAULT 'manual',
            tech_stack TEXT,
            requires_auth INTEGER DEFAULT 0,
            status TEXT DEFAULT 'new',
            priority INTEGER DEFAULT 0,
            notes TEXT,
            created_at TEXT DEFAULT (datetime('now','localtime')),
            validated_at TEXT
        );
        CREATE TABLE pages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_name TEXT,
            url TEXT UNIQUE,
            depth INTEGER DEFAULT 0,
            status TEXT DEFAULT 'done',
            title TEXT,
            js_files_json TEXT,
            forms_json TEXT,
            api_calls_json TEXT
        );
        """
    )


def test_matches_any_counts_duplicate_regex_objects_independently():
    import re

    patterns = [re.compile(r"admin"), re.compile(r"admin"), re.compile(r"login")]

    assert _matches_any("admin login", patterns) == 3


def test_unreachable_and_internal_only_assets_are_penalised_above_live_ones():
    """A host we cannot reach is not a low-resistance target.

    Regression: unreachable and internal_only previously carried no penalty at
    all, so confirmed-unreachable hosts outranked live ones in the soft ranking.
    """

    def _asset(live_status: str) -> dict:
        return {
            "id": 1,
            "asset_value": "app.example.test",
            "asset_type": "domain",
            "port": 443,
            "live_status": live_status,
        }

    penalties = {status: score_negative(_asset(status), []) for status in ("live", "unknown", "unreachable", "internal_only", "dead")}
    assert penalties["live"] < penalties["unknown"] < penalties["unreachable"]
    assert penalties["unreachable"] < penalties["internal_only"] < penalties["dead"]


def test_richer_row_wins_for_a_host_with_mixed_liveness_rows():
    from db.soft_target_scorer import _asset_row_is_better

    live = {"asset_value": "a.example", "live_status": "live", "id": 9}
    unreachable = {"asset_value": "a.example", "live_status": "unreachable", "id": 1}
    unknown = {"asset_value": "a.example", "live_status": "unknown", "id": 1}
    assert _asset_row_is_better(live, unreachable) is True
    assert _asset_row_is_better(unreachable, live) is False
    assert _asset_row_is_better(unreachable, unknown) is True
    assert _asset_row_is_better(unknown, unreachable) is False


def test_soft_targets_migration_and_schema_sql_create_tables_and_indexes():
    conn = _conn()
    ensure_schema_version(conn)

    assert apply_migration(conn, 25, str(MIGRATION_PATH)) is True
    assert apply_migration(conn, 25, str(MIGRATION_PATH)) is True
    assert {"soft_targets", "soft_target_events"}.issubset(_table_names(conn))
    assert {"idx_soft_targets_identity", "idx_soft_targets_rank", "idx_soft_target_events_target"}.issubset(_index_names(conn))
    assert conn.execute("SELECT COUNT(*) FROM schema_version WHERE version = 25").fetchone()[0] == 1

    fresh = _conn()
    fresh.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    assert {"soft_targets", "soft_target_events"}.issubset(_table_names(fresh))


def test_run_scorer_persists_seven_dimensions_evidence_and_caps_total_score():
    conn = _conn()
    _seed_scoring_schema(conn)
    conn.execute("INSERT INTO targets (target_name, domain) VALUES ('demo', 'example.com')")
    conn.execute(
        """
        INSERT INTO target_assets (
            target_name, asset_type, asset_value, port, protocol, tech_stack, notes
        )
        VALUES ('demo', 'subdomain', 'test-admin.example.com', 8443, 'https',
                'Struts2 jQuery 1.8 version 1.2.3', 'upload export tenant admin user debug exception phpinfo')
        """
    )
    conn.execute(
        """
        INSERT INTO pages (
            target_name, url, depth, title, js_files_json, forms_json, api_calls_json
        )
        VALUES (
            'demo',
            'https://test-admin.example.com/admin/login',
            0,
            'Debug Admin Login Swagger API Doc Exception',
            '["a.js","b.js","c.js","d.js","e.js"]',
            '[{"a":1},{"b":2}]',
            '["/api/user","/api/order","/api/export","/api/import","/api/admin"]'
        )
        """
    )

    payload = run_scorer(conn, target_name="demo")

    result = payload["results"][0]
    assert result["total_score"] <= 100
    assert result["rank"] == 1
    assert {
        "abandonment",
        "tech_age",
        "attack_surface",
        "permission",
        "exposure",
        "fingerprint",
        "anomaly",
        "pages_bonus",
    }.issubset(result["dimensions"])

    stored = conn.execute("SELECT * FROM soft_targets WHERE target_name = 'demo'").fetchone()
    dims = json.loads(stored["dimension_scores_json"])
    evidence = json.loads(stored["evidence_json"])
    assert dims["attack_surface"]["score"] > 0
    assert evidence
    assert stored["status"] == "ranked"


def test_pages_are_scoped_to_target_and_concrete_subdomain_asset():
    conn = _conn()
    _seed_scoring_schema(conn)
    conn.execute("INSERT INTO targets (target_name, domain) VALUES ('demo', 'example.com')")
    conn.execute("INSERT INTO targets (target_name, domain) VALUES ('other', 'example.com')")
    conn.execute("INSERT INTO target_assets (target_name, asset_type, asset_value) VALUES ('demo', 'subdomain', 'api.example.com')")
    conn.execute(
        """
        INSERT INTO pages (target_name, url, depth, title, js_files_json, forms_json, api_calls_json)
        VALUES ('other', 'https://api.example.com/debug', 0, 'Debug Admin', '[]', '[]', '[]')
        """
    )
    conn.execute(
        """
        INSERT INTO pages (target_name, url, depth, title, js_files_json, forms_json, api_calls_json)
        VALUES ('demo', 'https://other.example.com/debug', 0, 'Debug Admin', '[]', '[]', '[]')
        """
    )

    payload = run_scorer(conn, target_name="demo")

    assert payload["results"][0]["page_title"] == ""


def test_stable_sorting_uses_asset_identity_after_equal_score():
    conn = _conn()
    _seed_scoring_schema(conn)
    conn.executemany(
        "INSERT INTO target_assets (target_name, asset_type, asset_value) VALUES ('demo', 'domain', ?)",
        [("b.example.com",), ("a.example.com",)],
    )

    payload = run_scorer(conn, target_name="demo")

    assert [r["asset_value"] for r in payload["results"]] == ["a.example.com", "b.example.com"]
    assert [r["rank"] for r in payload["results"]] == [1, 2]


def test_compact_list_returns_sorting_reasons_unknowns_and_cost():
    conn = _conn()
    _seed_scoring_schema(conn)
    conn.executemany(
        "INSERT INTO target_assets (target_name, asset_type, asset_value, notes, tech_stack) VALUES ('demo', 'subdomain', ?, ?, ?)",
        [
            ("plain.example.com", "", ""),
            ("test-admin.example.com", "admin upload debug", "Struts2 version 1.2.3"),
        ],
    )
    run_scorer(conn, target_name="demo")

    listed = list_soft_targets(conn, target_name="demo")

    assert [row["asset"] for row in listed["results"]] == ["test-admin.example.com", "plain.example.com"]
    top = listed["results"][0]
    assert top["reason_summary"]
    assert "estimated_test_cost" in top
    assert "unknown_items" in top
    assert "dimension_scores_json" not in top
    assert "evidence_json" not in top


def test_focus_selected_soft_target_queues_entry_probe_without_auto_choice():
    conn = _conn()
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    conn.execute("INSERT INTO targets (id, target_name, domain) VALUES (1, 'demo', 'example.com')")
    conn.execute(
        "INSERT INTO target_assets (id, target_name, asset_type, asset_value, notes) VALUES (7, 'demo', 'subdomain', 'test-admin.example.com', 'admin upload')"
    )
    run_scorer(conn, target_name="demo")
    soft_id = conn.execute("SELECT id FROM soft_targets WHERE asset_id = 7").fetchone()[0]

    focused = focus_soft_target(conn, target_name="demo", soft_target_id=soft_id, actor="test")
    focused_again = focus_soft_target(conn, target_name="demo", soft_target_id=soft_id, actor="test")

    assert focused["status"] == "focused"
    assert focused["queued_work_item_id"] == focused_again["queued_work_item_id"]
    work = conn.execute("SELECT * FROM work_items WHERE id = ?", (focused["queued_work_item_id"],)).fetchone()
    assert work["lane"] == "entry_probe"
    assert work["subtype"] == "focused_soft_target"
    assert work["subject_table"] == "target_assets"
    assert work["subject_id"] == "7"


def test_failed_switch_returns_next_candidates_and_preserves_existing_evidence():
    conn = _conn()
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    conn.execute("INSERT INTO targets (id, target_name, domain) VALUES (1, 'demo', 'example.com')")
    conn.executemany(
        "INSERT INTO target_assets (target_name, asset_type, asset_value, notes) VALUES ('demo', 'subdomain', ?, ?)",
        [
            ("test-admin.example.com", "admin upload"),
            ("oa.example.com", "login workflow"),
        ],
    )
    run_scorer(conn, target_name="demo")
    first_id = conn.execute("SELECT id FROM soft_targets ORDER BY rank ASC LIMIT 1").fetchone()[0]
    conn.execute(
        "INSERT INTO soft_target_events (soft_target_id, target_name, asset_value, to_status, reason, evidence_json) VALUES (?, 'demo', 'test-admin.example.com', 'ranked', 'seed', ?)",
        (first_id, json.dumps({"evidence_refs": ["evidence_refs:1"]})),
    )
    conn.commit()

    failed = transition_soft_target(
        conn,
        target_name="demo",
        soft_target_id=first_id,
        status="failed",
        reason="no usable endpoint",
        actor="test",
    )

    assert failed["status"] == "failed"
    assert failed["selection_required"] is True
    assert all(item["id"] != first_id for item in failed["next_candidates"])
    events = conn.execute(
        "SELECT reason, evidence_json FROM soft_target_events WHERE soft_target_id = ? ORDER BY id", (first_id,)
    ).fetchall()
    seed_event = next(event for event in events if event["reason"] == "seed")
    assert json.loads(seed_event["evidence_json"])["evidence_refs"] == ["evidence_refs:1"]
    assert events[-1]["reason"] == "no usable endpoint"


def test_list_soft_targets_empty_safe_return():
    conn = _conn()
    ensure_soft_target_schema(conn)

    payload = list_soft_targets(conn, target_name="demo")

    assert payload["results"] == []
    assert payload["empty"] is True
    assert payload["selection_required"] is False


def test_failed_lifecycle_preserves_reason_evidence_and_history():
    conn = _conn()
    ensure_soft_target_schema(conn)
    conn.execute(
        """
        INSERT INTO soft_targets (target_name, asset_id, asset_value, tier, total_score)
        VALUES ('demo', 1, 'api.example.com', 'tier3_正常测试', 50)
        """
    )
    soft_target_id = conn.execute("SELECT id FROM soft_targets").fetchone()[0]

    update_soft_target_status(
        conn,
        soft_target_id,
        "failed",
        reason="auth_expired",
        evidence=[{"url": "https://api.example.com/me", "status": 401}],
        actor="test",
    )

    row = conn.execute("SELECT * FROM soft_targets WHERE id = ?", (soft_target_id,)).fetchone()
    assert row["status"] == "failed"
    assert row["failure_reason"] == "auth_expired"
    assert json.loads(row["failure_evidence_json"])[0]["status"] == 401

    event = conn.execute("SELECT * FROM soft_target_events WHERE soft_target_id = ?", (soft_target_id,)).fetchone()
    assert event["from_status"] == "ranked"
    assert event["to_status"] == "failed"
    assert event["reason"] == "auth_expired"


def test_invalid_lifecycle_status_is_rejected():
    conn = _conn()
    ensure_soft_target_schema(conn)
    conn.execute("INSERT INTO soft_targets (target_name, asset_id, asset_value, tier, total_score) VALUES ('demo', 1, 'a', 't', 1)")

    with pytest.raises(ValueError):
        update_soft_target_status(conn, 1, "auto_chosen")


def test_soft_target_cli_lists_focuses_and_fails_only_explicit_operator_choice(tmp_path):
    db_path = tmp_path / "soft.db"
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    conn.execute("INSERT INTO targets (id, target_name, domain) VALUES (1, 'demo', 'example.com')")
    conn.execute("INSERT INTO target_assets (target_name, asset_type, asset_value) VALUES ('demo', 'subdomain', 'b.example.com')")
    conn.execute(
        "INSERT INTO target_assets (target_name, asset_type, asset_value, notes) VALUES ('demo', 'subdomain', 'test-admin.example.com', 'admin upload')"
    )
    conn.commit()
    conn.close()

    score_cmd = [
        sys.executable,
        str(SCRIPT_PATH),
        "--db",
        str(db_path),
        "--target",
        "demo",
        "--json",
    ]
    scored = json.loads(
        subprocess.run(score_cmd, capture_output=True, text=True, check=True, cwd=PROJECT_ROOT).stdout  # noqa: S603
    )
    chosen_id = scored["results"][1]["id"]

    list_cmd = [
        sys.executable,
        str(SCRIPT_PATH),
        "--db",
        str(db_path),
        "--target",
        "demo",
        "--list-ranked",
        "--json",
    ]
    listed = json.loads(
        subprocess.run(list_cmd, capture_output=True, text=True, check=True, cwd=PROJECT_ROOT).stdout  # noqa: S603
    )
    assert listed["results"][0]["status"] == "ranked"

    focus_cmd = score_cmd[:-1] + ["--focus-id", str(chosen_id), "--json"]
    focused = json.loads(
        subprocess.run(focus_cmd, capture_output=True, text=True, check=True, cwd=PROJECT_ROOT).stdout  # noqa: S603
    )
    assert focused["id"] == chosen_id
    assert focused["status"] == "focused"

    fail_cmd = score_cmd[:-1] + ["--fail-id", str(chosen_id), "--reason", "no usable endpoint", "--json"]
    failed = json.loads(
        subprocess.run(fail_cmd, capture_output=True, text=True, check=True, cwd=PROJECT_ROOT).stdout  # noqa: S603
    )
    assert failed["status"] == "failed"
    assert failed["reason"] == "no usable endpoint"

    check = sqlite3.connect(db_path)
    check.row_factory = sqlite3.Row
    row = check.execute("SELECT * FROM soft_targets WHERE id = ?", (chosen_id,)).fetchone()
    events = check.execute("SELECT to_status FROM soft_target_events WHERE soft_target_id = ? ORDER BY id", (chosen_id,)).fetchall()
    check.close()
    assert row["status"] == "failed"
    assert row["failure_reason"] == "no usable endpoint"
    assert [event["to_status"] for event in events][-2:] == ["focused", "failed"]


def test_score_asset_caps_page_bonus_at_ten_and_final_at_one_hundred():
    asset = {
        "id": 1,
        "asset_type": "subdomain",
        "asset_value": "test-admin.example.com",
        "port": 9443,
        "protocol": "https",
        "tech_stack": "Struts2 jQuery 1.8 version 1.2.3 WebLogic 10 Tomcat 6",
        "notes": "upload import export download preview convert tenant admin teacher student debug exception phpinfo .env AKIAABCDEFGHIJKLMNOP",
        "page_title": "Debug Admin Swagger API Doc Stack Trace",
    }
    pages = [
        {
            "title": "Debug Admin Swagger API Doc Stack Trace",
            "url": "https://test-admin.example.com/admin",
            "js_files_json": json.dumps([f"{i}.js" for i in range(10)]),
            "forms_json": json.dumps([{"i": i} for i in range(5)]),
            "api_calls_json": json.dumps([f"/api/{i}" for i in range(20)]),
        }
    ]

    result = score_asset(asset, pages)

    assert result["dimensions"]["pages_bonus"]["score"] <= 10
    assert result["total_score"] <= 100


def test_root_site_and_large_authenticated_surface_do_not_rank_as_soft():
    root = score_asset(
        {
            "id": 1,
            "asset_type": "domain",
            "asset_value": "example.com",
            "target_root_domain": "example.com",
            "auth_required": 1,
            "has_login": 1,
            "notes": "admin api swagger dashboard upload export",
        },
        [
            {
                "title": "Admin Dashboard",
                "url": "https://example.com/admin",
                "js_files_json": json.dumps([f"{i}.js" for i in range(10)]),
                "forms_json": json.dumps([{"i": i} for i in range(5)]),
                "api_calls_json": json.dumps([f"/api/{i}" for i in range(20)]),
            }
        ],
    )
    soft = score_asset(
        {
            "id": 2,
            "asset_type": "subdomain",
            "asset_value": "test-old.example.com",
            "target_root_domain": "example.com",
            "tech_stack": "Struts2 jQuery 1.8",
            "notes": "debug test backup",
        },
        [],
    )

    assert root["dimensions"]["attack_surface"]["score"] <= 10
    assert root["penalty"] >= 39
    assert soft["total_score"] > root["total_score"]
