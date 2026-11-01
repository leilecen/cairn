import json
import sqlite3

from recon.system_type_store import ensure_system_type_schema, observe_asset_system_types


def _db():
    conn = sqlite3.connect(":memory:")
    conn.executescript(
        """
        CREATE TABLE target_assets (
            id INTEGER PRIMARY KEY, target_name TEXT, asset_value TEXT,
            last_title TEXT, tech_stack TEXT, last_tech_stack TEXT
        );
        CREATE TABLE entry_observations (
            id INTEGER PRIMARY KEY, target_name TEXT, asset_id INTEGER,
            url TEXT, entry_type TEXT, evidence_refs_json TEXT
        );
        CREATE TABLE asset_auth_entries (
            id INTEGER PRIMARY KEY, target_name TEXT, asset_id INTEGER,
            url TEXT, entry_type TEXT
        );
        CREATE TABLE target_systems (id INTEGER PRIMARY KEY);
        CREATE TABLE system_asset_links (id INTEGER PRIMARY KEY);
        """
    )
    ensure_system_type_schema(conn)
    return conn


def test_schema_has_compact_observation_table_and_no_system_merge_columns():
    conn = _db()
    columns = {row[1] for row in conn.execute("PRAGMA table_info(system_type_observations)")}
    assert {
        "target_name",
        "asset_id",
        "classifier",
        "rule_context",
        "label",
        "rule_id",
        "reasons_json",
        "evidence_refs_json",
        "observed_at",
    } <= columns
    assert not {"system_id", "system_key", "canonical_url"} & columns


def test_observe_is_idempotent_target_scoped_and_distinguishes_generic_admin_from_product():
    conn = _db()
    conn.executemany(
        "INSERT INTO target_assets(id,target_name,asset_value,last_title,tech_stack) VALUES(?,?,?,?,?)",
        [
            (1, "T", "admin.example", "Admin Management", ""),
            (2, "T", "druid.example", "Druid Console", "Apache Druid"),
            (3, "U", "admin.example", "Druid Console", "Apache Druid"),
        ],
    )
    conn.executemany(
        "INSERT INTO entry_observations(target_name,asset_id,url,entry_type,evidence_refs_json) VALUES(?,?,?,?,?)",
        [("T", 1, "/login", "login", '["ev:generic"]'), ("T", 2, "/druid", "admin", '["ev:druid"]')],
    )
    conn.commit()

    first = observe_asset_system_types(conn, target_name="T")
    second = observe_asset_system_types(conn, target_name="T")
    assert first["observed"] == second["observed"] == 2
    rows = conn.execute("SELECT target_name,asset_id,label FROM system_type_observations ORDER BY target_name,asset_id").fetchall()
    assert rows == [("T", 1, "admin_portal"), ("T", 2, "druid")]
    assert conn.execute("SELECT COUNT(*) FROM system_type_observations").fetchone()[0] == 2
    assert conn.execute("SELECT COUNT(*) FROM target_systems").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM system_asset_links").fetchone()[0] == 0


def test_observation_is_compact_and_does_not_store_secrets_or_raw_url():
    conn = _db()
    conn.execute(
        "INSERT INTO target_assets(id,target_name,asset_value,last_title,tech_stack) VALUES(?,?,?,?,?)",
        (1, "T", "secret.example", "Admin Console Authorization: Bearer super-secret", "Admin"),
    )
    conn.execute(
        "INSERT INTO entry_observations(target_name,asset_id,url,entry_type,evidence_refs_json) VALUES(?,?,?,?,?)",
        ("T", 1, "https://secret.example/login?token=raw-secret", "login", '["ev:login"]'),
    )
    observe_asset_system_types(conn, target_name="T")
    row = conn.execute("SELECT reasons_json,evidence_refs_json FROM system_type_observations").fetchone()
    rendered = " ".join(row)
    assert "super-secret" not in rendered
    assert "raw-secret" not in rendered
    assert "secret.example/login" not in rendered
    assert len(json.loads(row[0])) <= 3


def _db_with_response_class():
    conn = sqlite3.connect(":memory:")
    conn.executescript(
        """
        CREATE TABLE target_assets (
            id INTEGER PRIMARY KEY, target_name TEXT, asset_value TEXT,
            last_title TEXT, tech_stack TEXT, last_tech_stack TEXT
        );
        CREATE TABLE entry_observations (
            id INTEGER PRIMARY KEY, target_name TEXT, asset_id INTEGER,
            url TEXT, entry_type TEXT, evidence_refs_json TEXT,
            status_code INTEGER, response_class TEXT
        );
        CREATE TABLE asset_auth_entries (
            id INTEGER PRIMARY KEY, target_name TEXT, asset_id INTEGER,
            url TEXT, entry_type TEXT
        );
        CREATE TABLE target_systems (id INTEGER PRIMARY KEY);
        CREATE TABLE system_asset_links (id INTEGER PRIMARY KEY);
        """
    )
    ensure_system_type_schema(conn)
    return conn


def test_unanswered_and_not_found_entries_do_not_label_a_host_as_login():
    """Transport failures and 404s must not be read as login pages."""
    conn = _db_with_response_class()
    conn.execute(
        "INSERT INTO target_assets(id,target_name,asset_value,last_title,tech_stack) VALUES(?,?,?,?,?)",
        (1, "T", "dead.example", "", "Nginx"),
    )
    conn.execute(
        "INSERT INTO target_assets(id,target_name,asset_value,last_title,tech_stack) VALUES(?,?,?,?,?)",
        (2, "T", "gone.example", "", "Nginx"),
    )
    conn.executemany(
        "INSERT INTO entry_observations(target_name,asset_id,url,entry_type,evidence_refs_json,status_code,response_class)"
        " VALUES(?,?,?,?,?,?,?)",
        [
            ("T", 1, "https://dead.example/login", "login", '["ev:a"]', 0, "unknown"),
            ("T", 2, "https://gone.example/login", "login", '["ev:b"]', 404, "not_found"),
        ],
    )
    conn.commit()

    observe_asset_system_types(conn, target_name="T")
    labels = dict(conn.execute("SELECT asset_id,label FROM system_type_observations ORDER BY asset_id").fetchall())
    assert labels == {1: "unknown", 2: "unknown"}


def test_confirmed_auth_redirect_still_labels_a_login_system():
    conn = _db_with_response_class()
    conn.execute(
        "INSERT INTO target_assets(id,target_name,asset_value,last_title,tech_stack) VALUES(?,?,?,?,?)",
        (1, "T", "app.example", "", "Nginx"),
    )
    conn.execute(
        "INSERT INTO entry_observations(target_name,asset_id,url,entry_type,evidence_refs_json,status_code,response_class)"
        " VALUES(?,?,?,?,?,?,?)",
        ("T", 1, "https://app.example/portal/login", "login", '["ev:c"]', 302, "auth_redirect"),
    )
    conn.commit()

    observe_asset_system_types(conn, target_name="T")
    label = conn.execute("SELECT label FROM system_type_observations").fetchone()[0]
    assert label == "login"
