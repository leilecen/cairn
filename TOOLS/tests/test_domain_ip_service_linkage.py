from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from db.domain_ip_service_linkage import reconcile_domain_ip_service

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "TOOLS" / "db" / "schema.sql"
SCRIPT = ROOT / "TOOLS" / "db" / "domain_ip_service_linkage.py"


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA.read_text(encoding="utf-8"))
    conn.execute("INSERT INTO targets(target_name,domain) VALUES('T','app-a.example.test')")
    conn.execute("INSERT INTO targets(target_name,domain) VALUES('other','other.test')")
    conn.execute(
        """INSERT INTO target_assets(target_name,asset_type,asset_value,port,scope_status,authorization_state)
           VALUES('T','domain','app-a.example.test',443,'in_scope','authorized'),
                 ('T','domain','unrelated.example.net',443,'needs_review','unknown'),
                 ('other','domain','other.test',443,'in_scope','authorized')"""
    )
    conn.executemany(
        """INSERT INTO network_observations(
               target_name,asset_id,host,ip,port,protocol,service,http_json,source,evidence_refs_json,observed_at
           ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
        [
            ("T", 1, "app-a.example.test", "203.0.113.44", None, "dns", "A", "{}", "dns", '["ev:old"]', "2025-01-01"),
            (
                "T",
                1,
                "app-a.example.test",
                "203.0.113.45",
                None,
                "dns",
                "A",
                "{}",
                "passive_dns",
                '["ev:dns"]',
                "2026-08-13",
            ),
            (
                "T",
                1,
                "app-a.example.test",
                "203.0.113.45",
                443,
                "https",
                "https",
                "{}",
                "fixture",
                '["ev:svc"]',
                "2026-08-13",
            ),
            (
                "T",
                2,
                "unrelated.example.net",
                "203.0.113.45",
                443,
                "https",
                "https",
                "{}",
                "fixture",
                '["ev:other"]',
                None,
            ),
            ("other", 3, "other.test", "203.0.113.45", 443, "https", "https", "{}", "fixture", "[]", "2026-08-13"),
        ],
    )
    conn.execute(
        """INSERT INTO technology_observations(
               target_name,asset_id,host,technology,category,confidence,source,evidence_refs_json,observed_at
           ) VALUES('T',1,'app-a.example.test','Longshine HCM','product','high','login_js','["ev:hcm"]','2026-08-13')"""
    )
    conn.execute(
        """INSERT INTO target_systems(target_name,system_key,display_name,canonical_url,scope_class)
           VALUES('T','hcm','HCM','https://app-a.example.test','owned')"""
    )
    conn.execute(
        """INSERT INTO system_asset_links(target_name,system_id,asset_id,relationship,confidence,evidence_refs_json)
           VALUES('T',1,1,'entry','high','["ev:link"]')"""
    )
    conn.commit()
    return conn


def test_linkage_preserves_history_time_source_and_shared_ip_boundaries():
    conn = _conn()
    before = conn.total_changes
    preview = reconcile_domain_ip_service(conn, target_name="T", apply=False, include_items=True)
    assert conn.total_changes == before
    assert {item["ip"] for item in preview["items"] if item["domain"] == "app-a.example.test"} == {
        "203.0.113.44",
        "203.0.113.45",
    }
    current = next(
        item for item in preview["items"] if item["domain"] == "app-a.example.test" and item["ip"] == "203.0.113.45" and item["port"] == 443
    )
    assert current["product_candidates"] == ["Longshine HCM"]
    assert current["dns_observations"] == [{"source": "passive_dns", "observed_at": "2026-08-13", "temporal_status": "current"}]
    assert current["system_link_candidate"]["system_id"] == 1
    unrelated = next(item for item in preview["items"] if item["domain"] == "unrelated.example.net")
    assert unrelated["scope_status"] == "needs_review"
    assert unrelated["product_candidates"] == [] and unrelated["system_link_candidate"] is None
    assert unrelated["authorization_inherited"] is False
    assert unrelated["temporal_status"] == "missing" and unrelated["confidence"] == "unknown"
    old = next(item for item in preview["items"] if item["ip"] == "203.0.113.44")
    assert old["temporal_status"] == "stale" and old["confidence"] == "low"
    assert all(item["domain"] != "other.test" for item in preview["items"])
    assert all(len(json.dumps(item, ensure_ascii=False)) < 1199 for item in preview["items"])


def test_apply_is_idempotent_immediate_and_rolls_back():
    conn = _conn()
    trace: list[str] = []
    conn.set_trace_callback(trace.append)
    first = reconcile_domain_ip_service(conn, target_name="T", apply=True)
    second = reconcile_domain_ip_service(conn, target_name="T", apply=True)
    assert first["inserted"] > 0 and second["inserted"] == 0
    begin = next(i for i, sql in enumerate(trace) if sql.upper().startswith("BEGIN IMMEDIATE"))
    fact_read = next(
        i for i, sql in enumerate(trace) if "NETWORK_OBSERVATIONS" in sql.upper() and sql.lstrip().upper().startswith("SELECT")
    )
    assert fact_read > begin

    conn.execute("DELETE FROM recon_sources")
    conn.commit()
    conn.execute(
        """CREATE TRIGGER fail_link BEFORE INSERT ON recon_sources
           BEGIN SELECT RAISE(ABORT,'fixture failure'); END"""
    )
    with pytest.raises(sqlite3.IntegrityError):
        reconcile_domain_ip_service(conn, target_name="T", apply=True)
    assert conn.execute("SELECT COUNT(*) FROM recon_sources").fetchone()[0] == 0


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("ip", "999.1.1.1"),
        ("port", 70000),
        ("port", 443.5),
        ("host", "bad host"),
        ("source", "Authorization: Bearer x"),
        ("service", "Cookie: sid=x"),
        ("evidence_refs_json", '["GET / HTTP/1.1"]'),
    ],
)
def test_linkage_skips_invalid_or_sensitive_compact_fields_per_row(column, value):
    conn = _conn()
    conn.execute(f"UPDATE network_observations SET {column}=? WHERE id=3", (value,))  # noqa: S608 -- fixed columns
    conn.commit()
    preview = reconcile_domain_ip_service(conn, target_name="T", apply=False, include_items=True)
    assert preview["skipped"] >= 1
    assert preview["dirty"] and preview["dirty"][0]["table"] == "network_observations"
    # The rest of the target chain survives and is still planned.
    assert any(item["domain"] == "app-a.example.test" for item in preview["items"])
    # Apply mode also tolerates the dirty row and writes only clean candidates.
    conn.execute("DELETE FROM recon_sources")
    conn.commit()
    applied = reconcile_domain_ip_service(conn, target_name="T", apply=True)
    assert applied["skipped"] >= 1 and applied["inserted"] > 0


def test_linkage_tolerates_dirty_asset_row_without_failing_target():
    conn = _conn()
    conn.execute("UPDATE target_assets SET port='not-a-port' WHERE id=1")
    conn.execute("""UPDATE network_observations SET evidence_refs_json='{bad json' WHERE id=2""")
    conn.commit()
    preview = reconcile_domain_ip_service(conn, target_name="T", apply=False, include_items=True)
    assert preview["skipped"] >= 1
    # asset 1 was skipped, so its observations fall back to host-level facts with needs_review scope.
    assert any(item["domain"] == "app-a.example.test" and item["scope_status"] == "needs_review" for item in preview["items"])


def test_linkage_apply_uses_savepoint_and_preserves_caller_transaction_on_failure():
    conn = _conn()
    conn.execute("INSERT INTO targets(target_name,domain) VALUES('caller','caller.test')")
    reconcile_domain_ip_service(conn, target_name="T", apply=True)
    assert conn.in_transaction
    conn.rollback()
    assert conn.execute("SELECT COUNT(*) FROM targets WHERE target_name='caller'").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM recon_sources").fetchone()[0] == 0

    conn.execute("INSERT INTO targets(target_name,domain) VALUES('caller','caller.test')")
    conn.execute(
        """CREATE TRIGGER fail_link_nested BEFORE INSERT ON recon_sources
           BEGIN SELECT RAISE(ABORT,'nested failure'); END"""
    )
    with pytest.raises(sqlite3.IntegrityError):
        reconcile_domain_ip_service(conn, target_name="T", apply=True)
    assert conn.in_transaction
    assert conn.execute("SELECT COUNT(*) FROM targets WHERE target_name='caller'").fetchone()[0] == 1
    conn.rollback()


def test_domain_cli_default_is_compact_and_target_mismatch_is_zero_write(tmp_path):
    path = tmp_path / "linkage.db"
    source = _conn()
    disk = sqlite3.connect(path)
    source.backup(disk)
    disk.close()
    source.close()

    preview = subprocess.run(  # noqa: S603
        [sys.executable, str(SCRIPT), "--file", str(path), "--target", "T"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert preview.returncode == 0 and len(preview.stdout.encode()) < 1199
    mismatch = subprocess.run(  # noqa: S603
        [sys.executable, str(SCRIPT), "--file", str(path), "--target", "wrong", "--apply"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert mismatch.returncode == 1
    with sqlite3.connect(path) as verify:
        assert verify.execute("SELECT COUNT(*) FROM recon_sources").fetchone()[0] == 0
