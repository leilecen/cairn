import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

# ruff: noqa: S603
from db.system_cluster import apply_cluster_plan, build_cluster_plan, rollback_cluster_run

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "TOOLS" / "db" / "schema.sql"


def _db():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    c.executescript(SCHEMA.read_text(encoding="utf-8"))
    c.execute("INSERT INTO targets(id,target_name,domain) VALUES(1,'T','example.com')")
    c.executemany(
        """INSERT INTO target_assets(
          id,target_name,asset_value,port,protocol,resolved_ip,scope_status,scope_class,authorization_state
        ) VALUES(?,?,?,?,?,?,?,?,?)""",
        [
            (1, "T", "a.example.com", 443, "https", "1.1.1.1", "in_scope", "owned", "authorized"),
            (2, "T", "b.example.com", 443, "https", "1.1.1.1", "needs_review", "intel_only", "unknown"),
            (3, "T", "c.example.com", 8443, "https", "2.2.2.2", "in_scope", "owned", "authorized"),
        ],
    )
    c.commit()
    return c


def test_shared_ip_and_sld_do_not_auto_merge_without_auth_or_product_evidence():
    c = _db()
    plan = build_cluster_plan(c, "T")
    assert len(plan["systems"]) == 3
    assert all(len(item["asset_ids"]) == 1 for item in plan["systems"])
    assert plan["candidate_links"]
    assert {item["reason"] for item in plan["candidate_links"]} >= {"shared_ip", "shared_sld"}


def test_url_asset_uses_normalized_hostname_port_deployment_boundary():
    c = _db()
    c.execute(
        """INSERT INTO target_assets(
               target_name,asset_value,port,protocol,scope_class
           ) VALUES('T','https://portal.example.com/app',8443,'https','owned')"""
    )
    c.commit()

    plan = build_cluster_plan(c, "T")
    system = next(item for item in plan["systems"] if item["display_name"] == "https://portal.example.com/app")

    assert system["basis"] == "deployment_boundary"
    assert system["canonical_url"] == "https://portal.example.com:8443/"


def test_auth_boundary_merges_assets_and_preview_is_zero_write_then_apply_idempotent():
    c = _db()
    c.executemany(
        """INSERT INTO asset_auth_entries(target_name,asset_id,url,entry_type,source,confidence)
        VALUES('T',?,'https://sso.example.com/login','login','fixture','high')""",
        [(1,), (3,)],
    )
    c.commit()
    before = c.total_changes
    plan = build_cluster_plan(c, "T")
    assert c.total_changes == before
    merged = next(item for item in plan["systems"] if set(item["asset_ids"]) == {1, 3})
    assert merged["basis"] == "auth_boundary"

    statements = []
    c.set_trace_callback(statements.append)
    apply_cluster_plan(c, "T")
    normalized = [x.strip().upper() for x in statements]
    assert next(i for i, x in enumerate(normalized) if x.startswith("BEGIN IMMEDIATE")) < next(
        i for i, x in enumerate(normalized) if x.startswith("SELECT")
    )
    counts = (
        c.execute("SELECT COUNT(*) FROM target_systems").fetchone()[0],
        c.execute("SELECT COUNT(*) FROM system_asset_links").fetchone()[0],
    )
    audit_count = c.execute("SELECT COUNT(*) FROM recon_sources WHERE source_kind='system_cluster_apply'").fetchone()[0]
    apply_cluster_plan(c, "T")
    assert counts == (
        c.execute("SELECT COUNT(*) FROM target_systems").fetchone()[0],
        c.execute("SELECT COUNT(*) FROM system_asset_links").fetchone()[0],
    )
    assert c.execute("SELECT COUNT(*) FROM target_systems WHERE target_name<>'T'").fetchone()[0] == 0
    assert c.execute("SELECT COUNT(*) FROM recon_sources WHERE source_kind='system_cluster_apply'").fetchone()[0] == audit_count


def test_explicit_product_evidence_merges_but_generic_technology_does_not():
    c = _db()
    c.executemany(
        """INSERT INTO technology_observations(target_name,asset_id,host,technology,category,confidence,source)
           VALUES('T',?,?,?,?, 'high',?)""",
        [
            (1, "a.example.com", "AcmeAF", "product", "product_fingerprint"),
            (3, "c.example.com", "AcmeAF", "product", "product_fingerprint"),
            (2, "b.example.com", "nginx", "server", "header"),
        ],
    )
    c.commit()
    plan = build_cluster_plan(c, "T")
    merged = next(item for item in plan["systems"] if set(item["asset_ids"]) == {1, 3})
    assert merged["basis"] == "product_evidence"
    assert all(2 not in item["asset_ids"] or len(item["asset_ids"]) == 1 for item in plan["systems"])


def test_apply_rolls_back_all_system_and_link_writes_on_link_failure():
    c = _db()
    c.execute("""CREATE TRIGGER reject_cluster_link BEFORE INSERT ON system_asset_links
                 BEGIN SELECT RAISE(ABORT,'fixture link failure'); END""")
    with pytest.raises(sqlite3.IntegrityError):
        apply_cluster_plan(c, "T")
    assert c.execute("SELECT COUNT(*) FROM target_systems").fetchone()[0] == 0


def test_cli_missing_file_is_compact_nonzero_and_does_not_create_database(tmp_path):
    missing = tmp_path / "missing.db"
    script = ROOT / "TOOLS" / "db" / "system_cluster.py"
    result = subprocess.run(
        [sys.executable, str(script), "--file", str(missing), "--target-name", "T"],
        capture_output=True,
        text=True,
        check=False,
    )
    payload = json.loads(result.stdout)
    assert result.returncode == 1 and payload["ok"] is False and not missing.exists()


def test_changed_facts_remove_stale_managed_links_preserve_manual_and_cas_rollback():
    c = _db()
    c.executemany(
        """INSERT INTO asset_auth_entries(target_name,asset_id,url,entry_type,source,confidence)
           VALUES('T',?,'https://sso.example.com/login','login','fixture','high')""",
        [(1,), (3,)],
    )
    c.commit()
    first = apply_cluster_plan(c, "T")
    merged_id = c.execute("SELECT id FROM target_systems WHERE target_name='T' AND description='cluster basis: auth_boundary'").fetchone()[
        0
    ]
    c.execute(
        """INSERT INTO system_asset_links(target_name,system_id,asset_id,relationship,confidence,evidence_refs_json)
           VALUES('T',?,2,'dependency','high','[]')""",
        (merged_id,),
    )
    c.execute("DELETE FROM asset_auth_entries WHERE asset_id=3")
    c.commit()
    second = apply_cluster_plan(c, "T")
    assert (
        c.execute(
            "SELECT COUNT(*) FROM system_asset_links WHERE system_id=? AND asset_id=3 AND relationship='related'",
            (merged_id,),
        ).fetchone()[0]
        == 0
    )
    assert (
        c.execute(
            "SELECT COUNT(*) FROM system_asset_links WHERE system_id=? AND asset_id=2 AND relationship='dependency'",
            (merged_id,),
        ).fetchone()[0]
        == 1
    )
    assert c.execute("SELECT COUNT(*) FROM recon_sources WHERE source_kind='system_cluster_apply'").fetchone()[0] == 2
    assert rollback_cluster_run(c, "T", second["run_key"])["rolled_back"] is True
    assert rollback_cluster_run(c, "T", second["run_key"])["already_rolled_back"] is True
    # A changed managed after-image makes the older run fail closed.
    c.execute(
        """UPDATE system_asset_links SET confidence='medium' WHERE id=(
             SELECT id FROM system_asset_links WHERE evidence_refs_json LIKE '%cluster_basis%' ORDER BY id LIMIT 1)"""
    )
    c.commit()
    with pytest.raises(RuntimeError):
        rollback_cluster_run(c, "T", first["run_key"])
