from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from db.peer_document_reconcile import reconcile_peer_document

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "TOOLS" / "db" / "schema.sql"
SCRIPT = ROOT / "TOOLS" / "db" / "peer_document_reconcile.py"


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA.read_text(encoding="utf-8"))
    conn.execute("INSERT INTO targets(target_name,domain) VALUES('T','app.example.test')")
    conn.execute(
        """INSERT INTO target_assets(target_name,asset_type,asset_value,port,scope_status)
           VALUES('T','domain','app.example.test',443,'in_scope')"""
    )
    conn.execute(
        """INSERT INTO target_systems(target_name,system_key,display_name,canonical_url,scope_class)
           VALUES('T','portal','Portal','https://app.example.test','owned')"""
    )
    conn.execute(
        """INSERT INTO system_asset_links(target_name,system_id,asset_id,relationship,confidence,evidence_refs_json)
           VALUES('T',1,1,'entry','high','["ev:system-link"]')"""
    )
    conn.execute(
        """INSERT INTO endpoint_observations(
               target_name,asset_id,canonical_url,host,path,method,source,evidence_refs_json
           ) VALUES('T',1,'https://app.example.test/directdata/direct/router',
                    'app.example.test','/directdata/direct/router','POST','fixture','["ev:endpoint"]')"""
    )
    conn.commit()
    return conn


def _records():
    return [
        {
            "asset": {"host": "app.example.test", "port": 443, "vendor": "Acme", "product": "Portal"},
            "chain": {
                "path": "/directdata/direct/router",
                "method": "POST",
                "params": ["action"],
                "preconditions": ["version unknown"],
                "reference": "public-advisory-1",
            },
        }
    ]


def test_document_record_is_split_to_asset_and_chain_and_replay_stays_hypothesis():
    conn = _conn()
    before = conn.total_changes
    preview = reconcile_peer_document(conn, target_name="T", document_ref="ev:docx:1", records=_records(), apply=False, include_items=True)
    assert conn.total_changes == before and preview["planned_sources"] == 2
    first = reconcile_peer_document(conn, target_name="T", document_ref="ev:docx:1", records=_records(), apply=True)
    second = reconcile_peer_document(conn, target_name="T", document_ref="ev:docx:1", records=_records(), apply=True)
    assert first["sources_inserted"] == 2 and first["work_items_inserted"] == 1
    assert second["sources_inserted"] == 0 and second["work_items_inserted"] == 0
    rows = conn.execute("SELECT source_kind,status,result_json FROM recon_sources ORDER BY source_kind").fetchall()
    assert {row["source_kind"] for row in rows} == {"peer_document_asset", "peer_document_chain"}
    assert all(row["status"] == "needs_review" for row in rows)
    assert all("raw_document" not in row["result_json"] for row in rows)
    assert all(len(row["result_json"]) < 1199 for row in rows)
    work = conn.execute(
        """SELECT lane,subtype,status,risk_class,summary,system_id,subject_table,subject_id,objective
           FROM work_items"""
    ).fetchone()
    assert (work["lane"], work["subtype"], work["status"], work["risk_class"], work["system_id"]) == (
        "hypothesis",
        "peer_document_chain",
        "queued",
        "safe_passive",
        1,
    )
    assert work["subject_table"] == "recon_sources" and work["subject_id"].isdigit() and work["objective"]
    assert "confirmed" not in work["summary"].lower()


def test_raw_http_and_credentials_are_rejected_and_failure_rolls_back():
    conn = _conn()
    with pytest.raises(ValueError, match="raw HTTP or credential"):
        reconcile_peer_document(
            conn,
            target_name="T",
            document_ref="ev:bad",
            records=[{"asset": {"host": "x"}, "raw_http": "GET / HTTP/1.1\r\nAuthorization: Bearer x"}],
            apply=True,
        )
    assert conn.execute("SELECT COUNT(*) FROM recon_sources").fetchone()[0] == 0
    conn.execute(
        """CREATE TRIGGER fail_doc_work BEFORE INSERT ON work_items
           BEGIN SELECT RAISE(ABORT,'fixture failure'); END"""
    )
    with pytest.raises(sqlite3.IntegrityError):
        reconcile_peer_document(conn, target_name="T", document_ref="ev:docx:2", records=_records(), apply=True)
    assert conn.execute("SELECT COUNT(*) FROM recon_sources").fetchone()[0] == 0


@pytest.mark.parametrize(
    ("section", "field", "value"),
    [
        ("asset", "host", "bad host"),
        ("asset", "port", 0),
        ("asset", "port", "443"),
        ("chain", "method", "TRACE"),
        ("chain", "path", "/a/../b"),
        ("chain", "params", ["id=1 OR 1=1"]),
    ],
)
def test_peer_document_rejects_invalid_host_port_method_path_and_params(section, field, value):
    conn = _conn()
    records = _records()
    records[0][section][field] = value
    with pytest.raises(ValueError):
        reconcile_peer_document(conn, target_name="T", document_ref="ev:docx:bad", records=records, apply=False)


def test_matched_endpoint_without_system_link_stays_needs_review_without_work_item():
    conn = _conn()
    conn.execute("DELETE FROM system_asset_links")
    conn.commit()
    result = reconcile_peer_document(conn, target_name="T", document_ref="ev:docx:no-system", records=_records(), apply=True)
    assert result["sources_inserted"] == 2 and result["work_items_inserted"] == 0
    assert conn.execute("SELECT COUNT(*) FROM work_items").fetchone()[0] == 0


def test_peer_apply_uses_savepoint_and_preserves_caller_transaction_on_failure():
    conn = _conn()
    conn.execute("INSERT INTO targets(target_name,domain) VALUES('caller','caller.test')")
    reconcile_peer_document(conn, target_name="T", document_ref="ev:docx:nested", records=_records(), apply=True)
    assert conn.in_transaction
    conn.rollback()
    assert conn.execute("SELECT COUNT(*) FROM targets WHERE target_name='caller'").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM recon_sources").fetchone()[0] == 0

    conn.execute("INSERT INTO targets(target_name,domain) VALUES('caller','caller.test')")
    conn.execute(
        """CREATE TRIGGER fail_doc_nested BEFORE INSERT ON recon_sources
           BEGIN SELECT RAISE(ABORT,'nested failure'); END"""
    )
    with pytest.raises(sqlite3.IntegrityError):
        reconcile_peer_document(conn, target_name="T", document_ref="ev:docx:fail", records=_records(), apply=True)
    assert conn.execute("SELECT COUNT(*) FROM targets WHERE target_name='caller'").fetchone()[0] == 1
    conn.rollback()


def test_peer_cli_default_is_compact_and_target_mismatch_zero_write(tmp_path):
    path = tmp_path / "peer.db"
    source = _conn()
    disk = sqlite3.connect(path)
    source.backup(disk)
    disk.close()
    source.close()
    fixture = tmp_path / "peer.json"
    fixture.write_text(json.dumps([{"asset": _records()[0]["asset"]}]), encoding="utf-8")

    preview = subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(SCRIPT),
            "--file",
            str(path),
            "--target",
            "T",
            "--fixture",
            str(fixture),
            "--document-ref",
            "ev:docx:cli",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert preview.returncode == 0 and len(preview.stdout.encode()) < 1199
    mismatch = subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(SCRIPT),
            "--file",
            str(path),
            "--target",
            "wrong",
            "--fixture",
            str(fixture),
            "--document-ref",
            "ev:docx:cli",
            "--apply",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert mismatch.returncode == 1
    with sqlite3.connect(path) as verify:
        assert verify.execute("SELECT COUNT(*) FROM recon_sources").fetchone()[0] == 0
