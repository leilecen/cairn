import json
import sqlite3

from recon.recon_store import record_source


def test_record_source_can_join_callers_transaction_without_committing_it():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    record_source(conn, target_name="T", source_kind="fixture", result={"ok": True})
    conn.execute("UPDATE recon_sources SET status='caller-write'")
    record_source(
        conn,
        target_name="T",
        source_kind="nested",
        result={"token": "secret"},
        ensure_schema=False,
        commit=False,
    )
    assert conn.in_transaction
    conn.rollback()
    assert conn.execute("SELECT status FROM recon_sources WHERE source_kind='fixture'").fetchone()[0] == "observed"
    assert "secret" not in json.dumps([dict(row) for row in conn.execute("SELECT * FROM recon_sources")])


def test_legacy_record_source_large_list_remains_compact_and_idempotent():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    payload = {"items": [{"url": f"https://example.test/{index}"} for index in range(1199)]}
    record_source(conn, target_name="T", source_kind="legacy", query="q", result=payload)
    record_source(conn, target_name="T", source_kind="legacy", query="q", result=payload)
    row = conn.execute("SELECT result_json FROM recon_sources").fetchone()
    assert conn.execute("SELECT COUNT(*) FROM recon_sources").fetchone()[0] == 1
    assert len(json.loads(row[0])["items"]) == 100
