from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from recon.public_exposure_intel import import_public_exposure

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "TOOLS" / "db" / "schema.sql"


def _db():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA.read_text(encoding="utf-8"))
    conn.execute("INSERT INTO targets(id,target_name,domain) VALUES(1,'T','example.com')")
    conn.commit()
    return conn


def _payload(status="hits", hits=None, evidence_refs=None):
    return {
        "query": 'site:yuque.com "example.com"',
        "provider": "searxng",
        "status": status,
        "result_count": len(hits or []),
        "dedup_count": len(hits or []),
        "evidence_refs": ["fixture:1"] if evidence_refs is None else evidence_refs,
        "hits": hits or [],
    }


def test_preview_zero_write_apply_hits_needs_review_and_url_family_idempotent():
    conn = _db()
    hits = [
        {
            "url": "https://yuque.com/acme/public?utm_source=x",
            "title": "Public doc",
            "snippet": "indexed summary",
            "matched_anchor": "example.com",
            "evidence_refs": ["fixture:2"],
        },
        {
            "url": "https://yuque.com/acme/public?utm_source=y",
            "title": "duplicate",
            "snippet": "same URL",
            "matched_anchor": "example.com",
            "evidence_refs": ["fixture:3"],
        },
    ]
    before = conn.total_changes
    preview = import_public_exposure(conn, target_name="T", family="public_docs_search", payload=_payload(hits=hits), apply=False)
    assert conn.total_changes == before and preview["dedup_count"] == 1
    applied = import_public_exposure(conn, target_name="T", family="public_docs_search", payload=_payload(hits=hits), apply=True)
    row = conn.execute("SELECT status,result_json FROM recon_sources WHERE source_kind='public_docs_search:hit'").fetchone()
    assert row["status"] == "needs_review"
    assert json.loads(row["result_json"])["url"] == "https://yuque.com/acme/public"
    coverage = conn.execute(
        "SELECT status FROM coverage_ledger WHERE target_name='T' AND profile_id IS NULL AND item_key='public_exposure:public_docs_search'"
    ).fetchone()[0]
    assert coverage == "covered" and applied["coverage_status"] == "covered"
    import_public_exposure(conn, target_name="T", family="public_docs_search", payload=_payload(hits=hits), apply=True)
    assert conn.execute("SELECT COUNT(*) FROM recon_sources").fetchone()[0] == 2
    second_query = {**_payload(hits=[hits[0]]), "query": 'site:docs.qq.com "example.com"'}
    import_public_exposure(conn, target_name="T", family="public_docs_search", payload=second_query, apply=True)
    assert conn.execute("SELECT COUNT(*) FROM recon_sources").fetchone()[0] == 3
    assert conn.execute("SELECT COUNT(*) FROM recon_sources WHERE source_kind='public_docs_search:hit'").fetchone()[0] == 1
    import_public_exposure(
        conn,
        target_name="T",
        family="public_docs_search",
        payload={**_payload(status="not_run", evidence_refs=[]), "query": "not executed"},
        apply=True,
    )
    assert conn.execute("SELECT status FROM coverage_ledger WHERE item_key='public_exposure:public_docs_search'").fetchone()[0] == "covered"
    assert conn.execute("SELECT COUNT(*) FROM target_assets").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM work_items").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM suspicious_points").fetchone()[0] == 0


@pytest.mark.parametrize(
    ("status", "refs", "expected"),
    [
        ("not_run", [], "unknown"),
        ("anchor_insufficient", [], "unknown"),
        ("searched_empty", ["fixture:1"], "covered"),
        ("searched_empty", [], "unknown"),
        ("captcha", ["fixture:1"], "blocked"),
        ("quota", ["fixture:1"], "blocked"),
        ("extraction_code", ["fixture:1"], "blocked"),
        ("tool_failed", ["fixture:1"], "blocked"),
        ("no_adapter", ["fixture:1"], "uncovered"),
    ],
)
def test_status_mapping_distinguishes_not_run_searched_empty_blocked_and_uncovered(status, refs, expected):
    conn = _db()
    result = import_public_exposure(
        conn,
        target_name="T",
        family="public_share_search",
        payload=_payload(status=status, evidence_refs=refs),
        apply=True,
    )
    assert result["coverage_status"] == expected


def test_coverage_requires_auditable_execution_or_hit_evidence():
    conn = _db()
    assert (
        import_public_exposure(
            conn,
            target_name="T",
            family="public_share_search",
            payload=_payload(status="not_run", evidence_refs=[]),
            apply=True,
        )["coverage_status"]
        == "unknown"
    )
    assert (
        import_public_exposure(
            conn,
            target_name="T",
            family="public_share_search",
            payload=_payload(status="searched_empty", evidence_refs=["fixture:empty"]),
            apply=True,
        )["coverage_status"]
        == "covered"
    )
    assert (
        import_public_exposure(
            conn,
            target_name="T",
            family="public_file_search",
            payload=_payload(status="searched_empty", evidence_refs=[]),
            apply=True,
        )["coverage_status"]
        == "unknown"
    )

    hit = {
        "url": "https://outside.example.net/public",
        "title": "public result",
        "snippet": "compact summary",
        "matched_anchor": "example.com",
        "evidence_refs": ["fixture:hit"],
    }
    assert (
        import_public_exposure(
            conn,
            target_name="T",
            family="public_docs_search",
            payload=_payload(hits=[hit], evidence_refs=[]),
            apply=True,
        )["coverage_status"]
        == "covered"
    )
    with pytest.raises(ValueError, match="hit evidence_refs"):
        import_public_exposure(
            conn,
            target_name="T",
            family="code_search_external",
            payload=_payload(hits=[{**hit, "evidence_refs": []}], evidence_refs=["fixture:execution"]),
            apply=True,
        )


def test_secrets_are_redacted_external_urls_do_not_expand_scope_and_failure_rolls_back():
    conn = _db()
    hit = {
        "url": "https://outside.example.net/share?token=secret-value",
        "title": "password=hunter2",
        "snippet": "Authorization: Bearer abc Cookie: sid=raw 提取码: 1234",
        "matched_anchor": "example.com",
        "evidence_refs": ["fixture:9"],
        "password": "raw-secret",
    }
    import_public_exposure(conn, target_name="T", family="public_share_search", payload=_payload(hits=[hit]), apply=True)
    dumped = " ".join(str(value) for row in conn.execute("SELECT * FROM recon_sources") for value in row)
    assert all(secret not in dumped for secret in ("secret-value", "hunter2", "Bearer abc", "sid=raw", "1234", "raw-secret"))
    assert conn.execute("SELECT COUNT(*) FROM target_assets").fetchone()[0] == 0

    conn.execute(
        """CREATE TRIGGER fail_coverage BEFORE INSERT ON coverage_ledger
           BEGIN SELECT RAISE(ABORT,'fixture failure'); END"""
    )
    with pytest.raises(sqlite3.IntegrityError):
        import_public_exposure(conn, target_name="T", family="public_file_search", payload=_payload(status="searched_empty"), apply=True)
    assert conn.execute("SELECT COUNT(*) FROM recon_sources WHERE source_kind='public_file_search'").fetchone()[0] == 0


def test_cli_missing_db_is_compact_nonzero_and_does_not_create_file(tmp_path):
    missing = tmp_path / "missing.db"
    fixture = tmp_path / "fixture.json"
    fixture.write_text(json.dumps(_payload(status="searched_empty")), encoding="utf-8")
    result = subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(ROOT / "TOOLS" / "recon" / "recon_intel.py"),
            "--target",
            "T",
            "--db",
            str(missing),
            "--import-json",
            str(fixture),
            "--source-kind",
            "public_docs_search",
            "--apply",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1 and json.loads(result.stdout)["ok"] is False and not missing.exists()


def test_apply_locks_before_read_target_isolated_and_cli_1199_defaults_to_sample10(tmp_path):
    conn = _db()
    statements = []
    conn.set_trace_callback(statements.append)
    import_public_exposure(conn, target_name="T", family="public_file_search", payload=_payload(status="searched_empty"), apply=True)
    normalized = [item.strip().upper() for item in statements]
    assert next(i for i, item in enumerate(normalized) if item.startswith("BEGIN IMMEDIATE")) < next(
        i for i, item in enumerate(normalized) if item.startswith("SELECT")
    )
    with pytest.raises(ValueError):
        import_public_exposure(
            conn,
            target_name="OTHER",
            family="public_file_search",
            payload=_payload(status="searched_empty"),
            apply=True,
        )
    assert conn.execute("SELECT COUNT(*) FROM recon_sources WHERE target_name<>'T'").fetchone()[0] == 0

    db_path = tmp_path / "fixture.db"
    disk = sqlite3.connect(db_path)
    disk.executescript(SCHEMA.read_text(encoding="utf-8"))
    disk.execute("INSERT INTO targets(id,target_name,domain) VALUES(1,'T','example.com')")
    disk.commit()
    disk.close()
    fixture = tmp_path / "1199.json"
    hits = [
        {
            "url": f"https://docs.example.net/item/{index}",
            "title": f"item {index}",
            "snippet": "compact",
            "matched_anchor": "example.com",
            "evidence_refs": [f"fixture:{index}"],
        }
        for index in range(1, 1200)
    ]
    fixture.write_text(json.dumps(_payload(hits=hits)), encoding="utf-8")
    result = subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(ROOT / "TOOLS" / "recon" / "recon_intel.py"),
            "--target",
            "T",
            "--db",
            str(db_path),
            "--import-json",
            str(fixture),
            "--source-kind",
            "public_docs_search",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    output = json.loads(result.stdout)
    assert result.returncode == 0 and len(output["sample"]) == 10 and output["omitted"] == 1189
    disk = sqlite3.connect(db_path)
    assert disk.execute("SELECT COUNT(*) FROM recon_sources").fetchone()[0] == 0
    disk.close()


def test_1199_apply_replay_and_overlapping_different_query_are_fully_idempotent():
    conn = _db()
    hits = [
        {
            "url": f"https://docs.example.net/item/{index}",
            "title": f"item {index}",
            "snippet": "compact",
            "matched_anchor": "example.com",
            "evidence_refs": [f"fixture:{index}"],
        }
        for index in range(1, 1200)
    ]
    payload = _payload(hits=hits)
    import_public_exposure(conn, target_name="T", family="public_docs_search", payload=payload, apply=True)
    count = conn.execute("SELECT COUNT(*) FROM recon_sources").fetchone()[0]
    assert count == 1200
    execution = json.loads(conn.execute("SELECT result_json FROM recon_sources WHERE source_kind='public_docs_search'").fetchone()[0])
    assert len(execution["sample"]) == 10 and execution["omitted"] == 1189 and "hits" not in execution
    import_public_exposure(conn, target_name="T", family="public_docs_search", payload=payload, apply=True)
    assert conn.execute("SELECT COUNT(*) FROM recon_sources").fetchone()[0] == count
    overlap = {**payload, "query": 'site:docs.qq.com "example.com"'}
    import_public_exposure(conn, target_name="T", family="public_docs_search", payload=overlap, apply=True)
    assert conn.execute("SELECT COUNT(*) FROM recon_sources").fetchone()[0] == count + 1
    assert conn.execute("SELECT COUNT(*) FROM recon_sources WHERE source_kind='public_docs_search:hit'").fetchone()[0] == 1199


@pytest.mark.parametrize("status", ["searched_empty", "captcha", "no_adapter"])
def test_non_hit_status_rejects_embedded_hits(status):
    conn = _db()
    with pytest.raises(ValueError):
        import_public_exposure(
            conn,
            target_name="T",
            family="public_docs_search",
            payload=_payload(status=status, hits=[{"url": "https://docs.example/x"}]),
            apply=False,
        )


def test_hits_require_query_provider_anchor_and_evidence_and_url_identity_is_deterministic():
    conn = _db()
    base_hit = {
        "url": "https://例子.测试:443/path",
        "title": "doc",
        "snippet": "summary",
        "matched_anchor": "example.com",
        "evidence_refs": ["fixture:1"],
    }
    result = import_public_exposure(conn, target_name="T", family="public_docs_search", payload=_payload(hits=[base_hit]), apply=False)
    assert result["sample"][0]["url"] == "https://xn--fsqu00a.xn--0zwm56d/path"
    for mutation in (
        {"query": ""},
        {"provider": ""},
        {"hits": [{**base_hit, "matched_anchor": ""}]},
        {"evidence_refs": [], "hits": [{**base_hit, "evidence_refs": []}]},
        {"hits": [{**base_hit, "url": "https://docs.example/password=raw"}]},
        {"hits": [{**base_hit, "url": "https://docs.example/x#token=raw"}]},
    ):
        with pytest.raises(ValueError):
            import_public_exposure(
                conn,
                target_name="T",
                family="public_docs_search",
                payload={**_payload(hits=[base_hit]), **mutation},
                apply=False,
            )


def test_same_url_in_different_families_remains_independent():
    conn = _db()
    hit = {
        "url": "https://docs.example.net/public",
        "title": "doc",
        "snippet": "summary",
        "matched_anchor": "example.com",
        "evidence_refs": ["fixture:1"],
    }
    for family in ("public_docs_search", "public_file_search"):
        import_public_exposure(conn, target_name="T", family=family, payload=_payload(hits=[hit]), apply=True)
    assert conn.execute("SELECT COUNT(*) FROM recon_sources WHERE source_kind LIKE '%:hit'").fetchone()[0] == 2


def test_external_counts_are_ignored_and_recomputed_from_normalized_hits():
    conn = _db()
    hit = {
        "url": "https://docs.example.net/public",
        "title": "doc",
        "snippet": "summary",
        "matched_anchor": "example.com",
        "evidence_refs": ["fixture:1"],
    }
    payload = {**_payload(hits=[hit, hit]), "result_count": -99, "dedup_count": "999999999999999"}
    result = import_public_exposure(conn, target_name="T", family="public_docs_search", payload=payload, apply=False)
    assert result["result_count"] == 2 and result["dedup_count"] == 1
