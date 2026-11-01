from __future__ import annotations

import json
import socket
import sqlite3

import pytest
from db.db_admin import init_target_db
from recon.cdn_detect import (
    classify_cdn_observation,
    ingest_passive_origin_candidates,
)


def _conn(tmp_path):
    result = init_target_db(target_name="Demo", slug="demo", domain="demo.test", db_dir=tmp_path)
    conn = sqlite3.connect(result["db_path"])
    conn.row_factory = sqlite3.Row
    asset_id = conn.execute("SELECT id FROM target_assets WHERE target_name='Demo'").fetchone()[0]
    return conn, asset_id


@pytest.mark.parametrize(
    ("observation", "classification", "provider"),
    [
        ({"dns": {"cname": "demo.cloudflare.net"}}, "cdn", "cloudflare"),
        ({"dns": {"cname": "origin.demo.test"}, "tls": {"issuer": "Let's Encrypt"}}, "non_cdn", None),
        ({"dns": {"answers": ["203.0.113.10"]}}, "unknown", None),
    ],
)
def test_classify_cdn_observation_is_static_and_deterministic(observation, classification, provider):
    result = classify_cdn_observation(observation)
    assert result["classification"] == classification
    assert result["provider"] == provider


def test_ingest_aggregates_passive_evidence_into_review_only_candidate(tmp_path):
    conn, asset_id = _conn(tmp_path)
    observations = [
        {
            "asset_id": asset_id,
            "hostname": "demo.test",
            "dns": {"cname": "demo.cloudflare.net"},
            "origin_ips": ["8.8.8.8"],
            "evidence_refs": ["pdns:historic-a"],
        },
        {
            "asset_id": asset_id,
            "hostname": "demo.test",
            "tls": {"issuer": "Cloudflare Inc ECC CA-3"},
            "origin_ips": ["8.8.8.8"],
            "evidence_refs": ["ct:cert-a"],
        },
    ]

    result = ingest_passive_origin_candidates(conn, target_name="Demo", observations=observations)

    assert result == {"observations": 2, "cdn_detected": 2, "candidates": 1, "blocked": 0}
    row = conn.execute("SELECT * FROM origin_candidates").fetchone()
    assert row["candidate_ip"] == "8.8.8.8"
    assert row["verification_status"] == "candidate_ready_for_review"
    assert row["confidence"] == "medium"
    assert json.loads(row["evidence_refs_json"]) == ["ct:cert-a", "pdns:historic-a"]
    assert "cdn:cloudflare" in row["notes"]
    cdn_row = conn.execute("SELECT classification,provider FROM cdn_observations").fetchone()
    assert tuple(cdn_row) == ("cdn", "cloudflare")
    assert conn.execute("SELECT scope_status FROM target_assets WHERE id=?", (asset_id,)).fetchone()[0] == "in_scope"


def test_single_passive_evidence_stays_insufficient_and_non_ready(tmp_path):
    conn, asset_id = _conn(tmp_path)
    result = ingest_passive_origin_candidates(
        conn,
        target_name="Demo",
        observations=[
            {
                "asset_id": asset_id,
                "hostname": "demo.test",
                "dns": {"cname": "demo.cloudflare.net"},
                "origin_ips": ["8.8.8.8"],
                "evidence_refs": ["pdns:historic-a"],
            }
        ],
    )
    assert result["candidates"] == 1
    row = conn.execute("SELECT verification_status,confidence,notes FROM origin_candidates").fetchone()
    assert tuple(row) == (
        "evidence_insufficient",
        "low",
        "passive_only;cdn:cloudflare;needs a second independent evidence reference",
    )


def test_ingest_fails_closed_for_cross_target_or_out_of_scope_asset(tmp_path):
    conn, asset_id = _conn(tmp_path)
    conn.execute("UPDATE target_assets SET target_name='Other' WHERE id=?", (asset_id,))
    conn.commit()
    result = ingest_passive_origin_candidates(
        conn,
        target_name="Demo",
        observations=[
            {
                "asset_id": asset_id,
                "hostname": "demo.test",
                "dns": {"cname": "demo.cloudflare.net"},
                "origin_ips": ["8.8.8.8"],
                "evidence_refs": ["pdns:historic-a"],
            }
        ],
    )
    assert result["blocked"] == 1
    assert conn.execute("SELECT COUNT(*) FROM origin_candidates").fetchone()[0] == 0

    conn.execute("UPDATE target_assets SET target_name='Demo', scope_status='needs_review' WHERE id=?", (asset_id,))
    conn.commit()
    result = ingest_passive_origin_candidates(
        conn,
        target_name="Demo",
        observations=[
            {
                "asset_id": asset_id,
                "hostname": "demo.test",
                "dns": {"cname": "demo.cloudflare.net"},
                "origin_ips": ["8.8.8.8"],
            }
        ],
    )
    assert result["blocked"] == 1
    assert conn.execute("SELECT COUNT(*) FROM origin_candidates").fetchone()[0] == 0


def test_classification_and_intake_do_not_resolve_or_connect(tmp_path, monkeypatch):
    conn, asset_id = _conn(tmp_path)
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: pytest.fail("DNS must not run"))

    result = ingest_passive_origin_candidates(
        conn,
        target_name="Demo",
        observations=[
            {
                "asset_id": asset_id,
                "hostname": "demo.test",
                "dns": {"cname": "demo.cloudflare.net"},
                "origin_ips": ["8.8.8.8"],
                "evidence_refs": ["pdns:historic-a"],
            }
        ],
    )

    assert result["candidates"] == 1
