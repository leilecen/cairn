from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from db.identity_classification import classify_identity, vendor_family_view

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "TOOLS" / "db" / "schema.sql"


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA.read_text(encoding="utf-8"))
    conn.execute("INSERT INTO targets(target_name,domain) VALUES('T','app.example.test')")
    return conn


def test_identity_conflict_stays_open_until_two_independent_af_signals():
    conflict = classify_identity(
        [
            {"kind": "page_title", "vendor": "Synology", "product": "DSM", "evidence_ref": "ev:title"},
            {"kind": "login_js", "vendor": "Sangfor", "product": "AF", "evidence_ref": "ev:js"},
        ]
    )
    assert conflict["identity_status"] == "conflicted"
    assert conflict["contradictions"]
    assert conflict["next_discriminator"]

    corroborated = classify_identity(
        [
            {"kind": "login_js", "vendor": "Sangfor", "product": "AF", "evidence_ref": "ev:js"},
            {"kind": "public_index", "vendor": "Sangfor", "product": "AF", "evidence_ref": "ev:index"},
        ]
    )
    assert corroborated["identity_status"] == "corroborated"
    assert corroborated["product_candidates"][0]["name"] == "AF"
    assert corroborated["product_candidates"][0]["evidence_kinds"] == ["login_js", "public_index"]


def test_same_vendor_different_products_is_compact_and_never_grants_scope():
    conn = _conn()
    conn.executemany(
        """INSERT INTO technology_observations(
               target_name,host,technology,category,confidence,source,evidence_refs_json
           ) VALUES('T',?,?,?,?,?,?)""",
        [
            ("af.example.test", "Sangfor AF", "product", "high", "login_js", '["ev:af"]'),
            ("vpn.example.test", "Sangfor aTrust", "product", "medium", "archive", '["ev:vpn"]'),
        ],
    )
    view = vendor_family_view(conn, target_name="T")
    assert view == [
        {
            "vendor": "Sangfor",
            "products": ["AF", "aTrust"],
            "hosts": ["af.example.test", "vpn.example.test"],
            "evidence_refs": ["ev:af", "ev:vpn"],
            "scope_effect": "none",
        }
    ]
    assert len(str(view)) < 1199


def test_two_page_level_labels_are_one_evidence_class_and_credentials_are_rejected():
    result = classify_identity(
        [
            {"kind": "page_title", "vendor": "Sangfor", "product": "AF", "evidence_ref": "ev:title"},
            {"kind": "favicon", "vendor": "Sangfor", "product": "AF", "evidence_ref": "ev:favicon"},
        ]
    )
    assert result["identity_status"] == "candidate"
    assert result["product_candidates"][0]["evidence_kinds"] == ["page"]

    with pytest.raises(ValueError, match="raw HTTP or credential"):
        classify_identity(
            [
                {
                    "kind": "login_js",
                    "vendor": "Sangfor",
                    "product": "AF",
                    "evidence_ref": "ev:bad",
                    "Authorization": "Bearer forbidden",
                }
            ]
        )


def test_corroboration_requires_distinct_valid_refs_not_one_ref_with_two_kinds():
    disguised_duplicate = classify_identity(
        [
            {"kind": "page_title", "vendor": "Sangfor", "product": "AF", "evidence_ref": "ev:same"},
            {"kind": "login_js", "vendor": "Sangfor", "product": "AF", "evidence_ref": "ev:same"},
        ]
    )
    assert disguised_duplicate["identity_status"] == "candidate"

    with pytest.raises(ValueError, match="raw HTTP|evidence ref"):
        classify_identity([{"kind": "login_js", "vendor": "Sangfor", "product": "AF", "evidence_ref": "GET / HTTP/1.1"}])


def test_a_single_conflicting_product_signal_keeps_a_strong_identity_open():
    result = classify_identity(
        [
            {"kind": "login_js", "vendor": "Sangfor", "product": "AF", "evidence_ref": "ev:js"},
            {"kind": "public_index", "vendor": "Sangfor", "product": "AF", "evidence_ref": "ev:index"},
            {"kind": "page_title", "vendor": "Synology", "product": "DSM", "evidence_ref": "ev:title"},
        ]
    )
    assert result["identity_status"] == "conflicted"
