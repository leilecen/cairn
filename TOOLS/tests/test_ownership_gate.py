from __future__ import annotations

import json
import sqlite3

from recon.ownership_gate import (
    AFFILIATED,
    DIRECT,
    UNRELATED,
    UNVERIFIED,
    classify_asset,
    gate_fofa_payload,
    load_corporate_chain,
    recheck_needs_review,
)
from recon.recon_store import record_source


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        CREATE TABLE target_assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_name TEXT NOT NULL,
            asset_type TEXT DEFAULT 'domain',
            asset_value TEXT NOT NULL,
            port INTEGER,
            protocol TEXT DEFAULT 'https',
            source TEXT DEFAULT 'manual',
            status TEXT DEFAULT 'new',
            scope_status TEXT DEFAULT 'needs_review',
            scope_reason TEXT,
            scope_class TEXT DEFAULT 'unknown',
            authorization_state TEXT DEFAULT 'unknown',
            relation_to_target TEXT
        );
        CREATE UNIQUE INDEX idx_target_assets_identity
            ON target_assets(target_name, asset_value, COALESCE(port, 443));
        """
    )
    return conn


CHAIN = {
    "company": "example-client",
    "relations": [
        {"name": "example-client后勤服务有限公司", "relation_type": "subsidiary"},
        {"name": "浙江example-client教育发展基金会", "relation_type": "related"},
    ],
    "names": {
        "example-client后勤服务": "subsidiary",
        "浙江example-client教育发展基金会": "related",
    },
}


def test_classify_asset_direct_root_domain_match():
    kind, basis = classify_asset(host="www.example-client", domain="example-client", root_domains=["example-client"])
    assert kind == DIRECT
    assert basis == "root_domain"


def test_classify_asset_ip_under_root_domain():
    kind, _ = classify_asset(host="mail.example-client", root_domains=["example-client"], chain_names={})
    assert kind == DIRECT


def test_classify_asset_equity_affiliated_via_title():
    kind, basis = classify_asset(
        host="hq.tzc-service.com",
        title="example-client后勤服务有限公司官网",
        root_domains=["example-client"],
        chain_names=CHAIN["names"],
    )
    assert kind == AFFILIATED
    assert "equity" in basis


def test_classify_asset_unrelated_company_signal():
    kind, _ = classify_asset(
        host="login.other-bank.com",
        title="某某银行股份有限公司",
        root_domains=["example-client"],
        chain_names=CHAIN["names"],
    )
    assert kind == UNRELATED


def test_classify_asset_unverified_no_signal():
    kind, basis = classify_asset(host="cdn.edge-cache.net", root_domains=["example-client"], chain_names=CHAIN["names"])
    assert kind == UNVERIFIED
    assert basis == "no_signal"


def test_load_corporate_chain_from_recon_sources():
    conn = _conn()
    record_source(
        conn,
        target_name="demo",
        source_kind="tianyan_equity-tree",
        query="example-client",
        result={
            "status": "observed",
            "result": {"data": [{"name": "example-client后勤服务有限公司", "equityRatio": "100%"}]},
        },
    )
    chain = load_corporate_chain(conn, target_name="demo", company="example-client")
    assert "example-client后勤服务" in chain["names"]
    assert chain["relations"][0]["name"] == "example-client后勤服务有限公司"


def _fofa_payload():
    return {
        "query": 'domain="example-client"',
        "results": [
            {
                "host": "www.example-client",
                "ip": "1.1.1.1",
                "port": "443",
                "title": "example-client",
                "domain": "example-client",
            },
            {
                "host": "hq.example-client",
                "ip": "1.1.1.2",
                "port": "443",
                "title": "example-client后勤服务有限公司",
                "domain": "example-client",
            },
            {
                "host": "hq.tzc-service.com",
                "ip": "1.1.1.3",
                "port": "443",
                "title": "example-client后勤服务有限公司",
                "domain": "",
            },
            {
                "host": "login.other-bank.com",
                "ip": "2.2.2.2",
                "port": "443",
                "title": "某某银行股份有限公司",
                "domain": "",
            },
            {"host": "cdn.edge-cache.net", "ip": "3.3.3.3", "port": "443", "title": "", "domain": ""},
        ],
    }


def test_gate_fofa_payload_classifies_scope_and_never_queues():
    conn = _conn()
    result = gate_fofa_payload(
        conn,
        target_name="demo",
        payload=_fofa_payload(),
        root_domains=["example-client"],
        chain=CHAIN,
    )
    rows = {r["asset_value"]: r for r in conn.execute("SELECT * FROM target_assets WHERE target_name='demo' ORDER BY id").fetchall()}
    assert result["classified"] == {DIRECT: 2, AFFILIATED: 1, UNRELATED: 1, UNVERIFIED: 1}
    assert rows["www.example-client"]["scope_status"] == "in_scope"
    assert rows["www.example-client"]["scope_class"] == "owned"
    assert rows["www.example-client"]["authorization_state"] == "authorized"
    # 股权链关联但非根域 → needs_review，操作员 scope_cluster 确认
    assert rows["hq.tzc-service.com"]["scope_status"] == "needs_review"
    assert rows["hq.tzc-service.com"]["relation_to_target"] == "equity_affiliate"
    assert rows["login.other-bank.com"]["scope_status"] == "out_of_scope"
    assert rows["login.other-bank.com"]["scope_class"] == "intel_only"
    assert rows["login.other-bank.com"]["authorization_state"] == "revoked"
    # 无归属信号 → needs_review/intel_only，绝不 in_scope
    assert rows["cdn.edge-cache.net"]["scope_status"] == "needs_review"
    assert rows["cdn.edge-cache.net"]["scope_class"] == "intel_only"
    assert all(r["status"] != "queued" for r in rows.values())


def test_gate_fofa_payload_is_idempotent():
    conn = _conn()
    gate_fofa_payload(conn, target_name="demo", payload=_fofa_payload(), root_domains=["example-client"], chain=CHAIN)
    gate_fofa_payload(conn, target_name="demo", payload=_fofa_payload(), root_domains=["example-client"], chain=CHAIN)
    count = conn.execute("SELECT COUNT(*) FROM target_assets WHERE target_name='demo'").fetchone()[0]
    assert count == 5


def test_gate_fofa_falls_back_to_root_match_without_chain():
    conn = _conn()
    gate_fofa_payload(conn, target_name="demo", payload=_fofa_payload(), root_domains=["example-client"], chain={"names": {}})
    rows = {r["asset_value"]: r["scope_status"] for r in conn.execute("SELECT asset_value, scope_status FROM target_assets").fetchall()}
    assert rows["www.example-client"] == "in_scope"
    # 无股权链时：强公司信号落 out_of_scope（保留事实禁扫描），无信号落 needs_review
    assert rows["login.other-bank.com"] == "out_of_scope"
    assert rows["cdn.edge-cache.net"] == "needs_review"


def test_recheck_downgrades_unrelated_needs_review_assets():
    conn = _conn()
    conn.execute(
        """INSERT INTO target_assets
           (target_name, asset_value, scope_status, scope_class, authorization_state, relation_to_target)
           VALUES ('demo','cdn.edge-cache.net','needs_review','unknown','unknown','unverified'),
                  ('demo','www.example-client','needs_review','unknown','unknown','unverified'),
                  ('demo','login.other-bank.com','needs_review','unknown','unknown','unverified')"""
    )
    conn.commit()
    result = recheck_needs_review(conn, target_name="demo", root_domains=["example-client"], chain=CHAIN)
    states = {
        r["asset_value"]: (r["scope_status"], r["relation_to_target"])
        for r in conn.execute("SELECT asset_value, scope_status, relation_to_target FROM target_assets").fetchall()
    }
    assert states["www.example-client"] == ("in_scope", "root_domain")
    assert states["login.other-bank.com"] == ("out_of_scope", "unrelated")
    # 无信号资产保持 needs_review 待人工判定
    assert states["cdn.edge-cache.net"] == ("needs_review", "unverified")
    assert result["changed"] == 2


def test_chain_name_key_strips_company_suffix():
    from recon.ownership_gate import _chain_name_key

    assert _chain_name_key("example-client后勤服务有限公司") == "example-client后勤服务"
    assert _chain_name_key("浙江example-client教育发展基金会（普通合伙）") == "浙江example-client教育发展基金会"


def test_json_fixture_integrity():
    assert json.dumps(CHAIN, ensure_ascii=False)
