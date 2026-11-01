from __future__ import annotations

import sqlite3

from db.coverage_guard import find_negative_coverage, sp_keywords


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        CREATE TABLE coverage_ledger (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_name TEXT NOT NULL,
            profile_id INTEGER,
            work_item_id INTEGER,
            item_key TEXT NOT NULL,
            category TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'unknown',
            confidence TEXT DEFAULT 'unknown',
            evidence_refs_json TEXT NOT NULL DEFAULT '[]',
            summary TEXT,
            blocker_reason TEXT,
            next_action TEXT,
            created_at TEXT DEFAULT (datetime('now','localtime')),
            updated_at TEXT DEFAULT (datetime('now','localtime')),
            UNIQUE(target_name, profile_id, item_key)
        );
        CREATE TABLE suspicious_points (
            id TEXT PRIMARY KEY, url TEXT, param TEXT, method TEXT, test_type TEXT,
            evidence TEXT, reasoning TEXT, signal_reason TEXT, noise_reason TEXT,
            test_status TEXT DEFAULT 'untested'
        );
        """
    )
    return conn


def _seed_coverage(conn: sqlite3.Connection, *, key: str, status: str, summary: str = ""):
    conn.execute(
        """INSERT INTO coverage_ledger(target_name,item_key,category,status,summary,evidence_refs_json)
           VALUES ('demo', ?, 'generic_probe', ?, ?, '[]')""",
        (key, status, summary),
    )
    conn.commit()


def test_sp_keywords_extracts_compact_terms():
    words = sp_keywords(test_type="fastjson:rce", signal_reason="preauth_plaintext_body", reasoning="@type key")
    assert "fastjson" in words
    assert "rce" in words
    assert "preauth" in words  # 下划线是分隔符；子串匹配仍命中 preauth_plaintext_body
    assert "@type" in words


def test_find_negative_coverage_matches_by_keyword_and_status():
    conn = _conn()
    _seed_coverage(
        conn,
        key="generic_probe:fastjson_deserialization",
        status="covered",
        summary="FastJSON 反序列化 RCE 全版本验证为不可利用：@type key 被全局递归过滤(HTTP 400)",
    )
    _seed_coverage(conn, key="generic_probe:sqli_id", status="uncovered", summary="SQLi id 参数观察到未防护边界")

    # covered 命中 → 抑制
    hits = find_negative_coverage(conn, target_name="demo", keywords=["fastjson", "rce", "@type"])
    assert len(hits) == 1
    assert hits[0]["item_key"] == "generic_probe:fastjson_deserialization"
    assert hits[0]["status"] == "covered"

    # uncovered 不抑制（是正信号）
    hits = find_negative_coverage(conn, target_name="demo", keywords=["sqli", "id"])
    assert hits == []

    # 无关关键词不命中
    hits = find_negative_coverage(conn, target_name="demo", keywords=["ssrf"])
    assert hits == []


def test_find_negative_coverage_blocks_when_blocked():
    conn = _conn()
    _seed_coverage(conn, key="entry:recursive_js_expansion", status="blocked", summary="无登录态无法继续")
    hits = find_negative_coverage(conn, target_name="demo", keywords=["recursive", "js", "expansion"])
    assert len(hits) == 1
    assert hits[0]["status"] == "blocked"


def test_find_negative_coverage_returns_empty_without_table():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    assert find_negative_coverage(conn, target_name="demo", keywords=["fastjson"]) == []
