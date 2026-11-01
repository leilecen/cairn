from __future__ import annotations

import sqlite3

import pytest
from db.burp_action_queue import mark_burp_action_sent, prepare_burp_action


def test_burp_requires_card_and_sent_is_idempotent():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    c.executescript(
        """CREATE TABLE operator_inbox(id INTEGER PRIMARY KEY,target_name TEXT,status TEXT,kind TEXT,burp_action_id INTEGER); CREATE TABLE burp_actions(id INTEGER PRIMARY KEY AUTOINCREMENT,target_name TEXT,work_item_id INTEGER,action_type TEXT,method TEXT,url TEXT,headers_json TEXT,body TEXT,note TEXT,risk_class TEXT,repeater_tab_name TEXT,burp_request_ref TEXT,status TEXT DEFAULT 'queued',error TEXT,sent_at TEXT); CREATE TABLE evidence_refs(id INTEGER PRIMARY KEY AUTOINCREMENT,target_name TEXT,source_table TEXT,source_id TEXT,evidence_type TEXT,title TEXT,summary TEXT,ref_json TEXT,created_at TEXT);"""
    )
    with pytest.raises(PermissionError):
        prepare_burp_action(c, card_id=1, target_name="T", work_item_id=1)
    c.execute("INSERT INTO operator_inbox VALUES(1,'T','open','burp_action_required',NULL)")
    aid = prepare_burp_action(c, card_id=1, target_name="T", work_item_id=1, url="https://example.com")
    first = mark_burp_action_sent(c, action_id=aid)
    second = mark_burp_action_sent(c, action_id=aid)
    assert first == second and c.execute("SELECT burp_action_id FROM operator_inbox WHERE id=1").fetchone()[0] == aid
