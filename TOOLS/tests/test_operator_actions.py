from __future__ import annotations

import sqlite3

import pytest
from db.operator_actions import complete_action_card, create_action_card


def test_action_card_is_idempotent_and_complete_requires_compact_report():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    c.executescript(
        """CREATE TABLE operator_inbox(id INTEGER PRIMARY KEY AUTOINCREMENT,target_name TEXT,related_work_item_id INTEGER,kind TEXT,title TEXT,detail TEXT,suggested_action TEXT,url TEXT,burp_action_id INTEGER,evidence_ref_id INTEGER,status TEXT,created_at TEXT,system_id INTEGER,action_key TEXT,action_label TEXT,why_needed TEXT,steps_json TEXT,expected_observation TEXT,report_back_format TEXT,blocking INTEGER);"""
    )
    kwargs = dict(
        target_name="T",
        system_id=1,
        kind="evidence_capture",
        action_key="shot-1",
        action_label="补充截图",
        why_needed="缺少证据",
        steps=["打开页面", "截图"],
        expected_observation="一张图",
        report_back_format="回复完成",
        url="https://example.com",
    )
    first = create_action_card(c, **kwargs)
    second = create_action_card(c, **kwargs)
    assert first["id"] == second["id"]
    with pytest.raises(ValueError):
        complete_action_card(c, card_id=first["id"], report="")
    assert complete_action_card(c, card_id=first["id"], report="已完成")["status"] == "done"
