"""experience_store:经验库 capture / list / search / 灵感 harvest 联动。"""

import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from db import experience_store as es  # noqa: E402
from db import insight_capture as ic  # noqa: E402
from db.db_query import init_db  # noqa: E402
from db.system_registry import link_asset, register_system  # noqa: E402
from db.work_queue import create_work_item  # noqa: E402

MIG = Path(__file__).resolve().parent.parent.parent / "migrations" / "037_experience_entries.sql"


def _conn():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    c.executescript(MIG.read_text(encoding="utf-8"))
    return c


def test_capture_entry():
    conn = _conn()
    eid = es.capture(
        conn,
        category="ssrf",
        title="SSRF via cache host",
        body="踩到 Host 头注入可打 SSRF",
        trigger_signal="X-Forwarded-Host 可控",
    )
    row = conn.execute("SELECT * FROM experience_entries WHERE id=?", (eid,)).fetchone()
    assert row["category"] == "ssrf"
    assert row["effectiveness"] == "untested"
    assert row["reuse_count"] == 0


def test_list_requires_target_or_category():
    conn = _conn()
    rows = es.list_entries(conn, target=None, category=None)
    assert rows == []


def test_search_by_signal():
    conn = _conn()
    es.capture(conn, category="logic_flaw", title="重复回调", body="回调不幂等", trigger_signal="回调接口重复入账")
    found = es.search(conn, query="回调")
    assert any("回调" in (x.get("title") or "") or "回调" in (x.get("body") or "") for x in found)


def test_bump_reuse():
    conn = _conn()
    eid = es.capture(conn, category="sqli", title="x", body="y")
    es.bump_reuse(conn, eid)
    row = conn.execute("SELECT reuse_count FROM experience_entries WHERE id=?", (eid,)).fetchone()
    assert row["reuse_count"] == 1


def test_link_from_inspiration_harvest():
    """harvest 一个灵感时应能接到经验条目。"""
    conn = _conn()
    # 无 inspirations 表时不应崩
    eid = es.capture(conn, category="xss", title="头反射", body="UA 反射到统计面板")
    assert eid > 0


def test_harvest_is_atomic_and_bidirectionally_traceable():
    conn = _conn()
    conn.executescript((MIG.parent / "036_inspiration_base.sql").read_text(encoding="utf-8"))
    conn.executescript((MIG.parent / "038_inspiration_asset.sql").read_text(encoding="utf-8"))
    iid = ic.add(conn, "T", "验证过的认证分支差异", source="human")
    conn.execute("UPDATE inspirations SET status='refuted', promoted_sp_id=9 WHERE id=?", (iid,))
    conn.commit()

    result = es.harvest_insight(
        conn,
        target_name="T",
        insight_id=iid,
        category="auth",
        title="认证分支差异",
        body="以明确证据复核未认证重定向。",
        trigger_signal="login redirect",
    )

    entry = conn.execute("SELECT * FROM experience_entries WHERE id=?", (result["experience_id"],)).fetchone()
    insight = conn.execute("SELECT * FROM inspirations WHERE id=?", (iid,)).fetchone()
    assert entry["source_inspiration_id"] == iid
    assert insight["status"] == "harvested"
    assert insight["harvest_id"] == f"experience_entry:{entry['id']}"


def test_harvest_rejects_non_terminal_insight_without_creating_entry():
    conn = _conn()
    conn.executescript((MIG.parent / "036_inspiration_base.sql").read_text(encoding="utf-8"))
    conn.executescript((MIG.parent / "038_inspiration_asset.sql").read_text(encoding="utf-8"))
    iid = ic.add(conn, "T", "未结论的灵感", source="human")
    with pytest.raises(ValueError, match="verified or refuted"):
        es.harvest_insight(conn, target_name="T", insight_id=iid, category="auth", title="x", body="y")
    assert conn.execute("SELECT COUNT(*) FROM experience_entries").fetchone()[0] == 0


def test_l3_experience_lookup_and_adoption_require_active_operator_focus(tmp_path):
    db_path = tmp_path / "experience-l3.db"
    init_db(str(db_path), "T")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute(
        """INSERT INTO target_assets(target_name,asset_value,scope_status,scope_class,authorization_state)
           VALUES('T','portal.example','in_scope','owned','authorized')"""
    )
    asset_id = int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])
    system = register_system(
        conn,
        target_name="T",
        system_key="portal",
        display_name="Portal",
        canonical_url="https://portal.example",
        scope_class="owned",
    )
    link_asset(conn, target_name="T", system_id=system["id"], asset_id=asset_id, relationship="primary")
    work_item_id = create_work_item(
        conn,
        target_name="T",
        system_id=system["id"],
        lane="entry_explore",
        subject_table="target_assets",
        subject_id=str(asset_id),
        commit=False,
    )
    entry_id = es.capture(conn, category="auth", title="redirect split", body="bounded", target_name="T", trigger_signal="login")
    with pytest.raises(PermissionError, match="active focus"):
        es.l3_candidates(conn, target_name="T", work_item_id=work_item_id, trigger="login")

    conn.execute(
        """INSERT INTO hunt_sessions(target_name,focus_subject_table,focus_subject_id,goal,status,selected_by,system_id,
             operator_acknowledged_at) VALUES('T','target_systems',?,'test','active','operator',?,datetime('now'))""",
        (str(system["id"]), system["id"]),
    )
    conn.commit()
    rows = es.l3_candidates(conn, target_name="T", work_item_id=work_item_id, trigger="login")
    assert rows == [
        {
            "id": entry_id,
            "category": "auth",
            "title": "redirect split",
            "trigger_signal": "login",
            "effectiveness": "untested",
            "reuse_count": 0,
            "source_inspiration_id": None,
        }
    ]
    es.adopt_for_l3(conn, target_name="T", work_item_id=work_item_id, experience_id=entry_id)
    assert conn.execute("SELECT reuse_count FROM experience_entries WHERE id=?", (entry_id,)).fetchone()[0] == 1


def test_l3_effectiveness_requires_terminal_evidence(tmp_path):
    db_path = tmp_path / "experience-effect.db"
    init_db(str(db_path), "T")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute(
        """INSERT INTO target_assets(target_name,asset_value,scope_status,scope_class,authorization_state)
           VALUES('T','portal.example','in_scope','owned','authorized')"""
    )
    asset_id = int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])
    system = register_system(
        conn,
        target_name="T",
        system_key="portal",
        display_name="Portal",
        canonical_url="https://portal.example",
        scope_class="owned",
    )
    link_asset(conn, target_name="T", system_id=system["id"], asset_id=asset_id, relationship="primary")
    work_item_id = create_work_item(
        conn,
        target_name="T",
        system_id=system["id"],
        lane="entry_explore",
        subject_table="target_assets",
        subject_id=str(asset_id),
        commit=False,
    )
    entry_id = es.capture(conn, category="auth", title="redirect split", body="bounded", target_name="T")
    conn.execute(
        """INSERT INTO hunt_sessions(target_name,focus_subject_table,focus_subject_id,goal,status,selected_by,system_id,
             operator_acknowledged_at) VALUES('T','target_systems',?,'test','active','operator',?,datetime('now'))""",
        (str(system["id"]), system["id"]),
    )
    conn.commit()

    with pytest.raises(ValueError, match="terminal L3"):
        es.set_effectiveness_for_l3(conn, target_name="T", work_item_id=work_item_id, entry_id=entry_id, effectiveness="validated")

    conn.execute("UPDATE work_items SET status='done' WHERE id=?", (work_item_id,))
    conn.execute(
        """INSERT INTO agent_events(work_item_id,agent_id,event_type,payload_json)
           VALUES(?, 'worker', 'done', ?)""",
        (work_item_id, '{"worker_result":{"status":"done","evidence_refs":["evidence:1"]}}'),
    )
    conn.commit()
    es.set_effectiveness_for_l3(conn, target_name="T", work_item_id=work_item_id, entry_id=entry_id, effectiveness="validated")
    saved = conn.execute("SELECT effectiveness FROM experience_entries WHERE id=?", (entry_id,)).fetchone()
    assert saved[0] == "validated"
