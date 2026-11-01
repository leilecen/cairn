"""insight_capture 写入口:6 状态流转 + 追溯 + 校验。"""

import json
import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from db import insight_capture as ic  # noqa: E402
from db.db_query import init_db  # noqa: E402
from db.system_registry import link_asset, register_system  # noqa: E402
from db.work_queue import create_work_item  # noqa: E402

VALID_STATUS = {"open", "queued", "verified", "refuted", "harvested", "discarded"}


def _conn():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    base = Path(__file__).resolve().parent.parent.parent / "migrations"
    c.executescript((base / "036_inspiration_base.sql").read_text(encoding="utf-8"))
    # 038 补 asset_id(资产灵感归类所需列)
    c.executescript((base / "038_inspiration_asset.sql").read_text(encoding="utf-8"))
    return c


def test_gleam_inserts(monkeypatch):
    conn = _conn()
    monkeypatch.setattr(ic, "_get_conn", lambda t: conn)
    ic.capture_gleam(conn, "t", "灵光一句", source="agent", trigger="看到 OSS 桶")
    row = conn.execute("SELECT * FROM inspirations").fetchone()
    assert row["stage"] == "gleam"
    assert row["source"] == "agent"
    assert row["status"] == "open"


def test_refine_sets_refined_from_id_and_stage(monkeypatch):
    conn = _conn()
    monkeypatch.setattr(ic, "_get_conn", lambda t: conn)
    gid = ic.capture_gleam(conn, "t", "灵光", source="human")
    cid = ic.refine(conn, "t", gid, "可验证线索: 用 subfinder 找系统名")
    row = conn.execute("SELECT * FROM inspirations WHERE id=?", (cid,)).fetchone()
    assert row["stage"] == "clue"
    assert row["refined_from_id"] == gid


def test_transit_verified_requires_accepted_validation_outcome(monkeypatch):
    conn = _conn()
    monkeypatch.setattr(ic, "_get_conn", lambda t: conn)
    iid = ic.capture_gleam(conn, "t", "灵光", source="human")
    with pytest.raises(ValueError, match="accepted validation"):
        ic.transit(conn, "t", iid, "verified", sp_id=7)


def test_transit_invalid_status_raises(monkeypatch):
    conn = _conn()
    monkeypatch.setattr(ic, "_get_conn", lambda t: conn)
    iid = ic.capture_gleam(conn, "t", "灵光", source="human")
    with pytest.raises(ValueError):
        ic.transit(conn, "t", iid, "converting")


def test_blocked_on_text_sp_id_preserved(monkeypatch):
    """文本 id 的 suspicious_point(sp-xxx)必须能精确挂载(回归:曾因 int() 强转丢失)。"""
    conn = _conn()
    monkeypatch.setattr(ic, "_get_conn", lambda t: conn)
    iid = ic.capture_gleam(conn, "t", "灵感", source="human", blocked_on="suspicious_point:sp-ssrf-001")
    row = conn.execute("SELECT * FROM inspirations WHERE id=?", (iid,)).fetchone()
    assert row["blocked_on_kind"] == "suspicious_point"
    assert row["blocked_on_id"] == "sp-ssrf-001"


def test_blocked_on_int_work_item_preserved(monkeypatch):
    """整数 id 的 work_item 挂载仍正常(整数亲和列存回整数)。"""
    conn = _conn()
    monkeypatch.setattr(ic, "_get_conn", lambda t: conn)
    iid = ic.capture_gleam(conn, "t", "灵感", source="human", blocked_on="work_item:123")
    row = conn.execute("SELECT * FROM inspirations WHERE id=?", (iid,)).fetchone()
    assert row["blocked_on_kind"] == "work_item"
    assert row["blocked_on_id"] == 123


def test_parse_blocked_on_text_id():
    kind, bid = ic._parse_blocked_on("suspicious_point:sp-abc")
    assert kind == "suspicious_point"
    assert bid == "sp-abc"


def test_parse_blocked_on_int():
    kind, bid = ic._parse_blocked_on("work_item:7")
    assert kind == "work_item"
    assert bid == "7"


def test_gleam_stores_asset_id(monkeypatch):
    """capture_gleam(..., asset_id=5) 显式落 asset_id。"""
    conn = _conn()
    monkeypatch.setattr(ic, "_get_conn", lambda t: conn)
    iid = ic.capture_gleam(conn, "t", "灵光", source="human", asset_id=5)
    row = conn.execute("SELECT * FROM inspirations WHERE id=?", (iid,)).fetchone()
    assert row["asset_id"] == 5


def test_add_stores_asset_id(monkeypatch):
    """add(..., asset_id=9) 显式落 asset_id。"""
    conn = _conn()
    monkeypatch.setattr(ic, "_get_conn", lambda t: conn)
    iid = ic.add(conn, "t", "线索", source="human", asset_id=9)
    row = conn.execute("SELECT * FROM inspirations WHERE id=?", (iid,)).fetchone()
    assert row["asset_id"] == 9


def _acceptance_fixture(tmp_path):
    db_path = tmp_path / "insight-accept.db"
    init_db(str(db_path), "T")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute(
        """INSERT INTO target_assets(
            target_name,asset_value,scope_class,scope_status,authorization_state,status
        ) VALUES('T','portal.example','owned','in_scope','authorized','validated')"""
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
    conn.execute(
        """INSERT INTO hunt_sessions(
            target_name,focus_subject_table,focus_subject_id,goal,status,selected_by,system_id,
            operator_acknowledged_at,started_at
        ) VALUES('T','target_systems',?,'validate insight','active','operator',?,datetime('now'),datetime('now'))""",
        (str(system["id"]), system["id"]),
    )
    source_wi = create_work_item(
        conn,
        target_name="T",
        system_id=system["id"],
        lane="entry_explore",
        subject_table="target_assets",
        subject_id=str(asset_id),
        title="map portal",
        objective="map portal",
        commit=False,
    )
    conn.execute(
        """INSERT INTO agent_events(work_item_id,agent_id,event_type,severity,payload_json)
           VALUES(?, 'worker-1', 'partial_result', 'info', ?)""",
        (
            source_wi,
            json.dumps(
                {
                    "worker_result": {
                        "insight_proposals": [
                            {
                                "summary": "管理入口的认证分支值得验证",
                                "trigger": "login observed",
                                "asset_id": asset_id,
                                "evidence_refs": ["ev:login"],
                                "next_action": "compare unauthenticated redirect behavior",
                            }
                        ]
                    }
                }
            ),
        ),
    )
    conn.commit()
    return conn, system["id"], asset_id, source_wi


def test_accept_proposal_creates_same_system_queued_insight_and_safe_validation_work_item(tmp_path):
    conn, system_id, asset_id, source_wi = _acceptance_fixture(tmp_path)

    accepted = ic.accept_proposal(conn, "T", source_wi)

    insight = conn.execute("SELECT * FROM inspirations WHERE id=?", (accepted["inspiration_id"],)).fetchone()
    validation = conn.execute("SELECT * FROM work_items WHERE id=?", (accepted["validation_work_item_id"],)).fetchone()
    assert insight["status"] == "queued"
    assert insight["source"] == "agent"
    assert insight["blocked_on_kind"] == "work_item"
    assert insight["blocked_on_id"] == source_wi
    assert insight["asset_id"] == asset_id
    assert insight["promoted_wi_id"] == validation["id"]
    assert validation["system_id"] == system_id
    assert validation["lane"] == "quick_scout"
    assert validation["subtype"] == "insight_validation"
    assert validation["risk_class"] == "safe_passive"


def test_transit_keeps_validation_link_and_requires_terminal_outcome(tmp_path):
    conn, _, _, source_wi = _acceptance_fixture(tmp_path)
    accepted = ic.accept_proposal(conn, "T", source_wi)
    validation_id = accepted["validation_work_item_id"]
    conn.execute("UPDATE work_items SET status='done' WHERE id=?", (validation_id,))
    conn.execute(
        """INSERT INTO agent_events(work_item_id,agent_id,event_type,severity,payload_json)
           VALUES(?, 'worker-2', 'done', 'info', ?)""",
        (validation_id, json.dumps({"worker_result": {"status": "done", "evidence_refs": ["ev:validated"]}})),
    )
    conn.commit()

    ic.transit(conn, "T", accepted["inspiration_id"], "verified", sp_id=7)
    insight = conn.execute("SELECT * FROM inspirations WHERE id=?", (accepted["inspiration_id"],)).fetchone()
    assert insight["status"] == "verified"
    assert insight["promoted_wi_id"] == validation_id
    assert insight["promoted_sp_id"] == 7


@pytest.mark.parametrize("failure", ["no_focus", "cross_system", "out_of_scope", "latest_event_has_no_proposal"])
def test_accept_proposal_rejects_unsafe_or_stale_input_without_writes(tmp_path, failure):
    conn, system_id, asset_id, source_wi = _acceptance_fixture(tmp_path)
    if failure == "no_focus":
        conn.execute("UPDATE hunt_sessions SET status='paused'")
    elif failure == "cross_system":
        conn.execute("UPDATE work_items SET system_id=? WHERE id=?", (system_id + 99, source_wi))
    elif failure == "out_of_scope":
        conn.execute("UPDATE target_assets SET scope_status='needs_review' WHERE id=?", (asset_id,))
    elif failure == "latest_event_has_no_proposal":
        conn.execute(
            """INSERT INTO agent_events(work_item_id,agent_id,event_type,severity,payload_json)
               VALUES(?, 'worker-1', 'heartbeat', 'info', ?)""",
            (source_wi, json.dumps({"worker_result": {"summary": "still working"}})),
        )
    conn.commit()
    before = (
        conn.execute("SELECT COUNT(*) FROM inspirations").fetchone()[0],
        conn.execute("SELECT COUNT(*) FROM work_items").fetchone()[0],
    )

    with pytest.raises((PermissionError, ValueError)):
        ic.accept_proposal(conn, "T", source_wi)

    after = (
        conn.execute("SELECT COUNT(*) FROM inspirations").fetchone()[0],
        conn.execute("SELECT COUNT(*) FROM work_items").fetchone()[0],
    )
    assert after == before
