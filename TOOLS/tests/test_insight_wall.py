"""insight_wall 只读聚合器:6 类堵点 + 堵点→灵感精确挂载 + 向下兼容。"""

# ruff: noqa: E501 -- 测试内联 SQL DDL/INSERT 长串(同 test_focus_control 惯例)
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from db import insight_wall as iw  # noqa: E402


def _conn():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    base = Path(__file__).resolve().parent.parent.parent / "migrations"
    c.executescript((base / "036_inspiration_base.sql").read_text(encoding="utf-8"))
    # 038 补 asset_id(资产灵感归类所需列)
    c.executescript((base / "038_inspiration_asset.sql").read_text(encoding="utf-8"))
    # 最小补齐墙依赖的表
    c.executescript("""
        CREATE TABLE IF NOT EXISTS suspicious_points(id INTEGER PRIMARY KEY, target_name TEXT, url TEXT, test_type TEXT, risk TEXT, test_status TEXT, reasoning TEXT);
        CREATE TABLE IF NOT EXISTS coverage_ledger(id INTEGER PRIMARY KEY, target_name TEXT, category TEXT, item_key TEXT, status TEXT, summary TEXT);
        CREATE TABLE IF NOT EXISTS work_items(id INTEGER PRIMARY KEY, target_name TEXT, lane TEXT, title TEXT, subject_table TEXT, subject_id TEXT, blocker_reason TEXT, status TEXT);
        CREATE TABLE IF NOT EXISTS business_flow_steps(id INTEGER PRIMARY KEY, flow_id INTEGER, step_key TEXT, name TEXT, url TEXT);
        CREATE TABLE IF NOT EXISTS business_flow_progress(id INTEGER PRIMARY KEY, step_id INTEGER, step_status TEXT, blocked_reason TEXT);
        CREATE TABLE IF NOT EXISTS operator_inbox(id INTEGER PRIMARY KEY, target_name TEXT, kind TEXT, title TEXT, detail TEXT, status TEXT);
        CREATE TABLE IF NOT EXISTS target_assets(id INTEGER PRIMARY KEY, target_name TEXT, asset_value TEXT, resolved_ip TEXT);
    """)
    return c


def test_blocks_include_inspiration_and_blocked_work_item():
    conn = _conn()
    conn.execute(
        "INSERT INTO work_items(target_name, lane, title, blocker_reason, status) VALUES('t','preauth_probe','探测卡住','认证拦截','blocked')"
    )
    conn.execute(
        "INSERT INTO inspirations(target_name, content, source, blocked_on_kind, blocked_on_id, status) VALUES('t','用 subfinder 找系统名','human','work_item',1,'open')"
    )
    wall = iw.build_insight_wall(conn, target_name="t")
    kinds = {b["kind"] for b in wall["blocks"]}
    assert "work_item" in kinds
    wi = next(b for b in wall["blocks"] if b["kind"] == "work_item")
    assert wi["inspirations"] and wi["inspirations"][0]["content"] == "用 subfinder 找系统名"


def test_blocks_group_inspirations_under_admin():
    conn = _conn()
    wall = iw.build_insight_wall(conn, target_name="t")
    assert isinstance(wall["counts"], dict)
    assert "total" in wall["counts"]


def test_missing_inspirations_table_returns_empty_not_error():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    c.executescript("""
        CREATE TABLE IF NOT EXISTS work_items(id INTEGER PRIMARY KEY, target_name TEXT, lane TEXT, title TEXT, blocker_reason TEXT, status TEXT);
        CREATE TABLE IF NOT EXISTS suspicious_points(id INTEGER PRIMARY KEY, target_name TEXT, url TEXT, test_type TEXT, risk TEXT, test_status TEXT, reasoning TEXT);
        CREATE TABLE IF NOT EXISTS coverage_ledger(id INTEGER PRIMARY KEY, target_name TEXT, category TEXT, item_key TEXT, status TEXT, summary TEXT);
        CREATE TABLE IF NOT EXISTS business_flow_steps(id INTEGER PRIMARY KEY, flow_id INTEGER, step_key TEXT, name TEXT, url TEXT);
        CREATE TABLE IF NOT EXISTS business_flow_progress(id INTEGER PRIMARY KEY, step_id INTEGER, step_status TEXT, blocked_reason TEXT);
        CREATE TABLE IF NOT EXISTS operator_inbox(id INTEGER PRIMARY KEY, target_name TEXT, kind TEXT, title TEXT, detail TEXT, status TEXT);
        CREATE TABLE IF NOT EXISTS target_assets(id INTEGER PRIMARY KEY, target_name TEXT, asset_value TEXT);
    """)
    wall = iw.build_insight_wall(c, target_name="t")
    assert isinstance(wall["blocks"], list)


def test_detail_nonexistent_returns_not_found():
    conn = _conn()
    d = iw.build_insight_detail(conn, target_name="t", insight_id=999)
    assert d["found"] is False
    assert d["inspiration"] is None


def test_detail_resolves_blocker_work_item_context():
    """Detail with blocked_on → 解析出挂靠 work_item 的 blocker_reason。"""
    conn = _conn()
    cur = conn.execute(
        "INSERT INTO work_items(target_name, lane, title, blocker_reason, status) VALUES('t','preauth_probe','入口探测卡住','TLS 握手失败，无响应','blocked')"
    )
    wiid = cur.lastrowid
    conn.execute(
        "INSERT INTO inspirations(target_name, stage, content, source, blocked_on_kind, blocked_on_id, status) "
        "VALUES('t','gleam','用 nmap 重扫 443 端口','agent','work_item',?,'open')",
        (wiid,),
    )
    insid = conn.execute("SELECT id FROM inspirations LIMIT 1").fetchone()["id"]
    d = iw.build_insight_detail(conn, target_name="t", insight_id=insid)
    assert d["found"] is True
    blocker = d["upstream"]["blocker"]
    assert blocker is not None
    assert blocker["kind"] == "work_item"
    assert blocker["id"] == wiid
    assert "TLS" in blocker["detail"]


def test_detail_resolves_promoted_work_item_downstream():
    """Detail with promoted_wi_id → 解析出验证成果 work_item。"""
    conn = _conn()
    cur = conn.execute(
        "INSERT INTO work_items(target_name, lane, title, blocker_reason, status) VALUES('t','vuln_review','SQLi 疑点复核完成','入库','done')"
    )
    wiid = cur.lastrowid
    conn.execute(
        "INSERT INTO inspirations(target_name, stage, content, source, promoted_wi_id, status) "
        "VALUES('t','clue','怀疑 order 参数可注入','agent',?,'verified')",
        (wiid,),
    )
    insid = conn.execute("SELECT id FROM inspirations LIMIT 1").fetchone()["id"]
    d = iw.build_insight_detail(conn, target_name="t", insight_id=insid)
    assert d["found"] is True
    wi = d["downstream"]["promoted_wi"]
    assert wi is not None
    assert wi["id"] == wiid
    assert wi["kind"] == "work_item"


def test_detail_refined_from_and_promoted_sp_resolved():
    """refined_from → gleam 上游;promoted_sp_id → suspicious_point 下游。"""
    conn = _conn()
    cur = conn.execute(
        "INSERT INTO suspicious_points(target_name, url, test_type, risk, test_status, reasoning) "
        "VALUES('t','https://x.example/order','sql-error', 'high','confirmed','引号报错')"
    )
    spid = cur.lastrowid
    cur = conn.execute(
        "INSERT INTO inspirations(target_name, stage, content, source, status) VALUES('t','gleam','order 参数可疑','agent','open')"
    )
    parent = cur.lastrowid
    conn.execute(
        "INSERT INTO inspirations(target_name, stage, content, source, refined_from_id, promoted_sp_id, status) "
        "VALUES('t','clue','缩小到 order 排序参数','agent',?,?,'verified')",
        (parent, spid),
    )
    insid = conn.execute("SELECT id FROM inspirations ORDER BY id DESC LIMIT 1").fetchone()["id"]
    d = iw.build_insight_detail(conn, target_name="t", insight_id=insid)
    assert d["found"] is True
    assert d["upstream"]["refined_from"]["id"] == parent
    assert d["upstream"]["refined_from"]["content"] == "order 参数可疑"
    assert d["downstream"]["promoted_sp"]["id"] == spid
    assert d["downstream"]["promoted_sp"]["title"] == "sql-error"


def test_chains_resolve_refined_from_and_blocker_context():
    """build_insight_chains:全览链携带 refined_from(源头灵光) + blocker(挂靠堵点上下文)。"""
    conn = _conn()
    cur = conn.execute(
        "INSERT INTO work_items(target_name, lane, title, blocker_reason, status) "
        "VALUES('t','preauth_probe','入口探测卡住','TLS 握手失败，无响应','blocked')"
    )
    wiid = cur.lastrowid
    cur = conn.execute(
        "INSERT INTO inspirations(target_name, stage, content, source, status) VALUES('t','gleam','order 参数可疑','agent','open')"
    )
    parent = cur.lastrowid
    conn.execute(
        "INSERT INTO inspirations(target_name, stage, content, source, refined_from_id, blocked_on_kind, blocked_on_id, status) "
        "VALUES('t','clue','缩小到 order 排序参数','agent',?,?,?,'queued')",
        (parent, "work_item", wiid),
    )
    data = iw.build_insight_chains(conn, target_name="t")
    assert data["stats"]["total"] == 2
    assert data["stats"]["open"] == 1
    clue = next(c for c in data["chains"] if c["stage"] == "clue")
    assert clue["refined_from"] == "order 参数可疑"
    assert clue["blocker"] is not None
    assert clue["blocker"]["kind"] == "work_item"
    assert clue["blocker"]["id"] == wiid
    assert "TLS" in clue["blocker"]["detail"]
    # 无 sources 时 chains/stats 结构仍健全
    empty = iw.build_insight_chains(_conn(), target_name="t")
    assert empty["chains"] == [] and empty["stats"]["total"] == 0


def test_sort_recommended_orders_higher_confidence_first():
    """sort='recommended':游离灵感按 score_insight 降序,高置信度在前。"""
    conn = _conn()
    orders = [("low", 3), ("high", 1), ("medium", 2)]
    for conf, seq in orders:
        conn.execute(
            "INSERT INTO inspirations(target_name, stage, content, source, confidence, status) VALUES('t','gleam',?, 'agent', ?, 'open')",
            (f"i-{seq}", conf),
        )
    rec = iw.build_insight_wall(conn, target_name="t", sort="recommended")
    free_rec = rec["blocks"][0]["inspirations"]
    assert len(free_rec) == 3
    # 推荐排序:high 在前,且每条都带 score
    assert free_rec[0]["confidence"] == "high"
    assert all("score" in i for i in free_rec)
    assert free_rec[0]["score"] >= free_rec[1]["score"] >= free_rec[2]["score"]
    # 块内挂靠灵感同样被重排
    cur = conn.execute(
        "INSERT INTO work_items(target_name, lane, title, blocker_reason, status) VALUES('t','vuln_review','复核','why','blocked')"
    )
    wiid = cur.lastrowid
    for conf in ("medium", "high"):
        conn.execute(
            "INSERT INTO inspirations(target_name, stage, content, source, confidence, status, blocked_on_kind, blocked_on_id) "
            "VALUES('t','clue',?, 'agent', ?, 'open', 'work_item', ?)",
            (conf, conf, wiid),
        )
    rec2 = iw.build_insight_wall(conn, target_name="t", sort="recommended")
    wi_block = next(b for b in rec2["blocks"] if b["kind"] == "work_item")
    assert wi_block["inspirations"][0]["confidence"] == "high"


def test_build_asset_inspirations_returns_explicit_asset():
    """build_asset_inspirations:显式 asset_id 的灵感按资产命中返回。"""
    conn = _conn()
    cur = conn.execute("INSERT INTO target_assets(target_name, asset_value, resolved_ip) VALUES('t','x.example.com','1.2.3.4')")
    aid = cur.lastrowid
    cur = conn.execute(
        "INSERT INTO inspirations(target_name, stage, content, source, asset_id, status) "
        "VALUES('t','gleam','这个 IP 上有 OSS 桶','agent',?,'open')",
        (aid,),
    )
    insid = cur.lastrowid
    data = iw.build_asset_inspirations(conn, target_name="t", asset_id=aid)
    assert [i["id"] for i in data["inspirations"]] == [insid]
    assert data["inspirations"][0]["content"] == "这个 IP 上有 OSS 桶"
    # 无关资产不命中
    other = iw.build_asset_inspirations(conn, target_name="t", asset_id=999)
    assert other["inspirations"] == []


def test_build_asset_inspirations_fallbacks_via_blocked_on():
    """无显式 asset_id 时,从 blocked_on(work_item → target_assets)追溯归属资产。"""
    conn = _conn()
    cur = conn.execute("INSERT INTO target_assets(target_name, asset_value, resolved_ip) VALUES('t','login.example.com','5.6.7.8')")
    aid = cur.lastrowid
    cur = conn.execute(
        "INSERT INTO work_items(target_name, lane, title, subject_table, subject_id, blocker_reason, status) "
        "VALUES('t','entry_probe','入口探测卡住','target_assets',?,'TLS 失败','blocked')",
        (str(aid),),
    )
    wiid = cur.lastrowid
    cur = conn.execute(
        "INSERT INTO inspirations(target_name, stage, content, source, blocked_on_kind, blocked_on_id, status) "
        "VALUES('t','clue','重扫 443 端口','agent','work_item',?,'open')",
        (wiid,),
    )
    insid = cur.lastrowid
    data = iw.build_asset_inspirations(conn, target_name="t", asset_id=aid)
    assert [i["id"] for i in data["inspirations"]] == [insid]


def test_build_asset_inspirations_no_table_is_empty():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    c.executescript(
        "CREATE TABLE IF NOT EXISTS target_assets(id INTEGER PRIMARY KEY, target_name TEXT, asset_value TEXT, resolved_ip TEXT);"
    )
    data = iw.build_asset_inspirations(c, target_name="t", asset_id=1)
    assert data["inspirations"] == []
