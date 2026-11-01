"""测试 migration 035 业务状态机 + business_flow_view 图谱读取工具。

覆盖：
- migration 035 在 v34 夹具上干净应用（4 张表 + 索引），幂等可重放；
- 新 schema 直接就是 v35（fresh baseline）；
- templates seed 幂等（7 类启发式提醒，UNIQUE(category)）；
- build_flow_graph 输出完整图谱 JSON（flow/step/preconditions/progress/template hints）；
- blocked 步骤进 summary.stuck、exploited 进 summary.exploited；
- endpoint_id 回填后 step.endpoint 带接口信息（决策 1-B）；
- 隐私边界：evidence_refs 只出 id/title；
- CLI 主入口 --json / --seed-templates。
"""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import db.business_flow_view as bfv
from db.migrate import apply_migration, do_migrate

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "TOOLS" / "db" / "schema.sql"
MIGRATION = ROOT / "migrations" / "035_business_state_machine.sql"
VIEW_TOOL = ROOT / "TOOLS" / "db" / "business_flow_view.py"

EXPECTED_CATEGORIES = {"payment", "login", "order", "transfer", "redeem", "account", "other"}
LATEST_SCHEMA_VERSION = max(int(path.name[:3]) for path in (ROOT / "migrations").glob("[0-9][0-9][0-9]_*.sql"))


def _fresh_schema(path: Path, *, seed_version: int | None = None) -> None:
    """按 schema.sql 建全新 DB（默认即为 v35 baseline）。

    seed_version=34 时把 035 的 business state machine DDL 从 baseline 剥离，
    模拟真实 v34 库（同 test_migrate_034 的做法）。
    """
    with sqlite3.connect(path) as conn:
        schema = SCHEMA.read_text(encoding="utf-8")
        if seed_version == 34:
            marker = "-- ===== Business state machine (migration 035) ====="
            idx = schema.find(marker)
            assert idx != -1, "schema.sql should contain 035 section marker"
            schema = schema[:idx].rstrip() + "\n"
            schema = schema.replace(
                "INSERT OR IGNORE INTO schema_version(version, description)\nVALUES(35, '035_business_state_machine');\n",
                "",
            )
        conn.executescript(schema)
        if seed_version is not None:
            conn.execute("DELETE FROM schema_version")
            conn.execute(
                "INSERT INTO schema_version(version, description) VALUES(?, 'fixture')",
                (seed_version,),
            )


def _insert_sample_flow(conn: sqlite3.Connection, *, target: str = "Fixture Target") -> int:
    conn.execute("INSERT INTO targets(target_name, domain) VALUES(?, 'example.test')", (target,))
    conn.execute(
        """INSERT INTO target_assets(target_name, asset_value, asset_type)
           VALUES(?, 'pay.example.test', 'domain')""",
        (target,),
    )
    asset_id = conn.execute("SELECT id FROM target_assets").fetchone()[0]
    conn.execute(
        """INSERT INTO business_flows(target_name, asset_id, flow_key, name, category, entry_url,
           derivation, completeness, prerequisites_json, status, confidence, evidence_refs_json)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            target,
            asset_id,
            "payment:recharge",
            "充值支付",
            "payment",
            "https://pay.example.test/recharge",
            "auto_inferred",
            "mapped",
            '["登录"]',
            "active",
            "high",
            '[{"id":"ev-1","title":"recharge page","body":"should be stripped"}]',
        ),
    )
    flow_id = conn.execute("SELECT id FROM business_flows").fetchone()[0]
    steps = [
        (0, "enter_recharge", "进入充值页", "GET", "https://pay.example.test/recharge", None, "[]", "[]", "observed"),
        (
            1,
            "pay_create_order",
            "创建订单",
            "POST",
            "https://pay.example.test/order/create",
            "待支付",
            "[]",
            '[{"vuln":"order_id_predictable"}]',
            "observed",
        ),
        (
            2,
            "pay_launch",
            "发起支付",
            "POST",
            "https://pay.example.test/pay/launch",
            "待支付",
            '[{"step":"pay_create_order","state":"待支付"}]',
            "[]",
            "observed",
        ),
        (
            3,
            "pay_callback",
            "支付回调",
            "POST",
            "https://pay.example.test/pay/callback",
            "已支付",
            '[{"step":"pay_launch","state":"待支付"}]',
            '[{"vuln":"callback_sign_missing"},{"vuln":"amount_tamper"}]',
            "logical",
        ),
        (
            4,
            "pay_refund",
            "退款",
            "POST",
            "https://pay.example.test/pay/refund",
            "已退款",
            '[{"step":"pay_callback","state":"已支付"}]',
            '[{"vuln":"refund_not_idempotent"}]',
            "logical",
        ),
    ]
    for order, key, name, method, url, state, pre, plan, mapping in steps:
        conn.execute(
            """INSERT INTO business_flow_steps(flow_id, step_order, step_key, name, url, method,
               business_state, preconditions_json, test_plan_json, mapping_status)
               VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (flow_id, order, key, name, url, method, state, pre, plan, mapping),
        )
    # S3 blocked（前置满足但接口未探测到）
    s3 = conn.execute("SELECT id FROM business_flow_steps WHERE step_key='pay_callback'").fetchone()[0]
    conn.execute(
        """INSERT INTO business_flow_progress(flow_id, step_id, current_state, step_status, blocked_reason)
           VALUES(?,?,?,?,?)""",
        (flow_id, s3, "已支付", "blocked", "回调接口未探测到（缺 endpoint）"),
    )
    conn.commit()
    return flow_id


# ---------------------------------------------------------------------------
# migration 035
# ---------------------------------------------------------------------------


def test_fresh_schema_035_is_already_current(tmp_path):
    path = tmp_path / "fresh.db"
    _fresh_schema(path)

    result = do_migrate(str(path))

    assert result["current_version"] == LATEST_SCHEMA_VERSION
    assert [item["version"] for item in result["applied"]] == list(range(39, LATEST_SCHEMA_VERSION + 1))
    with sqlite3.connect(path) as conn:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'business_flow%'")}
        assert tables == {
            "business_flows",
            "business_flow_steps",
            "business_flow_progress",
            "business_flow_templates",
        }
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"


def test_v34_db_migrates_to_035_cleanly_and_is_replayable(tmp_path):
    """v34 夹具（无 4 张表）→ do_migrate 到 35；重放幂等。"""
    path = tmp_path / "v34.db"
    _fresh_schema(path, seed_version=34)
    with sqlite3.connect(path) as conn:
        assert bfv.schema_ready(conn) is False
        # v34 baseline 不应有 business_flow 表
        n = conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE name LIKE 'business_flow%'").fetchone()[0]
        assert n == 0

    result = do_migrate(str(path))

    assert result["current_version"] == LATEST_SCHEMA_VERSION
    assert [a["version"] for a in result["applied"]] == list(range(35, LATEST_SCHEMA_VERSION + 1))
    with sqlite3.connect(path) as conn:
        assert bfv.schema_ready(conn) is True
        assert conn.execute("SELECT COUNT(*) FROM schema_version WHERE version=35").fetchone()[0] == 1
        conn.execute("PRAGMA foreign_keys=ON")
        assert apply_migration(conn, 35, str(MIGRATION)) is True
        assert conn.execute("SELECT COUNT(*) FROM schema_version WHERE version=35").fetchone()[0] == 1


# ---------------------------------------------------------------------------
# templates seed
# ---------------------------------------------------------------------------


def test_seed_templates_idempotent(tmp_path):
    path = tmp_path / "seed.db"
    _fresh_schema(path)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        first = bfv.seed_templates(conn)
        assert first["seeded"] == 7
        assert first["total"] == 7
        second = bfv.seed_templates(conn)
        assert second["seeded"] == 0  # UNIQUE(category) + INSERT OR IGNORE
        assert second["total"] == 7
        rows = conn.execute("SELECT category FROM business_flow_templates").fetchall()
        assert {r["category"] for r in rows} == EXPECTED_CATEGORIES
    finally:
        conn.close()


def test_seed_templates_reports_missing_table(tmp_path):
    path = tmp_path / "old.db"
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE targets(id INTEGER PRIMARY KEY)")
    conn = sqlite3.connect(path)
    try:
        result = bfv.seed_templates(conn)
        assert result["seeded"] == 0
        assert "missing table" in result["error"]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# build_flow_graph
# ---------------------------------------------------------------------------


def test_build_flow_graph_full_payload(tmp_path):
    path = tmp_path / "graph.db"
    _fresh_schema(path)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        bfv.seed_templates(conn)
        _insert_sample_flow(conn)
        asset_id = conn.execute("SELECT id FROM target_assets").fetchone()[0]
        payload = bfv.build_flow_graph(conn, target_name="Fixture Target", asset_id=asset_id)

        assert payload["schema_version"] == 38
        assert payload["asset_value"] == "pay.example.test"
        assert payload["summary"]["flows"] == 1
        assert payload["summary"]["steps"] == 5
        assert payload["summary"]["by_status"] == {"not_reached": 4, "blocked": 1}

        flow = payload["flows"][0]
        assert flow["flow_key"] == "payment:recharge"
        assert flow["prerequisites"] == ["登录"]
        assert flow["template_hints"]["available"] is True
        assert any("回调验签缺失" in h for h in flow["template_hints"]["hints"])

        steps = flow["steps"]
        assert len(steps) == 5
        assert [s["step_order"] for s in steps] == [0, 1, 2, 3, 4]
        # S3 前置 = {step, state} 完整版（决策 3）
        assert steps[3]["preconditions"] == [{"step": "pay_launch", "state": "待支付"}]
        assert steps[4]["preconditions"] == [{"step": "pay_callback", "state": "已支付"}]
        # S3 进度回写
        assert steps[3]["progress"]["step_status"] == "blocked"
        assert steps[3]["progress"]["current_state"] == "已支付"
        assert steps[3]["progress"]["blocked_reason"] == "回调接口未探测到（缺 endpoint）"
        # 未回写步骤默认 not_reached
        assert steps[0]["progress"]["step_status"] == "not_reached"
        assert steps[0]["endpoint"] is None
        assert steps[0]["url"] == "https://pay.example.test/recharge"
        # summary 堵点
        assert len(payload["summary"]["stuck"]) == 1
        assert "pay_callback" in payload["summary"]["stuck"][0]
    finally:
        conn.close()


def test_endpoint_backfill_decision_1b(tmp_path):
    """endpoint_id 回填后 step.endpoint 带接口地图信息（决策 1-B）。"""
    path = tmp_path / "backfill.db"
    _fresh_schema(path)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        flow_id = _insert_sample_flow(conn)
        # 模拟探测到回调接口 → 回填 endpoint_id
        conn.execute(
            """INSERT INTO endpoint_observations(target_name, host, path, canonical_url, method, source)
               VALUES('Fixture Target', 'pay.example.test', '/pay/callback',
                      'https://pay.example.test/pay/callback', 'POST', 'test')"""
        )
        ep_id = conn.execute("SELECT id FROM endpoint_observations").fetchone()[0]
        s3 = conn.execute(
            "SELECT id FROM business_flow_steps WHERE flow_id=? AND step_key='pay_callback'",
            (flow_id,),
        ).fetchone()[0]
        conn.execute(
            "UPDATE business_flow_steps SET endpoint_id=?, mapping_status='verified' WHERE id=?",
            (ep_id, s3),
        )
        conn.commit()

        payload = bfv.build_flow_graph(conn, target_name="Fixture Target")
        step = next(s for s in payload["flows"][0]["steps"] if s["step_key"] == "pay_callback")
        assert step["mapping_status"] == "verified"
        assert step["endpoint"]["id"] == ep_id
        assert step["endpoint"]["url"] == "https://pay.example.test/pay/callback"
    finally:
        conn.close()


def test_evidence_refs_only_id_title_privacy(tmp_path):
    path = tmp_path / "privacy.db"
    _fresh_schema(path)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        _insert_sample_flow(conn)
        payload = bfv.build_flow_graph(conn, target_name="Fixture Target")
        refs = payload["flows"][0]["evidence_refs"]
        assert refs == [{"id": "ev-1", "title": "recharge page"}]
        for ref in refs:
            assert "body" not in ref  # 隐私：evidence 正文不输出
    finally:
        conn.close()


def test_exploited_step_in_summary(tmp_path):
    path = tmp_path / "exploited.db"
    _fresh_schema(path)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        _insert_sample_flow(conn)
        s3 = conn.execute("SELECT id FROM business_flow_steps WHERE step_key='pay_callback'").fetchone()[0]
        conn.execute(
            """UPDATE business_flow_progress
               SET step_status='exploited', current_state='已支付', finding_id='f-9'
               WHERE step_id=?""",
            (s3,),
        )
        conn.commit()
        payload = bfv.build_flow_graph(conn, target_name="Fixture Target")
        assert payload["summary"]["exploited"] == ["payment:recharge:pay_callback"]
        step = next(s for s in payload["flows"][0]["steps"] if s["step_key"] == "pay_callback")
        assert step["progress"]["finding_id"] == "f-9"
    finally:
        conn.close()


def test_missing_migration_returns_clear_error(tmp_path):
    path = tmp_path / "nomig.db"
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE targets(id INTEGER PRIMARY KEY)")
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        payload = bfv.build_flow_graph(conn, target_name="Fixture Target")
        assert payload["error"].startswith("migration 035 not applied")
        assert payload["flows"] == []
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _run_cli(*args: str, cwd: Path = ROOT) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603 -- fixed interpreter and repository script
        [sys.executable, str(VIEW_TOOL), *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env={**os.environ, "PYTHONUTF8": "1"},
        check=False,
    )


def test_cli_seed_templates_and_json(tmp_path):
    db = tmp_path / "cli.db"
    _fresh_schema(db)
    seeded = _run_cli("--db", str(db), "--seed-templates")
    assert seeded.returncode == 0
    assert json.loads(seeded.stdout)["total"] == 7

    _insert_sample_flow(sqlite3.connect(db))
    out = _run_cli("--db", str(db), "--target", "Fixture Target", "--json")
    assert out.returncode == 0
    payload = json.loads(out.stdout)
    assert payload["summary"]["flows"] == 1
    assert payload["flows"][0]["steps"][3]["progress"]["step_status"] == "blocked"

    text = _run_cli("--db", str(db), "--target", "Fixture Target")
    assert text.returncode == 0
    assert "[STATE_MACHINE]" in text.stdout
    assert "BLOCKED" in text.stdout


def test_cli_missing_target_and_db_rejected(tmp_path):
    out = _run_cli()
    assert out.returncode != 0
    assert "必须指定 --target 或 --db" in (out.stdout + out.stderr)


def test_cli_error_on_unmigrated_db(tmp_path):
    db = tmp_path / "old.db"
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE targets(id INTEGER PRIMARY KEY)")
    out = _run_cli("--db", str(db), "--target", "Fixture Target", "--json")
    assert out.returncode == 0
    payload = json.loads(out.stdout)
    assert payload["error"].startswith("migration 035 not applied")
