"""业务状态机图谱读取工具（business state machine view）。

读一个资产的「业务流 + 步骤 + 前置依赖 + 执行进度」完整状态机图谱 JSON，
供 AI 按图索骥（spec 6.1）与 warroom 看板（spec 6.2）消费。
配套 schema：migrations/035_business_state_machine.sql，
设计文档：local/archive/specs/2026-08-16-business-state-machine-design.md

用法:
  uv run python TOOLS/db/business_flow_view.py --target "example-client" --json
  uv run python TOOLS/db/business_flow_view.py --target "example-client" --asset 5 --json
  uv run python TOOLS/db/business_flow_view.py --db dbs/{client}_2026-08-11.db --flow payment:recharge
  uv run python TOOLS/db/business_flow_view.py --target "example-client" --seed-templates   # 幂等 seed 启发式提醒

隐私边界：只读结构化字段；evidence_refs 只出 id/title；不含 Cookie/Authorization/HTTP 正文。
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any

_TOOLS_DIR = Path(__file__).resolve().parent.parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

from db.db_utils import connect, find_db, force_utf8_stdout  # noqa: E402

# 业务状态机 4 张表（migration 035）— 表名是固定模块常量，SQL 用字面量，不插值
FLOW_TABLE = "business_flows"
STEP_TABLE = "business_flow_steps"
PROGRESS_TABLE = "business_flow_progress"
TEMPLATE_TABLE = "business_flow_templates"

STEP_STATUSES = ("not_reached", "reached", "testing", "blocked", "exploited", "covered")

# ---------------------------------------------------------------------------
# 启发式提醒 seed（spec 4.4：模板只做按 category 的高发漏洞面提示，不预定义步骤顺序）
# ---------------------------------------------------------------------------
TEMPLATE_SEEDS: dict[str, dict[str, Any]] = {
    "payment": {
        "attack_surface_hints": [
            "金额篡改（改 amount/price/fee 字段后发起支付）",
            "订单号可预测性（自增/时间戳可枚举）",
            "回调验签缺失/可伪造（直接 POST 回调接口伪造成功）",
            "重复回调/并发重复入账（TOCTOU 竞态）",
            "退款不幂等/越权退款（改退款单归属）",
            "支付方式/渠道切换绕过（切换支付方式逃掉校验）",
            "优惠券/折扣叠加（负金额、超额折扣）",
        ],
        "test_notes": "从 entry_url 进入，推进到「创建订单→发起支付→回调→入账→退款」中间态；"
        "重点测步骤间前置依赖与不规则分支（未支付跳已发货、重复回调）。",
    },
    "login": {
        "attack_surface_hints": [
            "验证码绕过/重放（响应码复用、图形码可识别）",
            "用户名枚举（错误信息区分）",
            "登录爆破（有界 ≤100 包自动，大范围需 gate）",
            "密码重置逻辑缺陷（重置链接可预测/任意账号重置）",
            "会话固定/并发登录（旧 token 不失效）",
            "SSO/OAuth 回调伪造（username 参数可控、state 缺失）",
            "空密码/默认口令（随手试几个，≤100 包自动）",
        ],
        "test_notes": "登录态是多数逻辑链的前置；优先测注册→登录→找回密码三段，回调与重置接口常缺验签。",
    },
    "order": {
        "attack_surface_hints": [
            "越权查看/修改他人订单（IDOR 改订单号）",
            "订单号枚举（批量拉取他人订单信息）",
            "价格/数量字段篡改（下单时改单价、数量为负）",
            "状态跳步（未支付→已发货/已完成）",
            "库存并发（超卖/负数库存）",
            "重复下单（幂等缺失，可无限下单）",
        ],
        "test_notes": "订单链中间态多：待支付/已支付/已发货/已完成，每个状态迁移都是校验边界。",
    },
    "transfer": {
        "attack_surface_hints": [
            "金额负值/溢出（-1、极大值、0.01 手续费绕过）",
            "越权转账（改收款人字段、批量转账目标）",
            "竞态重复转账（并发提交同一笔）",
            "手续费/汇率篡改（客户端参数可改）",
            "单笔/日限额绕过（分批、类型混淆）",
        ],
        "test_notes": "转账是金额敏感链，先建立「创建→确认→到账」骨架，再测各状态间跳步与并发。",
    },
    "redeem": {
        "attack_surface_hints": [
            "兑换码枚举/暴力（码空间小、可顺序猜测）",
            "核销竞态（同一码并发核销多次）",
            "一次码多次使用（核销后不失效）",
            "过期状态绕过（改时间参数/状态字段）",
            "他人码核销（越权用他人兑换码）",
        ],
        "test_notes": "兑换/卡密类核心是单次凭证的幂等性：真实消耗 vs 重复记录要区分（见 logic-audit-methods §2）。",
    },
    "account": {
        "attack_surface_hints": [
            "越权改他人资料（改 user_id 字段）",
            "手机号/邮箱绑定覆盖（他人手机号绑定到自己账号）",
            "身份混淆（注册/登录身份字段可控）",
            "权限提升（普通用户→管理员，改 role 字段）",
            "批量查询接口（列表接口泄露他人信息）",
        ],
        "test_notes": "账户链前置是认证与授权边界；测完登录后立即测资料修改/绑定/角色字段。",
    },
    "other": {
        "attack_surface_hints": [
            "通用 IDOR（资源 id 可枚举/越权）",
            "竞态/TOCTOU（配额、单次凭证、状态互斥）",
            "状态机跳步（跳过前置步骤直达后置动作）",
            "响应篡改（客户端改服务端返回再提交）",
            "幂等缺失（重复提交副作用）",
        ],
        "test_notes": "不属于上述类别的业务链；先画骨架再按通用中间态/竞态/越权方向测。",
    },
}


def table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
    return row is not None


def schema_ready(conn: sqlite3.Connection) -> bool:
    """migration 035 是否已应用（4 张表齐全）。"""
    return all(table_exists(conn, t) for t in (FLOW_TABLE, STEP_TABLE, PROGRESS_TABLE, TEMPLATE_TABLE))


def seed_templates(conn: sqlite3.Connection) -> dict[str, Any]:
    """幂等 seed business_flow_templates 启发式提醒（UNIQUE(category) + INSERT OR IGNORE）。"""
    if not table_exists(conn, TEMPLATE_TABLE):
        return {"seeded": 0, "error": f"missing table {TEMPLATE_TABLE} (run db_admin migrate first)"}
    inserted = 0
    for category, data in TEMPLATE_SEEDS.items():
        cur = conn.execute(
            "INSERT OR IGNORE INTO business_flow_templates(category, attack_surface_hints_json, test_notes) VALUES(?, ?, ?)",
            (
                category,
                json.dumps(data["attack_surface_hints"], ensure_ascii=False),
                data["test_notes"],
            ),
        )
        inserted += cur.rowcount
    conn.commit()
    total = conn.execute("SELECT COUNT(*) FROM business_flow_templates").fetchone()[0]
    return {"seeded": inserted, "total": total, "categories": sorted(TEMPLATE_SEEDS)}


def _json_list(raw: str | None, *, default: Any = None) -> Any:
    try:
        value = json.loads(raw or "[]")
    except json.JSONDecodeError:
        return default if default is not None else []
    return value


def _template_hints(conn: sqlite3.Connection, category: str | None) -> dict[str, Any]:
    if not category or not table_exists(conn, TEMPLATE_TABLE):
        return {"available": False, "hints": [], "test_notes": ""}
    row = conn.execute(
        "SELECT attack_surface_hints_json, test_notes FROM business_flow_templates WHERE category=?",
        (category,),
    ).fetchone()
    if not row:
        return {"available": False, "hints": [], "test_notes": ""}
    return {
        "available": True,
        "hints": _json_list(row["attack_surface_hints_json"], default=[]),
        "test_notes": row["test_notes"] or "",
    }


def _resolve_asset(conn: sqlite3.Connection, target_name: str, asset: str | int | None) -> int | None:
    """asset 参数 → target_assets.id。支持数字 id 或 asset_value 精确匹配。"""
    if asset is None:
        return None
    try:
        aid = int(asset)
        row = conn.execute("SELECT id FROM target_assets WHERE id=? AND target_name=?", (aid, target_name)).fetchone()
        if row:
            return aid
    except (TypeError, ValueError):
        pass
    row = conn.execute(
        "SELECT id FROM target_assets WHERE asset_value=? AND target_name=? ORDER BY id LIMIT 1",
        (str(asset), target_name),
    ).fetchone()
    return row["id"] if row else None


def _asset_label(conn: sqlite3.Connection, asset_id: int | None) -> str:
    if asset_id is None:
        return ""
    row = conn.execute("SELECT asset_value FROM target_assets WHERE id=?", (asset_id,)).fetchone()
    return row["asset_value"] if row else ""


def build_flow_graph(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    asset_id: int | None = None,
    flow_key: str | None = None,
) -> dict[str, Any]:
    """读一个资产的完整状态机图谱 JSON（spec 6.3）。

    - 不要求 endpoint 地图齐全：steps.url/method 是逻辑引用，endpoint_id 探测到才回填（决策 1-B）；
    - progress 按 step_id 关联回写（有序 + 中间态）；
    - 每个 flow 附 category 对应的模板启发式提醒；
    - 隐私边界：evidence_refs 只出 id/title。
    """
    if not schema_ready(conn):
        return {
            "target": target_name,
            "schema_version": None,
            "error": "migration 035 not applied — run: uv run python TOOLS/db/db_admin.py --target <目标> migrate",
            "flows": [],
            "summary": {
                "flows": 0,
                "steps": 0,
                "by_status": {},
                "stuck": [],
                "exploited": [],
            },
        }

    flows: list[dict[str, Any]] = []
    query = "SELECT * FROM business_flows WHERE target_name=?"
    params: list[Any] = [target_name]
    if asset_id is not None:
        query += " AND asset_id=?"
        params.append(asset_id)
    if flow_key:
        query += " AND flow_key=?"
        params.append(flow_key)
    query += " ORDER BY id"

    for f in conn.execute(query, params).fetchall():
        steps = _flow_steps(conn, f["id"])
        progress_rows = {
            p["step_id"]: p for p in conn.execute("SELECT * FROM business_flow_progress WHERE flow_id=?", (f["id"],)).fetchall()
        }
        step_out = []
        for s in steps:
            prog = progress_rows.get(s["id"])
            step_out.append(_step_payload(conn, s, prog))
        hints = _template_hints(conn, f["category"])
        flows.append(
            {
                "id": f["id"],
                "flow_key": f["flow_key"],
                "name": f["name"],
                "category": f["category"],
                "asset_id": f["asset_id"],
                "asset_value": _asset_label(conn, f["asset_id"]),
                "system_id": f["system_id"],
                "entry_url": f["entry_url"],
                "derivation": f["derivation"],
                "completeness": f["completeness"],
                "prerequisites": _json_list(f["prerequisites_json"], default=[]),
                "description": f["description"],
                "status": f["status"],
                "confidence": f["confidence"],
                "evidence_refs": _evidence_refs(f["evidence_refs_json"]),
                "template_hints": hints,
                "steps": step_out,
                "updated_at": f["updated_at"],
            }
        )

    summary = _graph_summary(flows)
    # schema 版本动态取（不硬编码：随 migrations/*.sql 增长，见 036+）
    try:
        schema_version = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0]
    except Exception:  # noqa: BLE001 无 schema_version 表时兜底为 None
        schema_version = None
    return {
        "target": target_name,
        "asset_id": asset_id,
        "asset_value": _asset_label(conn, asset_id) if asset_id is not None else None,
        "flows": flows,
        "summary": summary,
        "schema_version": schema_version,
    }


def _flow_steps(conn: sqlite3.Connection, flow_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM business_flow_steps WHERE flow_id=? ORDER BY step_order, id",
        (flow_id,),
    ).fetchall()


def _step_payload(conn: sqlite3.Connection, s: sqlite3.Row, prog: sqlite3.Row | None) -> dict[str, Any]:
    endpoint: dict[str, Any] | None = None
    if s["endpoint_id"] is not None:
        ep = conn.execute(
            "SELECT canonical_url, host, path, method FROM endpoint_observations WHERE id=?",
            (s["endpoint_id"],),
        ).fetchone()
        if ep:
            endpoint = {
                "id": s["endpoint_id"],
                "url": ep["canonical_url"],
                "host": ep["host"],
                "path": ep["path"],
                "method": ep["method"],
            }
    return {
        "id": s["id"],
        "step_order": s["step_order"],
        "step_key": s["step_key"],
        "name": s["name"],
        "endpoint": endpoint,
        "url": s["url"],
        "method": s["method"],
        "action_hint": s["action_hint"],
        "business_state": s["business_state"],
        "preconditions": _json_list(s["preconditions_json"], default=[]),
        "test_plan": _json_list(s["test_plan_json"], default=[]),
        "mapping_status": s["mapping_status"],
        "evidence_refs": _evidence_refs(s["evidence_refs_json"]),
        "progress": _progress_payload(prog),
    }


def _progress_payload(prog: sqlite3.Row | None) -> dict[str, Any]:
    if prog is None:
        return {
            "step_status": "not_reached",
            "current_state": None,
            "blocked_reason": None,
            "coverage_ledger_id": None,
            "suspicious_point_id": None,
            "finding_id": None,
        }
    return {
        "step_status": prog["step_status"],
        "current_state": prog["current_state"],
        "blocked_reason": prog["blocked_reason"],
        "coverage_ledger_id": prog["coverage_ledger_id"],
        "suspicious_point_id": prog["suspicious_point_id"],
        "finding_id": prog["finding_id"],
        "updated_at": prog["updated_at"],
    }


def _evidence_refs(raw: str | None) -> list[dict[str, Any]]:
    """evidence_refs_json 只出 id/title（隐私边界，spec 7）。"""
    out: list[dict[str, Any]] = []
    for item in _json_list(raw, default=[]):
        if not isinstance(item, dict):
            continue
        ref = {"id": item.get("id")}
        if item.get("title"):
            ref["title"] = item["title"]
        out.append(ref)
    return out


def _graph_summary(flows: list[dict[str, Any]]) -> dict[str, Any]:
    by_status: dict[str, int] = {s: 0 for s in STEP_STATUSES}
    total_steps = 0
    stuck: list[str] = []
    exploited: list[str] = []
    for flow in flows:
        for step in flow.get("steps", []):
            total_steps += 1
            status = step.get("progress", {}).get("step_status") or "not_reached"
            by_status[status] = by_status.get(status, 0) + 1
            if status == "blocked":
                stuck.append(
                    f"{flow.get('flow_key')}:{step.get('step_key')} — "
                    f"{step.get('progress', {}).get('blocked_reason') or '前置未满足/缺接口/缺账号'}"
                )
            if status == "exploited":
                exploited.append(f"{flow.get('flow_key')}:{step.get('step_key')}")
    return {
        "flows": len(flows),
        "steps": total_steps,
        "by_status": {k: v for k, v in by_status.items() if v},
        "stuck": stuck,
        "exploited": exploited,
    }


def format_flow_text(payload: dict[str, Any]) -> str:
    lines = []
    lines.append(f"[STATE_MACHINE] target={payload.get('target')} schema_v{payload.get('schema_version')}")
    if payload.get("error"):
        lines.append(f"error: {payload['error']}")
        return "\n".join(lines)
    summary = payload.get("summary", {})
    statuses = " ".join(f"{k}={v}" for k, v in summary.get("by_status", {}).items()) or "empty"
    lines.append(f"flows={summary.get('flows', 0)} steps={summary.get('steps', 0)} [{statuses}]")
    if summary.get("asset_value"):
        lines.append(f"asset={summary['asset_value']}")
    for flow in payload.get("flows", []):
        lines.append("")
        lines.append(
            f"FLOW #{flow['id']} {flow.get('flow_key')} ({flow.get('name')}) "
            f"cat={flow.get('category')} status={flow.get('status')} "
            f"complete={flow.get('completeness')} deriv={flow.get('derivation')}"
        )
        if flow.get("entry_url"):
            lines.append(f"  entry: {flow['entry_url']}")
        pre = flow.get("prerequisites") or []
        if pre:
            lines.append(f"  prerequisites: {', '.join(str(p) for p in pre)}")
        hints = flow.get("template_hints", {})
        if hints.get("available") and hints.get("hints"):
            lines.append(f"  hints({flow.get('category')}): " + " | ".join(hints["hints"][:6]))
        for step in flow.get("steps", []):
            prog = step.get("progress", {})
            status = prog.get("step_status") or "not_reached"
            mark = {
                "not_reached": "-",
                "reached": "o",
                "testing": "~",
                "blocked": "X",
                "exploited": "!",
                "covered": "v",
            }.get(status, "?")
            state = f" [{prog.get('current_state')}]" if prog.get("current_state") else ""
            blocked = f" BLOCKED:{prog.get('blocked_reason')}" if status == "blocked" else ""
            endpoint = step.get("endpoint") or {}
            url = endpoint.get("url") or step.get("url") or ""
            lines.append(
                f"  {mark} #{step.get('step_order')} {step.get('step_key')} {step.get('name')}{state}"
                f" map={step.get('mapping_status')} {step.get('method') or ''} {url}{blocked}"
            )
    if summary.get("stuck"):
        lines.append("")
        lines.append("[STUCK]")
        for item in summary["stuck"]:
            lines.append(f"  {item}")
    if summary.get("exploited"):
        lines.append("")
        lines.append("[EXPLOITED]")
        for item in summary["exploited"]:
            lines.append(f"  {item}")
    return "\n".join(lines)


def _resolve_db_path(args: argparse.Namespace) -> Path:
    if args.db:
        return Path(args.db)
    return find_db(args.target)


def main() -> None:
    force_utf8_stdout()
    parser = argparse.ArgumentParser(description="业务状态机图谱读取（AI 按图索骥 / warroom 状态机视图）")
    parser.add_argument("--target", help="target_name in the DB")
    parser.add_argument("--db", help="explicit DB path")
    parser.add_argument("--asset", help="asset id 或 asset_value（可空=全部资产）")
    parser.add_argument("--flow", help="flow_key 过滤（可空=全部）")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument(
        "--seed-templates",
        action="store_true",
        help="幂等 seed business_flow_templates 启发式提醒后退出",
    )
    args = parser.parse_args()

    if not args.target and not args.db:
        parser.print_help()
        raise SystemExit("必须指定 --target 或 --db")

    conn = connect(_resolve_db_path(args))
    try:
        if args.seed_templates:
            result = seed_templates(conn)
            print(json.dumps(result, ensure_ascii=False))
            return
        if not args.target:
            row = conn.execute("SELECT target_name FROM targets ORDER BY id LIMIT 1").fetchone()
            target = row["target_name"] if row else None
        else:
            target = args.target
        if not target:
            raise SystemExit(f"无法从 DB 解析 target_name：{args.db}")
        asset_id = _resolve_asset(conn, target, args.asset)
        payload = build_flow_graph(conn, target_name=target, asset_id=asset_id, flow_key=args.flow)
    finally:
        conn.close()

    if args.json:
        print(json.dumps(payload, ensure_ascii=False))
    else:
        print(format_flow_text(payload))


if __name__ == "__main__":
    main()
