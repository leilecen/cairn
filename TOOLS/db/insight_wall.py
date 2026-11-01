"""灵感墙只读聚合器:把目标当前所有「未闭环悬点/堵点」拼成一堵墙。

只读、不落新表:每次请求实时从 6 类来源查。聚合来源与「未闭环」判定见
local/archive/specs/2026-08-16-inspiration-v4-design.md 第 6 节。

隐私硬边界:只读;不碰 auth_credentials/auth_sessions/runtime_requests/burp_actions;截断大字段。
"""

# ruff: noqa: S608 -- SELECT 列来自硬编码白名单过滤 PRAGMA table_info,非用户输入
from __future__ import annotations

import sqlite3
from typing import Any


def _has_table(conn: sqlite3.Connection, name: str) -> bool:
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None


def _resolve_asset_id(conn: sqlite3.Connection, *, asset_id: int | None, kind: str | None, id) -> int | None:
    """把一条灵感归属到某个 target_assets.id(读资产名/resolved_ip)。

    - 优先用显式 asset_id。
    - 否则尝试从 blocked_on(work_item → subject_table/subject_id)追溯兜底。
    - 解析不出返回 None。只读;所有表访问都做存在性守卫。
    """
    if asset_id is not None:
        return int(asset_id)
    if not kind or id is None:
        return None
    # 只有 work_item 的 subject_* 能可靠映射到资产;其余 kind 交给服务器端 AssetResolver。
    kit = (kind or "").strip()
    if kit != "work_item" or not _has_table(conn, "work_items") or not _has_table(conn, "target_assets"):
        return None
    row = conn.execute("SELECT subject_table, subject_id FROM work_items WHERE id=? LIMIT 1", (str(id),)).fetchone()
    if row is None or not row["subject_table"] or row["subject_id"] is None:
        return None
    subj_table = (row["subject_table"] or "").strip()
    subj_id = str(row["subject_id"])
    # A: subject_table='target_assets' → 数字 id 或资产名
    if subj_table == "target_assets":
        if subj_id.isdigit():
            a = conn.execute("SELECT id FROM target_assets WHERE id=? LIMIT 1", (int(subj_id),)).fetchone()
            if a is not None:
                return int(a["id"])
        a = conn.execute("SELECT id FROM target_assets WHERE asset_value=? LIMIT 1", (subj_id,)).fetchone()
        if a is not None:
            return int(a["id"])
        return None
    # B: subject 关联表(带 url/asset_id 的表) → host 或 asset_id → 资产
    asset_col_tables = ("entry_observations", "endpoint_observations")
    if subj_table in asset_col_tables and _has_table(conn, subj_table):
        try:
            r = conn.execute(f"SELECT asset_id, url FROM {subj_table} WHERE id=? LIMIT 1", (subj_id,)).fetchone()
        except (sqlite3.OperationalError, sqlite3.ProgrammingError):
            r = None
        if r is not None:
            if r["asset_id"] is not None:
                return int(r["asset_id"])
            if r["url"]:
                h = _host_of(r["url"])
                a = _asset_by_host(conn, h)
                if a is not None:
                    return a
    url_cols = {
        "js_files": ("url", "page_url"),
        "js_signal_clusters": ("canonical_url",),
        "suspicious_points": ("url",),
        "findings": ("url",),
        "pages": ("url", "canonical_url"),
        "entry_observations": ("url",),
        "endpoint_observations": ("canonical_url",),
    }
    cols = url_cols.get(subj_table)
    if cols and _has_table(conn, subj_table):
        try:
            sel = ", ".join(cols)
            r = conn.execute(f"SELECT {sel} FROM {subj_table} WHERE id=? LIMIT 1", (subj_id,)).fetchone()
        except (sqlite3.OperationalError, sqlite3.ProgrammingError):
            r = None
        if r is not None:
            for c in cols:
                h = _host_of(r[c]) if r[c] else ""
                a = _asset_by_host(conn, h)
                if a is not None:
                    return a
    return None


def _asset_by_host(conn: sqlite3.Connection, host: str) -> int | None:
    """按 host(asset_value 或 resolved_ip)找 target_assets.id;找不到返回 None。"""
    if not host or not _has_table(conn, "target_assets"):
        return None
    row = conn.execute(
        "SELECT id FROM target_assets WHERE asset_value=? OR resolved_ip=? LIMIT 1",
        (host, host),
    ).fetchone()
    return int(row["id"]) if row is not None else None


def build_asset_inspirations(conn: sqlite3.Connection, *, target_name: str, asset_id: int) -> dict[str, Any]:
    """读资产自身的灵感(只读,不做表级写入)。

    一条灵感视为「属于该资产」,当显式 asset_id == asset_id,或其 blocked_on 追溯能
    解析到这个 asset_id。返回 {"inspirations": [{id, stage, content, trigger, status,
    confidence, created_at}]};inspirations 表缺失返回空列表。
    """
    if not _has_table(conn, "inspirations"):
        return {"inspirations": []}
    rows = conn.execute(
        """SELECT id, stage, content, trigger, status, confidence, created_at,
                  asset_id, blocked_on_kind, blocked_on_id
           FROM inspirations WHERE target_name=? ORDER BY id""",
        (target_name,),
    ).fetchall()
    out: list[dict[str, Any]] = []
    for r in rows:
        rid = int(r["id"])
        resolved = _resolve_asset_id(conn, asset_id=r["asset_id"], kind=r["blocked_on_kind"], id=r["blocked_on_id"])
        if resolved != asset_id:
            continue
        out.append(
            {
                "id": rid,
                "stage": r["stage"],
                "content": (r["content"] or "")[:300],
                "trigger": (r["trigger"] or "")[:200],
                "status": r["status"],
                "confidence": r["confidence"],
                "created_at": r["created_at"],
            }
        )
    return {"inspirations": out}


def _host_of(url: str | None) -> str:
    if not url:
        return ""
    s = url.strip()
    if "://" in s:
        s = s.split("://", 1)[1]
    for sep in ("/", ":", "?"):
        if sep in s:
            s = s.split(sep, 1)[0]
    return s


def _group_inspirations(conn: sqlite3.Connection, target: str, kind: str, id_col: str) -> dict[str, list[dict[str, Any]]]:
    """按 blocked_on_id 分组该 kind 下所有未闭环灵感(status IN open, queued)。

    id 统一按字符串归一(blocked_on 的实体 id 可能是文本如 sp-ssrf-001,也可能是数字)。
    """
    out: dict[str, list[dict[str, Any]]] = {}
    if not _has_table(conn, "inspirations"):
        return out
    rows = conn.execute(
        """SELECT id, stage, content, trigger, status, confidence, created_at, blocked_on_id
           FROM inspirations WHERE target_name=? AND blocked_on_kind=?
             AND status IN ('open','queued') ORDER BY id""",
        (target, kind),
    ).fetchall()
    for r in rows:
        if r["blocked_on_id"] is not None:
            out.setdefault(str(r["blocked_on_id"]), []).append(
                {
                    "id": r["id"],
                    "stage": r["stage"],
                    "content": (r["content"] or "")[:300],
                    "trigger": (r["trigger"] or "")[:200],
                    "status": r["status"],
                    "confidence": r["confidence"],
                    "created_at": r["created_at"],
                }
            )
    return out


_CONF_RANK = {"low": 0, "medium": 1, "high": 2}
_STATUS_BONUS = {"open": 1.0, "queued": 0.5}


def score_insight(item: dict[str, Any]) -> float:
    """确定性轻量评分(roadmap §3 优先推荐,无外部 ML)。

    score = 置信度 + 状态加成 + 时效(新近更高) + 有堵点小助推。
    纯确定性公式,便于测试与解释;只用于「优先推荐」开关打开时的排序,
    默认不调用保持现状。
    """
    base = _CONF_RANK.get((item.get("confidence") or "").lower(), 0)
    +_STATUS_BONUS.get((item.get("status") or "").lower(), 0)
    # 时效:比较 id 新近度(id 单调递增)或 created_at 文本倒序。有 created_at 时,
    # 越晚创建给越高的 0..1 比例加分;否则退化为按 id。
    recency = 0.0
    created = item.get("created_at")
    if created:
        s = str(created)
        # YYYY-MM-DD HH:MM:SS / YYYY-MM-DD 均可按时间序比较;前 10 位是日期
        recency = (ord(s[10:11]) if len(s) > 10 else 0) / 10.0 + ((s[:10] or "").count("-") / 20.0)
    else:
        try:
            recency = min(float(item.get("id") or 0) / 10000.0, 1.0)
        except (TypeError, ValueError):
            recency = 0.0
    # 有堵点上下文(挂靠 + 有解析内容)更可行动 → 小助推
    blocker = item.get("blocker") if isinstance(item.get("blocker"), dict) else None
    boost = 0.4 if blocker and (blocker.get("title") or blocker.get("detail")) else 0.0
    return round(base + recency * 0.5 + boost, 4)


def _sort_by_score(inspirations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """按 score_insight 降序排序,并把 score 写回每条 item(供前端展示)。"""
    for item in inspirations:
        item["score"] = score_insight(item)
    return sorted(inspirations, key=score_insight, reverse=True)


def _block_inspirations(grouped: dict[str, list[dict[str, Any]]], key, recommended: bool) -> list[dict[str, Any]]:
    """取某堵点分组下的灵感;recommended 时按 score 降序。"""
    items = grouped.get(str(key), [])
    return _sort_by_score(items) if recommended else items


def build_insight_wall(conn: sqlite3.Connection, *, target_name: str, sort: str | None = None) -> dict[str, Any]:
    """灵感墙只读聚合 6 类堵点;`sort="recommended"` 时按 score_insight 降序。

    默认(无 sort 参数)保持与现状一致的分组内顺序,不改变既有行为。
    """
    blocks: list[dict[str, Any]] = []
    recommended = sort == "recommended"
    insp_tbl = _has_table(conn, "inspirations")

    # 1) 灵感/线索(未闭环,未挂到任何堵点的游离灵感)
    free = []
    if insp_tbl:
        for r in conn.execute(
            """SELECT id, stage, content, trigger, status, confidence, created_at
               FROM inspirations WHERE target_name=? AND status IN ('open','queued')
                 AND (blocked_on_kind IS NULL OR blocked_on_id IS NULL)
               ORDER BY id DESC""",
            (target_name,),
        ).fetchall():
            free.append(
                {
                    "id": r["id"],
                    "stage": r["stage"],
                    "content": (r["content"] or "")[:300],
                    "trigger": (r["trigger"] or "")[:200],
                    "status": r["status"],
                    "confidence": r["confidence"],
                    "created_at": r["created_at"],
                }
            )
    if recommended:
        free = _sort_by_score(free)
    if free:
        blocks.append(
            {
                "kind": "inspiration",
                "id": None,
                "title": "游离灵感/线索",
                "summary": "",
                "reason": "",
                "asset_host": "",
                "url": "",
                "inspirations": free,
            }
        )

    # 2) 未验证疑点 suspicious_points(untested/confirmed)
    if _has_table(conn, "suspicious_points"):
        insp = _group_inspirations(conn, target_name, "suspicious_point", "id")
        for r in conn.execute(
            """SELECT id, url, test_type, risk, test_status, reasoning FROM suspicious_points
               WHERE test_status IN ('untested','confirmed')
               ORDER BY id DESC LIMIT 200""",
        ).fetchall():
            blocks.append(
                {
                    "kind": "suspicious_point",
                    "id": r["id"],
                    "title": (r["test_type"] or "疑点"),
                    "summary": (r["reasoning"] or "")[:200],
                    "reason": "",
                    "asset_host": _host_of(r["url"]),
                    "url": r["url"] or "",
                    "inspirations": _block_inspirations(insp, r["id"], recommended),
                }
            )

    # 3) 未覆盖账本 coverage_ledger(unknown/uncovered)
    if _has_table(conn, "coverage_ledger"):
        insp = _group_inspirations(conn, target_name, "coverage_ledger", "id")
        cols = [c[1] for c in conn.execute("PRAGMA table_info(coverage_ledger)").fetchall()]
        sel = ", ".join(c for c in ("id", "category", "item_key", "status", "summary") if c in cols) or "id"
        sql = f"SELECT {sel} FROM coverage_ledger WHERE target_name=? AND status IN ('unknown','uncovered') ORDER BY id DESC LIMIT 200"
        for r in conn.execute(sql, (target_name,)).fetchall():
            d = dict(r)
            blocks.append(
                {
                    "kind": "coverage_ledger",
                    "id": d.get("id"),
                    "title": (d.get("category") or "未覆盖"),
                    "summary": (d.get("item_key") or "")[:200],
                    "reason": (d.get("summary") or "")[:200],
                    "asset_host": "",
                    "url": "",
                    "inspirations": _block_inspirations(insp, d["id"], recommended),
                }
            )

    # 4) 卡住攻面 work_items(blocked)
    if _has_table(conn, "work_items"):
        insp = _group_inspirations(conn, target_name, "work_item", "id")
        for r in conn.execute(
            """SELECT id, lane, title, blocker_reason, status FROM work_items
               WHERE target_name=? AND status='blocked' ORDER BY id DESC LIMIT 200""",
            (target_name,),
        ).fetchall():
            blocks.append(
                {
                    "kind": "work_item",
                    "id": r["id"],
                    "title": (r["title"] or r["lane"] or "卡住任务"),
                    "summary": "",
                    "reason": (r["blocker_reason"] or "")[:200],
                    "asset_host": "",
                    "url": "",
                    "inspirations": _block_inspirations(insp, r["id"], recommended),
                }
            )

    # 5) 业务流中间态 business_flow_steps(+progress: blocked/中间态)
    if _has_table(conn, "business_flow_steps") and _has_table(conn, "business_flow_progress"):
        insp = _group_inspirations(conn, target_name, "business_flow_step", "id")
        for r in conn.execute(
            """SELECT s.id, s.name, s.step_key, p.step_status, p.blocked_reason
               FROM business_flow_steps s JOIN business_flow_progress p ON p.step_id=s.id
               WHERE p.step_status IN ('testing','blocked') OR p.blocked_reason IS NOT NULL
               ORDER BY s.id DESC LIMIT 200""",
        ).fetchall():
            blocks.append(
                {
                    "kind": "business_flow_step",
                    "id": r["id"],
                    "title": (r["name"] or r["step_key"]),
                    "summary": (r["step_status"] or ""),
                    "reason": (r["blocked_reason"] or "")[:200],
                    "asset_host": "",
                    "url": "",
                    "inspirations": _block_inspirations(insp, r["id"], recommended),
                }
            )

    # 6) 待操作员 operator_inbox(open)
    if _has_table(conn, "operator_inbox"):
        insp = _group_inspirations(conn, target_name, "operator_inbox", "id")
        for r in conn.execute(
            """SELECT id, kind, title, detail, status FROM operator_inbox
               WHERE target_name=? AND status='open' ORDER BY id DESC LIMIT 200""",
            (target_name,),
        ).fetchall():
            blocks.append(
                {
                    "kind": "operator_inbox",
                    "id": r["id"],
                    "title": (r["title"] or r["kind"] or "待办"),
                    "summary": (r["detail"] or "")[:200],
                    "reason": "",
                    "asset_host": "",
                    "url": "",
                    "inspirations": _block_inspirations(insp, r["id"], recommended),
                }
            )

    return {"blocks": blocks, "counts": {"total": len(blocks)}}


# ---------------------------------------------------------------------------
# 详情(完整前因后果)构建 build_insight_detail —— 只读,不写任何表。
# ---------------------------------------------------------------------------


def _row(conn: sqlite3.Connection, table: str, rowid) -> sqlite3.Row | None:
    """带安全校验的单行读取:表名来自调用方硬编码白名单,id 归一为字符串比较。

    只读;表不存在返回 None,不抛错。
    """
    if not _has_table(conn, table):
        return None
    try:
        return conn.execute(f"SELECT * FROM {table} WHERE id=?", (rowid,)).fetchone()
    except (sqlite3.OperationalError, sqlite3.ProgrammingError):
        # 幽灵/不一致表结构,读失败当未命中处理(只读聚合,不许炸墙)
        return None


def _truncate(v: Any, n: int = 200) -> str:
    if v is None:
        return ""
    return str(v).strip()[:n]


# blocked_on_kind(--inspirations.blocked_on_kind)→ 实际业务表名(均为系统硬编码白名单)。
_KIND_TABLE = {
    "suspicious_point": "suspicious_points",
    "coverage_ledger": "coverage_ledger",
    "work_item": "work_items",
    "business_flow_step": "business_flow_steps",
    "operator_inbox": "operator_inbox",
}


def _blocker_context(conn: sqlite3.Connection, kind: str | None, rowid, *, target_name: str) -> dict[str, Any] | None:
    """解析堵点来源记录的人读上下文,得到「前因」。

    返回 None 表示没有挂靠堵点或解析不到。kind 来自 inspirations.blocked_on_kind,
    由 _KIND_TABLE 白名单映射到实际表名(如 work_item → work_items)。
    """
    if not kind or rowid is None:
        return None
    table = _KIND_TABLE.get(kind)
    if not table:
        return None
    r = _row(conn, table, rowid)
    if r is None:
        return None

    def get(*keys: str) -> str:
        for k in keys:
            if k in r.keys():
                v = r[k]
                if v not in (None, ""):
                    return str(v)
        return ""

    ctx: dict[str, Any] = {"kind": kind, "id": rowid, "title": "", "detail": "", "host": ""}
    if kind == "work_item":
        ctx["title"] = get("title", "lane")
        ctx["detail"] = get("blocker_reason")
    elif kind == "suspicious_point":
        ctx["title"] = get("test_type") or "疑点"
        parts = "\n".join(x for x in (get("reasoning"), get("risk"), get("url")) if x)
        ctx["detail"] = parts[:300]
        if "url" in r.keys() and r["url"]:
            ctx["host"] = _host_of(r["url"])
            ctx["url"] = str(r["url"])[:300]
    elif kind == "coverage_ledger":
        ctx["title"] = get("category") or "未覆盖"
        ctx["detail"] = get("item_key", "summary")
    elif kind == "operator_inbox":
        ctx["title"] = get("title", "kind") or "待办"
        ctx["detail"] = get("detail")
    elif kind == "business_flow_step":
        ctx["title"] = get("name", "step_key")
        ctx["detail"] = get("blocked_reason", "step_status")
    else:
        # 兜底:尽量拼 title + 常见 detail 字段(只读,读不到就是空)
        ctx["title"] = get("title", "name")
        ctx["detail"] = get("detail", "reason", "summary", "blocker_reason")[:300]
    _trim(ctx)
    return ctx


def _trim(d: dict[str, Any]) -> None:
    for k in ("title", "detail", "host", "url", "reason", "content", "trigger", "summary"):
        if k in d and d[k] is not None:
            d[k] = str(d[k])[:300] if k in ("url", "detail", "content") else str(d[k])[:200]


def build_insight_detail(conn: sqlite3.Connection, *, target_name: str, insight_id) -> dict[str, Any]:
    """构建单条灵感的「完整前因后果」(只读)。

    - 该灵感全部字段
    - 前因上游:
        * refined_from_id → 源头 gleam 灵感
        * blocked_on_kind/blocked_on_id → 挂靠堵点的人读上下文
    - 后果下游:
        * promoted_sp_id → 验证出的 suspicious_point(或共享 sp_id 的 finding)
        * promoted_wi_id → 验证出的 work_item
    - 收割:harvest_id + harvest_note

    所有大字段截断 [:200]/[:300];绝不碰 auth/burp 类隐私表。
    """
    base: dict[str, Any] = {"found": False, "inspiration": None, "upstream": None, "downstream": None, "harvest": None}
    if not _has_table(conn, "inspirations"):
        return base
    row = _row(conn, "inspirations", insight_id)
    if row is None:
        return base

    insp: dict[str, Any] = {
        "id": row["id"],
        "stage": row["stage"],
        "content": _truncate(row["content"], 300),
        "trigger": _truncate(row["trigger"], 200),
        "source": row["source"],
        "confidence": row["confidence"],
        "status": row["status"],
        "blocked_on_kind": row["blocked_on_kind"],
        "blocked_on_id": row["blocked_on_id"],
        "promoted_sp_id": row["promoted_sp_id"],
        "promoted_wi_id": row["promoted_wi_id"],
        "refined_from_id": row["refined_from_id"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }
    # 可选列(老库可能没有 harvest 列)
    for col in ("harvest_id", "harvest_note", "notes", "agent_id", "session_id"):
        if col in row.keys():
            insp[col] = _truncate(row[col], 200)

    upstream: dict[str, Any] = {"refined_from": None, "blocker": None}
    # 源头灵光:refined_from_id → gleam
    if row["refined_from_id"] is not None:
        src = _row(conn, "inspirations", row["refined_from_id"])
        if src is not None:
            upstream["refined_from"] = {
                "id": src["id"],
                "stage": src["stage"],
                "content": _truncate(src["content"], 300),
                "trigger": _truncate(src["trigger"], 200),
                "confidence": src["confidence"],
                "status": src["status"],
            }
    # 挂靠堵点上下文
    upstream["blocker"] = _blocker_context(conn, row["blocked_on_kind"], row["blocked_on_id"], target_name=target_name)

    downstream: dict[str, Any] = {"promoted_sp": None, "promoted_wi": None}
    # 验证成果 suspicious_point / finding
    if row["promoted_sp_id"] is not None:
        sp = _row(conn, "suspicious_points", row["promoted_sp_id"])
        if sp is not None:
            d: dict[str, Any] = {
                "kind": "suspicious_point",
                "id": row["promoted_sp_id"],
                "title": _truncate(sp["test_type"]) if "test_type" in sp.keys() else "",
                "detail": _truncate(sp["reasoning"], 300) if "reasoning" in sp.keys() else "",
                "risk": _truncate(sp["risk"], 50) if "risk" in sp.keys() else "",
                "host": _host_of(sp["url"]) if "url" in sp.keys() else "",
                "url": _truncate(sp["url"], 300) if "url" in sp.keys() else "",
            }
            downstream["promoted_sp"] = d
    # 验证成果 work_item
    if row["promoted_wi_id"] is not None:
        wi = _row(conn, "work_items", row["promoted_wi_id"])
        if wi is not None:
            downstream["promoted_wi"] = {
                "kind": "work_item",
                "id": row["promoted_wi_id"],
                "title": _truncate(wi["title"], 200) if "title" in wi.keys() else "",
                "detail": _truncate(wi["blocker_reason"], 300) if "blocker_reason" in wi.keys() else "",
                "lane": _truncate(wi["lane"], 100) if "lane" in wi.keys() else "",
                "status": _truncate(wi["status"], 50) if "status" in wi.keys() else "",
            }

    harvest = None
    if row["harvest_id"]:
        note = _truncate(row["harvest_note"], 300) if "harvest_note" in row.keys() else ""
        harvest = {
            "harvest_id": str(row["harvest_id"])[:200],
            "harvest_note": note,
        }

    return {
        "found": True,
        "inspiration": insp,
        "upstream": upstream,
        "downstream": downstream,
        "harvest": harvest,
    }


# ---------------------------------------------------------------------------
# 堵点图谱 / 关系线 build_insight_chains —— 只读,不写任何表。
# 把一个 target 下所有灵感的 refined_from(灵光→线索)与 blocked_on(灵感→堵点)
# 串联成可见的因果链列表,让人一屏看全一个 target 的渗透思维脉络。
# ---------------------------------------------------------------------------


def build_insight_chains(conn: sqlite3.Connection, *, target_name: str) -> dict[str, Any]:
    """构建 target 的「同 target 全览链视图」(roadmap §2 务实形态)。

    遍历该 target 全部灵感(任意状态,按 id 升序),对每条:
    - 上游:refined_from_id → 源头 gleam 灵感内容(灵光→线索)
    - 堵点:blocked_on_kind/id → 复用 _blocker_context 解析人读上下文
    返回 {"chains": [...], "stats": {total, open, gleam, clue}};只读,截断字段。
    """
    chains: list[dict[str, Any]] = []
    stats = {"total": 0, "open": 0, "gleam": 0, "clue": 0}
    if not _has_table(conn, "inspirations"):
        return {"chains": chains, "stats": stats}

    for r in conn.execute(
        """SELECT id, stage, content, trigger, status, confidence,
                  refined_from_id, blocked_on_kind, blocked_on_id
           FROM inspirations WHERE target_name=? ORDER BY id""",
        (target_name,),
    ).fetchall():
        refined = None
        if r["refined_from_id"] is not None:
            src = _row(conn, "inspirations", r["refined_from_id"])
            if src is not None:
                refined = (src["content"] or "")[:300]

        blocker = _blocker_context(conn, r["blocked_on_kind"], r["blocked_on_id"], target_name=target_name)

        chains.append(
            {
                "inspiration_id": r["id"],
                "stage": r["stage"],
                "content": (r["content"] or "")[:300],
                "trigger": (r["trigger"] or "")[:200],
                "status": r["status"],
                "confidence": r["confidence"],
                "refined_from": refined,
                "blocker": blocker,
            }
        )
        stats["total"] += 1
        if r["status"] == "open":
            stats["open"] += 1
        if r["stage"] == "gleam":
            stats["gleam"] += 1
        elif r["stage"] == "clue":
            stats["clue"] += 1

    return {"chains": chains, "stats": stats}
