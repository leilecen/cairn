"""SRC 实时作战室 Dashboard — 完整版后端（纯 stdlib + SQLite，只读）。

VSCode 风格 UI 的数据后端。启动后托管 warroom/web/dist 构建产物 + /api/*。

启动:
  uv run python warroom/server.py [--port 8787]
  # 目标不通过 CLI 参数绑定——UI 内 /api/targets 列出 dbs/ 全部目标切换

端点:
  /api/targets        所有可用目标(DB 名 + target_name 解析)
  /api/view           五视图 + 堵点进展总数据(blackboard_view 聚合 + 补充查询)
  /api/queue          work_items 待测列表(含 URL)
  /api/assets         target_assets 资产 + 指纹
  /api/findings       漏洞成果
  /api/blockers       当前资产堵点/进展(blocked items + inbox + coverage)

隐私硬边界: 只读白名单列; auth_credentials/auth_sessions/runtime_requests/
burp_actions 零端点; evidence_refs 只出 id/title; 正文大字段截断。
"""
from __future__ import annotations

import argparse
import json
import mimetypes
import sqlite3
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

PROJECT_ROOT = Path(__file__).resolve().parent.parent
WARROOM = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT / "TOOLS"))
from db.blackboard_view import build_blackboard_view  # noqa: E402
from db.business_flow_view import build_flow_graph  # noqa: E402
from db.db_utils import connect, find_db, session  # noqa: E402
from db.insight_wall import (  # noqa: E402
    build_asset_inspirations,
    build_insight_chains,
    build_insight_detail,
    build_insight_wall,
)

DIST_DIR = WARROOM / "web" / "dist"
BLOCKED_LANES = {"preauth_probe", "entry_probe", "vuln_review", "logic_probe", "evidence_pack", "postexp", "replay"}


def _targets() -> list[dict]:
    """dbs/ 下所有 DB → (db_name, target_name)。"""
    out = []
    for db in sorted((PROJECT_ROOT / "dbs").glob("*.db")):
        tname = db.stem
        try:
            with session(db, read_only=True) as conn:
                row = conn.execute("SELECT target_name FROM targets WHERE target_name IS NOT NULL LIMIT 1").fetchone()
                tname = row["target_name"] if row else db.stem
        except Exception:  # noqa: BLE001
            # 无 schema / 无 targets 表的库：保留文件名兜底，连接由 session 保证关闭
            tname = db.stem
        out.append({"db": db.name, "target": tname})
    return out


def _resolve_url(conn, table: str, subj_id) -> str:
    if not table or not subj_id:
        return ""
    table = table.strip()
    try:
        if table == "endpoint_observations":
            r = conn.execute("SELECT canonical_url FROM endpoint_observations WHERE id=?", (subj_id,)).fetchone()
            return r["canonical_url"] if r else ""
        if table == "pages":
            r = conn.execute("SELECT url FROM pages WHERE id=?", (subj_id,)).fetchone()
            return r["url"] if r else ""
        if table == "suspicious_points":
            r = conn.execute("SELECT url FROM suspicious_points WHERE id=?", (subj_id,)).fetchone()
            return r["url"] if r else ""
        if table == "findings":
            r = conn.execute("SELECT url FROM findings WHERE id=?", (subj_id,)).fetchone()
            return r["url"] if r else ""
        if table == "target_assets":
            r = conn.execute(
                "SELECT asset_value, protocol, port FROM target_assets WHERE id=?", (subj_id,)
            ).fetchone()
            if r:
                scheme = (r["protocol"] or "https").rstrip("/")
                return f"{scheme}://{r['asset_value']}"
        if table == "js_files":
            r = conn.execute("SELECT local_path FROM js_files WHERE id=?", (subj_id,)).fetchone()
            if r and r["local_path"]:
                return f"file:///{r['local_path'].replace(chr(92), '/')}"
        if table == "soft_targets":
            r = conn.execute("SELECT asset_value FROM soft_targets WHERE id=?", (subj_id,)).fetchone()
            return r["asset_value"] if r else ""
    except Exception:
        return ""
    return ""


class AssetResolver:
    """work_items.subject_* → 资产 的统一归属解析器（2026-08-15 抽取，供 _queue/_asset_detail/_disclosure 共用）。

    历史数据有三类关联方式，全部支持：
      A. subject_table='target_assets' 且 subject_id 是数字 id（JOIN target_assets.id）
      B. subject_table='target_assets' 但 subject_id 是资产名（JOIN target_assets.asset_value）
      C. subject_table 是 js_files/js_signal_clusters/suspicious_points/findings/pages/
         entry_observations/endpoint_observations/coverage_ledger 等 → 关联表 url/asset_id → host → 资产

    一次性构建索引（按目标），之后 resolve() 为纯字典查找。
    """

    def __init__(self, conn, target: str):
        self.conn = conn
        self.target = target
        # 资产索引：id / asset_value / host(去端口, 含 resolved_ip)
        acols = [r[1] for r in conn.execute("PRAGMA table_info(target_assets)").fetchall()]
        apick = [c for c in ("id", "asset_value", "resolved_ip", "protocol", "port") if c in acols]
        asel = ", ".join(apick) if apick else "id, asset_value"
        rows = conn.execute(
            f"SELECT {asel} FROM target_assets WHERE target_name=? ORDER BY id", (target,)
        ).fetchall()
        self.assets = [dict(r) for r in rows]
        self.by_id = {a["id"]: a for a in self.assets}
        self.by_value = {a["asset_value"]: a for a in self.assets}
        self.by_host: dict[str, dict] = {}
        for a in self.assets:
            for key in (a.get("asset_value"), a.get("resolved_ip")):
                if key:
                    self.by_host.setdefault(_host_of(str(key)), a)

        # C 类：各关联表 id -> host 列表（js_files 的 url 可能是 CDN，需回退 page_url）
        self._table_hosts: dict[str, dict] = {}
        for table, url_cols in (
            ("js_files", ["url", "page_url"]),
            ("js_signal_clusters", ["canonical_url"]),
            ("suspicious_points", ["url"]),
            ("findings", ["url"]),
            ("pages", ["url", "canonical_url"]),
            ("entry_observations", ["url"]),
            ("endpoint_observations", ["canonical_url"]),
        ):
            self._table_hosts[table] = self._build_host_index(table, url_cols)

        # entry_observations/endpoint_observations 有 asset_id 直连资产（优先于 host）
        self._table_asset_ids: dict[str, dict] = {}
        for table in ("entry_observations", "endpoint_observations"):
            self._table_asset_ids[table] = self._build_asset_id_index(table)

    def _build_host_index(self, table: str, url_cols: list[str]) -> dict:
        idx = {}
        try:
            cols = [c[1] for c in self.conn.execute(f"PRAGMA table_info({table})").fetchall()]
            cols = [c for c in url_cols if c in cols]
            if not cols:
                return idx
            sel = ", ".join(["id"] + cols)
            rows = self.conn.execute(f"SELECT {sel} FROM {table}").fetchall()
        except Exception:  # noqa: BLE001 旧 schema 无此表/列
            return idx
        for r in rows:
            hosts = []
            for c in cols:
                h = _host_of(r[c])
                if h:
                    hosts.append(h)
            if hosts:
                idx[str(r["id"])] = hosts
        return idx

    def _build_asset_id_index(self, table: str) -> dict:
        idx = {}
        try:
            rows = self.conn.execute(f"SELECT id, asset_id, url FROM {table}").fetchall()
        except Exception:  # noqa: BLE001
            return idx
        for r in rows:
            if r["asset_id"] is not None:
                idx[str(r["id"])] = str(r["asset_id"])
            elif r["url"]:
                h = _host_of(r["url"])
                if h:
                    idx[str(r["id"])] = h
        return idx

    def resolve(self, subject_table: str | None, subject_id, text: str = "") -> int | None:
        """返回资产 id 或 None。text 用于 coverage_ledger 等无 url 字段时从标题提 host。"""
        table = (subject_table or "").strip()
        sid = str(subject_id) if subject_id is not None else ""

        if not table or not sid:
            return None

        if table == "target_assets":
            # A: 数字 id
            try:
                aid = int(sid)
                if aid in self.by_id:
                    return aid
            except (TypeError, ValueError):
                pass
            # B: 资产名
            if sid in self.by_value:
                return self.by_value[sid]["id"]

        # C1: asset_id 直连（entry/endpoint observations）
        ref = self._table_asset_ids.get(table, {}).get(sid)
        if ref is not None:
            if ref.isdigit() and int(ref) in self.by_id:
                return int(ref)
            a = self.by_host.get(ref)
            if a:
                return a["id"]

        # C2: url/canonical_url → host → 资产
        for h in self._table_hosts.get(table, {}).get(sid, []):
            a = self.by_host.get(h)
            if a:
                return a["id"]

        # C3: 从自由文本（title/objective）提 host（coverage_ledger 等）
        h = _host_from_text(text)
        if h:
            a = self.by_host.get(h)
            if a:
                return a["id"]

        return None

    def asset_value_of(self, asset_id: int | None) -> str:
        if asset_id is None:
            return ""
        a = self.by_id.get(asset_id)
        return (a.get("asset_value") or "") if a else ""

    def resolve_url(self, subject_table: str | None, subject_id) -> str:
        """subject → URL（用于队列行的可点击链接）。"""
        return _resolve_url(self.conn, subject_table, subject_id)


def _derive_display(objective, title):
    import re as _re
    obj = (objective or "").strip()
    title = (title or "").strip()
    hint = ""
    bracket = None
    for seg in obj.split("["):
        if "]" in seg:
            bracket = seg.split("]")[0]
            break
    if bracket:
        cleaned = bracket
        cleaned = _re.sub(r"^FOFA:\s*[A-Z]+\s*", "", cleaned)
        cleaned = _re.sub(r"^\d{4}-\d{2}-\d{2}\s*", "", cleaned)
        cleaned = cleaned.strip(" -\u2014|")
        title_out = cleaned if cleaned else title
        m = _re.search(r"FOFA ports=([^\s]+)(?:\s+server=([^\s\]]+))?", obj)
        if m:
            ports = m.group(1)
            server = m.group(2) or ""
            hint = f"端口 {ports}" + (f" · {server}" if server else "")
        return title_out, hint
    if title:
        return title, hint
    return (obj[:80] or "未分类"), hint


def _queue(conn, target: str) -> dict:
    rows = conn.execute(
        """SELECT id, lane, subtype, title, objective, status, subject_table, subject_id, priority,
                  summary, next_action, blocker_reason, claimed_by, heartbeat_at
           FROM work_items WHERE target_name=? AND status IN ('queued','claimed','partial')
           ORDER BY CASE status WHEN 'queued' THEN 0 WHEN 'claimed' THEN 1 ELSE 2 END,
                    COALESCE(priority,0) DESC, id LIMIT 200""",
        (target,),
    ).fetchall()
    resolver = AssetResolver(conn, target)
    items = []
    for r in rows:
        subj_table = r["subject_table"]
        subj_id = r["subject_id"]
        # 统一归属：A/B/C 三类（数字 id / 资产名 / 关联表 host）→ asset_host
        aid = resolver.resolve(subj_table, subj_id, f"{r['title'] or ''} {r['objective'] or ''}")
        asset_host = resolver.asset_value_of(aid)
        display_title, display_hint = _derive_display(r["objective"], r["title"])
        items.append({
            "id": r["id"], "lane": r["lane"], "subtype": r["subtype"],
            "title": display_title,
            "raw_title": r["title"] or "",
            "hint": display_hint,
            "status": r["status"], "url": _resolve_url(conn, subj_table, subj_id),
            "subject_table": subj_table, "subject_id": subj_id,
            "asset_host": asset_host,
            "priority": r["priority"], "claimed_by": r["claimed_by"],
            "summary": (r["summary"] or "")[:160],
            "next_action": (r["next_action"] or "")[:160],
            "blocker_reason": (r["blocker_reason"] or "")[:160],
        })
    return {"items": items}


def _assets(conn, target: str) -> dict:
    cols = [r[1] for r in conn.execute("PRAGMA table_info(target_assets)").fetchall()]
    pick = [c for c in ("id", "asset_value", "asset_type", "port", "protocol", "live_status", "scope_status",
                        "tech_stack", "resolved_ip", "source", "auth_required", "login_urls") if c in cols]
    sel = ", ".join(pick) if pick else "asset_value"
    rows = conn.execute(
        f"SELECT {sel} FROM target_assets WHERE target_name=? ORDER BY id", (target,)
    ).fetchall()
    assets = [{c: r[c] for c in pick} for r in rows]
    # 每资产 endpoint 计数（按 host 匹配）
    host_counts = {}
    for row in conn.execute(
        "SELECT host, COUNT(*) c FROM endpoint_observations WHERE target_name=? GROUP BY host", (target,)
    ).fetchall():
        if row["host"]:
            host_counts[row["host"]] = row["c"]
    for a in assets:
        a["endpoint_count"] = host_counts.get(a.get("asset_value"), 0)
    # endpoint_observations 统计(信息收集面)
    ep_count = conn.execute(
        "SELECT COUNT(*) c FROM endpoint_observations WHERE target_name=?", (target,)
    ).fetchone()["c"]
    js_count = conn.execute(
        "SELECT COUNT(*) c FROM js_files WHERE target_name=?", (target,)
    ).fetchone()["c"] if "target_name" in [r[1] for r in conn.execute("PRAGMA table_info(js_files)").fetchall()] else 0
    return {"assets": assets, "counts": {"endpoint_observations": ep_count, "js_files": js_count}}


def _asset_detail(conn, target: str, host: str) -> dict:
    """单个资产详情：指纹/端口/已探测目录(endpoints)/相关队列/相关 findings。"""
    cols = [r[1] for r in conn.execute("PRAGMA table_info(target_assets)").fetchall()]
    pick = [c for c in ("id", "asset_value", "asset_type", "port", "protocol", "live_status", "scope_status",
                        "tech_stack", "resolved_ip", "source", "auth_required", "login_urls",
                        # 2026-08-15 详情页新增字段
                        "notes", "last_title", "last_status_code", "last_tech_stack", "last_verified_at",
                        "last_verify_status", "scope_reason", "auth_blocker", "relation_to_target",
                        "authorization_state", "register_urls", "requires_auth", "status", "priority")
                if c in cols]
    sel = ", ".join(pick) if pick else "asset_value"
    arow = conn.execute(
        f"SELECT {sel} FROM target_assets WHERE target_name=? AND asset_value=? ORDER BY id LIMIT 1",
        (target, host),
    ).fetchone()
    if not arow:
        return {"asset": None, "endpoints": [], "queue": [], "findings": [], "note": f"no asset {host}"}
    asset = {c: arow[c] for c in pick}
    # 已探测端点（按 host 匹配 + 去同一条 host 下所有端口）
    hosts = [host]
    if arow["resolved_ip"]:
        hosts.append(arow["resolved_ip"])
    qmarks = ",".join("?" for _ in hosts)
    eps = conn.execute(
        f"""SELECT canonical_url, host, path, method, source, status_code, content_type,
                   business_hint, route_kind, service_hint, auth_state, waf_state, test_status
            FROM endpoint_observations
            WHERE target_name=? AND host IN ({qmarks})
            ORDER BY observed_count DESC, id DESC LIMIT 200""",
        (target, *hosts),
    ).fetchall()
    endpoints = [dict(e) for e in eps]
    # 相关队列（统一归属：数字 id / 资产名 / 关联表 host 都能归到该资产）
    resolver = AssetResolver(conn, target)
    qrows = conn.execute(
        """SELECT id, lane, subtype, title, objective, status, priority, subject_table, subject_id
           FROM work_items WHERE target_name=?
           ORDER BY COALESCE(priority,0) DESC LIMIT 300""",
        (target,),
    ).fetchall()
    queue = []
    for q in qrows:
        qaid = resolver.resolve(q["subject_table"], q["subject_id"], f"{q['title'] or ''} {q['objective'] or ''}")
        if qaid != arow["id"]:
            continue
        dt, dh = _derive_display(q["objective"], q["title"])
        queue.append({
            "id": q["id"], "lane": q["lane"], "subtype": q["subtype"],
            "title": dt, "hint": dh, "status": q["status"], "priority": q["priority"],
            "asset_host": resolver.asset_value_of(qaid),
            # 相关队列可点击：补 url（subject 解析）供跳转
            "url": _resolve_url(conn, q["subject_table"], q["subject_id"]),
        })
        if len(queue) >= 30:
            break
    # 相关 findings（按 url 包含 host）
    frows = conn.execute(
        """SELECT id, type, url, param, method, risk, review_status, confirmed_at
           FROM findings WHERE url LIKE ? ORDER BY id LIMIT 20""",
        (f"%{host}%",),
    ).fetchall()
    findings = [dict(f) for f in frows]
    # 该资产的灵感(只读):显式 asset_id 或从 blocked_on 追溯兜底
    asset_id = None
    if "id" in arow.keys():
        asset_id = arow["id"]
    if asset_id is None:
        row_a = conn.execute(
            "SELECT id FROM target_assets WHERE target_name=? AND asset_value=? ORDER BY id LIMIT 1",
            (target, host),
        ).fetchone()
        asset_id = int(row_a["id"]) if row_a else None
    inspirations = (
        build_asset_inspirations(conn, target_name=target, asset_id=asset_id).get("inspirations", [])
        if asset_id is not None
        else []
    )
    return {
        "asset": asset,
        "endpoints": endpoints,
        "queue": queue,
        "findings": findings,
        "inspirations": inspirations,
    }


def _findings(conn, target: str) -> dict:
    # conn 已由 find_db(target) 定位到目标库，findings 即该目标的成果，
    # 不再 JOIN targets（大量历史行 target_id 为 NULL 会被 WHERE 过滤丢失，
    # 其中含 critical 级证据）。补充详情字段供前端详情页展示；大字段截断。
    rows = conn.execute(
        """SELECT f.id, f.type, f.url, f.param, f.method, f.risk, f.review_status, f.confirmed_at,
                  f.report_file, f.audit_status, f.cvss, f.remediation, f.review_notes, f.audit_notes,
                  f.reported_platforms, f.sp_id,
                  substr(f.payload, 1, 500) AS payload,
                  substr(f.evidence, 1, 800) AS evidence
           FROM findings f
           ORDER BY CASE f.risk WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END, f.id
           LIMIT 80""",
    ).fetchall()
    return {"findings": [dict(r) for r in rows]}


def _sp_detail(conn, target: str, sp_id: str) -> dict:
    """疑点详情：suspicious_points 全字段（reasoning/evidence/response_summary/notes 等）。"""
    cols = [r[1] for r in conn.execute("PRAGMA table_info(suspicious_points)").fetchall()]
    pick = [c for c in ("id", "url", "page_url", "param", "method", "test_type", "evidence",
                        "reasoning", "risk", "test_status", "source", "notes", "created_at",
                        "endpoint_fingerprint", "response_summary", "risk_score",
                        "auth_surface_type", "signal_value", "signal_reason", "noise_reason",
                        "canonical_url")
            if c in cols]
    sel = ", ".join(pick) if pick else "id"
    row = conn.execute(
        f"SELECT {sel} FROM suspicious_points WHERE id=?", (sp_id,)
    ).fetchone()
    if not row:
        return {"sp": None, "note": f"no suspicious point {sp_id}"}
    sp = {c: row[c] for c in pick}
    # 关联的 findings（同 url 或 sp_id 关联）
    frows = conn.execute(
        """SELECT id, type, url, risk, review_status FROM findings
           WHERE sp_id=? OR (url IS NOT NULL AND url=?)
           LIMIT 10""",
        (sp_id, sp.get("url")),
    ).fetchall()
    sp["findings"] = [dict(f) for f in frows]
    # 大字段截断（evidence 可能是长 JSON）
    for k in ("evidence", "notes", "response_summary"):
        if sp.get(k) and len(str(sp[k])) > 1200:
            sp[k] = str(sp[k])[:1200] + "…"
    return {"sp": sp}


# 渐进式披露阶段链（顺序即披露推进方向）
DISCLOSURE_STAGES = [
    ("source_intel", "情报收集"),
    ("origin_verify", "归属验证"),
    ("quick_scout", "快速侦察"),
    ("network_profile", "端口/服务面"),
    ("entry_probe", "入口探测"),
    ("js_reverse", "JS 逆向"),
    ("preauth_probe", "未授权探测"),
    ("logic_probe", "逻辑漏洞"),
    ("vuln_review", "漏洞复核"),
    ("evidence_pack", "证据打包"),
    ("report_audit", "报告审核"),
]
# 其他 lane（asset_triage/entry_explore/operator_task/replay 等）归入"待分类"，不占阶段链
STAGE_KEYS = {s[0] for s in DISCLOSURE_STAGES}


def _stage_state(statuses: list[str]) -> str:
    """一个阶段多个 work_item 状态 → 单一状态：
    blocked 优先(卡住) > doing(claimed/partial) > done > queued > 无。
    """
    if not statuses:
        return "none"
    if any(s == "blocked" for s in statuses):
        # 有 blocked 且有 done 说明部分完成但仍卡 → 优先卡
        return "blocked"
    if any(s in ("claimed", "partial") for s in statuses):
        return "doing"
    if any(s == "done" for s in statuses):
        return "done"
    if any(s == "queued" for s in statuses):
        return "queued"
    return "none"


def _disclose_group(stages: dict[str, str], has_findings: bool) -> str:
    """资产披露分组：已打穿 / 进行中 / 卡住 / 未开始。"""
    states = [stages.get(k, "none") for k, _ in DISCLOSURE_STAGES]
    if any(s == "blocked" for s in states):
        return "blocked"  # 卡住
    if has_findings or any(s == "done" for s in states[-4:]):  # vm/vuln_review/evidence/report 阶段有 done
        return "penetrated"  # 已打穿(有产出或深阶段完成)
    if any(s in ("doing", "done") for s in states):
        return "progress"  # 进行中
    if any(s == "queued" for s in states):
        return "queued"  # 已排队待开始
    return "untouched"  # 未开始


def _disclosure(conn, target: str) -> dict:
    """按资产聚合渐进式披露进度：每个资产 → 各阶段状态 + 最深阶段 + 卡点 + 价值。

    2026-08-15 修复：work_items 归属不再只认 subject_table='target_assets' 的数字 id。
    历史数据有三类关联方式，全部支持：
      A. subject_table='target_assets' 且 subject_id 是数字 id（JOIN target_assets.id）
      B. subject_table='target_assets' 但 subject_id 是资产名（JOIN target_assets.asset_value）
      C. subject_table 是 js_files/js_signal_clusters/suspicious_points/findings/pages/
         endpoint_observations/coverage_ledger 等 → 通过关联表 url/asset_id 取 host → 匹配资产
    """
    # 1. 资产列表
    acols = [r[1] for r in conn.execute("PRAGMA table_info(target_assets)").fetchall()]
    apick = [c for c in ("id", "asset_value", "asset_type", "port", "protocol", "live_status",
                         "scope_status", "tech_stack", "resolved_ip", "source", "auth_required") if c in acols]
    asel = ", ".join(apick)
    assets = conn.execute(
        f"SELECT {asel} FROM target_assets WHERE target_name=? ORDER BY id", (target,)
    ).fetchall()
    assets = [dict(a) for a in assets]

    # 2. 每个资产的所有 work_item 状态（按 lane 聚合，统一归属）
    resolver = AssetResolver(conn, target)
    wrows = conn.execute(
        """SELECT w.id, w.subject_table, w.subject_id, w.lane, w.status, w.title, w.objective,
                  w.blocker_reason
           FROM work_items w WHERE w.target_name=?""",
        (target,),
    ).fetchall()

    from collections import defaultdict  # noqa: E402
    per_asset = defaultdict(lambda: defaultdict(lambda: {"statuses": [], "items": []}))

    for wr in wrows:
        lane = wr["lane"]
        aid = resolver.resolve(
            wr["subject_table"], wr["subject_id"],
            f"{wr['title'] or ''} {wr['objective'] or ''}",
        )
        if aid is None:
            continue  # 归属不了（如 targets 级任务）→ 不进资产
        pa = per_asset[aid]
        pa[lane]["statuses"].append(wr["status"])
        pa[lane]["items"].append({
            "id": wr["id"], "lane": lane, "status": wr["status"],
            "title": wr["title"] or "", "objective": (wr["objective"] or "")[:120],
            "blocker_reason": (wr["blocker_reason"] or "")[:160],
        })

    # 3. findings / suspicious_points 按 host 关联
    frows = conn.execute(
        """SELECT f.url, f.type, f.risk FROM findings f JOIN targets t ON t.id=f.target_id
           WHERE t.target_name=? ORDER BY f.id""", (target,)
    ).fetchall()
    sprows = conn.execute(
        """SELECT id, url, test_type, risk, test_status, reasoning FROM suspicious_points
           WHERE test_status IN ('untested','confirmed')""",
    ).fetchall()
    f_by_host = defaultdict(list)
    for f in frows:
        host = _host_of(f["url"])
        if host:
            f_by_host[host].append({"type": f["type"], "risk": f["risk"], "url": f["url"]})
    sp_by_host = defaultdict(list)
    for sp in sprows:
        host = _host_of(sp["url"])
        if host:
            sp_by_host[host].append({
                "id": sp["id"], "test_type": sp["test_type"], "risk": sp["risk"],
                "url": sp["url"], "status": sp["test_status"],
                "reasoning": (sp["reasoning"] or "")[:120],
            })

    # 4. endpoint 计数按 host
    ep_by_host = defaultdict(int)
    for r in conn.execute(
        "SELECT host, COUNT(*) c FROM endpoint_observations WHERE target_name=? GROUP BY host", (target,)
    ).fetchall():
        if r["host"]:
            ep_by_host[r["host"]] = r["c"]

    # 5. 组装每个资产
    out = []
    for a in assets:
        aid = a["id"]
        host = a["asset_value"] or ""
        lane_map = per_asset.get(aid, {})
        stages = {}
        for key, label in DISCLOSURE_STAGES:
            st = _stage_state(lane_map.get(key, {}).get("statuses", []))
            stages[key] = st
        # 最深推进阶段
        deepest = None
        deepest_idx = -1
        for i, (key, label) in enumerate(DISCLOSURE_STAGES):
            if stages[key] in ("done", "doing", "blocked"):
                deepest = key
                deepest_idx = i
        # 卡点（第一个 blocked 阶段）
        stuck = None
        for key, label in DISCLOSURE_STAGES:
            if stages[key] == "blocked":
                stuck = key
                break
        fs = f_by_host.get(host, [])
        sps = sp_by_host.get(host, [])
        group = _disclose_group(stages, bool(fs))
        out.append({
            "id": aid, "asset_value": host, "asset_type": a["asset_type"],
            "port": a["port"], "protocol": a["protocol"], "live_status": a["live_status"],
            "scope_status": a["scope_status"], "tech_stack": a["tech_stack"],
            "resolved_ip": a["resolved_ip"],
            "stages": stages,
            "stage_labels": [lbl for _, lbl in DISCLOSURE_STAGES],
            "deepest_stage": deepest,
            "deepest_index": deepest_idx,
            "stuck_stage": stuck,
            "group": group,
            "findings": fs,
            "suspicious_points": sps,
            "endpoint_count": ep_by_host.get(host, 0),
        })
    # 排序：分组优先级（blocked > progress > penetrated > queued > untouched），组内按端点/价值
    group_order = {"blocked": 0, "progress": 1, "penetrated": 2, "queued": 3, "untouched": 4}
    out.sort(key=lambda x: (group_order.get(x["group"], 9), -(x["endpoint_count"] or 0)))
    return {"assets": out, "stages": [{"key": k, "label": l} for k, l in DISCLOSURE_STAGES]}


def _host_of(url: str | None) -> str:
    """从 url 提取 host（去端口）。"""
    if not url:
        return ""
    s = url.strip()
    # 去掉协议
    if "://" in s:
        s = s.split("://", 1)[1]
    # 取到第一个 / 或 : 之前
    for sep in ("/", ":", "?"):
        if sep in s:
            s = s.split(sep, 1)[0]
    return s


def _host_from_text(text: str) -> str:
    """从自由文本提取 host（用于 coverage_ledger 等无 url 字段的 work_item title）。

    匹配域名（含多级/端口）或 IP，去端口；取第一个命中。
    """
    import re  # noqa: E402
    if not text:
        return ""
    m = re.search(r"(?:https?://)?([A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?)+)(?::\d+)?", text)
    if not m:
        return ""
    return _host_of(m.group(1))


def _has_col(conn, table: str, col: str) -> bool:
    return col in [r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]


BLOCKER_CLASS_ZH = {
    "auth_barrier": "认证拦截",
    "network": "网络不可达",
    "scope": "超范围",
    "operator_required": "待操作员",
    "other": "其他",
    "": "未分类",
}


def _summarize_blocker(reason: str) -> str:
    """把英文网络类 blocker_reason 提炼成一句中文结论；已含中文的直接保留。

    仅当原文以英文为主（含 unreachable/NXDOMAIN/TLS/TCP 等网络关键词）时做映射。
    """
    r = (reason or "").strip()
    if not r:
        return ""
    # 已含中文（常见安全日志是中文+英文术语混杂），直接返回原文，只截断过长的
    has_cn = any("\u4e00" <= ch <= "\u9fff" for ch in r)
    if has_cn:
        return r[:220]
    # 纯英文 → 提取关键结论
    low = r.lower()
    if "nslookup" in low or "nxdomain" in low or "no live host" in low:
        return "域名无法解析(NXDOMAIN)，无存活主机可探测"
    if "tls handshake" in low or "ssl" in low:
        return "TLS 握手失败，HTTPS 服务无法建立连接"
    if "unreachable" in low or "refused" in low or "closed" in low:
        return "端口不可达/连接被拒绝，无法进行入口探测"
    if "subagent" in low and ("fail" in low or "error" in low):
        return "子代理调用失败，需主会话接管"
    return r[:220]


def _blockers(conn, target: str) -> dict:
    """当前资产堵点/进展: blocked work_items + operator inbox + coverage 账本。"""
    wcols = [r[1] for r in conn.execute("PRAGMA table_info(work_items)").fetchall()]
    pick = [c for c in ("id", "lane", "title", "blocker_reason", "blocker_class", "status", "updated_at") if c in wcols]
    sel = ", ".join(pick) if pick else "id"
    blocked = conn.execute(
        f"SELECT {sel} FROM work_items WHERE target_name=? AND status IN ('blocked','failed') "
        "ORDER BY updated_at DESC LIMIT 30",
        (target,),
    ).fetchall()
    inbox = conn.execute(
        """SELECT kind, title, detail, url, status, created_at
           FROM operator_inbox WHERE target_name=? AND status='open' ORDER BY id DESC LIMIT 20""",
        (target,),
    ).fetchall()
    coverage = conn.execute(
        """SELECT category, item_key, status FROM coverage_ledger
           WHERE target_name=? AND status IN ('blocked','unknown','uncovered')
           ORDER BY id DESC LIMIT 40""",
        (target,),
    ).fetchall()
    # 进展: 最近 worker 结果（JOIN work_items 按目标过滤并补 lane）
    progress = conn.execute(
        """SELECT e.agent_id, e.event_type, e.payload_json, e.created_at, w.lane
           FROM agent_events e LEFT JOIN work_items w ON w.id=e.work_item_id
           WHERE w.target_name=? AND e.event_type IN ('partial_result','done','blocked')
           ORDER BY e.id DESC LIMIT 15""",
        (target,),
    ).fetchall()
    progress_rows = []
    for p in progress:
        try:
            pj = json.loads(p["payload_json"]) if p["payload_json"] else {}
        except Exception:
            pj = {}
        progress_rows.append({
            "agent": p["agent_id"], "event": p["event_type"],
            "lane": p["lane"] or "",
            "status": pj.get("status", p["event_type"]),
            "conclusion": (pj.get("conclusion") or "")[:200],
            "time": p["created_at"],
        })
    blocked_out = []
    for r in blocked:
        d = dict(r)
        d["class_zh"] = BLOCKER_CLASS_ZH.get(d.get("blocker_class") or "", "未分类")
        d["reason_zh"] = _summarize_blocker(d.get("blocker_reason") or "")
        blocked_out.append(d)
    return {
        "blocked_items": blocked_out,
        "operator_inbox": [dict(r) for r in inbox],
        "coverage_blocked": [dict(r) for r in coverage],
        "progress": progress_rows,
        "counts": {"blocked": len(blocked), "inbox": len(inbox), "coverage": len(coverage)},
    }


def _view(conn, target: str) -> dict:
    """五视图总数据: 复用 blackboard_view 聚合 + 补充 chain/state 派生。"""
    payload = build_blackboard_view(conn, target_name=target)
    # state 层: system/session/thread/experiment
    state = {
        "system": payload.get("human_brief", {}).get("current_system") or {},
        "focus_session": payload.get("human_brief", {}).get("focus_session") or {},
        "active_threads": payload.get("attack_threads", []),
        "cognitive": payload.get("cognitive_loop", {}),
    }
    # chain 层: suspicious_points / findings 摘要
    sp = conn.execute(
        """SELECT id, url, test_type, risk, test_status, source FROM suspicious_points
           WHERE test_status IN ('untested','confirmed') ORDER BY id DESC LIMIT 60"""
    ).fetchall()
    chain = {
        "suspicious_points": [dict(r) for r in sp],
        "findings": _findings(conn, target).get("findings", []),
        "attack_threads": payload.get("attack_threads", []),
    }

    # 时间线：直接从 agent_events 取全量事件（2026-08-15 重构，替代 blackboard_view 的薄数据）
    # agent_events 无 target_name/lane 列，经 work_items JOIN 过滤目标并补 lane；asset 经 AssetResolver 补
    resolver = AssetResolver(conn, target)
    recent_events = conn.execute(
        """SELECT e.id, e.work_item_id, e.agent_id, e.event_type, e.severity, e.created_at,
                  substr(e.payload_json, 1, 300) AS payload_json,
                  w.lane, w.status AS wi_status, w.subject_table, w.subject_id, w.title, w.objective
           FROM agent_events e LEFT JOIN work_items w ON w.id=e.work_item_id
           WHERE w.target_name=?
           ORDER BY e.id DESC LIMIT 60""",
        (target,),
    ).fetchall()
    # worker 结果：done/partial/blocked 且带结论的（从 payload_json 解析 status/conclusion）
    worker_rows = conn.execute(
        """SELECT e.id, e.work_item_id, e.agent_id, e.event_type, e.created_at, e.payload_json,
                  w.lane, w.subject_table, w.subject_id, w.title, w.objective
           FROM agent_events e LEFT JOIN work_items w ON w.id=e.work_item_id
           WHERE w.target_name=? AND e.event_type IN ('done','partial_result','blocked','heartbeat')
           ORDER BY e.id DESC LIMIT 40""",
        (target,),
    ).fetchall()
    workers = []
    for w in worker_rows:
        try:
            pj = json.loads(w["payload_json"]) if w["payload_json"] else {}
        except Exception:
            pj = {}
        wr = pj.get("worker_result") or {}
        # 关联资产（work_item → asset）
        wi_text = f"{w['title'] or ''} {w['objective'] or ''}"
        wia = resolver.resolve(w["subject_table"], w["subject_id"], wi_text)
        workers.append({
            "id": w["id"], "work_item_id": w["work_item_id"], "agent_id": w["agent_id"],
            "lane": w["lane"] or wr.get("lane") or "", "event_type": w["event_type"],
            "created_at": w["created_at"],
            "status": (wr.get("status") or pj.get("status") or w["event_type"]),
            "conclusion": (wr.get("conclusion") or pj.get("conclusion")
                           or pj.get("summary") or "")[:500],
            "confidence": wr.get("confidence") or pj.get("confidence") or "",
            "next_action": (wr.get("next_action") or pj.get("next_action") or "")[:300],
            "block_reason": (wr.get("block_reason") or pj.get("block_reason") or "")[:300],
            "asset_host": resolver.asset_value_of(wia),
            "wi_title": (w["title"] or "")[:120],
        })
    # 事件流也补 asset_host + 中文标题
    events_out = []
    for e in recent_events:
        e_text = f"{e['title'] or ''} {e['objective'] or ''}"
        eia = resolver.resolve(e["subject_table"], e["subject_id"], e_text)
        events_out.append({
            "id": e["id"], "work_item_id": e["work_item_id"], "agent_id": e["agent_id"],
            "event_type": e["event_type"], "severity": e["severity"], "created_at": e["created_at"],
            "lane": e["lane"] or "", "wi_status": e["wi_status"],
            "payload_json": e["payload_json"],
            "asset_host": resolver.asset_value_of(eia),
            "wi_title": (e["title"] or "")[:120],
        })
    # 下一步：队列里未认领的高优先级 + operator inbox 未处理
    nxt = conn.execute(
        """SELECT id, lane, title, objective, priority, status FROM work_items
           WHERE target_name=? AND status='queued'
           ORDER BY COALESCE(priority,0) DESC, id LIMIT 15""",
        (target,),
    ).fetchall()
    next_actions = []
    for n in nxt:
        dt, _dh = _derive_display(n["objective"], n["title"])
        next_actions.append({
            "work_item_id": n["id"], "lane": n["lane"], "title": dt,
            "priority": n["priority"] or 0,
        })

    return {
        "overview": {
            "work_summary": payload.get("work_summary", {}),
            "soft_targets": payload.get("soft_targets", {}),
            "operator_inbox": payload.get("operator_inbox", []),
            "worker_results": payload.get("recent_worker_results", []),
            "attack_surface": payload.get("attack_surface", {}),
            "next_actions": payload.get("next_recommended_actions", []),
        },
        "state": state,
        "chain": chain,
        "timeline": {
            "recent_events": events_out,
            "recent_worker_results": workers,
            "next_actions": next_actions,
            "cognitive_next": payload.get("cognitive_loop", {}).get("next_candidates", []),
        },
        "recon": payload.get("recon", {}),
    }


def _state_machine(conn, target: str, asset: str = "") -> dict:
    """状态机视图（spec 6.2）：业务流节点图 JSON，供看板画节点图。

    节点颜色 = step_status；堵点=blocked 步骤 + blocked_reason；发现=exploited 步骤。
    复用 business_flow_view.build_flow_graph（只读；模板 seed 走 CLI：
    uv run python TOOLS/db/business_flow_view.py --target <目标> --seed-templates）。
    """
    asset_id = None
    if asset:
        try:
            asset_id = int(asset)
        except ValueError:
            row = conn.execute(
                "SELECT id FROM target_assets WHERE asset_value=? AND target_name=? ORDER BY id LIMIT 1",
                (asset, target),
            ).fetchone()
            asset_id = row["id"] if row else None
    return build_flow_graph(conn, target_name=target, asset_id=asset_id)


def _insight_wall(conn, target: str, recommended: bool = False) -> dict:
    """灵感墙:只读聚合 6 类未闭环悬点 + 堵点→灵感精确挂载。

    `recommended=True` 时按 score_insight 降序(roadmap §3 优先推荐,默认关)。
    """
    sort = "recommended" if recommended else None
    return build_insight_wall(conn, target_name=target, sort=sort)


def _insight_chains(conn, target: str) -> dict:
    """堵点图谱/因果链全览:同 target 全览所有灵感的 refined_from + blocked_on(只读)。"""
    return build_insight_chains(conn, target_name=target)


def _insight_detail(conn, target: str, insight_id) -> dict:
    """单条灵感的完整前因后果(只读)。id 取首个非空参数,归一为字符串比较。"""
    id_raw = insight_id
    if isinstance(id_raw, list):
        id_raw = id_raw[0] if id_raw else ""
    if id_raw is None or id_raw == "":
        return {"found": False, "error": "missing insight id"}
    # 灵感 id 是 INTEGER;数字字符串转 int 提升命中率
    try:
        normalized = int(id_raw)
    except (TypeError, ValueError):
        normalized = id_raw
    return build_insight_detail(conn, target_name=target, insight_id=normalized)


class Handler(BaseHTTPRequestHandler):
    def _send_json(self, payload: dict, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _serve_static(self, path: str) -> None:
        """托管 web/dist 构建产物；SPA fallback 到 index.html（2026-08-15 补）。"""
        if path in ("", "/"):
            rel = Path("index.html")
        else:
            rel = Path(path.lstrip("/"))
        file = (DIST_DIR / rel).resolve()
        # 防目录穿越：必须仍在 DIST_DIR 内
        if not str(file).startswith(str(DIST_DIR.resolve())) or not file.is_file():
            file = DIST_DIR / "index.html"
        if not file.exists():
            self.send_error(404, "frontend not built — run: cd warroom/web && npm run build")
            return
        ctype = mimetypes.guess_type(str(file))[0] or "application/octet-stream"
        body = file.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def _conn(self, target: str) -> sqlite3.Connection | None:
        try:
            db = find_db(target)
        except BaseException:
            # find_db 命中失败会 sys.exit()（SystemExit 继承 BaseException）；
            # 在 HTTP handler 内绝不能让其杀死线程，这里兜底返回 None。
            return None
        if not db:
            return None
        return connect(db)

    def do_GET(self) -> None:  # noqa: C901
        parsed = urlparse(self.path)
        path = parsed.path
        # 用 parse_qs 正确做 URL 解码（含 UTF-8 中文目标名）
        qs = parse_qs(parsed.query)
        target = (qs.get("target", [""])[0]) if qs.get("target") else ""

        # 静态文件：dist 构建产物（2026-08-15 补，使 8787 单端口直接出页面）
        if not path.startswith("/api"):
            self._serve_static(path)
            return

        try:
            # 目标列表(无 target 依赖)
            if path == "/api/targets":
                self._send_json({"targets": _targets()})
                return
            if not target:
                self._send_json({"error": "missing target param"}, 400)
                return
            conn = self._conn(target)
            if not conn:
                self._send_json({"error": f"no DB for target={target}"}, 404)
                return
            try:
                if path == "/api/view":
                    self._send_json(_view(conn, target))
                elif path == "/api/queue":
                    self._send_json(_queue(conn, target))
                elif path == "/api/assets":
                    self._send_json(_assets(conn, target))
                elif path == "/api/findings":
                    self._send_json(_findings(conn, target))
                elif path == "/api/blockers":
                    self._send_json(_blockers(conn, target))
                elif path == "/api/asset":
                    host = (qs.get("host", [""])[0]) if qs.get("host") else ""
                    self._send_json(_asset_detail(conn, target, host))
                elif path == "/api/sp":
                    sp_id = (qs.get("id", [""])[0]) if qs.get("id") else ""
                    self._send_json(_sp_detail(conn, target, sp_id))
                elif path == "/api/disclosure":
                    self._send_json(_disclosure(conn, target))
                elif path == "/api/state-machine":
                    asset = (qs.get("asset", [""])[0]) if qs.get("asset") else ""
                    self._send_json(_state_machine(conn, target, asset))
                elif path == "/api/insight-wall":
                    rec = (qs.get("recommended", [""])[0]) if qs.get("recommended") else ""
                    self._send_json(_insight_wall(conn, target, recommended=rec in ("1", "true", "yes")))
                elif path == "/api/insight-chains":
                    self._send_json(_insight_chains(conn, target))
                elif path == "/api/insight-detail":
                    ins_id = (qs.get("id", [""])[0]) if qs.get("id") else ""
                    self._send_json(_insight_detail(conn, target, ins_id))
                else:
                    self._send_json({"error": "not found"}, 404)
            finally:
                conn.close()
        except Exception as exc:  # noqa: BLE001
            self._send_json({"error": f"{type(exc).__name__}: {exc}"}, 500)

    def log_message(self, fmt: str, *args) -> None:
        pass


def main() -> int:
    parser = argparse.ArgumentParser(description="SRC 实时作战室 Dashboard(只读, VSCode 风格)")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument(
        "--host", default="127.0.0.1",
        help="监听地址;默认 127.0.0.1(仅本机)。局域网/手机访问用 0.0.0.0",
    )
    args = parser.parse_args()

    targets = _targets()
    if not targets:
        print("[warroom] dbs/ 下没有目标库", file=sys.stderr)
        return 1

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"[warroom] http://{args.host}:{args.port}  (Ctrl+C 停止)")
    print(f"[warroom] 可用目标 {len(targets)} 个: {', '.join(t['target'] for t in targets[:5])}...")
    if not (DIST_DIR / "index.html").exists():
        print("[warroom] 警告: 前端未构建, 请先 cd warroom/web && npm install && npm run build")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[warroom] 停止")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
