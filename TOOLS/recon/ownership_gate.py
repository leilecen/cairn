"""股权穿透归属门控 — 防止信息收集把无关资产入库。

信息收集（FOFA/ZoomEye/subfinder/amass/邻居反查等）发现的资产在写入
`target_assets` 前必须先过本门控：只有根域直连、或能通过股权穿透链
（天眼查 equity-tree / actual-controller / beneficial-owners）关联到目标
企业的资产才允许进入队列；明确无关或无法归属的资产只保留被动事实
（intel_only / out_of_scope），绝不入扫描队列。

分类结果（scope_status / scope_class / authorization_state / relation_to_target）：
- direct      → in_scope / owned / authorized / root_domain
- affiliated  → needs_review / owned / unknown / equity_affiliate（操作员 scope_cluster 确认）
- unrelated   → out_of_scope / intel_only / revoked / unrelated（保留事实，禁止扫描）
- unverified  → needs_review / intel_only / unknown / unverified（无归属信号，需人工判定）

股权链持久化：复用 recon_sources（source_kind=tianyan_equity-tree 等），不新增表。
门控不删除任何证据；只调整 scope/eligibility 状态。
"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
from pathlib import Path
from typing import Any, Iterable

try:
    from .recon_intel import run_tianyan_company
    from .recon_store import record_source
except ImportError:  # pragma: no cover - direct script execution
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from recon_intel import run_tianyan_company  # type: ignore[no-redef]  # 回退分支与包内导入同一批名字
    from recon_store import record_source  # type: ignore[no-redef]  # 回退分支与包内导入同一批名字

TIANYAN_KINDS = ("equity-tree", "actual-controller", "beneficial-owners")

# 归属判定结果
DIRECT = "direct"
AFFILIATED = "affiliated"
UNRELATED = "unrelated"
UNVERIFIED = "unverified"

_SCOPE_COLUMNS = {
    "scope_status": "TEXT DEFAULT 'needs_review'",
    "scope_reason": "TEXT",
    "scope_class": "TEXT DEFAULT 'unknown'",
    "authorization_state": "TEXT DEFAULT 'unknown'",
    "relation_to_target": "TEXT",
}


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}  # noqa: S608 - fixed table


def ensure_scope_columns(conn: sqlite3.Connection) -> None:
    """target_assets 存在 scope 相关列（与 init_scan 保持同一套列）。"""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS target_assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_name TEXT NOT NULL,
            asset_type TEXT DEFAULT 'domain',
            asset_value TEXT NOT NULL,
            port INTEGER,
            protocol TEXT DEFAULT 'https',
            source TEXT DEFAULT 'manual',
            status TEXT DEFAULT 'new',
            scope_status TEXT DEFAULT 'needs_review',
            scope_reason TEXT,
            scope_class TEXT DEFAULT 'unknown',
            authorization_state TEXT DEFAULT 'unknown',
            relation_to_target TEXT
        )
        """
    )
    conn.execute(
        """CREATE UNIQUE INDEX IF NOT EXISTS idx_target_assets_identity
           ON target_assets(target_name, asset_value, COALESCE(port, 443))"""
    )
    existing = _columns(conn, "target_assets")
    for name, ddl in _SCOPE_COLUMNS.items():
        if name not in existing:
            conn.execute(f"ALTER TABLE target_assets ADD COLUMN {name} {ddl}")  # noqa: S608 - fixed column list
    conn.commit()


# --------------------------------------------------------------------------
# 股权链
# --------------------------------------------------------------------------


def _chain_name_key(name: str) -> str:
    """归一化公司名：去空白/括号/公司后缀，便于包含匹配。"""
    text = re.sub(r"[（(].*?[)）]", "", str(name or ""))
    text = re.sub(r"(公司|集团|有限公司|股份有限公司|有限责任公司|股份公司)", "", text)
    return re.sub(r"\s+", "", text)


def load_corporate_chain(conn: sqlite3.Connection, *, target_name: str, company: str = "") -> dict[str, Any]:
    """从 recon_sources 读回天眼查股权结果，聚合成企业链。

    返回 {"company": 目标企业, "relations": [{name, relation_type}], "names": {归一化名: 关系}}
    """
    relations: list[dict[str, str]] = []
    names: dict[str, str] = {}
    if not any(row[0] == "recon_sources" for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()):
        # 尚未录过任何 source：fail-safe，只靠根域直连判定
        return {"company": company, "relations": relations, "names": names}
    query = company or None
    if query:
        row = conn.execute(
            """SELECT result_json FROM recon_sources
               WHERE target_name=? AND source_kind IN
                 ('tianyan_equity-tree','tianyan_actual-controller','tianyan_beneficial-owners')
                 AND query=? ORDER BY id DESC LIMIT 1""",
            (target_name, query),
        ).fetchone()
        if row:
            _collect_relations(json.loads(row[0]), relations, names)
    if not relations:
        for source_kind, q in conn.execute(
            """SELECT source_kind, query FROM recon_sources
               WHERE target_name=? AND source_kind LIKE 'tianyan_%' ORDER BY id DESC LIMIT 20""",
            (target_name,),
        ).fetchall():
            row = conn.execute(
                "SELECT result_json FROM recon_sources WHERE target_name=? AND source_kind=? AND query=? LIMIT 1",
                (target_name, source_kind, q),
            ).fetchone()
            if row:
                _collect_relations(json.loads(row[0]), relations, names)
    return {"company": company, "relations": relations, "names": names}


def _collect_relations(payload: dict[str, Any], relations: list[dict[str, str]], names: dict[str, str]) -> None:
    """从天眼查 compact 响应里提取关联公司名（兼容多种响应形态）。"""
    result = payload.get("result") if isinstance(payload, dict) else None
    candidates: list[dict[str, Any]] = []
    if isinstance(result, dict):
        for key in ("data", "items", "list", "relations", "equityTree", "equity-tree"):
            value = result.get(key)
            if isinstance(value, list):
                candidates.extend(item for item in value if isinstance(item, dict))
    elif isinstance(payload.get("data"), list):
        candidates.extend(item for item in payload["data"] if isinstance(item, dict))
    for item in candidates:
        name = item.get("name") or item.get("companyName") or item.get("company") or item.get("subCompanyName")
        relation = str(item.get("relation_type") or item.get("relation") or item.get("type") or item.get("equityRatio") or "related")
        if name:
            key = _chain_name_key(name)
            if key:
                relations.append({"name": str(name), "relation_type": relation})
                names.setdefault(key, relation)


# --------------------------------------------------------------------------
# 资产分类
# --------------------------------------------------------------------------


def _host_suffix(host: str) -> str:
    value = (host or "").strip().lower()
    value = re.sub(r"^[a-z]+://", "", value)
    value = value.split("/", 1)[0]
    value = re.sub(r":\d+$", "", value)
    return value.rstrip(".")


def _matches_root(host: str, domain: str, root_domains: Iterable[str]) -> bool:
    suffix = _host_suffix(host)
    dom = _host_suffix(domain)
    for root in root_domains:
        root = _host_suffix(root)
        if not root:
            continue
        if suffix == root or suffix.endswith(f".{root}") or (dom and (dom == root or dom.endswith(f".{root}"))):
            return True
    return False


def classify_asset(
    *,
    host: str = "",
    domain: str = "",
    title: str = "",
    icp: str = "",
    root_domains: Iterable[str] = (),
    chain_names: dict[str, str] | None = None,
) -> tuple[str, str]:
    """返回 (归属类型, 依据说明)。

    归属类型 ∈ {direct, affiliated, unrelated, unverified}：
    - direct: 根域直连（host/domain 后缀命中）
    - affiliated: 文本里出现股权链企业名
    - unrelated: 文本里出现"明显是别的企业"的信号（公司/集团后缀 + 不在股权链）
    - unverified: 无任何归属信号
    """
    chain_names = chain_names or {}
    if _matches_root(host, domain, root_domains):
        return DIRECT, "root_domain"
    text = " ".join(filter(None, [host, domain, title, icp]))
    if not text.strip():
        return UNVERIFIED, "no_signal"
    matched = [key for key in chain_names if key and key in text]
    if matched:
        return AFFILIATED, f"equity:{','.join(sorted(matched)[:3])}"
    # 出现公司/集团/金融机构后缀但不在股权链 → 疑似无关主体
    if re.search(
        r"(有限公司|股份有限公司|集团|银行|保险|证券|控股|信托|基金|"
        r"bank|insurance|hospital|university|gov\.|edu\.)",
        text,
    ):
        return UNRELATED, "other_company_signal"
    return UNVERIFIED, "no_signal"


_ATTRIBUTION: dict[str, dict[str, str]] = {
    DIRECT: {
        "scope_status": "in_scope",
        "scope_class": "owned",
        "authorization_state": "authorized",
        "relation_to_target": "root_domain",
    },
    AFFILIATED: {
        "scope_status": "needs_review",
        "scope_class": "owned",
        "authorization_state": "unknown",
        "relation_to_target": "equity_affiliate",
    },
    UNRELATED: {
        "scope_status": "out_of_scope",
        "scope_class": "intel_only",
        "authorization_state": "revoked",
        "relation_to_target": "unrelated",
    },
    UNVERIFIED: {
        "scope_status": "needs_review",
        "scope_class": "intel_only",
        "authorization_state": "unknown",
        "relation_to_target": "unverified",
    },
}


# --------------------------------------------------------------------------
# 入库
# --------------------------------------------------------------------------


def _parse_asset(host: str, ip: str, port: str, protocol: str) -> tuple[str, int | None, str]:
    value = (host or "").strip()
    if value.startswith(("http://", "https://")):
        scheme, rest = value.split("://", 1)
        protocol = scheme
        host_part = rest.split("/", 1)[0]
    else:
        host_part = value.split("/", 1)[0]
    port_part: int | None = None
    m = re.search(r":(\d+)$", host_part)
    if m:
        port_part = int(m.group(1))
        host_part = host_part[: m.start()]
    if not port_part and str(port).isdigit():
        port_part = int(port)
    if not protocol:
        protocol = "https" if port_part == 443 else "http"
    return host_part or ip, port_part, protocol


def gate_fofa_payload(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    payload: dict[str, Any],
    root_domains: Iterable[str],
    chain: dict[str, Any],
    source_kind: str = "fofa",
) -> dict[str, Any]:
    """分类并 upsert FOFA 结果到 target_assets；绝不入扫描队列。

    返回 compact 统计。未配置股权链时只靠根域直连判定，其余落 needs_review/intel_only。
    """
    ensure_scope_columns(conn)
    roots = list(root_domains)
    names = chain.get("names", {})
    items = (payload.get("results") or payload.get("data") or []) if isinstance(payload, dict) else []
    stats = {kind: 0 for kind in (DIRECT, AFFILIATED, UNRELATED, UNVERIFIED)}
    written = 0
    for item in items:
        if isinstance(item, list):
            host, ip, port, title, domain, server = (list(item) + [""] * 6)[:6]
            icp = ""
        elif isinstance(item, dict):
            fields = item.get("fields", item)
            host = fields.get("host") or fields.get("link") or ""
            ip = fields.get("ip", "")
            port = str(fields.get("port", ""))
            title = fields.get("title", "")
            domain = fields.get("domain", "")
            icp = fields.get("icp", "") or fields.get("icp_number", "")
        else:
            continue
        kind, basis = classify_asset(host=host, domain=domain, title=title, icp=icp, root_domains=roots, chain_names=names)
        stats[kind] += 1
        asset_value, port_num, protocol = _parse_asset(host, ip, port, "")
        if not asset_value:
            continue
        attr = _ATTRIBUTION[kind]
        scope_reason = f"ownership_gate:{kind}:{basis}"
        if kind == AFFILIATED:
            scope_reason = f"ownership_gate:{basis}; operator confirm via scope_cluster"
        cur = conn.execute(
            """INSERT INTO target_assets
               (target_name, asset_type, asset_value, port, protocol, source, status,
                scope_status, scope_reason, scope_class, authorization_state, relation_to_target)
               VALUES (?, 'domain', ?, ?, ?, ?, 'new', ?, ?, ?, ?, ?)
               ON CONFLICT(target_name, asset_value, COALESCE(port, 443))
               DO UPDATE SET protocol=excluded.protocol, source=excluded.source,
                 scope_status=excluded.scope_status, scope_reason=excluded.scope_reason,
                 scope_class=excluded.scope_class, authorization_state=excluded.authorization_state,
                 relation_to_target=excluded.relation_to_target""",
            (
                target_name,
                asset_value,
                port_num,
                protocol,
                source_kind,
                attr["scope_status"],
                scope_reason,
                attr["scope_class"],
                attr["authorization_state"],
                attr["relation_to_target"],
            ),
        )
        written += int(cur.rowcount > 0)
    conn.commit()
    return {"target": target_name, "written": written, "classified": stats}


def recheck_needs_review(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    root_domains: Iterable[str],
    chain: dict[str, Any],
) -> dict[str, Any]:
    """把已入库的 needs_review 资产按股权链重分类，无关资产降级 out_of_scope。

    只动 needs_review（自动入库、未经操作员确认）的资产；in_scope 是操作员领地，不碰。
    不删除任何行，只调整 scope/eligibility 状态。
    """
    ensure_scope_columns(conn)
    roots = list(root_domains)
    names = chain.get("names", {})
    rows = conn.execute(
        """SELECT id, asset_value, scope_reason FROM target_assets
           WHERE target_name=? AND scope_status='needs_review'""",
        (target_name,),
    ).fetchall()
    stats = {kind: 0 for kind in (DIRECT, AFFILIATED, UNRELATED, UNVERIFIED)}
    changed = 0
    for row in rows:
        host = row["asset_value"]
        domain = host
        kind, basis = classify_asset(host=host, domain=domain, root_domains=roots, chain_names=names)
        stats[kind] += 1
        attr = _ATTRIBUTION[kind]
        if attr["scope_status"] == "needs_review" and kind == UNVERIFIED:
            # 无信号就保持现状，不反复改
            continue
        scope_reason = f"ownership_gate:recheck:{kind}:{basis}"
        if kind == AFFILIATED:
            scope_reason = f"ownership_gate:recheck:{basis}; operator confirm via scope_cluster"
        conn.execute(
            """UPDATE target_assets SET scope_status=?, scope_reason=?, scope_class=?,
               authorization_state=?, relation_to_target=? WHERE id=?""",
            (
                attr["scope_status"],
                scope_reason,
                attr["scope_class"],
                attr["authorization_state"],
                attr["relation_to_target"],
                row["id"],
            ),
        )
        changed += 1
    conn.commit()
    return {"target": target_name, "rechecked": len(rows), "changed": changed, "classified": stats}


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description="股权穿透归属门控")
    parser.add_argument("--target", required=True, help="target_name")
    parser.add_argument("--db", required=True, help="DB 路径")
    parser.add_argument("--company", default="", help="目标企业名（天眼查股权穿透用）")
    parser.add_argument("--root-domain", action="append", default=[], help="根域（可重复）")
    parser.add_argument(
        "--build-chain",
        action="store_true",
        help="用天眼查构建/刷新股权链（equity-tree/actual-controller/beneficial-owners）",
    )
    parser.add_argument("--gate-fofa", metavar="JSON", help="分类并 upsert FOFA 结果文件")
    parser.add_argument("--recheck", action="store_true", help="重分类已入库 needs_review 资产")
    parser.add_argument("--preview", action="store_true", help="只打印判定，不写库")
    args = parser.parse_args()

    if not args.db and not Path(args.db).is_file():
        parser.error(f"database file not found: {args.db}")
    try:
        from db.db_utils import connect  # noqa: PLC0415 - 与 recon_intel 相同的运行期导入
    except ImportError:
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
        from db.db_utils import connect  # noqa: PLC0415
    conn = connect(args.db)
    conn.row_factory = sqlite3.Row

    try:
        if args.build_chain:
            if not args.company:
                parser.error("--company is required with --build-chain")
            for kind in TIANYAN_KINDS:
                result = run_tianyan_company(args.company, kind=kind)
                record_source(
                    conn,
                    target_name=args.target,
                    source_kind=f"tianyan_{kind}",
                    query=args.company,
                    result=result,
                    status=result["status"],
                    error=result.get("error", ""),
                )
                print(json.dumps({"kind": kind, "status": result["status"]}, ensure_ascii=False))
            conn.commit()

        chain = load_corporate_chain(conn, target_name=args.target, company=args.company)
        print(
            json.dumps(
                {
                    "chain": {
                        "company": chain["company"],
                        "relations": len(chain["relations"]),
                        "names": sorted(chain["names"])[:20],
                    }
                },
                ensure_ascii=False,
            )
        )
        if args.preview:
            conn.rollback()
            print(json.dumps({"preview": True}, ensure_ascii=False))
            return 0

        if args.gate_fofa:
            payload = json.loads(Path(args.gate_fofa).read_text(encoding="utf-8"))
            print(
                json.dumps(
                    gate_fofa_payload(conn, target_name=args.target, payload=payload, root_domains=args.root_domain, chain=chain),
                    ensure_ascii=False,
                )
            )
        if args.recheck:
            print(
                json.dumps(
                    recheck_needs_review(conn, target_name=args.target, root_domains=args.root_domain, chain=chain),
                    ensure_ascii=False,
                )
            )
        if not args.gate_fofa and not args.recheck:
            print(json.dumps({"ok": True, "note": "chain loaded; use --gate-fofa / --recheck to gate assets"}, ensure_ascii=False))
        return 0
    except (ValueError, RuntimeError, OSError, json.JSONDecodeError, sqlite3.Error) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return 1
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
