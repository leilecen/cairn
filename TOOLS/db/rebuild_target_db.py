"""将旧目标 DB 回填到规范化侦察/接口地图事实表。

该脚本只做幂等回填和范围标记，不删除旧事实、不发网络请求。
所有目标必须显式通过 --target 或 --file 指定，不读取 SRC_TARGET 等环境变量。
"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
from pathlib import Path
from urllib.parse import urlparse

TOOLS_DIR = Path(__file__).resolve().parent.parent
PROJECT_ROOT = TOOLS_DIR.parent
sys.path.insert(0, str(TOOLS_DIR))

from db.db_utils import find_db, session  # noqa: E402
from db.migrate import do_migrate  # noqa: E402
from recon.endpoint_normalizer import normalize_endpoint  # noqa: E402


def _host(value: str | None) -> str:
    if not value:
        return ""
    raw = value if "://" in value else f"https://{value}"
    return (urlparse(raw).hostname or "").lower().rstrip(".")


def _same_or_subdomain(host: str, root: str) -> bool:
    return bool(host and root and (host == root or host.endswith(f".{root}")))


def _json(value: object, default: object = None) -> str:
    if value in (None, "", "null"):
        value = default if default is not None else []
    if isinstance(value, str):
        try:
            json.loads(value)
            return value
        except json.JSONDecodeError:
            return json.dumps([value], ensure_ascii=False)
    return json.dumps(value, ensure_ascii=False, default=str)


def _confidence(value: object) -> str:
    if isinstance(value, int):
        return "high" if value >= 75 else "medium" if value >= 45 else "low"
    value = str(value or "").lower()
    return value if value in {"low", "medium", "high", "unknown"} else "unknown"


def _row_value(row: sqlite3.Row, key: str, default: object = None) -> object:
    return row[key] if key in row.keys() else default


def _ensure_rebuild_columns(conn: sqlite3.Connection) -> None:
    additions = {
        "target_assets": {
            "scope_class": "TEXT DEFAULT 'unknown'",
            "authorization_state": "TEXT DEFAULT 'unknown'",
            "relation_to_target": "TEXT",
        },
        "endpoint_observations": {
            "raw_endpoint": "TEXT",
            "resolved_url": "TEXT",
            "base_url": "TEXT",
            "source_page_url": "TEXT",
            "source_js_url": "TEXT",
            "origin_host": "TEXT",
            "route_kind": "TEXT",
            "service_hint": "TEXT",
            "resolution_status": "TEXT DEFAULT 'unresolved'",
            "scope_class": "TEXT DEFAULT 'unknown'",
            "redirect_location": "TEXT",
            "response_fingerprint": "TEXT",
        },
    }
    for table, columns in additions.items():
        present = {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
        for name, ddl in columns.items():
            if name not in present:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS asset_relationships (
            id INTEGER PRIMARY KEY AUTOINCREMENT, target_name TEXT NOT NULL,
            asset_id INTEGER NOT NULL, related_host TEXT NOT NULL,
            relation_type TEXT NOT NULL, scope_class TEXT NOT NULL DEFAULT 'unknown',
            authorization_state TEXT NOT NULL DEFAULT 'unknown',
            evidence_refs_json TEXT NOT NULL DEFAULT '[]', notes TEXT,
            observed_at TEXT DEFAULT (datetime('now','localtime')),
            UNIQUE(target_name, asset_id, related_host, relation_type)
        );
        """
    )


def _scope_status(host: str, root: str) -> tuple[str, str]:
    if _same_or_subdomain(host, root):
        return "in_scope", "same target root domain"
    return "needs_review", "host is outside target root domain; provenance review required"


def _asset_for_host(conn: sqlite3.Connection, target: str, host: str) -> int | None:
    if not host:
        return None
    rows = conn.execute(
        "SELECT id, asset_value FROM target_assets WHERE target_name=?",
        (target,),
    ).fetchall()
    exact = [r["id"] for r in rows if _host(r["asset_value"]) == host]
    return exact[0] if exact else None


def _ensure_asset_scope(conn: sqlite3.Connection, target: str, root: str) -> int:
    changed = 0
    for row in conn.execute(
        "SELECT id, asset_value, scope_status FROM target_assets WHERE target_name=?",
        (target,),
    ).fetchall():
        host = _host(row["asset_value"])
        status, reason = _scope_status(host, root)
        scope_class = "owned" if status == "in_scope" else "intel_only"
        authorization = "inherited_target_scope" if scope_class == "owned" else "unknown"
        if row["scope_status"] != status:
            conn.execute(
                "UPDATE target_assets SET scope_status=?, scope_reason=?, scope_class=?, authorization_state=? WHERE id=?",
                (status, reason, scope_class, authorization, row["id"]),
            )
            changed += 1
        else:
            conn.execute(
                """UPDATE target_assets
                   SET scope_class=CASE WHEN scope_class IN ('owned','authorized_vendor','intel_only') THEN scope_class ELSE ? END,
                       authorization_state=CASE WHEN authorization_state IS NULL OR authorization_state='unknown' THEN ? ELSE authorization_state END
                   WHERE id=?""",
                (scope_class, authorization, row["id"]),
            )
        if scope_class == "intel_only":
            conn.execute(
                """INSERT OR IGNORE INTO asset_relationships
                   (target_name,asset_id,related_host,relation_type,scope_class,authorization_state,notes)
                   VALUES(?,?,?,?,?,?,?)""",
                (
                    target,
                    row["id"],
                    host,
                    "external_association",
                    scope_class,
                    authorization,
                    "outside target root; retained for passive intelligence only",
                ),
            )
    return changed


def _link_pages(conn: sqlite3.Connection, target: str) -> int:
    count = 0
    for row in conn.execute("SELECT id, url FROM pages WHERE url IS NOT NULL").fetchall():
        asset_id = _asset_for_host(conn, target, _host(row["url"]))
        if asset_id is None:
            continue
        conn.execute(
            "INSERT OR IGNORE INTO page_asset_links(page_id,asset_id,relation,confidence) VALUES(?,?,?,?)",
            (row["id"], asset_id, "same_host", "high"),
        )
        count += 1
    return count


def _link_js(conn: sqlite3.Connection, target: str) -> int:
    count = 0
    for row in conn.execute("SELECT id, url, page_url FROM js_files").fetchall():
        asset_id = _asset_for_host(conn, target, _host(row["url"]) or _host(row["page_url"]))
        if asset_id is None:
            continue
        conn.execute(
            "INSERT OR IGNORE INTO js_asset_links(js_file_id,asset_id,relation,confidence) VALUES(?,?,?,?)",
            (row["id"], asset_id, "same_host", "high"),
        )
        count += 1
    return count


def _endpoint(
    conn: sqlite3.Connection,
    *,
    target: str,
    asset_id: int | None,
    page_id: int | None,
    js_file_id: int | None,
    js_signal_id: str | None,
    source_table: str,
    source_id: str,
    url: str,
    method: str,
    source: str,
    auth_state: str = "unknown",
    response_class: str | None = None,
    status_code: int | None = None,
    business_hint: str | None = None,
    params: object = None,
    evidence_refs: object = None,
    confidence: str = "unknown",
    test_status: str = "not_tested",
    page_url: str = "",
    js_url: str = "",
    base_url: str = "",
    target_hosts: set[str] | None = None,
) -> None:
    normalized = normalize_endpoint(
        url,
        page_url=page_url,
        js_url=js_url,
        base_url=base_url,
        target_hosts=target_hosts or set(),
    )
    canonical = str(normalized["resolved_url"] or normalized["raw_endpoint"] or url).split("#", 1)[0].rstrip("/") or url
    existing = conn.execute(
        """SELECT id FROM endpoint_observations
           WHERE target_name=? AND method=? AND source=? AND source_id=? LIMIT 1""",
        (target, (method or "GET").upper(), source, str(source_id)),
    ).fetchone()
    if existing:
        conn.execute(
            """UPDATE endpoint_observations SET asset_id=COALESCE(?,asset_id), page_id=COALESCE(?,page_id),
               js_file_id=COALESCE(?,js_file_id), js_signal_id=COALESCE(?,js_signal_id), canonical_url=?,
               host=?, path=?, auth_state=?, response_class=?, status_code=?, business_hint=?,
               parameter_names_json=?, evidence_refs_json=?, confidence=?, test_status=?,
               raw_endpoint=?, resolved_url=?, base_url=?, source_page_url=?, source_js_url=?, origin_host=?,
               route_kind=?, service_hint=?, resolution_status=?, scope_class=?, last_seen_at=datetime('now','localtime'),
               observed_count=observed_count+1 WHERE id=?""",
            (
                asset_id,
                page_id,
                js_file_id,
                js_signal_id,
                canonical,
                normalized["origin_host"],
                normalized["path"] or "/",
                auth_state,
                response_class,
                status_code,
                business_hint,
                _json(params),
                _json(evidence_refs),
                _confidence(confidence),
                test_status,
                normalized["raw_endpoint"],
                normalized["resolved_url"],
                normalized["base_url"],
                page_url or None,
                js_url or None,
                normalized["origin_host"],
                normalized["route_kind"],
                normalized["service_hint"],
                normalized["resolution_status"],
                normalized["scope_class"],
                existing["id"],
            ),
        )
        return
    conn.execute(
        """
        INSERT INTO endpoint_observations(
          target_name,asset_id,page_id,js_file_id,js_signal_id,source_table,source_id,
          canonical_url,host,path,method,source,auth_state,response_class,status_code,
          business_hint,parameter_names_json,evidence_refs_json,confidence,test_status,
          raw_endpoint,resolved_url,base_url,source_page_url,source_js_url,origin_host,
          route_kind,service_hint,resolution_status,scope_class)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(target_name,canonical_url,method,source,source_id) DO UPDATE SET
          asset_id=COALESCE(excluded.asset_id,endpoint_observations.asset_id),
          page_id=COALESCE(excluded.page_id,endpoint_observations.page_id),
          js_file_id=COALESCE(excluded.js_file_id,endpoint_observations.js_file_id),
          js_signal_id=COALESCE(excluded.js_signal_id,endpoint_observations.js_signal_id),
          auth_state=CASE WHEN excluded.auth_state!='unknown' THEN excluded.auth_state ELSE endpoint_observations.auth_state END,
          response_class=COALESCE(excluded.response_class,endpoint_observations.response_class),
          status_code=COALESCE(excluded.status_code,endpoint_observations.status_code),
          business_hint=COALESCE(excluded.business_hint,endpoint_observations.business_hint),
          last_seen_at=datetime('now','localtime'), observed_count=endpoint_observations.observed_count+1,
          confidence=CASE WHEN excluded.confidence!='unknown' THEN excluded.confidence ELSE endpoint_observations.confidence END,
          test_status=CASE WHEN excluded.test_status!='not_tested' THEN excluded.test_status ELSE endpoint_observations.test_status END,
          raw_endpoint=COALESCE(excluded.raw_endpoint,endpoint_observations.raw_endpoint),
          resolved_url=COALESCE(excluded.resolved_url,endpoint_observations.resolved_url),
          base_url=COALESCE(excluded.base_url,endpoint_observations.base_url),
          source_page_url=COALESCE(excluded.source_page_url,endpoint_observations.source_page_url),
          source_js_url=COALESCE(excluded.source_js_url,endpoint_observations.source_js_url),
          origin_host=COALESCE(excluded.origin_host,endpoint_observations.origin_host),
          route_kind=COALESCE(excluded.route_kind,endpoint_observations.route_kind),
          service_hint=COALESCE(excluded.service_hint,endpoint_observations.service_hint),
          resolution_status=excluded.resolution_status, scope_class=excluded.scope_class
        """,
        (
            target,
            asset_id,
            page_id,
            js_file_id,
            js_signal_id,
            source_table,
            str(source_id),
            canonical,
            normalized["origin_host"],
            normalized["path"] or "/",
            (method or "GET").upper(),
            source,
            auth_state,
            response_class,
            status_code,
            business_hint,
            _json(params),
            _json(evidence_refs),
            _confidence(confidence),
            test_status,
            normalized["raw_endpoint"],
            normalized["resolved_url"],
            normalized["base_url"],
            page_url or None,
            js_url or None,
            normalized["origin_host"],
            normalized["route_kind"],
            normalized["service_hint"],
            normalized["resolution_status"],
            normalized["scope_class"],
        ),
    )


def _backfill_endpoints(conn: sqlite3.Connection, target: str) -> int:
    count = 0
    root_row = conn.execute("SELECT domain FROM targets WHERE target_name=? LIMIT 1", (target,)).fetchone()
    target_hosts = {_host(root_row["domain"])} if root_row else set()
    js_urls = {row["id"]: row["url"] for row in conn.execute("SELECT id,url FROM js_files WHERE url IS NOT NULL").fetchall()}
    for row in conn.execute("SELECT id,url,status,title,signal_reason,source FROM pages WHERE url IS NOT NULL").fetchall():
        _endpoint(
            conn,
            target=target,
            asset_id=_asset_for_host(conn, target, _host(row["url"])),
            page_id=row["id"],
            js_file_id=None,
            js_signal_id=None,
            source_table="pages",
            source_id=str(row["id"]),
            url=row["url"],
            method="GET",
            source=row["source"] or "page",
            response_class=row["status"],
            business_hint=row["title"] or row["signal_reason"],
            test_status="observed" if row["status"] in {"visited", "crawled", "scanned"} else "not_tested",
            page_url=row["url"],
            target_hosts=target_hosts,
        )
        count += 1
    for row in conn.execute("SELECT * FROM js_signals WHERE url IS NOT NULL").fetchall():
        url = row["url"] or row["path"]
        if not url:
            continue
        _endpoint(
            conn,
            target=target,
            asset_id=_asset_for_host(conn, target, row["host"] or _host(url)),
            page_id=None,
            js_file_id=row["js_file_id"],
            js_signal_id=str(row["id"]),
            source_table="js_signals",
            source_id=str(row["id"]),
            url=url,
            method=row["method"] or "GET",
            source=row["source_kind"] or "js_signal",
            business_hint=row["business_hint"] or row["caller_hint"],
            params=row["params_json"],
            evidence_refs=[row["evidence_location"]] if row["evidence_location"] else [],
            confidence=row["confidence"],
            test_status="observed" if row["runtime_seen"] else "not_tested",
            js_url=str(js_urls.get(row["js_file_id"]) or ""),
            target_hosts=target_hosts,
        )
        count += 1
    for row in conn.execute("SELECT * FROM hunt_queue WHERE url IS NOT NULL").fetchall():
        _endpoint(
            conn,
            target=target,
            asset_id=_asset_for_host(conn, target, _host(row["url"])),
            page_id=None,
            js_file_id=None,
            js_signal_id=None,
            source_table="hunt_queue",
            source_id=str(row["id"]),
            url=row["url"],
            method=row["method"] or "GET",
            source=row["source"] or "hunt_queue",
            auth_state="auth_required" if row["endpoint_type"] in {"auth_sso_config", "noLogin_api"} else "unknown",
            business_hint=row["business_intent"] or row["signal_reason"],
            params=row["query_string"],
            confidence="medium" if row["status"] == "tested" else "unknown",
            test_status="tested" if row["status"] == "tested" else "queued" if row["status"] == "queued" else "not_tested",
            target_hosts=target_hosts,
        )
        count += 1
    return count


def _normalize_existing_endpoints(conn: sqlite3.Connection, target: str) -> int:
    """Repair legacy endpoint rows in place; keep collisions as explicit duplicates."""
    root_row = conn.execute("SELECT domain FROM targets WHERE target_name=? LIMIT 1", (target,)).fetchone()
    target_hosts = {_host(root_row["domain"])} if root_row else set()
    repaired = 0
    rows = conn.execute("SELECT * FROM endpoint_observations WHERE target_name=? ORDER BY id", (target,)).fetchall()
    for row in rows:
        page_url = None
        js_url = None
        if row["page_id"] is not None:
            page = conn.execute("SELECT url FROM pages WHERE id=?", (row["page_id"],)).fetchone()
            page_url = page[0] if page else None
        if row["js_file_id"] is not None:
            js = conn.execute("SELECT url FROM js_files WHERE id=?", (row["js_file_id"],)).fetchone()
            js_url = js[0] if js else None
        normalized = normalize_endpoint(
            row["raw_endpoint"] or row["canonical_url"],
            page_url=page_url or row["source_page_url"] or "",
            js_url=js_url or row["source_js_url"] or "",
            base_url=row["base_url"] or "",
            target_hosts=target_hosts,
        )
        canonical = str(normalized["resolved_url"] or normalized["raw_endpoint"] or row["canonical_url"]).split("#", 1)[0].rstrip("/")
        conflict = conn.execute(
            """SELECT id FROM endpoint_observations
               WHERE target_name=? AND canonical_url=? AND method=? AND source=? AND source_id=? AND id<>?""",
            (target, canonical, row["method"], row["source"], row["source_id"], row["id"]),
        ).fetchone()
        if conflict:
            conn.execute(
                "UPDATE endpoint_observations SET resolution_status='duplicate', scope_class='unknown' WHERE id=?",
                (row["id"],),
            )
            continue
        conn.execute(
            """UPDATE endpoint_observations SET canonical_url=?, host=?, path=?, raw_endpoint=?,
               resolved_url=?, base_url=?, source_page_url=?, source_js_url=?, origin_host=?,
               route_kind=?, service_hint=?, resolution_status=?, scope_class=? WHERE id=?""",
            (
                canonical,
                normalized["origin_host"],
                normalized["path"] or "/",
                normalized["raw_endpoint"],
                normalized["resolved_url"],
                normalized["base_url"],
                page_url,
                js_url,
                normalized["origin_host"],
                normalized["route_kind"],
                normalized["service_hint"],
                normalized["resolution_status"],
                normalized["scope_class"],
                row["id"],
            ),
        )
        repaired += 1
    return repaired


def _park_legacy_work_items(conn: sqlite3.Connection, target: str) -> int:
    """Keep broad legacy work visible but prevent accidental claiming."""
    columns = {row[1] for row in conn.execute("PRAGMA table_info(work_items)").fetchall()}
    if "dispatch_state" not in columns:
        return 0
    parked = conn.execute(
        """UPDATE work_items SET dispatch_state='parked',
               blocker_reason=COALESCE(blocker_reason,'legacy broad task requires explicit scope'),
               next_action=COALESCE(next_action,'reactivate only after explicit asset selection')
           WHERE target_name=? AND lane='quick_scout' AND subject_table='pages'
             AND COALESCE(subtype,'')<>'explicit_single_page'
             AND status IN ('queued','partial')""",
        (target,),
    ).rowcount
    rows = conn.execute(
        """SELECT w.id,h.url FROM work_items w JOIN hunt_queue h ON CAST(w.subject_id AS INTEGER)=h.id
           WHERE w.target_name=? AND w.lane IN ('logic_probe','replay')
             AND w.subject_table='hunt_queue' AND w.status IN ('queued','partial')""",
        (target,),
    ).fetchall()
    for row in rows:
        host = (urlparse(row["url"]).hostname or "").lower().rstrip(".")
        active = conn.execute(
            """SELECT 1 FROM target_assets
               WHERE target_name=? AND scope_class IN ('owned','authorized_vendor')
                 AND scope_status='in_scope' AND authorization_state<>'revoked'
                 AND (?=asset_value OR ? LIKE '%.' || asset_value) LIMIT 1""",
            (target, host, host),
        ).fetchone()
        if active is None:
            conn.execute(
                """UPDATE work_items SET dispatch_state='parked',
                       blocker_reason=COALESCE(blocker_reason,'URL outside active asset scope'),
                       next_action=COALESCE(next_action,'operator must confirm scope before reactivation')
                   WHERE id=?""",
                (row["id"],),
            )
            parked += 1
    return parked


def _backfill_recon_facts(conn: sqlite3.Connection, target: str) -> dict[str, int]:
    """把旧 target_assets/asset_auth_entries 的扁平字段转成 v28 事实记录。"""
    required = {"recon_sources", "network_observations", "technology_observations", "entry_observations"}
    present = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    if not required.issubset(present):
        return {"recon_sources": 0, "network_observations": 0, "technology_observations": 0, "entry_observations": 0}
    sources = technologies = networks = entries = 0
    source_counts: dict[str, int] = {}
    assets = conn.execute("SELECT * FROM target_assets WHERE target_name=? ORDER BY id", (target,)).fetchall()
    for row in assets:
        source = str(_row_value(row, "source") or "legacy_asset_import")
        source_counts[source] = source_counts.get(source, 0) + 1
        host = _host(row["asset_value"])
        if not host:
            continue
        conn.execute(
            """
            INSERT OR IGNORE INTO network_observations(
              target_name,asset_id,host,ip,port,protocol,service,http_json,status,source)
            VALUES(?,?,?,?,?,?,?,?,'observed',?)
            """,
            (
                target,
                row["id"],
                host,
                _row_value(row, "resolved_ip"),
                _row_value(row, "port"),
                _row_value(row, "protocol"),
                _row_value(row, "last_tech_stack") or _row_value(row, "tech_stack") or "",
                _json(
                    {
                        "status_code": _row_value(row, "last_status_code"),
                        "title": _row_value(row, "last_title"),
                        "verify_status": _row_value(row, "last_verify_status"),
                    }
                ),
                "asset_verify",
            ),
        )
        networks += 1
        tech_text = str(_row_value(row, "last_tech_stack") or _row_value(row, "tech_stack") or "")
        for technology in [part.strip() for part in re.split(r"[,;]", tech_text) if part.strip()]:
            conn.execute(
                """
                INSERT OR IGNORE INTO technology_observations(
                  target_name,asset_id,host,technology,category,confidence,source
                ) VALUES(?,?,?,?,?,?,?)
                """,
                (target, row["id"], host, technology, "fingerprint", "medium", "asset_verify"),
            )
            technologies += 1
    for source, count in source_counts.items():
        conn.execute(
            """
            INSERT OR IGNORE INTO recon_sources(target_name,source_kind,query,result_json,status)
            VALUES(?,?,?,?,?)
            """,
            (target, source, target, _json({"legacy_asset_rows": count}), "imported"),
        )
        sources += 1
    if conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='asset_auth_entries'").fetchone():
        for row in conn.execute("SELECT * FROM asset_auth_entries WHERE target_name=?", (target,)).fetchall():
            conn.execute(
                """
                INSERT OR IGNORE INTO entry_observations(
                  target_name,asset_id,url,entry_type,source,status,confidence,notes
                ) VALUES(?,?,?,?,?,?,?,?)
                """,
                (
                    target,
                    row["asset_id"],
                    row["url"],
                    row["entry_type"],
                    row["source"],
                    row["status"] or "observed",
                    _confidence(row["confidence"]),
                    row["notes"],
                ),
            )
            entries += 1
    return {
        "recon_sources": sources,
        "network_observations": networks,
        "technology_observations": technologies,
        "entry_observations": entries,
    }


def rebuild(conn: sqlite3.Connection, target: str) -> dict[str, int | str]:
    _ensure_rebuild_columns(conn)
    root_row = conn.execute("SELECT domain FROM targets WHERE target_name=? ORDER BY id LIMIT 1", (target,)).fetchone()
    if root_row is None:
        raise ValueError(f"target not found: {target}")
    root = _host(root_row["domain"])
    result = {
        "target": target,
        "root_domain": root,
        "assets_scope_updated": _ensure_asset_scope(conn, target, root),
        "page_links": _link_pages(conn, target),
        "js_links": _link_js(conn, target),
        **_backfill_recon_facts(conn, target),
        "endpoint_rows_seen": _backfill_endpoints(conn, target),
        "endpoint_rows_repaired": _normalize_existing_endpoints(conn, target),
        "legacy_work_items_parked": _park_legacy_work_items(conn, target),
    }
    conn.commit()
    counts = result
    counts["endpoint_rows"] = int(conn.execute("SELECT COUNT(*) FROM endpoint_observations WHERE target_name=?", (target,)).fetchone()[0])
    counts["in_scope_assets"] = int(
        conn.execute("SELECT COUNT(*) FROM target_assets WHERE target_name=? AND scope_status='in_scope'", (target,)).fetchone()[0]
    )
    counts["needs_review_assets"] = int(
        conn.execute("SELECT COUNT(*) FROM target_assets WHERE target_name=? AND scope_status='needs_review'", (target,)).fetchone()[0]
    )
    return {key: (value if isinstance(value, (int, str)) else str(value)) for key, value in counts.items()}


def main() -> int:
    parser = argparse.ArgumentParser(description="回填目标 DB 的资产关联和接口地图")
    parser.add_argument("--target", help="显式目标名")
    parser.add_argument("--file", help="显式 DB 路径")
    args = parser.parse_args()
    if bool(args.target) == bool(args.file):
        parser.error("必须且只能指定 --target 或 --file")
    path = Path(args.file) if args.file else find_db(args.target)
    migration = do_migrate(str(path))
    target = args.target
    with session(path) as conn:
        if not target:
            row = conn.execute("SELECT target_name FROM targets ORDER BY id LIMIT 1").fetchone()
            if row is None:
                raise SystemExit("DB 中没有 targets 记录")
            target = row[0]
        result = rebuild(conn, target)
    result["migration"] = migration
    print(json.dumps(result, ensure_ascii=False, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
