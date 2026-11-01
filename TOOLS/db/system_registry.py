"""Human-readable system registry and explicit asset membership operations."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from db.system_contract import ASSET_RELATIONSHIPS, SYSTEM_LIFECYCLES, validate_system


def register_system(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    system_key: str,
    display_name: str,
    canonical_url: str,
    scope_class: str,
    description: str = "",
    lifecycle_state: str = "discovered",
    actor: str = "operator",
) -> dict[str, Any]:
    data = validate_system(
        system_key=system_key,
        display_name=display_name,
        canonical_url=canonical_url,
        scope_class=scope_class,
        lifecycle_state=lifecycle_state,
    )
    existing = conn.execute(
        "SELECT id FROM target_systems WHERE target_name=? AND system_key=?", (target_name, data["system_key"])
    ).fetchone()
    if existing:
        conn.execute(
            """UPDATE target_systems SET display_name=?,canonical_url=?,description=?,scope_class=?,lifecycle_state=?,updated_at=datetime('now','localtime') WHERE id=?""",
            (
                data["display_name"],
                data["canonical_url"],
                str(description or "")[:1000],
                data["scope_class"],
                data["lifecycle_state"],
                int(existing[0]),
            ),
        )
        system_id = int(existing[0])
        action = "updated"
    else:
        cur = conn.execute(
            """INSERT INTO target_systems(target_name,system_key,display_name,canonical_url,description,scope_class,lifecycle_state,created_by) VALUES(?,?,?,?,?,?,?,?)""",
            (
                target_name,
                data["system_key"],
                data["display_name"],
                data["canonical_url"],
                str(description or "")[:1000],
                data["scope_class"],
                data["lifecycle_state"],
                actor,
            ),
        )
        system_id = int(cur.lastrowid or 0)
        action = "created"
    conn.commit()
    return {"id": system_id, "target_name": target_name, **data, "action": action}


def get_system(conn: sqlite3.Connection, *, target_name: str, system_id: int) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM target_systems WHERE id=? AND target_name=?", (system_id, target_name)).fetchone()
    if row is None:
        raise ValueError(f"system not found: {system_id}")
    return dict(row)


def list_systems(conn: sqlite3.Connection, *, target_name: str) -> list[dict[str, Any]]:
    return [
        dict(row)
        for row in conn.execute("SELECT * FROM target_systems WHERE target_name=? ORDER BY display_name,id", (target_name,)).fetchall()
    ]


def set_system_state(
    conn: sqlite3.Connection, *, target_name: str, system_id: int, lifecycle_state: str, actor: str = "operator"
) -> dict[str, Any]:
    if lifecycle_state not in SYSTEM_LIFECYCLES:
        raise ValueError(f"invalid system lifecycle: {lifecycle_state}")
    get_system(conn, target_name=target_name, system_id=system_id)
    conn.execute(
        "UPDATE target_systems SET lifecycle_state=?,updated_at=datetime('now','localtime') WHERE id=? AND target_name=?",
        (lifecycle_state, system_id, target_name),
    )
    conn.commit()
    return get_system(conn, target_name=target_name, system_id=system_id)


def link_asset(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    system_id: int,
    asset_id: int,
    relationship: str,
    confidence: str = "unknown",
    evidence_refs: list[Any] | None = None,
) -> dict[str, Any]:
    if relationship not in ASSET_RELATIONSHIPS:
        raise ValueError(f"invalid asset relationship: {relationship}")
    if confidence not in {"low", "medium", "high", "unknown"}:
        raise ValueError(f"invalid confidence: {confidence}")
    get_system(conn, target_name=target_name, system_id=system_id)
    asset = conn.execute(
        "SELECT id,target_name,scope_class,scope_status,authorization_state FROM target_assets WHERE id=?", (asset_id,)
    ).fetchone()
    if asset is None or asset["target_name"] != target_name:
        raise ValueError("asset does not belong to target")
    conn.execute(
        """INSERT INTO system_asset_links(target_name,system_id,asset_id,relationship,confidence,evidence_refs_json) VALUES(?,?,?,?,?,?) ON CONFLICT(system_id,asset_id,relationship) DO UPDATE SET confidence=excluded.confidence,evidence_refs_json=excluded.evidence_refs_json,updated_at=datetime('now','localtime')""",
        (
            target_name,
            system_id,
            asset_id,
            relationship,
            confidence,
            json.dumps(evidence_refs or [], ensure_ascii=False),
        ),
    )
    conn.commit()
    return dict(
        conn.execute(
            "SELECT * FROM system_asset_links WHERE system_id=? AND asset_id=? AND relationship=?",
            (system_id, asset_id, relationship),
        ).fetchone()
    )


def system_compact(conn: sqlite3.Connection, *, target_name: str, system_id: int) -> dict[str, Any]:
    row = get_system(conn, target_name=target_name, system_id=system_id)
    links = conn.execute(
        """SELECT l.id,l.asset_id,l.relationship,l.confidence,a.asset_value,a.scope_class,a.scope_status,a.authorization_state FROM system_asset_links l JOIN target_assets a ON a.id=l.asset_id WHERE l.system_id=? AND l.target_name=? ORDER BY l.id""",
        (system_id, target_name),
    ).fetchall()
    return {
        "id": row["id"],
        "display_name": row["display_name"],
        "canonical_url": row["canonical_url"],
        "scope_class": row["scope_class"],
        "lifecycle_state": row["lifecycle_state"],
        "assets": [dict(item) for item in links],
    }


def main(argv: list[str] | None = None) -> int:
    import argparse

    from db.db_utils import connect, find_db

    p = argparse.ArgumentParser(description="Register human-readable target systems")
    p.add_argument("--target", required=True)
    p.add_argument("--db")
    sub = p.add_subparsers(dest="command", required=True)
    create = sub.add_parser("propose")
    create.add_argument("--system-key", required=True)
    create.add_argument("--display-name", required=True)
    create.add_argument("--canonical-url", required=True)
    create.add_argument("--scope-class", required=True)
    create.add_argument("--description", default="")
    sub.add_parser("list")
    link = sub.add_parser("asset-link")
    link.add_argument("--system-id", type=int, required=True)
    link.add_argument("--asset-id", type=int, required=True)
    link.add_argument("--relationship", required=True)
    link.add_argument("--confidence", default="unknown")
    args = p.parse_args(argv)
    conn = connect(args.db or find_db(args.target))
    try:
        if args.command == "propose":
            result = register_system(
                conn,
                target_name=args.target,
                system_key=args.system_key,
                display_name=args.display_name,
                canonical_url=args.canonical_url,
                scope_class=args.scope_class,
                description=args.description,
            )
        elif args.command == "asset-link":
            result = link_asset(
                conn,
                target_name=args.target,
                system_id=args.system_id,
                asset_id=args.asset_id,
                relationship=args.relationship,
                confidence=args.confidence,
            )
        else:
            result = {"target_name": args.target, "systems": list_systems(conn, target_name=args.target)}
        print(json.dumps(result, ensure_ascii=False, default=str))
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
