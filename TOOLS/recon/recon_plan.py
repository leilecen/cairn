"""Small-slice L0/L1 reconnaissance planner with explicit execution only."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

_TOOLS_DIR = Path(__file__).resolve().parent.parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

from db.db_utils import connect, force_utf8_stdout  # noqa: E402

SLICES = {
    "ct": {"source": "sslmate_ct"},
    "subfinder": {"source": "subfinder_passive"},
}


def _get_conn(target_name: str, db: str):
    path = Path(db)
    if not path.is_file():
        raise ValueError(f"database file not found: {path}")
    conn = connect(path)
    if conn.execute("SELECT 1 FROM targets WHERE target_name=? LIMIT 1", (target_name,)).fetchone() is None:
        conn.close()
        raise ValueError("target is not present in the explicit database")
    return conn, path.resolve()


def _authorized_root_domains(conn, *, target_name: str) -> list[str]:
    rows = conn.execute(
        """SELECT asset_value FROM target_assets
           WHERE target_name=? AND asset_type='domain' AND scope_status='in_scope'
             AND scope_class IN ('owned','authorized_vendor')
           ORDER BY id""",
        (target_name,),
    ).fetchall()
    return [str(row["asset_value"]).lower().rstrip(".") for row in rows]


def build_plan(conn, *, target_name: str, db_path: Path) -> dict[str, Any]:
    """Return compact, zero-write next slices; never selects a system or runs one."""
    roots = _authorized_root_domains(conn, target_name=target_name)
    runs = conn.execute(
        """SELECT source,status,attempt,next_retry_at,updated_at
           FROM recon_runs WHERE target_name=? ORDER BY updated_at DESC,id DESC""",
        (target_name,),
    ).fetchall()
    latest: dict[str, dict[str, Any]] = {}
    for row in runs:
        latest.setdefault(
            str(row["source"]),
            {key: row[key] for key in ("status", "attempt", "next_retry_at", "updated_at")},
        )
    recommendations: list[dict[str, str]] = []
    if not roots:
        recommendations.append({"slice": "none", "reason": "blocked:no_authorized_root_domain", "next_action": "operator_scope_review"})
    else:
        for slice_name, spec in SLICES.items():
            state = latest.get(spec["source"], {}).get("status")
            if state in {"running", "rate_limited"}:
                continue
            reason = "not_run" if state is None else f"resume_after:{state}"
            recommendations.append({"slice": slice_name, "reason": reason, "next_action": "explicit_execute_one_slice"})
    return {
        "target": target_name,
        "db": str(db_path),
        "authorized_root_domains": roots,
        "source_health": latest,
        "recommendations": recommendations,
        "execution_boundary": "pass --execute <one slice> and --domain <authorized root>; no queue or system selection",
    }


def _command_for_slice(*, slice_name: str, target_name: str, db_path: Path, domain: str) -> list[str]:
    normalized = domain.lower().rstrip(".")
    if slice_name == "ct":
        return [
            sys.executable,
            str(Path(__file__).with_name("ct_search.py")),
            "--target",
            target_name,
            "--db",
            str(db_path),
            "--domain",
            normalized,
        ]
    if slice_name == "subfinder":
        return [
            sys.executable,
            str(Path(__file__).with_name("recon_intel.py")),
            "--target",
            target_name,
            "--db",
            str(db_path),
            "--subfinder-domain",
            normalized,
        ]
    raise ValueError(f"unsupported slice: {slice_name}")


def execute_slice(
    conn,
    *,
    target_name: str,
    db_path: Path,
    slice_name: str,
    domain: str,
    runner=subprocess.run,
) -> dict[str, Any]:
    """Run exactly one explicit passive slice after rechecking root authorization."""
    normalized = domain.lower().rstrip(".")
    if normalized not in _authorized_root_domains(conn, target_name=target_name):
        raise PermissionError("--domain must be an explicit in-scope owned or authorized root domain")
    command = _command_for_slice(slice_name=slice_name, target_name=target_name, db_path=db_path, domain=normalized)
    completed = runner(command, cwd=str(_TOOLS_DIR.parent), text=True, capture_output=True, check=False)
    try:
        result = json.loads(completed.stdout)
    except (TypeError, json.JSONDecodeError):
        result = {}
    return {
        "slice": slice_name,
        "returncode": completed.returncode,
        "status": result.get("status", "failed"),
        "provider": result.get("provider", ""),
        "items": len(result.get("items", [])) if isinstance(result.get("items"), list) else 0,
        "db": str(db_path),
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="L0/L1 compact planner; executes one explicit passive slice")
    parser.add_argument("--target", required=True)
    parser.add_argument("--db", required=True)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--execute", choices=sorted(SLICES))
    parser.add_argument("--domain", help="explicit authorized root; required with --execute")
    return parser


def main() -> int:
    force_utf8_stdout()
    args = _build_parser().parse_args()
    if args.execute and not args.domain:
        raise SystemExit("--domain is required with --execute")
    try:
        conn, db_path = _get_conn(args.target, args.db)
        with conn:
            result = (
                execute_slice(
                    conn,
                    target_name=args.target,
                    db_path=db_path,
                    slice_name=args.execute,
                    domain=args.domain,
                )
                if args.execute
                else build_plan(conn, target_name=args.target, db_path=db_path)
            )
        print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
        return 0 if not args.execute or result["returncode"] == 0 else 1
    except (OSError, PermissionError, ValueError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=True, separators=(",", ":")))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
