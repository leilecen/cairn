"""Offline lifecycle for bounded, evidence-seeded pattern hypotheses."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
import sys
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

TOOLS_DIR = Path(__file__).resolve().parent.parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from db.db_utils import connect, find_db  # noqa: E402
from db.work_queue import create_work_item  # noqa: E402
from db.worker_result import compact_public_text  # noqa: E402

PATTERN_TYPES = {"url_replace", "route_guess", "prefix", "subdomain_guess", "bucket_guess"}
GATED_TYPES = {"prefix", "subdomain_guess", "bucket_guess"}
ACTIONS = {"entry_probe", "logic_probe", "asset_ingest", "operator_gate"}
ACTION_BY_TYPE = {
    "url_replace": "entry_probe",
    "route_guess": "entry_probe",
    "prefix": "asset_ingest",
    "subdomain_guess": "asset_ingest",
    "bucket_guess": "asset_ingest",
}
EVIDENCE_REF = re.compile(r"(?:[A-Za-z][A-Za-z0-9_.-]*:[A-Za-z0-9_.-]+|[0-9]+)\Z")


def _normalize_evidence_refs(values: list[Any]) -> list[str]:
    refs: list[str] = []
    for value in values[:20]:
        if isinstance(value, bool) or not isinstance(value, str | int):
            raise ValueError("evidence_refs must contain short scalar references")
        ref = str(value).strip()
        if len(ref) > 120 or not EVIDENCE_REF.fullmatch(ref):
            raise ValueError("invalid evidence_ref; raw HTTP or authorization data is forbidden")
        if ref not in refs:
            refs.append(ref)
    return refs


def _ensure_gate_card(conn: sqlite3.Connection, *, row_id: int, target_name: str, url: str) -> None:
    action_key = f"pattern-guess-{row_id}-approval"
    if conn.execute("SELECT 1 FROM operator_inbox WHERE target_name=? AND action_key=? LIMIT 1", (target_name, action_key)).fetchone():
        return
    conn.execute(
        """INSERT INTO operator_inbox(
          target_name,kind,title,detail,suggested_action,url,status,action_key,action_label,why_needed,
          steps_json,expected_observation,report_back_format,blocking
        ) VALUES(?,'manual_review',?,?,?,?, 'open',?,?,?,?,?,?,1)""",
        (
            target_name,
            f"Approve pattern guess {row_id}",
            "Review bounded hypothesis; no request has been sent.",
            "Approve or reject this exact bounded pattern.",
            url or None,
            action_key,
            f"Review pattern guess {row_id}",
            "This pattern crosses an automatic safety boundary.",
            json.dumps(["Review seed evidence and exact pattern.", "Approve or reject."], ensure_ascii=False),
            "An explicit approve/reject decision.",
            "decision=<approved|rejected>; note=<compact reason>",
        ),
    )


def _validate_candidate(candidate: str, *, seed_url: str, allow_cross_origin: bool) -> None:
    parsed = urlsplit(candidate)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        raise ValueError("candidate must be an absolute http(s) URL")
    if parsed.username or parsed.password:
        raise ValueError("candidate credentials are forbidden")
    if ".." in unquote(parsed.path).split("/"):
        raise ValueError("candidate path traversal is forbidden")
    if not allow_cross_origin and _origin(candidate) != _origin(seed_url):
        raise ValueError("safe pattern candidate must remain same-origin")


def _origin(url: str) -> tuple[str, str, int | None]:
    parsed = urlsplit(url)
    return parsed.scheme.lower(), (parsed.hostname or "").lower(), parsed.port


def _validate_seed(pattern: str, pattern_type: str, verify_action: str | None, seed_evidence: list[dict[str, Any]]) -> bool:
    if pattern_type not in PATTERN_TYPES:
        raise ValueError("invalid pattern_type")
    if verify_action is not None and verify_action not in ACTIONS:
        raise ValueError("invalid verify_action")
    parsed = urlsplit(pattern.replace("{route}", "x").replace("{value}", "x"))
    if parsed.username or parsed.password:
        raise ValueError("pattern must not contain credentials")
    if ".." in parsed.path.split("/"):
        raise ValueError("path traversal pattern is forbidden")
    urls = [str(item.get("url") or "") for item in seed_evidence if item.get("url")]
    if not urls:
        raise ValueError("seed_evidence requires an observed URL")
    for url in urls:
        observed = urlsplit(url)
        if observed.scheme.lower() not in {"http", "https"} or not observed.netloc:
            raise ValueError("seed_evidence URL must be an absolute http(s) URL")
        if observed.username or observed.password:
            raise ValueError("seed_evidence URL credentials are forbidden")
    return pattern_type in {"url_replace", "route_guess"} and _origin(urls[0]) != _origin(pattern.replace("{route}", "x"))


def seed_guess(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    actor: str,
    attack_thread_id: int | None,
    pattern: str,
    pattern_type: str,
    seed_evidence: list[dict[str, Any]],
    verify_action: str | None = None,
    verify_bound: int = 100,
) -> int:
    if not 0 <= verify_bound <= 100:
        raise ValueError("verify_bound must be between 0 and 100")
    cross_origin = _validate_seed(pattern, pattern_type, verify_action, seed_evidence)
    action = verify_action or ACTION_BY_TYPE[pattern_type]
    gate = pattern_type in GATED_TYPES or action == "operator_gate" or cross_origin
    compact_seed = [
        {key: compact_public_text(item.get(key), max_chars=300) for key in ("source_table", "source_id", "url", "note") if item.get(key)}
        for item in seed_evidence[:20]
    ]
    seed_json = json.dumps(compact_seed, ensure_ascii=False, sort_keys=True)
    stable = hashlib.sha256(
        json.dumps([target_name, pattern_type, pattern, compact_seed], ensure_ascii=False, sort_keys=True).encode()
    ).hexdigest()
    conn.execute("BEGIN IMMEDIATE")
    try:
        if actor != "main":
            thread = conn.execute(
                "SELECT 1 FROM attack_threads WHERE id=? AND target_name=? AND evaluation_status='blocked'",
                (attack_thread_id, target_name),
            ).fetchone()
            if thread is None:
                raise ValueError("guess requires a blocked thread or explicit main-model seed")
        if attack_thread_id is not None:
            thread = conn.execute(
                "SELECT evaluation_status FROM attack_threads WHERE id=? AND target_name=?",
                (attack_thread_id, target_name),
            ).fetchone()
            if thread is None:
                raise ValueError("attack_thread target mismatch or thread not found")
            if actor != "main" and thread["evaluation_status"] != "blocked":
                raise ValueError("worker guess requires a blocked thread")
        existing = conn.execute(
            """SELECT id FROM pattern_guesses
            WHERE target_name=? AND pattern_type=? AND pattern=? AND seed_evidence_json=? LIMIT 1""",
            (target_name, pattern_type, pattern, seed_json),
        ).fetchone()
        if existing:
            if gate:
                _ensure_gate_card(conn, row_id=int(existing[0]), target_name=target_name, url=compact_seed[0].get("url", ""))
            conn.commit()
            return int(existing[0])
        cur = conn.execute(
            """
        INSERT INTO pattern_guesses(target_name,seed_evidence_json,pattern,pattern_type,derived_candidates_json,
          verify_action,verify_bound,gate_required,gate_status,status,result_summary,attack_thread_id,work_item_ids_json)
        VALUES(?,?,?,?,?,?,?,?,?,'generated',?,?, '[]')
        """,
            (
                target_name,
                seed_json,
                pattern,
                pattern_type,
                "[]",
                action,
                verify_bound,
                int(gate),
                "gated" if gate else "auto_allowed",
                f"seed_key={stable}",
                attack_thread_id,
            ),
        )
        if gate:
            _ensure_gate_card(conn, row_id=int(cur.lastrowid or 0), target_name=target_name, url=compact_seed[0].get("url", ""))
        conn.commit()
        return int(cur.lastrowid or 0)
    except Exception:
        conn.rollback()
        raise


def _guess(conn: sqlite3.Connection, target_name: str, guess_id: int) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM pattern_guesses WHERE id=?", (guess_id,)).fetchone()
    if row is None:
        raise ValueError("pattern guess not found")
    if row["target_name"] != target_name:
        raise ValueError("pattern guess target mismatch")
    return row


def generate_candidates(conn: sqlite3.Connection, *, target_name: str, guess_id: int, values: list[str], budget: int) -> list[str]:
    if not 0 <= budget <= 100:
        raise ValueError("budget must be between 0 and 100")
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = _guess(conn, target_name, guess_id)
        bound = min(budget, int(row["verify_bound"] or 0), 100)
        if bound == 0:
            conn.commit()
            return []
        candidates = json.loads(row["derived_candidates_json"] or "[]")
        seen = set(candidates)
        seeds = json.loads(row["seed_evidence_json"] or "[]")
        seed_url = next((str(item.get("url")) for item in seeds if item.get("url")), "")
        allow_cross = bool(row["gate_required"] and row["gate_status"] == "approved")
        changed = False
        for value in values:
            raw_value = str(value)
            if ".." in unquote(raw_value) or raw_value.startswith(("/", "\\")):
                raise ValueError("candidate value contains path traversal or authority syntax")
            clean = re.sub(r"[^A-Za-z0-9_-]", "", raw_value)[:100]
            candidate = row["pattern"].replace("{route}", clean).replace("{value}", clean)
            _validate_candidate(candidate, seed_url=seed_url, allow_cross_origin=allow_cross)
            if candidate not in seen and len(candidates) < bound:
                candidates.append(candidate)
                seen.add(candidate)
                changed = True
        if changed:
            conn.execute(
                """UPDATE pattern_guesses
                SET derived_candidates_json=?,updated_at=datetime('now','localtime') WHERE id=?""",
                (json.dumps(candidates, ensure_ascii=False), guess_id),
            )
        conn.commit()
        return candidates[:bound]
    except Exception:
        conn.rollback()
        raise


def approve_guess(conn: sqlite3.Connection, *, target_name: str, guess_id: int, approved: bool, actor: str) -> None:
    if actor != "operator":
        raise ValueError("only operator can decide a pattern gate")
    conn.execute("BEGIN IMMEDIATE")
    try:
        _guess(conn, target_name, guess_id)
        conn.execute(
            "UPDATE pattern_guesses SET gate_status=?,status=CASE WHEN ? THEN status ELSE 'parked' END WHERE id=?",
            ("approved" if approved else "rejected", int(approved), guess_id),
        )
        conn.execute(
            """UPDATE operator_inbox SET status='done',resolved_at=datetime('now','localtime')
            WHERE target_name=? AND action_key=?""",
            (target_name, f"pattern-guess-{guess_id}-approval"),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def dispatch_guess(conn: sqlite3.Connection, *, target_name: str, guess_id: int) -> list[int]:
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = _guess(conn, target_name, guess_id)
        if row["gate_required"] and row["gate_status"] != "approved":
            conn.commit()
            return []
        if row["verify_action"] == "operator_gate":
            conn.commit()
            return []
        existing = json.loads(row["work_item_ids_json"] or "[]")
        if existing:
            conn.commit()
            return [int(x) for x in existing]
        candidates = json.loads(row["derived_candidates_json"] or "[]")[: int(row["verify_bound"] or 0)]
        ids = []
        for candidate in candidates:
            wid = create_work_item(
                conn,
                target_name=target_name,
                lane=row["verify_action"],
                subtype=f"pattern_guess:{guess_id}",
                subject_table="pattern_guesses",
                subject_id=str(guess_id),
                attack_thread_id=row["attack_thread_id"],
                title=f"Verify bounded pattern candidate {guess_id}",
                objective=compact_public_text(candidate, max_chars=400),
                risk_class="safe_passive",
                timebox_minutes=10,
                heartbeat_minutes=5,
                commit=False,
            )
            ids.append(wid)
        conn.execute("UPDATE pattern_guesses SET work_item_ids_json=? WHERE id=?", (json.dumps(ids), guess_id))
        conn.commit()
        return ids
    except Exception:
        conn.rollback()
        raise


def verify_guess(
    conn: sqlite3.Connection,
    *,
    target_name: str,
    guess_id: int,
    outcome: str,
    summary: str,
    evidence_refs: list[str],
    anomaly: str = "",
) -> None:
    if outcome not in {"verified", "refuted", "blocked", "parked"}:
        raise ValueError("outcome must be verified, refuted, blocked, or parked")
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = _guess(conn, target_name, guess_id)
        refs = _normalize_evidence_refs(evidence_refs)
        if row["gate_required"] and row["gate_status"] != "approved":
            raise ValueError("pattern gate must be approved before verification")
        if row["verify_action"] == "operator_gate":
            if outcome not in {"blocked", "parked"}:
                raise ValueError("operator_gate guesses cannot be verified or refuted")
        else:
            work_ids = json.loads(row["work_item_ids_json"] or "[]")
            if not work_ids:
                raise ValueError("pattern guess must be dispatched before verification")
            placeholders = ",".join("?" for _ in work_ids)
            linked = conn.execute(
                f"""SELECT 1 FROM work_items
                WHERE id IN ({placeholders}) AND target_name=? AND subtype=? LIMIT 1""",  # noqa: S608
                (*work_ids, target_name, f"pattern_guess:{guess_id}"),
            ).fetchone()
            if linked is None:
                raise ValueError("pattern work_item_ids do not match target and subtype")
        compact = compact_public_text(summary, max_chars=500)
        status = "blocked" if outcome in {"blocked", "parked"} else "covered"
        item_key = f"pattern_guess:{guess_id}"
        existing = conn.execute(
            "SELECT id FROM coverage_ledger WHERE target_name=? AND item_key=? ORDER BY id LIMIT 1",
            (target_name, item_key),
        ).fetchone()
        if existing:
            conn.execute(
                """UPDATE coverage_ledger
            SET status=?,confidence='medium',evidence_refs_json=?,summary=?,
                updated_at=datetime('now','localtime') WHERE id=?""",
                (status, json.dumps(refs), compact, existing[0]),
            )
        else:
            conn.execute(
                """INSERT INTO coverage_ledger(
                  target_name,item_key,category,status,confidence,evidence_refs_json,summary)
            VALUES(?,?,'pattern_guess',?,'medium',?,?)""",
                (target_name, item_key, status, json.dumps(refs), compact),
            )
        conn.execute(
            "UPDATE pattern_guesses SET status=?,result_summary=?,updated_at=datetime('now','localtime') WHERE id=?",
            ("parked" if outcome in {"blocked", "parked"} else outcome, compact, guess_id),
        )
        if anomaly and refs and row["verify_action"] != "operator_gate":
            sp_id = f"SP-PG-{guess_id}"
            conn.execute(
                """INSERT OR IGNORE INTO suspicious_points(id,url,test_type,evidence,source,reasoning,risk,test_status)
            VALUES(?,?,'pattern_guess',?,'pattern_guess',?,'Medium','untested')""",
                (
                    sp_id,
                    json.loads(row["derived_candidates_json"] or "[]")[0] if json.loads(row["derived_candidates_json"] or "[]") else "",
                    json.dumps(refs),
                    compact_public_text(anomaly, max_chars=500),
                ),
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def list_guesses(conn: sqlite3.Connection, *, target_name: str, include_items: bool = False) -> dict[str, Any]:
    rows = [
        dict(row)
        for row in conn.execute(
            """SELECT id,target_name,pattern_type,verify_action,verify_bound,gate_status,status,result_summary
            FROM pattern_guesses WHERE target_name=? ORDER BY id""",
            (target_name,),
        ).fetchall()
    ]
    return {
        "count": len(rows),
        "items": rows if include_items else rows[:10],
        "omitted": 0 if include_items else max(0, len(rows) - 10),
    }


def _cli_path(args: argparse.Namespace) -> Path:
    if bool(args.target) == bool(args.file):
        raise ValueError("exactly one of --target or --file is required")
    if args.file:
        path = Path(args.file)
        if not path.is_file():
            raise FileNotFoundError(f"DB file does not exist: {path}")
        return path
    return find_db(args.target)


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline bounded pattern-guess ledger")
    parser.add_argument("--target")
    parser.add_argument("--file")
    parser.add_argument("--target-name")
    parser.add_argument("--include-items", action="store_true")
    args = parser.parse_args()
    try:
        path = _cli_path(args)
        conn = connect(path)
        try:
            target_name = args.target or args.target_name
            if not target_name:
                raise ValueError("--target-name is required with --file")
            if conn.execute("SELECT 1 FROM targets WHERE target_name=?", (target_name,)).fetchone() is None:
                raise ValueError(f"target not found in DB: {target_name}")
            result = {
                "status": "ok",
                "target": target_name,
                **list_guesses(conn, target_name=target_name, include_items=args.include_items),
            }
        finally:
            conn.close()
    except (FileNotFoundError, RuntimeError, sqlite3.Error, ValueError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False, sort_keys=True))
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
