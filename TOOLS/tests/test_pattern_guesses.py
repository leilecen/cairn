from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from db.blackboard_seed import apply_seed
from db.pattern_guesses import (
    approve_guess,
    dispatch_guess,
    generate_candidates,
    seed_guess,
    verify_guess,
)
from db.work_queue import create_work_item

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = PROJECT_ROOT / "TOOLS" / "db" / "schema.sql"
SCRIPT_PATH = PROJECT_ROOT / "TOOLS" / "db" / "pattern_guesses.py"


def _conn():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    conn.execute("INSERT INTO targets(id,target_name,domain) VALUES(1,'demo','example.com')")
    conn.execute("INSERT INTO targets(id,target_name,domain) VALUES(2,'other','other.example')")
    conn.commit()
    return conn


def _blocked_thread(conn, target="demo"):
    thread = conn.execute(
        """
        INSERT INTO attack_threads(target_name,hypothesis,status,evaluation_status)
        VALUES(?,'blocked route family','parked','blocked')
        """,
        (target,),
    ).lastrowid
    conn.commit()
    return thread


def test_no_seed_means_no_guesses_and_only_blocked_or_main_seed_is_accepted():
    conn = _conn()
    apply_seed(conn, target_name="demo", dry_run=False)
    assert conn.execute("SELECT COUNT(*) FROM pattern_guesses").fetchone()[0] == 0
    active = conn.execute("INSERT INTO attack_threads(target_name,hypothesis,status) VALUES('demo','active','active')").lastrowid
    conn.commit()
    with pytest.raises(ValueError, match="blocked thread or explicit main-model seed"):
        seed_guess(
            conn,
            target_name="demo",
            actor="worker",
            attack_thread_id=active,
            pattern="https://example.com/{route}",
            pattern_type="route_guess",
            seed_evidence=[{"source_table": "pages", "source_id": "1", "url": "https://example.com/login"}],
        )


def test_seed_generate_is_idempotent_target_isolated_and_budgeted():
    conn = _conn()
    thread = _blocked_thread(conn)
    kwargs = dict(
        target_name="demo",
        actor="worker",
        attack_thread_id=thread,
        pattern="https://example.com/{route}",
        pattern_type="route_guess",
        seed_evidence=[{"source_table": "pages", "source_id": "1", "url": "https://example.com/login"}],
    )
    guess_id = seed_guess(conn, **kwargs)
    assert seed_guess(conn, **kwargs) == guess_id
    assert generate_candidates(conn, target_name="demo", guess_id=guess_id, values=["register", "forgot"], budget=1) == [
        "https://example.com/register"
    ]
    assert generate_candidates(conn, target_name="demo", guess_id=guess_id, values=["register", "forgot"], budget=1) == [
        "https://example.com/register"
    ]
    with pytest.raises(ValueError, match="between 0 and 100"):
        generate_candidates(conn, target_name="demo", guess_id=guess_id, values=["x"], budget=101)
    assert generate_candidates(conn, target_name="demo", guess_id=guess_id, values=["x"], budget=0) == []
    many_id = seed_guess(
        conn,
        target_name="demo",
        actor="main",
        attack_thread_id=None,
        pattern="https://example.com/api/{route}",
        pattern_type="url_replace",
        seed_evidence=[{"source_table": "pages", "source_id": "2", "url": "https://example.com/api/"}],
    )
    candidates = generate_candidates(conn, target_name="demo", guess_id=many_id, values=[str(index) for index in range(120)], budget=100)
    assert len(candidates) == 100
    with pytest.raises(ValueError, match="target mismatch"):
        generate_candidates(conn, target_name="other", guess_id=guess_id, values=["x"], budget=1)


def test_seed_and_generate_take_write_lock_before_mutable_reads():
    conn = _conn()
    thread = _blocked_thread(conn)
    statements = []
    conn.set_trace_callback(statements.append)
    guess_id = seed_guess(
        conn,
        target_name="demo",
        actor="worker",
        attack_thread_id=thread,
        pattern="https://example.com/{route}",
        pattern_type="route_guess",
        seed_evidence=[{"source_table": "pages", "source_id": "1", "url": "https://example.com/login"}],
    )
    normalized = [item.strip().upper() for item in statements]
    assert next(i for i, item in enumerate(normalized) if item.startswith("BEGIN IMMEDIATE")) < next(
        i for i, item in enumerate(normalized) if item.startswith("SELECT")
    )
    statements.clear()
    generate_candidates(conn, target_name="demo", guess_id=guess_id, values=["register"], budget=1)
    normalized = [item.strip().upper() for item in statements]
    assert next(i for i, item in enumerate(normalized) if item.startswith("BEGIN IMMEDIATE")) < next(
        i for i, item in enumerate(normalized) if item.startswith("SELECT")
    )


def test_main_seed_cannot_link_cross_target_thread():
    conn = _conn()
    other_thread = _blocked_thread(conn, "other")
    with pytest.raises(ValueError, match="target mismatch"):
        seed_guess(
            conn,
            target_name="demo",
            actor="main",
            attack_thread_id=other_thread,
            pattern="https://example.com/{route}",
            pattern_type="route_guess",
            seed_evidence=[{"source_table": "pages", "source_id": "1", "url": "https://example.com/"}],
        )


def test_seed_rejects_observed_url_with_embedded_credentials_before_persisting():
    conn = _conn()
    thread = _blocked_thread(conn)

    with pytest.raises(ValueError, match="credentials"):
        seed_guess(
            conn,
            target_name="demo",
            actor="worker",
            attack_thread_id=thread,
            pattern="https://example.com/{route}",
            pattern_type="route_guess",
            seed_evidence=[
                {
                    "source_table": "pages",
                    "source_id": "1",
                    "url": "https://user:secret@example.com/login",
                }
            ],
        )

    assert conn.execute("SELECT COUNT(*) FROM pattern_guesses").fetchone()[0] == 0


def test_gate_and_dispatch_are_bounded_idempotent_and_never_cross_origin():
    conn = _conn()
    thread = _blocked_thread(conn)
    guess_id = seed_guess(
        conn,
        target_name="demo",
        actor="worker",
        attack_thread_id=thread,
        pattern="https://{value}.example.com/",
        pattern_type="subdomain_guess",
        seed_evidence=[{"source_table": "recon_sources", "source_id": "2", "url": "https://example.com/"}],
    )
    assert dispatch_guess(conn, target_name="demo", guess_id=guess_id) == []
    card = conn.execute(
        "SELECT kind,action_key,status FROM operator_inbox WHERE action_key=?",
        (f"pattern-guess-{guess_id}-approval",),
    ).fetchone()
    assert dict(card) == {
        "kind": "manual_review",
        "action_key": f"pattern-guess-{guess_id}-approval",
        "status": "open",
    }
    statements = []
    conn.set_trace_callback(statements.append)
    approve_guess(conn, target_name="demo", guess_id=guess_id, approved=True, actor="operator")
    normalized = [item.strip().upper() for item in statements]
    assert next(i for i, item in enumerate(normalized) if item.startswith("BEGIN IMMEDIATE")) < next(
        i for i, item in enumerate(normalized) if item.startswith("SELECT")
    )
    conn.set_trace_callback(None)
    generate_candidates(conn, target_name="demo", guess_id=guess_id, values=["api"], budget=1)
    ids = dispatch_guess(conn, target_name="demo", guess_id=guess_id)
    assert ids == dispatch_guess(conn, target_name="demo", guess_id=guess_id)
    row = conn.execute("SELECT * FROM work_items WHERE id=?", (ids[0],)).fetchone()
    assert row["subtype"] == f"pattern_guess:{guess_id}"
    assert row["attack_thread_id"] == thread
    assert row["lane"] == "asset_ingest"

    cross_id = seed_guess(
        conn,
        target_name="demo",
        actor="main",
        attack_thread_id=None,
        pattern="https://evil.example.net/{route}",
        pattern_type="route_guess",
        seed_evidence=[{"source_table": "pages", "source_id": "1", "url": "https://example.com/"}],
    )
    cross = conn.execute("SELECT gate_required,gate_status FROM pattern_guesses WHERE id=?", (cross_id,)).fetchone()
    assert dict(cross) == {"gate_required": 1, "gate_status": "gated"}


def test_safe_types_auto_allow_and_verify_updates_coverage_without_raw_or_duplicate_sp():
    conn = _conn()
    thread = _blocked_thread(conn)
    guess_id = seed_guess(
        conn,
        target_name="demo",
        actor="main",
        attack_thread_id=thread,
        pattern="https://example.com/{route}",
        pattern_type="url_replace",
        seed_evidence=[{"source_table": "pages", "source_id": "1", "url": "https://example.com/login"}],
        verify_bound=100,
    )
    generate_candidates(conn, target_name="demo", guess_id=guess_id, values=["register"], budget=100)
    ids = dispatch_guess(conn, target_name="demo", guess_id=guess_id)
    assert len(ids) == 1
    raw = "HTTP/1.1 500 Error\r\nCookie: sid=secret"
    verify_guess(
        conn,
        target_name="demo",
        guess_id=guess_id,
        outcome="verified",
        summary=raw,
        evidence_refs=["evidence_refs:9"],
        anomaly="response shape differs",
    )
    verify_guess(
        conn,
        target_name="demo",
        guess_id=guess_id,
        outcome="verified",
        summary=raw,
        evidence_refs=["evidence_refs:9"],
        anomaly="response shape differs",
    )
    coverage = conn.execute("SELECT * FROM coverage_ledger WHERE item_key=?", (f"pattern_guess:{guess_id}",)).fetchone()
    assert coverage["status"] == "covered"
    assert conn.execute("SELECT COUNT(*) FROM coverage_ledger WHERE item_key=?", (f"pattern_guess:{guess_id}",)).fetchone()[0] == 1
    assert "sid=secret" not in coverage["summary"]
    points = conn.execute("SELECT * FROM suspicious_points WHERE source='pattern_guess'").fetchall()
    assert len(points) == 1
    assert "sid=secret" not in points[0]["reasoning"]


def test_generate_expands_to_new_bound_rejects_malicious_values_and_verify_is_locked():
    conn = _conn()
    guess_id = seed_guess(
        conn,
        target_name="demo",
        actor="main",
        attack_thread_id=None,
        pattern="https://example.com/{route}",
        pattern_type="route_guess",
        seed_evidence=[{"source_table": "pages", "source_id": "1", "url": "https://example.com/"}],
    )
    assert len(generate_candidates(conn, target_name="demo", guess_id=guess_id, values=["a"], budget=1)) == 1
    assert len(generate_candidates(conn, target_name="demo", guess_id=guess_id, values=["a", "b"], budget=100)) == 2
    for value in ("../admin", "//evil.example"):
        with pytest.raises(ValueError):
            generate_candidates(conn, target_name="demo", guess_id=guess_id, values=[value], budget=100)

    dispatch_guess(conn, target_name="demo", guess_id=guess_id)
    statements = []
    conn.set_trace_callback(statements.append)
    verify_guess(
        conn,
        target_name="demo",
        guess_id=guess_id,
        outcome="refuted",
        summary="no match",
        evidence_refs=["evidence_refs:1"],
    )
    normalized = [item.strip().upper() for item in statements]
    assert next(i for i, item in enumerate(normalized) if item.startswith("BEGIN IMMEDIATE")) < next(
        i for i, item in enumerate(normalized) if item.startswith("SELECT")
    )
    assert conn.execute("SELECT status FROM coverage_ledger WHERE item_key=?", (f"pattern_guess:{guess_id}",)).fetchone()[0] == "covered"


def test_operator_gate_never_becomes_lane_and_anomaly_requires_evidence():
    conn = _conn()
    guess_id = seed_guess(
        conn,
        target_name="demo",
        actor="main",
        attack_thread_id=None,
        pattern="https://example.com/{route}",
        pattern_type="route_guess",
        verify_action="operator_gate",
        seed_evidence=[{"source_table": "pages", "source_id": "1", "url": "https://example.com/"}],
    )
    assert (
        conn.execute("SELECT COUNT(*) FROM operator_inbox WHERE action_key=?", (f"pattern-guess-{guess_id}-approval",)).fetchone()[0] == 1
    )
    approve_guess(conn, target_name="demo", guess_id=guess_id, approved=True, actor="operator")
    generate_candidates(conn, target_name="demo", guess_id=guess_id, values=["admin"], budget=1)
    assert dispatch_guess(conn, target_name="demo", guess_id=guess_id) == []
    assert conn.execute("SELECT COUNT(*) FROM work_items WHERE lane='operator_gate'").fetchone()[0] == 0
    verify_guess(
        conn,
        target_name="demo",
        guess_id=guess_id,
        outcome="blocked",
        summary="shape changed",
        evidence_refs=[],
        anomaly="difference",
    )
    assert conn.execute("SELECT COUNT(*) FROM suspicious_points WHERE source='pattern_guess'").fetchone()[0] == 0


def test_verify_requires_approved_gate_and_real_target_linked_dispatch():
    conn = _conn()
    gated = seed_guess(
        conn,
        target_name="demo",
        actor="main",
        attack_thread_id=None,
        pattern="https://{value}.example.com/",
        pattern_type="subdomain_guess",
        seed_evidence=[{"source_table": "pages", "source_id": "1", "url": "https://example.com/"}],
    )
    with pytest.raises(ValueError, match="gate must be approved"):
        verify_guess(conn, target_name="demo", guess_id=gated, outcome="blocked", summary="not run", evidence_refs=[])

    safe = seed_guess(
        conn,
        target_name="demo",
        actor="main",
        attack_thread_id=None,
        pattern="https://example.com/{route}",
        pattern_type="route_guess",
        seed_evidence=[{"source_table": "pages", "source_id": "2", "url": "https://example.com/"}],
    )
    generate_candidates(conn, target_name="demo", guess_id=safe, values=["login"], budget=1)
    with pytest.raises(ValueError, match="dispatched"):
        verify_guess(conn, target_name="demo", guess_id=safe, outcome="verified", summary="not run", evidence_refs=["1"])
    conn.execute("UPDATE pattern_guesses SET work_item_ids_json='[999]' WHERE id=?", (safe,))
    conn.commit()
    with pytest.raises(ValueError, match="do not match"):
        verify_guess(conn, target_name="demo", guess_id=safe, outcome="verified", summary="forged", evidence_refs=["1"])
    foreign = create_work_item(
        conn,
        target_name="other",
        lane="entry_probe",
        subtype=f"pattern_guess:{safe}",
        subject_table="pattern_guesses",
        subject_id=str(safe),
    )
    conn.execute("UPDATE pattern_guesses SET work_item_ids_json=? WHERE id=?", (json.dumps([foreign]), safe))
    conn.commit()
    with pytest.raises(ValueError, match="do not match"):
        verify_guess(conn, target_name="demo", guess_id=safe, outcome="refuted", summary="foreign", evidence_refs=["1"])


def test_invalid_raw_evidence_ref_rolls_back_without_ledger_or_sp():
    conn = _conn()
    guess_id = seed_guess(
        conn,
        target_name="demo",
        actor="main",
        attack_thread_id=None,
        pattern="https://example.com/{route}",
        pattern_type="route_guess",
        seed_evidence=[{"source_table": "pages", "source_id": "1", "url": "https://example.com/"}],
    )
    generate_candidates(conn, target_name="demo", guess_id=guess_id, values=["login"], budget=1)
    dispatch_guess(conn, target_name="demo", guess_id=guess_id)
    for raw in (
        "GET /secret HTTP/1.1\r\nAuthorization: Bearer secret",
        "Authorization: Bearer secret",
    ):
        with pytest.raises(ValueError, match="invalid evidence_ref"):
            verify_guess(
                conn,
                target_name="demo",
                guess_id=guess_id,
                outcome="verified",
                summary="must roll back",
                evidence_refs=[raw],
                anomaly="difference",
            )
    assert conn.execute("SELECT COUNT(*) FROM coverage_ledger WHERE item_key=?", (f"pattern_guess:{guess_id}",)).fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM suspicious_points WHERE source='pattern_guess'").fetchone()[0] == 0


@pytest.mark.parametrize("pattern_type", ["prefix", "subdomain_guess", "bucket_guess"])
def test_traversal_families_always_require_gate(pattern_type):
    conn = _conn()
    guess_id = seed_guess(
        conn,
        target_name="demo",
        actor="main",
        attack_thread_id=None,
        pattern="https://example.com/{value}",
        pattern_type=pattern_type,
        seed_evidence=[{"source_table": "pages", "source_id": "1", "url": "https://example.com/"}],
    )
    row = conn.execute("SELECT gate_required,gate_status FROM pattern_guesses WHERE id=?", (guess_id,)).fetchone()
    assert dict(row) == {"gate_required": 1, "gate_status": "gated"}


def test_illegal_pattern_type_action_and_credential_pattern_fail_closed():
    conn = _conn()
    for updates, match in (
        ({"pattern_type": "regex"}, "pattern_type"),
        ({"verify_action": "shell"}, "verify_action"),
        ({"pattern": "https://user:pass@example.com/{route}"}, "credentials"),
        ({"pattern": "https://example.com/../{route}"}, "traversal"),
    ):
        base = dict(
            target_name="demo",
            actor="main",
            attack_thread_id=None,
            pattern="https://example.com/{route}",
            pattern_type="route_guess",
            seed_evidence=[{"source_table": "pages", "source_id": "1", "url": "https://example.com/"}],
        )
        base.update(updates)
        with pytest.raises(ValueError, match=match):
            seed_guess(conn, **base)


def test_cli_missing_file_and_target_fail_compact_without_creating_db(tmp_path):
    missing = tmp_path / "missing.db"
    run = subprocess.run(  # noqa: S603
        [sys.executable, str(SCRIPT_PATH), "--file", str(missing), "--target-name", "demo"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert run.returncode == 1 and json.loads(run.stdout)["status"] == "error"
    assert not missing.exists() and run.stderr == ""

    path = tmp_path / "existing.db"
    with sqlite3.connect(path) as conn:
        conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        conn.execute("INSERT INTO targets(id,target_name) VALUES(1,'demo')")
    run = subprocess.run(  # noqa: S603
        [sys.executable, str(SCRIPT_PATH), "--file", str(path), "--target-name", "other"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert run.returncode == 1 and "target not found" in run.stdout and run.stderr == ""


def test_cli_1199_guesses_is_compact_by_default(tmp_path):
    path = tmp_path / "many.db"
    with sqlite3.connect(path) as conn:
        conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        conn.execute("INSERT INTO targets(id,target_name) VALUES(1,'demo')")
        conn.executemany(
            """INSERT INTO pattern_guesses(
              target_name,seed_evidence_json,pattern,pattern_type,derived_candidates_json
            ) VALUES('demo','[]',?,'route_guess','[]')""",
            [(f"https://example.com/{index}",) for index in range(1199)],
        )
        conn.commit()
    run = subprocess.run(  # noqa: S603
        [sys.executable, str(SCRIPT_PATH), "--file", str(path), "--target-name", "demo"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    payload = json.loads(run.stdout)
    assert run.returncode == 0
    assert payload["count"] == 1199 and len(payload["items"]) == 10 and payload["omitted"] == 1189
    assert len(run.stdout) < 5000
