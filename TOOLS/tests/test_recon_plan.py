"""recon_plan keeps L0/L1 planning read-only and execution single-slice."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from db.db_admin import init_target_db  # noqa: E402
from db.db_utils import connect  # noqa: E402
from recon import recon_plan  # noqa: E402


def _fresh_target(tmp_path):
    return init_target_db(target_name="Demo", slug="demo", domain="example.test", db_dir=tmp_path)


def test_plan_is_read_only_and_recommends_small_passive_slices(tmp_path):
    initialized = _fresh_target(tmp_path)
    db_path = Path(initialized["db_path"])
    with connect(db_path) as conn:
        before = conn.execute("SELECT COUNT(*) FROM work_items").fetchone()[0]
        plan = recon_plan.build_plan(conn, target_name="Demo", db_path=db_path)
        after = conn.execute("SELECT COUNT(*) FROM work_items").fetchone()[0]
    assert before == after == 0
    assert plan["authorized_root_domains"] == ["example.test"]
    assert {item["slice"] for item in plan["recommendations"]} == {"ct", "subfinder"}


def test_execute_rejects_unapproved_domain_before_subprocess(tmp_path):
    initialized = _fresh_target(tmp_path)
    db_path = Path(initialized["db_path"])
    with connect(db_path) as conn:
        with pytest.raises(PermissionError, match="authorized root"):
            recon_plan.execute_slice(
                conn,
                target_name="Demo",
                db_path=db_path,
                slice_name="ct",
                domain="other.test",
                runner=lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError()),
            )


def test_execute_runs_one_explicit_slice_and_returns_compact_result(tmp_path):
    initialized = _fresh_target(tmp_path)
    db_path = Path(initialized["db_path"])
    calls = []

    class Completed:
        returncode = 0
        stdout = '{"status":"observed","provider":"fixture","items":[{},{}]}'

    def runner(command, **kwargs):
        calls.append((command, kwargs))
        return Completed()

    with connect(db_path) as conn:
        result = recon_plan.execute_slice(
            conn,
            target_name="Demo",
            db_path=db_path,
            slice_name="ct",
            domain="example.test",
            runner=runner,
        )
    assert result == {
        "slice": "ct",
        "returncode": 0,
        "status": "observed",
        "provider": "fixture",
        "items": 2,
        "db": str(db_path),
    }
    assert "ct_search.py" in calls[0][0][1]
    assert "--domain" in calls[0][0]
