import sqlite3

# ruff: noqa: E501
from pathlib import Path

from db.system_cluster import apply_cluster_plan
from db.system_scorer import score_systems

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "TOOLS" / "db" / "schema.sql"


def _db():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    c.executescript(SCHEMA.read_text(encoding="utf-8"))
    c.execute("INSERT INTO targets(id,target_name,domain) VALUES(1,'T','example.com')")
    c.executemany(
        """INSERT INTO target_assets(
          id,target_name,asset_value,scope_status,scope_class,authorization_state,auth_entry_found
        ) VALUES(?,?,?,?,?,?,?)""",
        [
            (1, "T", "high.example.com", "needs_review", "intel_only", "unknown", 1),
            (2, "T", "ok.example.com", "in_scope", "owned", "authorized", 1),
        ],
    )
    c.executemany(
        """INSERT INTO technology_observations(target_name,asset_id,host,technology,confidence,source)
        VALUES('T',?,?,?,'high','fixture')""",
        [(1, "high.example.com", "vendor-rich"), (2, "ok.example.com", "vendor-basic")],
    )
    c.executemany(
        """INSERT INTO endpoint_observations(target_name,asset_id,canonical_url,source,auth_state,business_hint)
        VALUES('T',?,?,'fixture','authenticated',?)""",
        [(1, f"https://high.example.com/api/{i}", "business") for i in range(8)] + [(2, "https://ok.example.com/api/1", "fixture")],
    )
    c.commit()
    apply_cluster_plan(c, "T")
    return c


def test_intel_only_can_score_high_but_only_authorized_system_is_eligible_and_ranking_is_stable():
    c = _db()
    result = score_systems(c, "T", apply=True)
    rows = c.execute(
        "SELECT s.canonical_url,st.* FROM system_soft_targets st JOIN target_systems s ON s.id=st.system_id ORDER BY rank"
    ).fetchall()
    high = next(r for r in rows if "high.example" in r["canonical_url"])
    ok = next(r for r in rows if "ok.example" in r["canonical_url"])
    assert high["total_score"] > ok["total_score"]
    assert high["eligibility_status"] == "scope_blocked"
    assert ok["eligibility_status"] == "eligible"
    snapshot = [(r["system_id"], r["rank"], r["total_score"]) for r in rows]
    score_systems(c, "T", apply=True)
    assert snapshot == [(r[0], r[1], r[2]) for r in c.execute("SELECT system_id,rank,total_score FROM system_soft_targets ORDER BY rank")]
    assert result["count"] == 2


def test_scoring_does_not_read_findings_or_suspicious_points():
    c = _db()
    baseline = score_systems(c, "T", apply=False)
    c.execute("INSERT INTO suspicious_points(id,risk,test_status) VALUES('X','Critical','confirmed')")
    c.execute("INSERT INTO findings(id,sp_id,risk,review_status) VALUES('F','X','Critical','confirmed')")
    c.commit()
    assert score_systems(c, "T", apply=False) == baseline


def test_apply_locks_before_first_mutable_read_and_ties_are_deterministic():
    c = _db()
    statements = []
    c.set_trace_callback(statements.append)
    score_systems(c, "T", apply=True)
    normalized = [item.strip().upper() for item in statements]
    begin = next(i for i, item in enumerate(normalized) if item.startswith("BEGIN IMMEDIATE"))
    select = next(i for i, item in enumerate(normalized) if item.startswith("SELECT"))
    assert begin < select
    c.execute("DELETE FROM endpoint_observations")
    c.execute("DELETE FROM technology_observations")
    c.execute("UPDATE target_assets SET auth_entry_found=0")
    c.commit()
    first = score_systems(c, "T", apply=False)["items"]
    second = score_systems(c, "T", apply=False)["items"]
    assert [(x["system_key"], x["rank"]) for x in first] == [(x["system_key"], x["rank"]) for x in second]


def test_register_entry_is_only_operator_required_not_can_register():
    c = _db()
    c.execute(
        """INSERT INTO asset_auth_entries(target_name,asset_id,url,entry_type,source,confidence)
           VALUES('T',2,'https://ok.example.com/register','register','fixture','high')"""
    )
    c.commit()
    item = next(row for row in score_systems(c, "T", apply=False)["items"] if "ok.example" in row["canonical_url"])
    assert item["login_access"] == "operator_required"


def test_eligibility_downgrade_atomically_parks_focus_session_and_queued_tasks():
    c = _db()
    score_systems(c, "T", apply=True)
    system_id = c.execute("SELECT system_id FROM system_soft_targets WHERE eligibility_status='eligible'").fetchone()[0]
    c.execute(
        """INSERT INTO hunt_sessions(target_name,focus_subject_table,focus_subject_id,goal,status,selected_by,system_id)
           VALUES('T','target_systems',?,'g','active','operator',?)""",
        (str(system_id), system_id),
    )
    c.execute("UPDATE system_soft_targets SET status='focused' WHERE system_id=?", (system_id,))
    c.execute("UPDATE target_systems SET lifecycle_state='testing' WHERE id=?", (system_id,))
    work_id = c.execute(
        """INSERT INTO work_items(target_name,lane,subject_table,subject_id,system_id)
           VALUES('T','entry_probe','target_assets','1',?)""",
        (system_id,),
    ).lastrowid
    c.commit()
    # Revoke the authorization of the eligible system's only asset, then re-apply.
    c.execute("UPDATE target_assets SET authorization_state='unknown' WHERE asset_value='ok.example.com'")
    c.commit()
    result = score_systems(c, "T", apply=True)
    assert result["downgrade_stop"]["systems"] == 1
    assert result["downgrade_stop"]["sessions"] == 1
    assert result["downgrade_stop"]["work_items"] == 1
    assert c.execute("SELECT status FROM system_soft_targets WHERE system_id=?", (system_id,)).fetchone()[0] == "parked"
    assert c.execute("SELECT status FROM hunt_sessions WHERE system_id=?", (system_id,)).fetchone()[0] == "paused"
    assert c.execute("SELECT dispatch_state FROM work_items WHERE id=?", (work_id,)).fetchone()[0] == "parked"
    assert "not execution-eligible" in c.execute("SELECT park_reason FROM work_items WHERE id=?", (work_id,)).fetchone()[0]
    decision = c.execute("SELECT * FROM decision_events WHERE actor='system_scorer'").fetchone()
    assert decision is not None and decision["decision_type"] == "park"
    # Re-running apply with the same downgraded state is a no-op.
    again = score_systems(c, "T", apply=True)
    assert again["downgrade_stop"] == {"systems": 0, "sessions": 0, "work_items": 0, "decisions": 0}


def test_eligibility_restore_does_not_stop_eligible_system():
    c = _db()
    score_systems(c, "T", apply=True)
    before_count = c.execute("SELECT COUNT(*) FROM decision_events").fetchone()[0]
    result = score_systems(c, "T", apply=True)
    assert result["downgrade_stop"] == {"systems": 0, "sessions": 0, "work_items": 0, "decisions": 0}
    assert c.execute("SELECT COUNT(*) FROM decision_events").fetchone()[0] == before_count
