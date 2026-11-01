import sqlite3


def test_baseline_is_offline_and_unknown_is_measurable():
    c = sqlite3.connect(":memory:")
    c.executescript(
        "CREATE TABLE endpoint_observations(target_name TEXT,auth_state TEXT); CREATE TABLE work_items(target_name TEXT,lane TEXT,status TEXT); CREATE TABLE experiments(outcome TEXT,evidence_refs_json TEXT);"
    )
    c.executemany("INSERT INTO endpoint_observations VALUES('demo','unknown')", [()] * 3)
    c.execute("INSERT INTO work_items VALUES('demo','asset_triage','queued')")
    assert c.execute("SELECT COUNT(*) FROM endpoint_observations WHERE auth_state='unknown'").fetchone()[0] == 3
    assert c.execute("SELECT COUNT(*) FROM work_items WHERE lane='asset_triage'").fetchone()[0] == 1
