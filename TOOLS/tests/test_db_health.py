from __future__ import annotations

import sqlite3

from db.db_health import collect_health


def _schema33_fixture(path):
    with sqlite3.connect(path) as conn:
        conn.executescript(
            """
            CREATE TABLE targets(id INTEGER PRIMARY KEY, target_name TEXT);
            INSERT INTO targets VALUES(1, 'demo');

            CREATE TABLE target_assets(
                id INTEGER PRIMARY KEY, target_name TEXT, notes TEXT
            );
            INSERT INTO target_assets VALUES(1, 'demo', NULL);
            INSERT INTO target_assets VALUES(2, 'demo', '');
            INSERT INTO target_assets VALUES(3, 'demo', 'useful');

            CREATE TABLE suspicious_points(
                id TEXT PRIMARY KEY, test_status TEXT, notes TEXT
            );
            INSERT INTO suspicious_points VALUES(NULL, 'confirmed', NULL);
            INSERT INTO suspicious_points VALUES('sp-finding', 'confirmed', 'evidence');
            INSERT INTO suspicious_points VALUES('sp-returned', 'confirmed', 'reviewed');
            INSERT INTO suspicious_points VALUES('sp-gated', 'confirmed', 'operator');
            INSERT INTO suspicious_points VALUES('sp-open', 'confirmed', NULL);
            INSERT INTO suspicious_points VALUES('sp-silent-done', 'confirmed', NULL);
            INSERT INTO suspicious_points VALUES('', 'untested', NULL);

            CREATE TABLE findings(id TEXT PRIMARY KEY, sp_id TEXT);
            INSERT INTO findings VALUES('f-1', 'sp-finding');

            CREATE TABLE attack_threads(
                id INTEGER PRIMARY KEY, status TEXT, evaluation_status TEXT
            );
            INSERT INTO attack_threads VALUES(10, 'parked', 'blocked');
            INSERT INTO attack_threads VALUES(11, 'active', 'untested');

            CREATE TABLE work_items(
                id INTEGER PRIMARY KEY, target_name TEXT, lane TEXT, subtype TEXT,
                subject_table TEXT, subject_id TEXT, attack_thread_id INTEGER,
                status TEXT, summary TEXT
            );
            INSERT INTO work_items VALUES(1, 'demo', 'asset_triage', NULL, 'target_assets', '1', NULL, 'queued', NULL);
            INSERT INTO work_items VALUES(
                2, 'demo', 'vuln_review', 'single_sp_review',
                'suspicious_points', 'sp-returned', NULL, 'done', 'refuted'
            );
            INSERT INTO work_items VALUES(
                3, 'demo', 'vuln_review', 'single_sp_review',
                'suspicious_points', 'sp-gated', NULL, 'blocked', NULL
            );
            INSERT INTO work_items VALUES(4, 'demo', 'preauth_probe', NULL, 'target_assets', '1', 10, 'blocked', NULL);
            INSERT INTO work_items VALUES(
                5, 'demo', 'preauth_probe', NULL,
                'target_assets', '2', NULL, 'blocked', NULL
            );
            INSERT INTO work_items VALUES(6, 'demo', 'preauth_probe', NULL, 'target_assets', '3', 11, 'blocked', NULL);
            INSERT INTO work_items VALUES(
                7, 'demo', 'vuln_review', 'single_sp_review',
                'suspicious_points', 'sp-silent-done', NULL, 'done', 'completed'
            );

            CREATE TABLE operator_inbox(
                id INTEGER PRIMARY KEY, target_name TEXT, related_work_item_id INTEGER,
                kind TEXT, status TEXT
            );
            INSERT INTO operator_inbox VALUES(1, 'demo', 3, 'manual_review', 'open');

            CREATE TABLE coverage_ledger(
                id INTEGER PRIMARY KEY, target_name TEXT, item_key TEXT,
                category TEXT, status TEXT
            );
            INSERT INTO coverage_ledger VALUES(1, 'demo', 'system:profile', 'system', 'unknown');
            INSERT INTO coverage_ledger VALUES(
                2, 'demo', 'public_exposure:public_docs_search',
                'public_exposure', 'covered'
            );
            INSERT INTO coverage_ledger VALUES(3, 'demo', 'entry:mobile_h5_discovery', 'entry_recursion', 'blocked');
            INSERT INTO coverage_ledger VALUES(4, 'demo', 'entry:recursive_js_expansion', 'entry_recursion', 'unknown');
            """
        )


def test_health_reports_schema33_metrics_without_writing(tmp_path):
    db_path = tmp_path / "fixture.db"
    _schema33_fixture(db_path)
    before = db_path.read_bytes()

    result = collect_health(db_path, "demo")

    assert result["asset_triage"] == {"status": "available", "queued": 1}
    assert result["coverage"]["total"] == 4
    assert result["coverage"]["by_status"] == {"blocked": 1, "covered": 1, "unknown": 2}
    assert result["confirmed_sp"]["total"] == 6
    assert result["confirmed_sp"]["without_disposition"] == 3
    assert result["blocked_work_items"]["total"] == 4
    assert result["blocked_work_items"]["without_blocked_thread"] == 3
    assert result["blocked_work_items"]["without_classification"] == 4
    assert result["blocked_work_items"]["classification_column"] == "missing"
    assert result["blocked_work_items"]["without_parked_event"] == 4
    assert result["blocked_work_items"]["without_decision_card"] == 4
    assert result["asset_notes"] == {
        "status": "available",
        "total": 3,
        "empty": 2,
        "empty_ratio": 2 / 3,
    }
    assert result["sp_ids"]["all_empty"] == 2
    assert result["sp_ids"]["confirmed_empty"] == 1
    assert result["coverage_domains"]["system"]["total"] == 1
    assert result["coverage_domains"]["public_exposure"]["by_status"] == {"covered": 1}
    assert result["coverage_domains"]["entry_recursion"]["by_status"] == {"blocked": 1, "unknown": 1}
    assert db_path.read_bytes() == before


def test_health_marks_missing_tables_not_available_instead_of_zero(tmp_path):
    db_path = tmp_path / "partial.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute("CREATE TABLE targets(id INTEGER PRIMARY KEY, target_name TEXT)")
        conn.execute("INSERT INTO targets VALUES(1, 'demo')")

    result = collect_health(db_path, "demo")

    assert result["asset_triage"] == {"status": "not_available", "missing_tables": ["work_items"]}
    assert result["coverage"] == {"status": "not_available", "missing_tables": ["coverage_ledger"]}
    assert result["confirmed_sp"]["status"] == "not_available"
    assert result["blocked_work_items"]["status"] == "not_available"
    assert result["asset_notes"] == {"status": "not_available", "missing_tables": ["target_assets"]}
    assert result["sp_ids"] == {"status": "not_available", "missing_tables": ["suspicious_points"]}
    assert result["coverage_domains"]["system"]["status"] == "not_available"


def test_health_marks_missing_columns_not_available_instead_of_zero(tmp_path):
    db_path = tmp_path / "missing-columns.db"
    with sqlite3.connect(db_path) as conn:
        conn.executescript(
            """
            CREATE TABLE targets(id INTEGER PRIMARY KEY, target_name TEXT);
            INSERT INTO targets VALUES(1, 'demo');
            CREATE TABLE coverage_ledger(id INTEGER PRIMARY KEY, target_name TEXT, status TEXT);
            CREATE TABLE work_items(id INTEGER PRIMARY KEY, target_name TEXT, lane TEXT, status TEXT);
            """
        )

    result = collect_health(db_path, "demo")

    assert result["coverage"] == {
        "status": "not_available",
        "missing_columns": ["coverage_ledger.category", "coverage_ledger.item_key"],
    }
    assert result["asset_triage"] == {"status": "available", "queued": 0}


def test_health_rejects_target_mismatch(tmp_path):
    db_path = tmp_path / "wrong-target.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute("CREATE TABLE targets(id INTEGER PRIMARY KEY, target_name TEXT)")
        conn.execute("INSERT INTO targets VALUES(1, 'other')")

    try:
        collect_health(db_path, "demo")
    except ValueError as exc:
        assert "demo" in str(exc)
    else:
        raise AssertionError("target mismatch must fail closed")


def test_health_reports_blocked_classification_and_thread_gaps_together(tmp_path):
    db_path = tmp_path / "blocked-health.db"
    with sqlite3.connect(db_path) as conn:
        conn.executescript(
            """
            CREATE TABLE targets(id INTEGER PRIMARY KEY, target_name TEXT);
            INSERT INTO targets VALUES(1, 'demo');
            CREATE TABLE attack_threads(
                id INTEGER PRIMARY KEY, status TEXT, evaluation_status TEXT
            );
            INSERT INTO attack_threads VALUES(1, 'parked', 'blocked');
            CREATE TABLE work_items(
                id INTEGER PRIMARY KEY, target_name TEXT, lane TEXT, status TEXT,
                attack_thread_id INTEGER, blocker_class TEXT
            );
            INSERT INTO work_items VALUES(1, 'demo', 'preauth_probe', 'blocked', 1, 'auth_barrier');
            INSERT INTO work_items VALUES(2, 'demo', 'preauth_probe', 'blocked', NULL, NULL);
            CREATE TABLE attack_thread_events(
                id INTEGER PRIMARY KEY, attack_thread_id INTEGER, event_type TEXT, payload_json TEXT
            );
            CREATE TABLE operator_inbox(
                id INTEGER PRIMARY KEY, target_name TEXT, related_work_item_id INTEGER, kind TEXT
            );
            """
        )

    result = collect_health(db_path, "demo")

    assert result["blocked_work_items"] == {
        "status": "available",
        "total": 2,
        "without_blocked_thread": 1,
        "without_classification": 1,
        "classification_column": "available",
        "without_parked_event": 2,
        "without_decision_card": 2,
    }


def test_health_requires_exact_parked_event_and_blocked_decision_card(tmp_path):
    db_path = tmp_path / "blocked-ledger-health.db"
    with sqlite3.connect(db_path) as conn:
        conn.executescript(
            """
            CREATE TABLE targets(id INTEGER PRIMARY KEY, target_name TEXT);
            INSERT INTO targets VALUES(1, 'demo');
            CREATE TABLE attack_threads(
                id INTEGER PRIMARY KEY, status TEXT, evaluation_status TEXT
            );
            INSERT INTO attack_threads VALUES(1, 'parked', 'blocked');
            CREATE TABLE work_items(
                id INTEGER PRIMARY KEY, target_name TEXT, lane TEXT, status TEXT,
                attack_thread_id INTEGER, blocker_class TEXT
            );
            INSERT INTO work_items VALUES(7, 'demo', 'preauth_probe', 'blocked', 1, 'scope');
            CREATE TABLE attack_thread_events(
                id INTEGER PRIMARY KEY, attack_thread_id INTEGER, event_type TEXT, payload_json TEXT
            );
            INSERT INTO attack_thread_events VALUES(1, 1, 'parked', '{"work_item_id": 999}');
            CREATE TABLE operator_inbox(
                id INTEGER PRIMARY KEY, target_name TEXT, related_work_item_id INTEGER, kind TEXT
            );
            INSERT INTO operator_inbox VALUES(1, 'other', 7, 'blocked_decision');
            """
        )

    result = collect_health(db_path, "demo")["blocked_work_items"]

    assert result["without_blocked_thread"] == 0
    assert result["without_classification"] == 0
    assert result["without_parked_event"] == 1
    assert result["without_decision_card"] == 1


def test_health_special_character_target_is_parameterized_and_fails_closed(tmp_path):
    db_path = tmp_path / "quoted-target.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute("CREATE TABLE targets(id INTEGER PRIMARY KEY, target_name TEXT)")
        conn.execute("INSERT INTO targets VALUES(1, 'demo')")

    injected_target = "demo' OR 1=1 --"
    try:
        collect_health(db_path, injected_target)
    except ValueError as exc:
        assert injected_target in str(exc)
    else:
        raise AssertionError("special-character target must not alter query scope")
