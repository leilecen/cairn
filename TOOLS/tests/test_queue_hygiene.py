import sqlite3

from utils.queue_hygiene import analyze_queue, apply_low_value


def _conn():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        CREATE TABLE hunt_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            method TEXT NOT NULL,
            url TEXT NOT NULL,
            query_string TEXT,
            status TEXT DEFAULT 'queued',
            source TEXT DEFAULT 'auto',
            notes TEXT,
            tested_at TEXT,
            noise_reason TEXT,
            risk_score INTEGER DEFAULT 0,
            signal_value TEXT,
            signal_reason TEXT,
            canonical_url TEXT
        );
        INSERT INTO hunt_queue (method, url, query_string, status)
        VALUES
          ('GET', 'https://portal.example.edu/portal-api/v2/theme/themeInfo', 'random_number=1', 'queued'),
          ('GET', 'https://portal.example.edu/portal-api/v2/theme/themeInfo', 'random_number=2', 'queued'),
          ('GET', 'https://portal.example.edu/api/user/profile', 'uid=42&random_number=1', 'queued');
        """
    )
    return conn


class TestQueueHygiene:
    def test_analyze_is_dry_run(self):
        conn = _conn()

        summary = analyze_queue(conn)
        queued = conn.execute("SELECT count(*) AS c FROM hunt_queue WHERE status='queued'").fetchone()["c"]
        conn.close()

        assert summary["queued"] == 3
        assert len(summary["duplicate_groups"]) == 1
        assert summary["random_param_duplicates"] == 1
        assert summary["low_value_queued"] == 2
        assert summary["noise_marked"] == 0
        assert summary["risk_score_distribution"]["0"] == 2
        assert summary["risk_score_distribution"]["60+"] == 1
        assert summary["top_candidate_sample"][0]["id"] == 3
        assert queued == 3

    def test_apply_marks_only_low_value_queued_tested(self):
        conn = _conn()
        summary = analyze_queue(conn)

        changed = apply_low_value(conn, summary["low_value_rows"])
        statuses = conn.execute("SELECT url, status, noise_reason FROM hunt_queue ORDER BY id").fetchall()
        conn.close()

        assert changed == 2
        assert [row["status"] for row in statuses] == ["tested", "tested", "queued"]
        assert statuses[0]["noise_reason"] == "public_or_configuration_signal"
        assert statuses[2]["noise_reason"] is None

    def test_manual_replay_rows_preserved_by_default(self):
        conn = _conn()
        conn.execute(
            """
            INSERT INTO hunt_queue (method, url, query_string, status, source)
            VALUES ('GET', 'https://portal.example.edu/api/theme/list', '', 'queued', 'manual_replay')
            """
        )
        summary = analyze_queue(conn)
        changed = apply_low_value(conn, summary["low_value_rows"])
        row = conn.execute("SELECT status FROM hunt_queue WHERE source='manual_replay'").fetchone()
        conn.close()

        assert changed == 2
        assert row["status"] == "queued"

    def test_include_manual_marks_manual_replay_rows(self):
        conn = _conn()
        conn.execute(
            """
            INSERT INTO hunt_queue (method, url, query_string, status, source)
            VALUES ('GET', 'https://portal.example.edu/api/theme/list', '', 'queued', 'manual_replay')
            """
        )
        summary = analyze_queue(conn, include_manual=True)
        changed = apply_low_value(conn, summary["low_value_rows"])
        row = conn.execute("SELECT status, noise_reason FROM hunt_queue WHERE source='manual_replay'").fetchone()
        conn.close()

        assert changed == 3
        assert row["status"] == "tested"
        assert row["noise_reason"] == "public_or_configuration_signal"
