"""migration 036 inspirations 表结构验证。"""

import sqlite3
from pathlib import Path

MIG = Path(__file__).resolve().parent.parent.parent / "migrations" / "036_inspiration_base.sql"


def _db():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(MIG.read_text(encoding="utf-8"))
    return conn


def test_table_created():
    conn = _db()
    cols = {r[1] for r in conn.execute("PRAGMA table_info(inspirations)").fetchall()}
    for c in (
        "id",
        "target_name",
        "stage",
        "content",
        "trigger",
        "source",
        "blocked_on_kind",
        "blocked_on_id",
        "refined_from_id",
        "status",
        "confidence",
    ):
        assert c in cols


def test_status_check_rejects_bad_value():
    conn = _db()
    import pytest

    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO inspirations(target_name, content, status) VALUES(?,?,?)",
            ("t", "x", "converting"),
        )


def test_stage_check_rejects_bad_value():
    conn = _db()
    import pytest

    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO inspirations(target_name, content, stage) VALUES(?,?,?)",
            ("t", "x", "raw"),
        )
