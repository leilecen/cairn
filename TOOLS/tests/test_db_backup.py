from __future__ import annotations

import sqlite3
import sys
from types import SimpleNamespace

from db import db_backup


def _make_wal_db(path):
    writer = sqlite3.connect(path)
    writer.execute("PRAGMA journal_mode=WAL")
    writer.execute("PRAGMA wal_autocheckpoint=0")
    writer.execute("CREATE TABLE evidence(id INTEGER PRIMARY KEY, value TEXT)")
    writer.commit()
    writer.execute("INSERT INTO evidence(value) VALUES('wal-row')")
    writer.commit()
    return writer


def _rows(path):
    with sqlite3.connect(path) as conn:
        return conn.execute("SELECT value FROM evidence ORDER BY id").fetchall()


def test_cli_nonzero_falls_back_to_python_backup_and_keeps_wal_data(tmp_path, monkeypatch):
    src = tmp_path / "source.db"
    dst = tmp_path / "backup.db"
    writer = _make_wal_db(src)
    monkeypatch.setattr(
        db_backup.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=1, stdout="", stderr="cli failed"),
    )

    try:
        assert db_backup.sqlite3_backup(src, dst) is True
        assert _rows(dst) == [("wal-row",)]
        with sqlite3.connect(dst) as conn:
            assert conn.execute("PRAGMA quick_check").fetchone()[0] == "ok"
    finally:
        writer.close()


def test_missing_sqlite_cli_falls_back_to_python_backup(tmp_path, monkeypatch):
    src = tmp_path / "source.db"
    dst = tmp_path / "backup.db"
    writer = _make_wal_db(src)

    def missing(*args, **kwargs):
        raise FileNotFoundError("sqlite3")

    monkeypatch.setattr(db_backup.subprocess, "run", missing)
    try:
        assert db_backup.sqlite3_backup(src, dst) is True
        assert _rows(dst) == [("wal-row",)]
    finally:
        writer.close()


def test_cli_zero_with_corrupt_output_is_not_silent_success(tmp_path, monkeypatch):
    src = tmp_path / "source.db"
    dst = tmp_path / "backup.db"
    writer = _make_wal_db(src)

    def corrupt(*args, **kwargs):
        dst.write_bytes(b"not a sqlite database")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(db_backup.subprocess, "run", corrupt)
    try:
        assert db_backup.sqlite3_backup(src, dst) is True
        assert _rows(dst) == [("wal-row",)]
    finally:
        writer.close()


def test_python_backup_failure_does_not_leave_success_artifact(tmp_path, monkeypatch):
    src = tmp_path / "missing.db"
    dst = tmp_path / "backup.db"
    monkeypatch.setattr(
        db_backup.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=1, stdout="", stderr="failed"),
    )

    assert db_backup.sqlite3_backup(src, dst) is False
    assert not dst.exists()


def test_cli_returns_nonzero_when_backup_failed(tmp_path, monkeypatch, capsys):
    src = tmp_path / "source.db"
    src.touch()
    monkeypatch.setattr(db_backup, "find_target_db", lambda target: src)
    monkeypatch.setattr(
        db_backup,
        "backup_one",
        lambda db_path, backup_dir, keep: {"db": db_path.name, "status": "failed", "reason": "invalid"},
    )
    monkeypatch.setattr(sys, "argv", ["db_backup.py", "--target", "demo", "--backup-dir", str(tmp_path)])

    assert db_backup.main() == 1
    assert '"failed": 1' in capsys.readouterr().out
