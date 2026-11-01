from __future__ import annotations

import io
import sqlite3
import sys

from db.db_query import _json_safe, do_select
from db.db_utils import force_utf8_stdout


def test_json_safe_decodes_invalid_bytes_without_crashing():
    value = {"名称": b"\xe4\xb8\xad\xe6\x96\x87", "bad": b"\xff"}
    result = _json_safe(value)
    assert result["名称"] == "中文"
    assert result["bad"] == "�"


def test_do_select_preserves_unicode_and_normalizes_bytes():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE records (name TEXT, payload BLOB)")
    conn.execute("INSERT INTO records VALUES (?, ?)", ("浙江农业厅", "测试".encode("utf-8")))
    result = do_select(conn, "SELECT name, payload FROM records", [])
    assert result == [{"name": "浙江农业厅", "payload": "测试"}]


def test_force_utf8_stdout_handles_streams_without_newline_argument(monkeypatch):
    class MinimalStream(io.StringIO):
        def reconfigure(self, *, encoding=None, errors=None):
            super().reconfigure(encoding=encoding, errors=errors)

    out = MinimalStream()
    err = MinimalStream()
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", err)
    force_utf8_stdout()
    print("浙江农业厅", file=out)
    assert "浙江农业厅" in out.getvalue()
