# -*- coding: utf-8 -*-
"""ui_context 回归测试。

对应吸收自 CyberStrike `hackbrowser/src/capture.ts: snapshotPageUI` 的三条契约：
  1. 作用域顺序 form → dialog → page
  2. 字段元数据（label / required / type / hidden-CSRF 标记）
  3. **绝不落字段值**（口令、验证码、CSRF token 的内容不得出现在输出里）
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_TOOLS))

from pipeline.ui_context import extract  # noqa: E402

LOGIN_HTML = """
<html><body>
  <form id="loginForm" action="/api/auth/login" method="post">
    <label for="user">用户名</label>
    <input id="user" name="username" type="text" placeholder="手机号" required />
    <label>密码 <input name="password" type="password" value="Secret123!" /></label>
    <input type="hidden" name="_csrf_token" value="aabbccddeeff00112233" />
    <input type="hidden" name="tenant" value="acme" />
    <input type="submit" value="登录" />
    <select name="scope"><option>web</option></select>
  </form>
  <div role="dialog" aria-label="验证码弹窗">
    <input name="smsCode" type="text" aria-label="短信验证码" />
  </div>
  <input name="stray" type="text" placeholder="表单外字段" />
</body></html>
"""


def test_scope_resolution_form_dialog_page():
    r = extract(LOGIN_HTML, page_url="https://app.example.com/login")
    assert [f["scope"] for f in r["forms"]] == ["form"]
    assert [d["scope"] for d in r["dialogs"]] == ["dialog"]
    # 表单外、弹窗外的那一个字段落到 page 桶
    assert [f["name"] for f in r["page_fields"]] == ["stray"]
    assert r["counts"] == {"forms": 1, "dialogs": 1, "page_fields": 1, "fields_total": 7}


def test_form_metadata_and_action_resolution():
    r = extract(LOGIN_HTML, page_url="https://app.example.com/login")
    form = r["forms"][0]
    assert form["action"] == "https://app.example.com/api/auth/login"
    assert form["method"] == "POST"
    assert form["field_names"] == ["username", "password", "_csrf_token", "tenant", "scope"]
    # submit 按钮不入选
    assert "登录" not in json.dumps(r, ensure_ascii=False)


def test_field_metadata_label_required_hidden_csrf():
    r = extract(LOGIN_HTML, page_url="https://app.example.com/login")
    fields = {f["name"]: f for f in r["forms"][0]["fields"]}
    assert fields["username"]["label"] == "用户名"
    assert fields["username"]["required"] is True
    assert fields["username"]["placeholder"] == "手机号"
    assert fields["password"]["label"].startswith("密码")  # 包裹式 <label>
    assert fields["password"]["type"] == "password"
    assert fields["_csrf_token"]["type"] == "hidden"
    assert fields["_csrf_token"]["csrf_like"] is True
    assert fields["tenant"].get("csrf_like") is None
    assert fields["scope"]["tag"] == "select"
    assert fields["scope"]["type"] == "select"
    assert fields["username"]["type"] == "text"


def test_never_leaks_field_values():
    """口令/验证码/CSRF 的**值**绝不能出现在输出里（只留 has_value 与 value_len）。"""
    r = extract(LOGIN_HTML, page_url="https://app.example.com/login")
    blob = json.dumps(r, ensure_ascii=False)
    assert "Secret123!" not in blob
    assert "aabbccddeeff00112233" not in blob
    assert "acme" not in blob
    fields = {f["name"]: f for f in r["forms"][0]["fields"]}
    assert fields["password"]["has_value"] is True
    assert fields["password"]["value_len"] == len("Secret123!")
    assert fields["tenant"]["has_value"] is True


def test_business_hint_from_field_names():
    r = extract(LOGIN_HTML, page_url="https://app.example.com/login")
    assert r["business_hint"] == "login"
    pay = extract('<form action="/pay" method="post"><input name="amount"><input name="orderId"></form>')
    assert pay["business_hint"] == "payment"
    plain = extract('<form action="/search" method="get"><input name="q"></form>')
    assert plain["business_hint"] is None


def test_page_without_forms_falls_back_to_page_scope():
    r = extract('<div><input name="kw" type="text"><textarea name="body"></textarea></div>')
    assert r["forms"] == [] and r["dialogs"] == []
    assert [f["name"] for f in r["page_fields"]] == ["kw", "body"]


def test_relative_action_and_missing_page_url():
    assert extract('<form action="/x"><input name="a"></form>')["forms"][0]["action"] == "/x"
    assert (
        extract('<form action="/x"><input name="a"></form>', page_url="https://t.example/dir/p")["forms"][0]["action"]
        == "https://t.example/x"
    )


# ---------------------------------------------------------------- 落库（endpoint_observations）
def _temp_db(tmp_path):
    import sqlite3

    db = tmp_path / "t.db"
    schema = (_TOOLS / "db" / "schema.sql").read_text(encoding="utf-8")
    conn = sqlite3.connect(db)
    conn.executescript(schema)
    conn.commit()
    return db, conn


def test_store_writes_form_endpoint_with_parameter_names(tmp_path):
    from pipeline.ui_context import extract, store

    db, conn = _temp_db(tmp_path)
    result = extract(LOGIN_HTML, page_url="https://app.example.com/login")
    written = store("T", result, db_path=db)
    assert written == 1
    row = conn.execute(
        "SELECT canonical_url, method, source, parameter_names_json, business_hint, source_page_url FROM endpoint_observations"
    ).fetchone()
    assert row[0] == "https://app.example.com/api/auth/login"
    assert row[1] == "POST"
    assert row[2] == "ui_context"
    assert json.loads(row[3]) == ["username", "password", "_csrf_token", "tenant", "scope"]
    assert row[4] == "login"
    assert row[5] == "https://app.example.com/login"


def test_store_is_idempotent_on_same_form(tmp_path):
    from pipeline.ui_context import extract, store

    db, conn = _temp_db(tmp_path)
    result = extract(LOGIN_HTML, page_url="https://app.example.com/login")
    store("T", result, db_path=db)
    store("T", result, db_path=db)
    assert conn.execute("SELECT COUNT(*) FROM endpoint_observations").fetchone()[0] == 1
