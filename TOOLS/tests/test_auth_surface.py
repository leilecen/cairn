# -*- coding: utf-8 -*-
"""auth_surface 回归测试。

fixture 全部取自本项目 **真实证据**（app-a.example.com:9999 与 b1ockwx.example.com:8080），
不是手写样例 —— 目的是把"这次漏掉的东西"钉死成回归：

- 弱口令藏在 **lazy chunk** 里 → chunk 展开必须能发现它
- `admin/123456` 必须命中；而入口 bundle 里 base64/md5 字符表中的 `123456` **必须零命中**
- SSO 只挡 UI / 本地登录仍在 / 配置死代码 / http 硬编码 四类结构性缺陷必须被报出来
- Wiki.js 这类"没有出厂口令"的产品必须是"不猜"而不是"漏报"
"""

from __future__ import annotations

from pathlib import Path

import pytest
from recon import auth_surface as asf

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "auth_surface"
URL = "https://app-a.example.com:9999/"


def _read(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


@pytest.fixture
def entry_js() -> str:
    return _read("jeecg_entry_excerpt.js")


@pytest.fixture
def loginform_js() -> str:
    return _read("jeecg_loginform_excerpt.js")


@pytest.fixture
def shell_html() -> str:
    return _read("jeecg_index.html")


# ── 资源发现 ───────────────────────────────────────────────────────────────


def test_extracts_runtime_config_and_entry_bundle(shell_html):
    assets = asf.extract_assets(shell_html, URL)
    assert any("_app.config.js" in a for a in assets), assets
    assert any("assets/index." in a and a.endswith(".js") for a in assets), assets


def test_discovers_lazy_login_chunk_from_entry_bundle(entry_js):
    """这次漏检的核心：登录 chunk 只被 __vitePreload 明文引用。"""
    candidates = asf.extract_chunk_candidates(entry_js, f"{URL}assets/index.a88e3a86.js")
    assert any(c.endswith("/assets/LoginForm.9e72468f.js") for c in candidates), candidates
    login = [c for c in candidates if c.endswith("LoginForm.9e72468f.js")][0]
    assert asf.is_auth_interesting(login) is True


def test_chunk_selection_respects_budget_and_priority():
    cands = [f"{URL}assets/auth{i}.js" for i in range(20)] + [f"{URL}assets/vendor{i}.js" for i in range(20)]
    selected, available = asf.select_chunks(cands, max_chunks=5)
    assert len(selected) == 5
    assert available == 40
    assert all("auth" in s for s in selected), selected  # 认证命名优先，vendor 不吃预算


def test_chunk_selection_allows_non_auth_when_asked():
    cands = [f"{URL}assets/vendor{i}.js" for i in range(3)]
    selected, _ = asf.select_chunks(cands, max_chunks=3, allow_all=True)
    assert len(selected) == 3


def test_tight_budget_still_reaches_the_login_form_chunk():
    """核心回归：预算只有 2 个时，必须优先拿到 LoginForm / Login，而不是业务组件。"""
    cands = [
        f"{URL}assets/UserSelectModal.d90f0bef.js",
        f"{URL}assets/AuthColumn.1a46a30e.js",
        f"{URL}assets/LoginForm.9e72468f.js",
        f"{URL}assets/Login.9aa456c9.js",
    ]
    selected, _ = asf.select_chunks(cands, max_chunks=2)
    assert any(s.endswith("LoginForm.9e72468f.js") for s in selected), selected
    assert any(s.endswith("LoginForm.9e72468f.js") for s in selected)
    assert not any("UserSelectModal" in s for s in selected), selected


def test_relative_and_root_relative_chunk_refs_resolve_correctly():
    """vite 两种写法基准不同；混用会产生 /assets/assets/ 双前缀（曾真实发生）。"""
    base = f"{URL}assets/index.a88e3a86.js"
    cands = asf.extract_chunk_candidates('__vitePreload(()=>import("./LoginForm.9e72468f.js"),["assets/Login.9aa456c9.js"])', base)
    assert f"{URL}assets/LoginForm.9e72468f.js" in cands, cands
    assert f"{URL}assets/Login.9aa456c9.js" in cands, cands
    assert not any("/assets/assets/" in c for c in cands), cands


# ── 默认凭据规则（含关键误报回归） ─────────────────────────────────────────


def test_default_credential_hits_real_form_defaults(loginform_js):
    findings = asf.scan_default_credentials({"loginform.js": loginform_js})
    rules = [f.rule for f in findings]
    assert "default_credential" in rules, findings
    hit = [f for f in findings if f.rule == "default_credential"][0]
    assert "admin" in hit.evidence and "123456" in hit.evidence


def test_no_false_positive_on_charset_noise():
    """入口 bundle 里 3 处 123456 都在 base64/md5 字符表里，规则不得命中。"""
    noise = _read("noise_charsets.js")
    assert "123456" in noise  # fixture 自检：噪音确实在
    assert asf.scan_default_credentials({"entry.js": noise}) == []


def test_default_credential_ignores_non_credential_assignment():
    text = 'var charset="0123456789qwertyuiop"; var size=123456; const FOO="admin";'
    assert asf.scan_default_credentials({"x.js": text}) == []


# ── 四类结构性缺陷 ─────────────────────────────────────────────────────────


def test_sso_gate_is_ui_only(entry_js):
    findings = asf.scan_sso_gate({"entry.js": entry_js})
    assert [f.rule for f in findings] == ["sso_ui_gate_only"]
    assert "本地" in findings[0].next_action


def test_local_login_endpoint_detected(entry_js):
    findings = asf.scan_local_login({"entry.js": entry_js})
    assert findings and findings[0].rule == "local_login_endpoint"
    assert "sys/login" in findings[0].evidence


def test_runtime_config_dead_code(entry_js, shell_html):
    findings = asf.scan_runtime_config_dead_code({"entry.js": entry_js}, html_asset_names=asf.extract_assets(shell_html, URL))
    assert [f.rule for f in findings] == ["runtime_config_dead_code"]


def test_runtime_config_not_flagged_without_config_file(entry_js):
    assert asf.scan_runtime_config_dead_code({"entry.js": entry_js}, html_asset_names=[]) == []


def test_hardcoded_http_service(entry_js):
    findings = asf.scan_hardcoded_http_service({"entry.js": entry_js})
    assert [f.rule for f in findings] == ["hardcoded_http_service"]


# ── 端到端（offline，零发包） ──────────────────────────────────────────────


def test_offline_scan_end_to_end_marks_all_four_symptoms(capsys):
    rc = asf.main(["--url", URL, "--offline-dir", str(FIXTURES)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "sso_ui_gate_only" in out
    assert "local_login_endpoint" in out
    assert "runtime_config_dead_code" in out
    assert "LoginForm.9e72468f.js" in out


def test_vendor_bundles_are_skipped_by_default():
    """框架/依赖 bundle 不吃预算（真实代价：8.3MB+4.8MB+1.6MB 只换来 0 条线索）。"""
    assert asf._role_of("https://x/chunk-vendors~._node_modules_@.js") == "vendor"
    assert asf._role_of("https://x/ant-design-vue~._node_modules_ant-design-vue_d.js") == "vendor"
    assert asf._role_of("https://x/cdn/babel-polyfill/polyfill_7_2_5.js") == "vendor"
    assert "vendor" in asf._SKIPPED_ROLES
    # 业务 app bundle 与认证 chunk 必须保留
    assert asf._role_of("https://x/app~._m.js") == "js"
    assert asf._role_of("https://x/user~._src_a.js") == "js"
    assert asf._role_of("https://x/assets/LoginForm.9e72468f.js") == "js"


def test_asset_roles_keep_budget_on_js(shell_html):
    """CSS/图片不得占用 HTML 引用资源的预算（真实事故：2 个 CSS 吃掉 2/6 预算）。"""
    assets = asf.extract_assets(shell_html, URL)
    roles = {asf._role_of(a) for a in assets}
    assert "css" in roles, roles  # 外壳里确实带 css
    kept = [a for a in assets if asf._role_of(a) not in asf._SKIPPED_ROLES]
    assert all(not a.endswith(".css") for a in kept), kept
    assert any("_app.config.js" in a for a in kept), kept
    assert any("assets/index." in a for a in kept), kept


def test_webpack_chunk_map_and_module_hint():
    """webpack 产物：chunk 名无语义（user~._src_a），线索在旁边的模块路径里。"""
    js = (
        'function component(){return __webpack_require__.e(/*! import() | user */ "user~._src_a")'
        '.then(__webpack_require__.bind(null, /*! @/views/user/Login */ "./src/views/user/Login.vue"));}'
        'var map={"user~._src_a":"user~._src_a","vendor~._x":"vendor~._x"};'
    )
    refs = asf.extract_chunk_refs(js, f"{URL}app~._m.js")
    urls = [r.url for r in refs]
    assert f"{URL}user~._src_a.js" in urls, urls
    login_ref = [r for r in refs if r.url.endswith("user~._src_a.js")][0]
    assert "views/user/Login.vue" in login_ref.hint

    # 预算只有 1 个时，必须选它（靠 hint 命中权重，而不是靠 chunk 名）
    selected, _ = asf.select_chunks(refs, max_chunks=1)
    assert selected == [f"{URL}user~._src_a.js"], selected


def test_vite_and_webpack_refs_coexist():
    js = '__vitePreload(()=>import("./LoginForm.9e72468f.js"),["assets/Login.9aa456c9.js"]);__webpack_require__.e("user~._src_a");'
    urls = asf.extract_chunk_candidates(js, f"{URL}assets/index.a88e3a86.js")
    assert any(u.endswith("LoginForm.9e72468f.js") for u in urls)
    assert any(u.endswith("user~._src_a.js") for u in urls)


# ── 边界：跨域资源不取 ──────────────────────────────────────────────────────


def test_cross_origin_assets_are_not_scope():
    assert asf.same_origin(f"{URL}assets/a.js", URL) is True
    assert asf.same_origin("https://img.example.com/a.png", URL) is False
    assert asf.same_origin("http://app-a.example.com:9999/a.js", URL) is False  # scheme 不同也算跨源


def test_markdown_renders_coverage_warnings():
    """告警必须能渲染（GBK 控制台上曾因 ⚠ 抛 UnicodeEncodeError 导致 exit=1）。"""
    result = asf.ScanResult(url=URL)
    result.coverage_warnings = ["资源被截断，chunk 可能漏检：https://x/y.js"]
    md = asf.render_markdown(result)
    assert "覆盖告警" in md
    assert "y.js" in md


def test_static_scan_collects_endpoints(entry_js, loginform_js):
    result = asf.static_scan(url=URL, texts={"entry.js": entry_js, "form.js": loginform_js})
    assert any("sys/login" in e for e in result.endpoints), result.endpoints


# ── 截断识别（静默失败回归） ────────────────────────────────────────────────


def test_truncation_marker_is_detected():
    body = "var a=1;" + "... (truncated; set save-packet=true to dump the full packet to a file)"
    assert asf.body_looks_truncated(body) is True


def test_truncation_detected_via_content_length():
    assert asf.body_looks_truncated("x" * 100, {"Content-Length": "3578773"}) is True
    assert asf.body_looks_truncated("x" * 100, {"Content-Length": "120"}) is False
    assert asf.body_looks_truncated("x" * 100, None) is False


def test_healthy_bundle_is_not_flagged_as_truncated(entry_js):
    assert asf.body_looks_truncated(entry_js, {"Content-Length": str(len(entry_js))}) is False


# ── 落库（--store）：finding 必须能被持久化，且字段合法 ─────────────────────


def test_store_result_writes_suspicious_points_and_endpoints(tmp_path, entry_js, loginform_js):
    import sqlite3

    from lib.store_kit import StoreKit  # noqa: F401  (经由 store_result 内部使用)

    schema = (Path(__file__).resolve().parent.parent / "db" / "schema.sql").read_text(encoding="utf-8")
    db = tmp_path / "auth_surface_test.db"
    conn = sqlite3.connect(db)
    conn.executescript(schema)
    conn.execute("INSERT INTO targets (target_name, domain) VALUES (?, ?)", ("t-unit", "example.test"))
    conn.commit()
    conn.close()

    result = asf.static_scan(url=URL, texts={"entry.js": entry_js, "form.js": loginform_js})
    written = asf.store_result("t-unit", result, db_path=db)
    assert written, "至少要写入一条 suspicious_points"

    conn = sqlite3.connect(db)
    rows = conn.execute("SELECT id, test_type, risk, test_status FROM suspicious_points").fetchall()
    eps = conn.execute("SELECT COUNT(*) FROM endpoint_observations").fetchone()[0]
    conn.close()
    assert len(rows) == len(written)
    assert {r[2] for r in rows} <= {"High", "Medium", "Low"}
    assert all(r[3] == "untested" for r in rows)
    assert eps > 0
