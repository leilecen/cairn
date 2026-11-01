# -*- coding: utf-8 -*-
"""auth_logic_probe 回归测试。

fixture 全部取自 app-a.example.com:9999 **真实响应 + 真实状态码**（2026-10-12），
把这次的三个判定钉死成回归：

- `checkOnlyUser` 一组对照 → **必须**识别出"未认证用户枚举 oracle"；
- `getLoginQrcode`/`third/*`/`permission/*` 401 → **必须**判"需鉴权"，不许误报成"裸奔"；
- `register`/`sms` 等状态改变类 → **默认必须 skip**，只有显式批准才规划执行。
"""

from __future__ import annotations

from pathlib import Path

import pytest
from recon import auth_logic_probe as alp

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "auth_logic"
BASE = "https://app-a.example.com:9999"
API = f"{BASE}/api/gateway/example-authority"


def _resp(name: str) -> tuple[int, str]:
    body = (FIXTURES / f"{name}.json").read_text(encoding="utf-8")
    status = int((FIXTURES / f"{name}.status").read_text(encoding="utf-8").strip())
    return status, body


# ── 分类 ───────────────────────────────────────────────────────────────────


def test_classify_unauthenticated_reachable():
    st, body = _resp("checkOnlyUser_exists")
    v = alp.classify(st, body)
    assert v.kind == "unauthenticated_reachable" and v.reachable_unauth is True


def test_classify_auth_required_from_real_401():
    st, body = _resp("login_qrcode")
    v = alp.classify(st, body)
    assert v.kind == "auth_required" and v.reachable_unauth is False
    assert "Token失效" in v.message


def test_classify_backend_down_502():
    st, body = _resp("backend_down_sample")
    v = alp.classify(st, body)
    assert v.kind == "backend_down" and v.reachable_unauth is False


def test_classify_not_found():
    assert alp.classify(404, "<html>404</html>").kind == "not_found"


# ── 规划：门控与预算 ───────────────────────────────────────────────────────


def test_state_changing_endpoints_skipped_by_default():
    endpoints = [f"{API}/sys/user/register", f"{API}/sys/sms", f"{API}/sys/user/passwordChange"]
    probes = alp.plan_probes(endpoints, approve_state_change=False)
    assert probes and all(p.skipped for p in probes)
    assert all("操作员门控" in p.skip_reason for p in probes)


def test_state_changing_endpoints_included_when_approved():
    endpoints = [f"{API}/sys/user/register"]
    probes = alp.plan_probes(endpoints, approve_state_change=True)
    assert len(probes) == 1 and probes[0].skipped is False
    assert probes[0].body == {}  # 只发空 body


def test_existence_check_plans_test_and_control_only():
    probes = alp.plan_probes([f"{API}/sys/user/checkOnlyUser"], existence_values=("admin",))
    assert len(probes) == 2, probes
    ids = {p.id for p in probes}
    assert ids == {"existence_check:test", "existence_check:control"}
    assert any("username=admin" in p.url_path for p in probes)
    assert any("zz-nonexist-" in p.url_path for p in probes)
    assert all(p.method == "GET" and p.body == {} for p in probes)


def test_budget_marks_excess_as_skipped():
    endpoints = [f"{API}/sys/phoneLogin", f"{API}/sys/user/phoneVerification", f"{API}/sys/tenant/queryList"]
    probes = alp.plan_probes(endpoints, max_probes=1)
    assert sum(1 for p in probes if not p.skipped) == 1
    assert any("超出预算" in p.skip_reason for p in probes)


# ── 判定 ───────────────────────────────────────────────────────────────────


def test_enumeration_oracle_detected_from_real_pair():
    probes = alp.plan_probes([f"{API}/sys/user/checkOnlyUser"], existence_values=("admin",))
    responses = {
        "existence_check:test": _resp("checkOnlyUser_exists"),
        "existence_check:control": _resp("checkOnlyUser_control"),
    }
    findings = alp.analyze(probes, responses)
    rules = [f.rule for f in findings]
    assert "user_enumeration_oracle" in rules, findings
    hit = [f for f in findings if f.rule == "user_enumeration_oracle"][0]
    assert "用户账号已存在" in hit.summary and "操作成功" in hit.summary


def test_no_oracle_when_responses_identical():
    probes = alp.plan_probes([f"{API}/sys/user/checkOnlyUser"])
    same = _resp("checkOnlyUser_exists")
    findings = alp.analyze(probes, {"existence_check:test": same, "existence_check:control": same})
    assert [f.rule for f in findings] == []


def test_protected_endpoints_with_401_are_not_flagged():
    """真实 401 组不得被误报成未认证可达。"""
    endpoints = [f"{API}/sys/getLoginQrcode", f"{API}/sys/permission/getPermCode", f"{API}/sys/third/user/create"]
    probes = alp.plan_probes(endpoints, approve_state_change=True)
    responses = {p.id: _resp("login_qrcode") for p in probes}
    assert alp.analyze(probes, responses) == []


def test_backend_down_reported_as_blocked_not_refuted():
    probes = alp.plan_probes([f"{API}/sys/phoneLogin"])
    findings = alp.analyze(probes, {probes[0].id: _resp("backend_down_sample")})
    assert [f.rule for f in findings] == ["auth_backend_unavailable"]
    assert "blocked" in findings[0].next_action


# ── 端到端（offline，零发包） ──────────────────────────────────────────────


def test_offline_end_to_end_marks_oracle_and_skips_state_change(capsys, tmp_path):
    rc = alp.main(
        [
            "--url",
            BASE,
            "--offline-dir",
            str(FIXTURES),
            "--endpoint",
            f"{API}/sys/user/checkOnlyUser",
            "--endpoint",
            f"{API}/sys/user/register",
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "user_enumeration_oracle" in out
    assert "已跳过" in out


def test_load_endpoints_filters_non_auth_paths():
    eps = alp.load_endpoints(endpoint=["/sys/phoneLogin", "/gateway/api/upload/create", "/sys/permission/getPermCode"])
    kinds = {alp.match_kind(e)[0] for e in eps}
    assert "phone_login" in kinds and "permission" in kinds
    assert "file_io" in kinds  # upload/create 属状态改变类，会在 plan 阶段被门控
    assert all(alp.match_kind(e)[0] != "generic" for e in eps)


def test_markdown_renders_skipped_and_findings():
    probes = alp.plan_probes([f"{API}/sys/sms", f"{API}/sys/user/checkOnlyUser"])
    responses = {
        "existence_check:test": _resp("checkOnlyUser_exists"),
        "existence_check:control": _resp("checkOnlyUser_control"),
    }
    result = alp.ProbeResult(url=BASE)
    result.probes = [p.__dict__ for p in probes]
    result.verdicts = alp.summarize(probes, responses)
    result.findings = alp.analyze(probes, responses)
    md = alp.render_markdown(result)
    assert "user_enumeration_oracle" in md
    assert "已跳过" in md  # 状态改变类必须显示为跳过而不是"没发现"


@pytest.mark.parametrize(
    "path,expected",
    [
        ("/sys/user/checkOnlyUser", "existence_check"),
        ("/sys/phoneLogin", "phone_login"),
        ("/sys/user/register", "register"),
        ("/sys/sms", "sms_send"),
        ("/sys/getLoginQrcode", "qrcode_login"),
        ("/sys/permission/getPermCode", "permission"),
    ],
)
def test_rule_table_matches_real_paths(path, expected):
    assert alp.match_kind(path)[0] == expected
