"""可复现性门的回归。

这批用例全部来自**真实交付缺陷**：一份报告同时具备前置条件/复现步骤/证据/证伪说明/
置信度理由/改级条件/修复建议，却一个 `curl` 都没有、IP 被掩码成 `10.x.x.41` 之后
又让人「全文检索 10.x.x.41」。结构门查不出来，可复现门必须查出来。
"""

from __future__ import annotations

from lib.report_repro_gate import (
    check_report_file,
    check_report_text,
    format_findings,
    is_deliverable,
    summarize,
)


def _codes(issues) -> set[str]:
    return {i.code for i in issues}


# 真实缺陷的浓缩形态：字段齐全、无一处可执行
BROKEN_REPORT = """# 某单位 — 授权渗透测试报告

## 一、执行摘要

发现若干问题。

## 二、有攻击依据的漏洞

### YJ-01｜人员接口可批量读取

| 项 | 内容 |
|---|---|
| 等级 | **high（70）** |
| 位置 | `GET https://app.example.com/api/person/list` |
| 前置条件 | 需要登录会话（X-Access-Token） |
| 复现步骤 | 1) 取得会话令牌 2) 请求 `person/list?pageNo=1&pageSize=1` 3) 响应返回 total |
| 证据 | `evidence_refs` #16（`tmp/case/r16/person.txt`） |
| 修复建议 | 服务端强制数据权限过滤 |

### YJ-02｜前端 bundle 硬编码内网地址

| 项 | 内容 |
|---|---|
| 等级 | **high（62）** |
| 位置 | `https://app.example.com/static/js/app.js` |
| 复现步骤 | 1) 下载 bundle 2) 全文检索 `10.x.x.41` 3) 得到 7 个内网地址 |
| 修复建议 | 前端构建期外置内网地址 |
"""

# 可复现的合格报告
GOOD_REPORT = """# 某单位 — 授权渗透测试报告

## 二、有攻击依据的漏洞

### YJ-01｜人员接口可批量读取

- 等级：**high**
- 前置条件：需要业务系统登录会话

**复现步骤**

1. 取会话令牌后发请求：

```bash
curl -s 'https://app.example.com/api/person/list?pageNo=1&pageSize=1' \\
  -H 'X-Access-Token: <REDACTED-见内部版#L12>'
```

响应关键片段（已脱敏）：

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"success":true,"code":200,"result":{"records":[{"name":"张*"}],"total":1963258}}
```

- 证据：`reports/example/evidence/r16-person.txt`（随包交付）
- 掩码↔真值映射：`app.example.com` = 真实主机；令牌原值见内部未脱敏版（`reports/example/internal/`）
"""


def test_flags_report_without_any_executable_request():
    issues = check_report_text(BROKEN_REPORT)
    assert "no_executable_request" in _codes(issues)


def test_flags_prose_only_repro_steps():
    issues = check_report_text(BROKEN_REPORT)
    where = [i.where for i in issues if i.code == "prose_only_repro"]
    assert any("YJ-01" in w for w in where)
    assert any("YJ-02" in w for w in where)


def test_flags_masked_self_reference():
    """让人去检索一个已被掩码的值——复现指令本身是假的。"""
    issues = check_report_text(BROKEN_REPORT)
    hits = [i for i in issues if i.code == "masked_self_reference"]
    assert hits, "必须识别「检索 10.x.x.41」这类自指矛盾"
    assert "10.x.x.41" in hits[0].detail


def test_flags_mask_without_mapping():
    issues = check_report_text(BROKEN_REPORT)
    assert "mask_without_mapping" in _codes(issues)


def test_flags_tmp_only_evidence():
    issues = check_report_text(BROKEN_REPORT)
    assert "evidence_tmp_only" in _codes(issues)


def test_flags_missing_response_sample():
    issues = check_report_text(BROKEN_REPORT)
    assert "no_response_sample" in _codes(issues)


def test_broken_report_is_not_deliverable():
    issues = check_report_text(BROKEN_REPORT)
    assert is_deliverable(issues) is False


def test_good_report_passes():
    issues = check_report_text(GOOD_REPORT)
    blocks = [i for i in issues if i.severity == "block"]
    assert blocks == [], format_findings(issues)
    assert is_deliverable(issues) is True


def test_appendix_with_fuxian_in_title_is_not_flagged():
    """回归：标题含「可复现性」的附录不能被误判成复现步骤节（实测误报）。"""
    text = """# R

## 二、漏洞

**复现步骤**

```bash
curl -s 'https://a.example.com/x'
```
```http
HTTP/1.1 200 OK

{"ok":true,"data":1}
```

## 附录 A：证据与可复现性

- 事实库、原始证据、出口台账
"""
    issues = check_report_text(text)
    assert not any(i.code == "prose_only_repro" for i in issues), format_findings(issues)


def test_empty_report_is_blocked():
    issues = check_report_text("")
    assert _codes(issues) == {"empty_report"}


def test_matched_host_curl_without_fence_is_not_enough():
    """请求必须放在代码块里——行内 `curl` 复制出来容易带上下文噪声。"""
    text = """# R

## 二、漏洞

**复现步骤**

用 curl 请求 https://a.example.com/x 即可，响应 HTTP/1.1 200 且 body 含 {"ok":true,"data":1}。
"""
    issues = check_report_text(text)
    codes = _codes(issues)
    assert "no_executable_request" in codes
    assert "no_response_sample" in codes


def test_summarize_and_format():
    issues = check_report_text(BROKEN_REPORT)
    stats = summarize(issues)
    assert stats["block"] >= 4
    assert stats["total"] == stats["block"] + stats["warn"]
    text = format_findings(issues)
    assert "阻断" in text
    assert "修法" in text


def test_format_ok_when_clean():
    assert "[OK]" in format_findings([])


def test_check_report_file(tmp_path):
    path = tmp_path / "r.md"
    path.write_text(BROKEN_REPORT, encoding="utf-8")
    issues = check_report_file(path)
    assert "no_executable_request" in _codes(issues)
