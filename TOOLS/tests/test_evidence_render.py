"""证据→可执行复现块的渲染回归。

全部样本取自真实落盘证据的形态（`tmp/<target>/rN/*.txt`），包括两个实测踩过的坑：
1. 响应体第一行就是 JSON，含冒号 → 早期实现把它当 header，**响应体整段丢失**；
2. curl 多行拼接缩进错乱，复制出来不能跑。
"""

from __future__ import annotations

from lib.evidence_render import (
    parse_evidence_file,
    parse_evidence_text,
    render_repro_markdown,
)

# 真实形态：token 已脱敏，响应体是单行 JSON
PERSON_EVIDENCE = """=== REQUEST ===
GET https://app.example.com/api/person/list?pageNo=1&pageSize=1
X-Access-Token: <redacted>

=== RESPONSE ===
status: 200 size: 421
{"success":true,"code":200,"result":{"records":[{"name":"俞**"}],"total":1963258}}
"""

# POST + form body
POST_EVIDENCE = """=== REQUEST ===
POST http://10.1.2.3:6060/api/sso/ticket
Content-Type: application/x-www-form-urlencoded

ticket=invalid-value

=== RESPONSE ===
status: 200
Server: nginx
Content-Length: 0

"""


def test_parse_request_line_and_header():
    rec = parse_evidence_text(PERSON_EVIDENCE)
    assert rec is not None
    assert rec.method == "GET"
    assert rec.host == "app.example.com"
    assert rec.path == "/api/person/list?pageNo=1&pageSize=1"
    assert rec.req_headers["X-Access-Token"] == "<redacted>"


def test_response_body_starting_with_json_is_not_swallowed():
    """回归：`{"success":...}` 含冒号，但不能被当成 header。"""
    rec = parse_evidence_text(PERSON_EVIDENCE)
    assert rec is not None
    assert rec.status == 200
    assert rec.resp_size == 421
    assert rec.resp_body.startswith('{"success":true')
    assert "1963258" in rec.resp_body


def test_post_body_is_preserved():
    rec = parse_evidence_text(POST_EVIDENCE)
    assert rec is not None
    assert rec.method == "POST"
    assert rec.req_body.strip() == "ticket=invalid-value"
    assert rec.status == 200


def test_render_emits_curl_raw_request_and_response():
    rec = parse_evidence_text(PERSON_EVIDENCE)
    assert rec is not None
    md = render_repro_markdown(rec, note="（测试账号会话）")

    assert "```bash" in md
    assert "curl -sS -i 'https://app.example.com/api/person/list?pageNo=1&pageSize=1'" in md
    assert "```http" in md
    assert "GET /api/person/list?pageNo=1&pageSize=1 HTTP/1.1" in md
    assert "Host: app.example.com" in md
    # 响应样例必须在
    assert "HTTP/1.1 200" in md
    assert "1963258" in md


def test_credential_header_is_redacted_with_actionable_hint():
    rec = parse_evidence_text(PERSON_EVIDENCE)
    assert rec is not None
    md = render_repro_markdown(rec)
    assert "REDACTED" in md
    # 原值不得残留
    assert "<redacted>" not in md


def test_post_renders_method_and_data():
    rec = parse_evidence_text(POST_EVIDENCE)
    assert rec is not None
    md = render_repro_markdown(rec)
    assert "-X POST" in md
    assert "--data-raw 'ticket=invalid-value'" in md
    assert "POST /api/sso/ticket HTTP/1.1" in md


def test_curl_block_is_copy_pasteable():
    """每行续行符必须是 ` \\` 且下一行以两个空格缩进，不能出现空续行。"""
    rec = parse_evidence_text(PERSON_EVIDENCE)
    assert rec is not None
    md = render_repro_markdown(rec)
    bash = md.split("```bash", 1)[1].split("```", 1)[0].strip()
    lines = bash.splitlines()
    for line in lines[:-1]:
        assert line.rstrip().endswith("\\"), f"缺少续行符: {line!r}"
    assert not any(line.strip() == "\\" for line in lines), "出现了空续行"


def test_redact_masks_ip_but_keeps_hint_that_mapping_is_needed():
    rec = parse_evidence_text(POST_EVIDENCE)
    assert rec is not None
    md = render_repro_markdown(rec, redact=True)
    assert "10.x.x.3" in md
    assert "10.1.2.3" not in md


def test_no_redact_keeps_real_ip():
    """默认不脱敏：`reports/` 不入库，掩码是零收益纯损失。"""
    rec = parse_evidence_text(POST_EVIDENCE)
    assert rec is not None
    md = render_repro_markdown(rec)
    assert "10.1.2.3" in md
    assert "10.x.x.3" not in md


def test_long_response_body_is_truncated_with_marker():
    long_body = '{"data":"' + "A" * 3000 + '"}'
    text = f"=== REQUEST ===\nGET https://a.example.com/x\n\n=== RESPONSE ===\nstatus: 200\n{long_body}\n"
    rec = parse_evidence_text(text)
    assert rec is not None
    md = render_repro_markdown(rec, resp_body_max=200)
    assert "已截断" in md


def test_missing_request_marker_returns_none():
    assert parse_evidence_text("不是证据格式的内容") is None


def test_parse_evidence_file_missing_path_returns_none(tmp_path):
    assert parse_evidence_file(tmp_path / "nope.txt") is None
