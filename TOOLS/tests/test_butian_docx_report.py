"""测试补天 docx 报告生成器（butian_docx_report）。

覆盖：
- 字段提取：类别映射 / 风险中文 / 标题 / 简要描述 / 概述 / 利用链 / PoC / 修复 / 截图占位
- batch ops 结构：标题 Heading1、信息表 4 行、章节标题
- 数据缺失时留「待人工补充」占位
- 单 finding 过滤（含 refuted 选项）
- officecli 缺失时报错
- 真实生成 end-to-end（monkeypatch 掉 officecli 子进程调用）
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import db.butian_docx_report as bdr
from db.butian_docx_report import (
    _build_batch_ops,
    _category_of,
    _extract_brief,
    _extract_chain,
    _extract_overview,
    _extract_poc,
    _extract_remediation,
    _extract_screenshots,
    _load_findings,
    _risk_zh,
    _title,
    generate_butian_docx,
)

SCHEMA = Path(__file__).resolve().parents[2] / "TOOLS" / "db" / "schema.sql"


def _conn(tmp_path: Path) -> sqlite3.Connection:
    path = tmp_path / "bt.db"
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA.read_text(encoding="utf-8"))
    conn.execute("INSERT INTO targets(id, target_name, domain) VALUES(1, 'Fixture Target', 'example.test')")
    conn.execute(
        """INSERT INTO findings(id, target_id, type, url, param, method, payload, evidence, risk,
           remediation, review_status, review_notes)
           VALUES('F-001', 1, 'ssrf_lfi', 'https://pay.example.test/service', 'in0', 'POST',
                  '{"url":"http://127.0.0.1:80/"}',
                  '{"summary":"unauth SSRF confirmed","sp_evidence":{"ssrf":"127.0.0.1 loaded","unauth":"confirmed"}}',
                  'medium', '对 in0 参数做 URI 协议白名单校验', 'candidate', 'confirmed SP: unauth SSRF')"""
    )
    conn.execute(
        """INSERT INTO findings(id, target_id, type, url, risk, review_status)
           VALUES('F-REF', 1, 'xss', 'https://pay.example.test/x', 'high', 'refuted')"""
    )
    conn.execute(
        """INSERT INTO evidence_refs(id, target_name, source_table, source_id, evidence_type, title, summary)
           VALUES(1, 'Fixture Target', 'findings', 'F-001', 'request', 'PoC 请求', 'POST /service HTTP/1.1')"""
    )
    conn.execute(
        """INSERT INTO evidence_refs(id, target_name, source_table, source_id, evidence_type, title, summary)
           VALUES(2, 'Fixture Target', 'findings', 'F-001', 'screenshot', 'SSRF 验证截图', 'Collaborator 面板')"""
    )
    conn.commit()
    return conn


def _finding(conn: sqlite3.Connection, fid: str = "F-001"):
    return conn.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()


# ---------------------------------------------------------------------------
# 字段提取
# ---------------------------------------------------------------------------


def test_category_mapping():
    assert _category_of(_row(type="rce")) == "Web安全"
    assert _category_of(_row(type="weak_password")) == "口令安全"
    assert _category_of(_row(type="unknown_type")) == "Web安全"


class _Row:
    """Row-like: 支持 row['key'] / row.keys() / row[key] (但但 _value 用 row.keys() 和 row[key])。"""

    def __init__(self, data: dict):
        self._data = data

    def keys(self):
        return self._data.keys()

    def __getitem__(self, key):
        return self._data.get(key)

    def __setitem__(self, key, value):
        self._data[key] = value

    def __contains__(self, key):
        return key in self._data


def _row(**kw) -> _Row:
    return _Row(
        {
            "id": "F-001",
            "type": kw.get("type", "ssrf_lfi"),
            "risk": kw.get("risk", "medium"),
            "url": kw.get("url", "https://x.test/"),
            "method": kw.get("method", "POST"),
            "param": kw.get("param"),
            "payload": kw.get("payload"),
            "evidence": kw.get("evidence", "{}"),
            "remediation": kw.get("remediation", ""),
            "review_notes": kw.get("review_notes", ""),
            "sp_id": kw.get("sp_id"),
            "review_status": kw.get("review_status", "candidate"),
        }
    )


def test_risk_zh():
    assert _risk_zh("high") == "高危"
    assert _risk_zh("critical") == "严重"
    assert _risk_zh("medium") == "中危"
    assert _risk_zh("") == "待人工补充：风险等级"


def test_title_includes_host():
    t = _title(_row(url="https://pay.example.test:8443/service"), "Fixture Target")
    assert "pay.example.test" in t
    assert "中危" in t


def test_extract_brief_prefers_review_notes():
    row = _row(review_notes="confirmed SP: unauth SSRF", evidence='{"summary":"summary text"}')
    assert _extract_brief(row, {}) == "confirmed SP: unauth SSRF"


def test_extract_overview_from_sp_evidence():
    row = _row(evidence='{"sp_evidence":{"ssrf":"127.0.0.1 loaded","unauth":"confirmed"}}')
    out = _extract_overview(row, json.loads(row["evidence"]))
    assert "127.0.0.1 loaded" in out


def test_extract_chain_steps():
    row = _row(payload='{"url":"http://127.0.0.1/"}', param="in0")
    steps = _extract_chain(row, {})
    assert any("POST https://x.test/" in s for s in steps)
    assert any("关键参数" in s for s in steps)


def test_extract_poc_from_payload_and_refs(tmp_path):
    conn = _conn(tmp_path)
    finding = _finding(conn)
    refs = bdr._load_evidence_refs(conn, target_name="Fixture Target", finding=finding)
    poc = _extract_poc(finding, json.loads(finding["evidence"]), refs)
    assert "POST /service HTTP/1.1" in poc  # request 证据进入 PoC


def test_extract_screenshots(tmp_path):
    conn = _conn(tmp_path)
    finding = _finding(conn)
    refs = bdr._load_evidence_refs(conn, target_name="Fixture Target", finding=finding)
    shots = _extract_screenshots(refs)
    assert len(shots) == 1
    assert "SSRF 验证截图" in shots[0]


def test_extract_remediation_default():
    assert "鉴权" in _extract_remediation(_row(type="ssrf_lfi", remediation=""))


# ---------------------------------------------------------------------------
# batch ops 结构
# ---------------------------------------------------------------------------


def test_build_batch_ops_structure(tmp_path):
    conn = _conn(tmp_path)
    finding = _finding(conn)
    refs = bdr._load_evidence_refs(conn, target_name="Fixture Target", finding=finding)
    ops = _build_batch_ops(finding, target_name="Fixture Target", refs=refs)

    add_ops = [o for o in ops if o["command"] == "add"]
    table_ops = [o for o in add_ops if o["type"] == "table"]
    assert len(table_ops) == 1
    assert table_ops[0]["props"]["rows"] == 4
    assert table_ops[0]["props"]["cols"] == 2

    texts = [o["props"].get("text", "") for o in add_ops if o["type"] == "paragraph"]
    assert "简要描述" in texts
    assert "详细细节" in texts
    assert "漏洞概述" in texts
    assert "利用链" in texts
    assert "PoC" in texts
    assert "修复方案" in texts
    assert any(t.startswith("【截图 1】") for t in texts)

    # 信息表 cell 写入
    set_ops = [o for o in ops if o["command"] == "set"]
    assert any(o["path"] == "/body/tbl[1]/tr[1]/tc[1]" and o["props"]["text"] == "漏洞类别" for o in set_ops)
    assert any(o["path"] == "/body/tbl[1]/tr[1]/tc[2]" and o["props"]["text"] == "Web安全" for o in set_ops)


# ---------------------------------------------------------------------------
# DB 加载
# ---------------------------------------------------------------------------


def test_load_findings_excludes_refuted(tmp_path):
    conn = _conn(tmp_path)
    rows = _load_findings(conn, target_name="Fixture Target")
    ids = [r["id"] for r in rows]
    assert "F-001" in ids
    assert "F-REF" not in ids


def test_load_findings_single_and_include_refuted(tmp_path):
    conn = _conn(tmp_path)
    rows = _load_findings(conn, target_name="Fixture Target", finding_id="F-REF", include_refuted=True)
    assert [r["id"] for r in rows] == ["F-REF"]


# ---------------------------------------------------------------------------
# 生成 end-to-end（mock officecli）
# ---------------------------------------------------------------------------


class _FakeProc:
    returncode = 0
    stdout = ""
    stderr = ""


def test_generate_butian_docx_end_to_end(tmp_path, monkeypatch):
    conn = _conn(tmp_path)
    monkeypatch.setattr(bdr, "_officecli_available", lambda: True)
    calls = []

    def fake_run(*args, **kwargs):
        calls.append(list(args))
        return _FakeProc()

    monkeypatch.setattr(bdr.subprocess, "run", fake_run)
    monkeypatch.setattr(bdr, "_run_officecli", lambda args, check=True: _FakeProc())

    out_dir = tmp_path / "out"
    result = generate_butian_docx(conn, target_name="Fixture Target", output_root=out_dir)

    assert result["count"] == 1
    report = result["reports"][0]
    assert report["finding_id"] == "F-001"
    assert report["output_path"].endswith(".docx")
    # 更新了 report_file
    assert conn.execute("SELECT report_file FROM findings WHERE id='F-001'").fetchone()[0] == report["output_path"]


def test_officecli_missing_raises(tmp_path, monkeypatch):
    conn = _conn(tmp_path)
    monkeypatch.setattr(bdr, "_officecli_available", lambda: False)
    try:
        generate_butian_docx(conn, target_name="Fixture Target")
        raise AssertionError("should have raised")
    except RuntimeError as exc:
        assert "officecli" in str(exc)


def test_no_findings_raises(tmp_path, monkeypatch):
    conn = _conn(tmp_path)
    monkeypatch.setattr(bdr, "_officecli_available", lambda: True)
    try:
        generate_butian_docx(conn, target_name="No Such Target")
        raise AssertionError("should have raised")
    except ValueError as exc:
        assert "no findings" in str(exc)
