"""`chunk_discover` 的三道硬门与预算行为的回归（假 egress，不打网络）。

真实抓取已在 `tmp/fixture-verify/e2e_local_fixture.py` 用本机 fixture 服务验证过；
这里只钉住**安全边界**，因为边界一旦退化，后果是抓到授权范围外的资产。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import pytest
from pipeline.chunk_discover import ScopeViolation, check_scope, discover

ENTRY = "https://app.example.com/"
HASH = "a1b2c3d4e5f6a1b2c3d4"
RUNTIME = f'__webpack_require__.p="/";__webpack_require__.u=e=>"js/"+e+"."+{{101:"{HASH}",102:"{HASH}"}}[e]+".js"'
HTML = '<html><head><script src="/runtime.js"></script></head></html>'


@dataclass
class FakeResult:
    status_code: int = 200
    body: bytes = b""
    url: str = ""
    error: str = ""
    headers: dict[str, str] = field(default_factory=dict)

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="ignore")


@dataclass
class FakeEgress:
    """按 URL 后缀返回预置内容，并记录被请求的 URL。

    签名必须接受 `**kwargs`：真实路径走 `recon.auth_surface.fetch_asset`，
    它会带 `profile=` / `timeout=` / `note=` 调用 `get`。
    """

    routes: dict[str, str] = field(default_factory=dict)
    calls: list[str] = field(default_factory=list)
    fail_status: set[str] = field(default_factory=set)

    def get(self, url: str, **kwargs: object) -> FakeResult:
        self.calls.append(url)
        for suffix, body in self.routes.items():
            if url.endswith(suffix):
                if suffix in self.fail_status:
                    return FakeResult(status_code=404, body=b"", url=url)
                return FakeResult(status_code=200, body=body.encode("utf-8"), url=url)
        return FakeResult(status_code=404, body=b"", url=url)


# --------------------------------------------------------------- 同源门


def test_check_scope_allows_same_origin():
    check_scope("https://app.example.com/x.js", entry_url=ENTRY, allow_hosts=set())


def test_check_scope_rejects_cross_origin_by_default():
    with pytest.raises(ScopeViolation):
        check_scope("https://cdn.other.com/x.js", entry_url=ENTRY, allow_hosts=set())


def test_check_scope_allows_explicit_allow_host():
    check_scope("https://cdn.other.com/x.js", entry_url=ENTRY, allow_hosts={"cdn.other.com"})


def test_check_scope_distinguishes_port():
    """端口不同视为不同源，避免误抓管理端口。"""
    with pytest.raises(ScopeViolation):
        check_scope("https://app.example.com:8443/x.js", entry_url=ENTRY, allow_hosts=set())


def test_cross_origin_candidates_are_skipped_not_fetched(tmp_path):
    """CDN 候选在未放行时必须进 skipped，且不得真的发出请求。"""
    cross_runtime = '__webpack_require__.p="https://cdn.other.com/js/";__webpack_require__.u=e=>e+"."+' + f'{{9:"{HASH}"}}[e]+".js"'
    egress = FakeEgress(routes={"/": HTML, "/runtime.js": cross_runtime})
    report = discover(ENTRY, out_dir=tmp_path, egress=egress, max_chunks=10)

    assert any("cdn.other.com" in c for c in egress.calls) is False, "跨域候选不得被请求"
    assert any(item["gate"] == "scope" for item in report["skipped"])


# --------------------------------------------------------------- 预算门


def _chunk_routes() -> dict[str, str]:
    """让两个 chunk 真能取到 —— 否则 404 只会进 failed，不会消耗 fetched 预算。"""
    return {
        "/": HTML,
        "/runtime.js": RUNTIME,
        f"/js/101.{HASH}.js": "fetch('/api/a')",
        f"/js/102.{HASH}.js": "fetch('/api/b')",
    }


def test_max_chunks_budget_stops(tmp_path):
    egress = FakeEgress(routes=_chunk_routes())
    report = discover(ENTRY, out_dir=tmp_path, egress=egress, max_chunks=2)
    assert len(report["fetched"]) == 2
    assert "max-chunks" in report["stop_reason"]


def test_max_bytes_budget_stops(tmp_path):
    big = "x" * 5000
    routes = _chunk_routes()
    routes["/runtime.js"] = RUNTIME + big
    egress = FakeEgress(routes=routes)
    report = discover(ENTRY, out_dir=tmp_path, egress=egress, max_chunks=10, max_bytes=3000)
    assert "max-bytes" in report["stop_reason"]
    assert report["total_bytes"] >= 3000


# --------------------------------------------------------------- dry-run


def test_dry_run_fetches_entry_and_scripts_but_no_chunks(tmp_path):
    """预演必须抓入口页与入口脚本（否则算不出计划），但绝不抓清单推导出的 chunk。

    早期版本连入口脚本都不抓，导致 --dry-run 永远显示"没有候选"，等于没法预演。
    """
    egress = FakeEgress(routes={"/": HTML, "/runtime.js": RUNTIME})
    report = discover(ENTRY, out_dir=tmp_path, egress=egress, dry_run=True)

    assert report["dry_run"] is True
    # 入口页 + 入口脚本会被真实请求
    assert ENTRY in egress.calls
    assert any(c.endswith("/runtime.js") for c in egress.calls)
    # 但由清单推导出的 chunk 不得被请求
    assert not any("/js/" in c for c in egress.calls), f"预演却抓了 chunk: {egress.calls}"

    # 计划里的 chunk 要如实列出来（带 planned_only 标记）
    planned = [f for f in report["fetched"] if f.get("planned_only")]
    assert planned, "预演必须列出计划抓取的 chunk"
    # 预演会落盘入口脚本（那是真抓到的），但不得落盘推导出的 chunk
    js_dir = tmp_path / "js"
    if js_dir.exists():
        saved = [p.name for p in js_dir.glob("*")]
        assert all(".js" in n for n in saved)
        # 清单里计划抓的 chunk 不应出现在已落盘文件里
        for item in planned:
            assert not any(item["url"].rsplit("/", 1)[-1].split("_")[-1] in n for n in saved), f"预演却落盘了 chunk: {item['url']}"


# --------------------------------------------------------------- 失败路径


def test_entry_fetch_failure_reports_stop_reason(tmp_path):
    egress = FakeEgress(routes={})  # 入口 404
    report = discover(ENTRY, out_dir=tmp_path, egress=egress)
    assert "入口页抓取失败" in report["stop_reason"]
    assert report["fetched"] == []


def test_chunk_failure_is_recorded_not_swallowed(tmp_path):
    egress = FakeEgress(routes={"/": HTML, "/runtime.js": RUNTIME})
    # 让 chunk 全部 404：只有 entry + runtime 能取到
    report = discover(ENTRY, out_dir=tmp_path, egress=egress, max_chunks=10)
    failed_urls = [f["url"] for f in report["failed"]]
    assert any(".js" in u and "runtime" not in u for u in failed_urls), "chunk 抓不到必须如实记录"


def test_no_manifest_warning_only_when_nothing_parsed(tmp_path):
    """能解析出清单时，不得报『未识别出清单』（chunk 文件自身无清单是正常的）。"""
    egress = FakeEgress(routes={"/": HTML, "/runtime.js": RUNTIME})
    report = discover(ENTRY, out_dir=tmp_path, egress=egress, max_chunks=10)
    assert not any("未识别出" in w for w in report["warnings"])
    assert report["manifests_found"] >= 1


def test_no_manifest_warning_when_truly_absent(tmp_path):
    """真的没有任何清单时要给出警告，不能静默。"""
    egress = FakeEgress(routes={"/": HTML, "/runtime.js": "var x=1;"})
    report = discover(ENTRY, out_dir=tmp_path, egress=egress, max_chunks=10)
    assert any("未识别出" in w for w in report["warnings"])


# --------------------------------------------------------------- 落盘安全


def test_saved_filenames_have_no_path_traversal(tmp_path):
    """URL 里带 ../ 也不能写到 out_dir 之外。"""
    evil_runtime = '__webpack_require__.p="/";__webpack_require__.u=e=>"js/"+e+"."+' + f'{{1:"{HASH}"}}[e]+".js"'
    routes = {
        "/": HTML,
        "/runtime.js": evil_runtime,
        f"/js/1.{HASH}.js": "fetch('/api/x')",
    }
    egress = FakeEgress(routes=routes)
    report = discover(ENTRY, out_dir=tmp_path, egress=egress, max_chunks=10)

    js_dir = (tmp_path / "js").resolve()
    for item in report["fetched"]:
        saved = Path(item["saved"]).resolve()
        assert str(saved).startswith(str(js_dir)), f"写到了 js/ 之外: {saved}"
