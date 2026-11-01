"""静态 chunk 清单推导（吸收自 ARTEX api-recon，修正其 3 处缺陷）的回归。

为什么这些用例长这样：ARTEX 原实现（`skills/api-recon/scripts/harvest_static.py:51`）
在读代码时看起来没问题，但用真实 webpack/Vite 形状一跑就 2/5 正确。所以本文测试
**以真实运行时形状为单位**，而不是以函数分支为单位——分支覆盖再全，形状错了也没用。

三个被修正的缺陷各有对应用例：
  1. 哈希长度门（20 位 contenthash）→ test_webpack5_*
  2. 内联目录前缀被丢 → test_webpack5_contenthash20_inline_prefix
  3. 具名 chunk 被丢 → test_webpack5_named_chunks
"""

from __future__ import annotations

from utils.js_chunk_manifest import extract_entry_scripts, parse_chunk_manifest

BASE = "https://app.example.com/"

# --------------------------------------------------------------- 真实形状样本

# webpack 5 默认 [contenthash] 为 20 位 hex；目录 "js/" 内联在拼接式里，.p 是 "/"
WEBPACK5_INLINE_PREFIX_20 = (
    '__webpack_require__.p="/",__webpack_require__.u=e=>"js/"+e+"."+{123:"a1b2c3d4e5f6a1b2c3d4",456:"b2c3d4e5f6a1b2c3d4e5"}[e]+".js"'
)

# webpack 4：函数体 + publicPath 提供目录 + 16 位 hash
WEBPACK4_PUBLICPATH_16 = (
    '__webpack_require__.p="/static/";'
    '__webpack_require__.u=function(e){return e+"."+'
    '{111:"aaaabbbbccccdddd",222:"bbbbccccddddeeee"}[e]+".js"}'
)

# webpack 5 具名 chunk：名字表在前、哈希表在后
WEBPACK5_NAMED = (
    '__webpack_require__.p="/";'
    '__webpack_require__.u=e=>"js/"+({900:"vendors",901:"commons"}[e]||e)+"."+'
    '{900:"d4e5f6a1b2c3d4e5f6a1",901:"e5f6a1b2c3d4e5f6a1b2"}[e]+".js"'
)

# Vite
VITE_MAPDEPS = (
    'const __vite__mapDeps=(i,m=__vite__mapDeps,d=(m.f||(m.f=["assets/index-a1b2c3d4.js","assets/vendor-e5f6a7b8.js"])))=>i.map(i=>d[i]);'
)

# 微前端：publicPath 是 CDN 绝对地址
MICRO_FRONTEND_CDN = (
    '__webpack_require__.p="https://cdn.example.com/app-main/";__webpack_require__.u=e=>e+"."+{11:"ffff0000111122223333"}[e]+".js"'
)


def _urls(text: str, base: str = BASE) -> list[str]:
    return [c["url"] for c in parse_chunk_manifest(text, base_url=base)["candidates"]]


# --------------------------------------------------------------- 缺陷 1+2


def test_webpack5_contenthash20_inline_prefix():
    """20 位 contenthash（webpack 5 默认）必须能被解析，且保留内联的 "js/" 前缀。

    ARTEX 原实现：哈希门 {6,16} 直接丢掉整张表 → 0 个 chunk；
    即使放宽哈希门，前缀只从 .p 取（此处为 "/"）→ URL 少一层 "js/" → 抓取 404。
    """
    urls = _urls(WEBPACK5_INLINE_PREFIX_20)
    assert urls == [
        "https://app.example.com/js/123.a1b2c3d4e5f6a1b2c3d4.js",
        "https://app.example.com/js/456.b2c3d4e5f6a1b2c3d4e5.js",
    ]


def test_webpack4_publicpath_16():
    """webpack 4 形状：目录来自 .p，hash 16 位。"""
    urls = _urls(WEBPACK4_PUBLICPATH_16)
    assert urls == [
        "https://app.example.com/static/111.aaaabbbbccccdddd.js",
        "https://app.example.com/static/222.bbbbccccddddeeee.js",
    ]


# --------------------------------------------------------------- 缺陷 3


def test_webpack5_named_chunks():
    """具名 chunk：文件名用名字而非数字 id，hash 从哈希表配对。

    ARTEX 原实现把 `{900:"vendors"}` 当成"没有 hash 的表"整张丢弃。
    """
    urls = _urls(WEBPACK5_NAMED)
    assert urls == [
        "https://app.example.com/js/vendors.d4e5f6a1b2c3d4e5f6a1.js",
        "https://app.example.com/js/commons.e5f6a1b2c3d4e5f6a1b2.js",
    ]


def test_named_chunks_are_not_treated_as_hashes():
    """名字表的值（vendors/commons）不能被误当成 hash 拼进文件名。"""
    urls = _urls(WEBPACK5_NAMED)
    assert not any(".vendors." in u for u in urls)
    assert not any(u.endswith("900.js") for u in urls)


# --------------------------------------------------------------- Vite / 微前端


def test_vite_mapdeps():
    assert _urls(VITE_MAPDEPS) == [
        "https://app.example.com/assets/index-a1b2c3d4.js",
        "https://app.example.com/assets/vendor-e5f6a7b8.js",
    ]


def test_micro_frontend_cdn_publicpath():
    """publicPath 是绝对 CDN 地址时，chunk URL 必须指向 CDN 而不是主站。"""
    urls = _urls(MICRO_FRONTEND_CDN)
    assert urls == ["https://cdn.example.com/app-main/11.ffff0000111122223333.js"]


def test_multiple_public_paths_all_used():
    """微前端多个 publicPath：每个前缀都要出一个候选。"""
    text = '__webpack_require__.p="/a/";__webpack_require__.p="/b/";__webpack_require__.u=e=>e+"."+{7:"aaaabbbbccccdddd"}[e]+".js"'
    urls = _urls(text)
    assert "https://app.example.com/a/7.aaaabbbbccccdddd.js" in urls
    assert "https://app.example.com/b/7.aaaabbbbccccdddd.js" in urls


# --------------------------------------------------------------- 不伪造


def test_no_manifest_yields_no_candidates_and_warns():
    """没有 chunk 清单时必须返回空 + 警告，不能凭空造 URL。"""
    result = parse_chunk_manifest('var a=1;function foo(){return "bar"}', base_url=BASE)
    assert result["candidates"] == []
    assert result["warnings"], "识别不出清单时必须留下警告，不能静默"


def test_empty_input_is_safe():
    result = parse_chunk_manifest("", base_url=BASE)
    assert result["candidates"] == []
    assert result["warnings"]


def test_hash_without_suffix_is_rejected():
    """`...u=...` 里出现了 hash 表但没有 .js 后缀 → 不是 chunk 文件名模板，不该产出。"""
    text = '__webpack_require__.u=e=>{5:"aaaabbbbccccdddd"}[e]'
    result = parse_chunk_manifest(text, base_url=BASE)
    assert result["candidates"] == []


def test_confidence_is_graded_not_flat():
    """置信度必须分级：能确定 hash 的 high，只有名字的 low。"""
    high = parse_chunk_manifest(WEBPACK5_INLINE_PREFIX_20, base_url=BASE)
    assert high["counts"]["high"] == 2
    assert high["counts"]["low"] == 0

    named_only = '__webpack_require__.p="/";__webpack_require__.u=e=>({12:"chunky"}[e]||e)+".js"'
    low = parse_chunk_manifest(named_only, base_url=BASE)
    assert low["counts"]["low"] >= 1


def test_candidate_cap_prevents_explosion():
    """畸形 bundle 不能把候选数炸到内存里。"""
    pairs = ",".join(f'{i}:"aaaabbbbccccdddd"' for i in range(3000))
    text = f'__webpack_require__.p="/";__webpack_require__.u=e=>e+"."+{{{pairs}}}[e]+".js"'
    result = parse_chunk_manifest(text, base_url=BASE)
    assert len(result["candidates"]) <= 2000


def test_dedupes_identical_candidates():
    text = WEBPACK5_INLINE_PREFIX_20 * 2
    urls = _urls(text)
    assert len(urls) == len(set(urls))


# --------------------------------------------------------------- 入口脚本抽取


def test_extract_entry_scripts_resolves_relative_and_absolute():
    html = (
        "<html><head>"
        '<link rel="modulepreload" href="/assets/vendor.js">'
        '<script src="/static/js/runtime.abc123.js"></script>'
        '<script src="https://cdn.example.com/remote.chunk.js"></script>'
        "</head></html>"
    )
    urls = extract_entry_scripts(html, base_url=BASE)
    assert "https://app.example.com/static/js/runtime.abc123.js" in urls
    assert "https://cdn.example.com/remote.chunk.js" in urls
    assert "https://app.example.com/assets/vendor.js" in urls


def test_extract_entry_scripts_ignores_non_js_links():
    html = '<link rel="stylesheet" href="/app.css"><script src="/a.js"></script>'
    urls = extract_entry_scripts(html, base_url=BASE)
    assert urls == ["https://app.example.com/a.js"]


def test_extract_entry_scripts_handles_unquoted_attributes():
    """真机实测：目标返回 `<script src=/static/config.js>`（HTML5 允许无引号）。

    早期正则只认带引号写法 → 入口脚本数恒为 0 → 后续 chunk 推导全部落空。
    """
    html = "<script src=/static/config.js></script><script src=/a/b.js></script>"
    urls = extract_entry_scripts(html, base_url=BASE)
    assert "https://app.example.com/static/config.js" in urls
    assert "https://app.example.com/a/b.js" in urls


def test_extract_entry_scripts_supports_single_quotes():
    html = "<script src='/x/y.js'></script>"
    assert extract_entry_scripts(html, base_url=BASE) == ["https://app.example.com/x/y.js"]


def test_extract_entry_scripts_filters_css_and_images():
    """SPA 的 HTML 常有几百个 prefetch CSS，不过滤会白耗抓取预算。"""
    html = (
        "<link rel=prefetch href=/css/chunk-0bc59918.0abf8784.css>"
        "<link rel=icon href=/logo.png>"
        "<link rel=preload href=/js/app.js as=script>"
        "<script src=/static/config.js></script>"
    )
    urls = extract_entry_scripts(html, base_url=BASE)
    # 顺序：<script src> 优先于 <link>（实入口脚本更值得先抓）
    assert urls == [
        "https://app.example.com/static/config.js",
        "https://app.example.com/js/app.js",
    ]


def test_extract_entry_scripts_keeps_modulepreload():
    html = '<link rel=modulepreload href="/assets/chunk-abc">'
    assert extract_entry_scripts(html, base_url=BASE) == ["https://app.example.com/assets/chunk-abc"]


# --------------------------------------------------------------- Vue CLI / webpackJsonp

# 真机样本（某政务大屏站点的 app.js 形态，已脱敏为示例 hash）：
# 压缩后 chunk 文件名函数是**匿名独立函数**，且 `u.u=` 字面量根本不存在；
# 键名是带引号的字符串 "chunk-xxxx"，不是数字 id。
_VUE_CLI_MINIFIED = (
    'function o(e){return u.p+"js/"+({user:"user",fail:"fail"}[e]||e)+"."+'
    '{"chunk-0060191c":"22ce3654","chunk-00870a14":"dde1b5ae","chunk-01185aa4":"eeb28c9e"}[e]+".js"}'
    "function u(t){if(a[t])return a[t].exports;var n=a[t]={i:t,l:!1,exports:{}}}"
    'u.e=function(e){var t=[],n={"chunk-0060191c":1}}'
)


def test_vue_cli_minified_signature_without_u_assignment():
    """Vue CLI 压缩形态：没有 `__webpack_require__.u=`，必须靠清单签名定位。

    真机踩过：只认锚点的版本在这个 bundle 上返回 0 个 chunk（全丢）。
    """
    result = parse_chunk_manifest(_VUE_CLI_MINIFIED + '__webpack_require__.p="/"', base_url=BASE)
    urls = [c["url"] for c in result["candidates"]]
    assert "https://app.example.com/js/chunk-0060191c.22ce3654.js" in urls
    assert "https://app.example.com/js/chunk-00870a14.dde1b5ae.js" in urls
    assert len(urls) == 3, urls


def test_quoted_keys_in_hash_map_are_parsed():
    """键名带引号（"chunk-xxxx"）必须能解析——早期只认裸键会整表漏掉。"""
    result = parse_chunk_manifest(_VUE_CLI_MINIFIED, base_url=BASE)
    assert result["counts"]["high"] == 3


def test_string_chunk_ids_survive_reconstruction():
    """字符串 chunk id 必须原样进文件名，不能被当成数字/丢弃。"""
    urls = [c["url"] for c in parse_chunk_manifest(_VUE_CLI_MINIFIED, base_url=BASE)["candidates"]]
    assert all("/js/chunk-" in u for u in urls)
    assert not any(u.endswith("/js/0.js") for u in urls)


def test_signature_scan_survives_huge_hash_map():
    """哈希表极大时（真机 965 条约 29k 字符）不能因为窗口太短而落进表内部。

    早期实现向前取固定 3000 字符窗口，结果整个窗口落在表中间，解析直接返回 0。
    """
    entries = ",".join(f'"chunk-{i:08x}":"{i:08x}"' for i in range(600))
    text = 'function o(e){return u.p+"js/"+(e)+"."+{' + entries + '}[e]+".js"}'
    result = parse_chunk_manifest(text, base_url=BASE)
    assert len(result["candidates"]) == 600, len(result["candidates"])


def test_signature_scan_does_not_fire_on_unrelated_code():
    """普通数组下标拼接不能被误判成 chunk 清单。"""
    text = 'function f(arr,i){return arr[i]+".js"}; var x = {a:1}[k]+".js"'
    result = parse_chunk_manifest(text, base_url=BASE)
    assert result["candidates"] == []
