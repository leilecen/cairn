"""静态推导前端打包器的 chunk 清单：把「站点自己声明的资源清单」还原成 URL 列表。

为什么要有这个文件
------------------
SPA 的 chunk 是**按路由懒加载**的：没访问过的页面，其 JS 永远不会被请求，于是
「接口地图」在那一整块上是空白。此前 `js_recon.py` 的设计边界是「只消费已观测/
已加载脚本」，这条边界本身是对的（防越界乱扫），但代价就是上述空白。

本模块补的是另一半：**读打包器自己写在运行时代码里的清单**。
manifest 是前端为了让浏览器能加载 chunk 而必须暴露的映射表——知道它存在等于知道
「这个站点有这些页面代码」，这是**读站点公开声明的清单，不是猜路径**。区别在于：
字典扫描是「我猜它可能有 /admin/」，本模块是「它自己说它有 123.abc.js」。

吸收边界（重要）
----------------
本模块只做**离线解析**，不发任何请求。抓取由调用方经受管出口（`TOOLS/utils/egress.py`）
串行低频执行，并受委托 scope 与预算约束。解析出来的 URL 也可能 404（站点改了未部署、
CDN 剔除旧 chunk），所以每条都带 `confidence` 与推导依据，不假装确定。

为什么不照抄 ARTEX 同名实现
---------------------------
其 `skills/api-recon/scripts/harvest_static.py:51 parse_chunk_maps` 的思路正确，但
实测（见 `tmp/artex-verify/`）有 3 处硬缺陷，直接照抄会在现代站点上全军覆没：

1. 哈希长度门 `{6,16}`：webpack 5 默认 `[contenthash]` 是 **20 位** hex，
   整张表被丢弃 → 现代 webpack 5 站点得到 **0 个 chunk**（是全丢，不是少几个）。
2. 前缀只取 `__webpack_require__.p`：webpack 5 常把目录内联在拼接式里
   （`"js/"+e+"."+{...}[e]+".js"`），此时 `.p` 往往是 `/`，重建的 URL 少一层路径 →
   抓取必然 404。
3. 字符串型 chunk id 丢弃：`{900:"vendors"}` 这类具名表不含 hash，被当成「没有 chunk」。

本实现改为**模板重建**：定位 hash 表在拼接式中的位置，把它前后的字符串字面量抽出来，
拼成 `前缀 + id + 分隔 + hash + 后缀` 的真实形状，而不是假设某一种写法。

用法
----
    from utils.js_chunk_manifest import parse_chunk_manifest

    result = parse_chunk_manifest(js_text, base_url="https://app.example.com/")
    result["candidates"]   # [{"url","chunk_id","confidence","via"}]
    result["warnings"]     # 推导不出形状时的说明，别静默
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlparse

# 上限：防止畸形/恶意 bundle 造出百万条候选
MAX_CANDIDATES = 2000

# hex 长度放宽到 4–64：webpack 4 用 16、webpack 5 默认 20、`[fullhash]` 可到 32+
_HASH_RE = re.compile(r"^[0-9a-fA-F]{4,64}$")

# 一张 {id:"value"} 表，value 允许 hex 哈希或具名。**键可以带引号**：
# webpackJsonp 形态（Vue CLI）里键是 `"chunk-0060191c"` 这种字符串，早期只认裸键会整表漏掉。
_PAIR_RE = re.compile(r'(?:"([^"\\]{1,60})"|([A-Za-z0-9_$]+))\s*:\s*"([^"\\]{1,80})"')

# `{...}[expr]` —— hash 表被下标取值的位置，是模板重建的锚点
_MAP_INDEX_RE = re.compile(r"\}\s*\[\s*[A-Za-z0-9_$.]+\s*\]")

# 清单签名：`{...}[expr]` 之后紧跟一个以 .js 结尾的字面量。
# 不依赖函数名/挂载点，因此对压缩后的 `function o(e){return u.p+"js/"+...}` 也成立。
_MANIFEST_SIG_RE = re.compile(r'\}\s*\[\s*[A-Za-z0-9_$.]+\s*\]\s*\+\s*"[^"]{0,24}\.js"')

# webpack 运行时给 chunk URL 函数赋值的位置
_WEBPACK_U_RE = re.compile(r"__webpack_require__\.u\s*=\s*")

# publicPath 赋值
_PUBLIC_PATH_RE = re.compile(r'(?:__webpack_require__\.p|\.p|publicPath)\s*=\s*"([^"]*)"')

# 函数体截断：遇到这些就认为表达式结束
_BODY_END = (";", "\n\n")

_STRING_LIT_RE = re.compile(r'"((?:[^"\\]|\\.){0,200})"')

# Vite：__vite__mapDeps 的 f 数组
_VITE_F_ARRAY_RE = re.compile(r"__vite__mapDeps\s*=.*?m\.f\s*=\s*\[([^\]]{0,20000})\]", re.DOTALL)
_VITE_ASSET_RE = re.compile(r'"([^"]{1,200}\.js)"')


def _slice_body(text: str, start: int) -> str:
    """从 start 起截出 chunk URL 函数体（到 `;` 或双换行为止，带上限）。"""
    window = text[start : start + 4000]
    cut = len(window)
    for marker in _BODY_END:
        pos = window.find(marker)
        if pos != -1:
            cut = min(cut, pos)
    return window[:cut]


def _literals_with_positions(body: str) -> list[tuple[int, str]]:
    """抽出函数体里的字符串字面量及其位置。"""
    return [(m.start(), m.group(1)) for m in _STRING_LIT_RE.finditer(body)]


def _maps_with_positions(body: str) -> list[dict[str, Any]]:
    """找出函数体里所有 `{id:"value"}[var]` 形态的表，并判定它是不是哈希表。

    一张 chunk 文件名模板里可能出现**两张表**：
      `({900:"vendors"}[e]||e)+"."+{900:"d4e5..."}[e]+".js"`
        └ 名字表（[name] 替换）        └ 哈希表（[contenthash] 替换）
    必须区分开，否则会用名字表当锚点算出错误模板。
    """
    maps: list[dict[str, Any]] = []
    for anchor in _MAP_INDEX_RE.finditer(body):
        map_start = body.rfind("{", 0, anchor.start())
        if map_start == -1:
            continue
        map_text = body[map_start : anchor.start()]
        pairs: dict[str, str] = {}
        for m in _PAIR_RE.finditer(map_text):
            key = m.group(1) or m.group(2)
            pairs[key] = m.group(3)
        if not pairs:
            continue
        hash_like = sum(1 for v in pairs.values() if _HASH_RE.match(v))
        maps.append(
            {
                "start": map_start,
                "end": anchor.end(),
                "pairs": pairs,
                "is_hash": hash_like * 2 > len(pairs),  # 过半像哈希即视为哈希表
            }
        )
    return maps


def _template_from_body(body: str) -> dict[str, Any] | None:
    """从 `__webpack_require__.u` 的函数体重建文件名模板。

    做法：
      1. 找出所有 `{...}[var]` 表，分成哈希表与名字表；
      2. 以哈希表为锚点（没有哈希表时退化为名字表）；
      3. 只取**表范围之外**的字符串字面量：
         - 锚点前最后一个 = id 与 hash 之间的分隔符（通常是 "."）
         - 再往前的拼接 = 内联目录前缀（如 "js/"）
         - 锚点后的拼接 = 后缀（如 ".js"）
      4. 若名字表出现在锚点之前，说明文件名用的是 chunk 名字而非数字 id。
    """
    maps = _maps_with_positions(body)
    if not maps:
        return None

    hash_maps = [m for m in maps if m["is_hash"]]
    name_maps = [m for m in maps if not m["is_hash"]]
    anchor = hash_maps[0] if hash_maps else name_maps[0]

    # 表内的字面量不是路径片段，必须排除
    inside = [(m["start"], m["end"]) for m in maps]

    def outside(pos: int) -> bool:
        return not any(start <= pos <= end for start, end in inside)

    literals = [(pos, v) for pos, v in _literals_with_positions(body) if outside(pos)]

    before = [v for pos, v in literals if pos < anchor["start"]]
    after = [v for pos, v in literals if pos > anchor["end"]]

    separator = before[-1] if before else ""
    prefix = "".join(before[:-1]) if len(before) > 1 else ""
    suffix = "".join(after)

    # 名字表在哈希表之前 → 文件名占位符用的是 chunk 名字
    use_name = bool(hash_maps) and any(m["start"] < anchor["start"] for m in name_maps)
    name_map = name_maps[0]["pairs"] if name_maps else {}
    hash_map = hash_maps[0]["pairs"] if hash_maps else {}

    return {
        "prefix": prefix,
        "separator": separator,
        "suffix": suffix,
        "use_name": use_name,
        "name_map": name_map,
        "hash_map": hash_map,
        "all_ids": dict(list(anchor["pairs"].items())),
    }


def _normalize_public_path(public_paths: list[str], base_url: str) -> list[str]:
    """把 publicPath 归一化成可用于拼接的前缀列表（去重、保留顺序）。"""
    origin = f"{urlparse(base_url).scheme}://{urlparse(base_url).netloc}"
    out: list[str] = []
    for raw in public_paths or ["/"]:
        value = raw.strip()
        if not value:
            value = "/"
        if value.startswith("http://") or value.startswith("https://"):
            candidate = value if value.endswith("/") else value + "/"
        else:
            if not value.startswith("/"):
                value = "/" + value
            candidate = origin + (value if value.endswith("/") else value + "/")
        if candidate not in out:
            out.append(candidate)
    return out or [origin + "/"]


def parse_chunk_manifest(js_text: str, *, base_url: str) -> dict[str, Any]:
    """从 JS 文本推导 chunk 候选 URL。

    返回：
      candidates   [{"url", "chunk_id", "confidence", "via"}]
      warnings     [str] 推导不出/被截断时的说明
      public_paths 实际采用的 publicPath 列表
    """
    warnings: list[str] = []
    candidates: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add(url: str, *, chunk_id: str, confidence: str, via: str) -> None:
        if len(candidates) >= MAX_CANDIDATES:
            return
        if not url or url in seen:
            return
        seen.add(url)
        candidates.append({"url": url, "chunk_id": chunk_id, "confidence": confidence, "via": via})

    public_paths = _PUBLIC_PATH_RE.findall(js_text)
    normalized = _normalize_public_path(public_paths, base_url)

    # ---------------- webpack ----------------
    # 两个来源，按顺序尝试：
    #   1) 精确锚点 `__webpack_require__.u=`（标准构建，能准确截出函数体）
    #   2) 清单签名扫描（webpackJsonp 压缩后函数名/挂载点都被改掉，锚点不存在）
    # 真机实测：Vue CLI 构建里 `u.u=` 字面量根本没有，只有
    #   `function o(e){return u.p+"js/"+({user:"user"}[e]||e)+"."+{"chunk-00..":"22ce.."}[e]+".js"}`
    # 这时必须靠签名定位，否则整站漏掉。
    found_webpack = False
    bodies: list[str] = [_slice_body(js_text, assign.end()) for assign in _WEBPACK_U_RE.finditer(js_text)]
    bodies.extend(_manifest_bodies_by_signature(js_text))

    for body in bodies:
        parsed = _template_from_body(body)
        if parsed is None:
            continue
        prefix = parsed["prefix"]
        separator = parsed["separator"]
        suffix = parsed["suffix"]
        if not suffix:
            # 没有后缀说明不是 chunk 文件名模板（可能是别的 .u 赋值），跳过但留痕
            warnings.append("__webpack_require__.u 找到 hash 表但没有文件后缀，已跳过")
            continue
        found_webpack = True
        # 单文件里同一张清单可能被扫到多次（锚点 + 签名），靠 seen 去重即可。

        hash_map: dict[str, str] = parsed["hash_map"]
        name_map: dict[str, str] = parsed["name_map"]
        all_ids: dict[str, str] = parsed["all_ids"]
        use_name: bool = parsed["use_name"]

        for public_path in normalized:
            for chunk_id, value in all_ids.items():
                if use_name and chunk_id in name_map:
                    # 文件名用名字：<prefix><name><sep><hash><suffix>
                    chunk_name = name_map[chunk_id]
                    digest = hash_map.get(chunk_id, "")
                    if digest:
                        filename = f"{prefix}{chunk_name}{separator}{digest}{suffix}"
                        add(
                            urljoin(public_path, filename),
                            chunk_id=chunk_id,
                            confidence="high",
                            via="webpack:named-with-hash",
                        )
                    else:
                        filename = f"{prefix}{chunk_name}{suffix}"
                        add(
                            urljoin(public_path, filename),
                            chunk_id=chunk_id,
                            confidence="low",
                            via="webpack:named-no-hash",
                        )
                elif value and _HASH_RE.match(value):
                    # 数字 id + hash：<prefix><id><sep><hash><suffix>
                    filename = f"{prefix}{chunk_id}{separator}{value}{suffix}"
                    add(urljoin(public_path, filename), chunk_id=chunk_id, confidence="high", via="webpack:hash-template")
                else:
                    # 只有名字没有 hash
                    filename = f"{prefix}{chunk_id}{suffix}"
                    add(urljoin(public_path, filename), chunk_id=chunk_id, confidence="low", via="webpack:no-hash")

    # ---------------- Vite ----------------
    vite_matched = False
    for array_match in _VITE_F_ARRAY_RE.finditer(js_text):
        vite_matched = True
        for asset in _VITE_ASSET_RE.findall(array_match.group(1)):
            # Vite 的 f 数组是相对于 base 的路径，通常以 assets/ 开头
            add(urljoin(base_url, asset.lstrip("/")), chunk_id=asset, confidence="high", via="vite:mapDeps")

    if not vite_matched:
        # 兜底：直接出现在 __vite__mapDeps 附近但正则没抓到的独立 assets/*.js
        if "__vite__mapDeps" in js_text:
            for asset in _VITE_ASSET_RE.findall(js_text):
                if asset.startswith("assets/"):
                    add(urljoin(base_url, asset), chunk_id=asset, confidence="medium", via="vite:loose-asset")

    if not found_webpack and not vite_matched and not candidates:
        warnings.append(
            "未识别出 webpack/Vite chunk 清单：该 bundle 可能用其它打包器、chunk 清单被拆分到"
            "独立 runtime 文件，或已做混淆。请把 runtime chunk 一并交给本函数。"
        )

    return {
        "base_url": base_url,
        "public_paths": normalized,
        "candidates": candidates,
        "warnings": warnings,
        "counts": _count_by_confidence(candidates),
    }


def _manifest_bodies_by_signature(js_text: str) -> list[str]:
    """按清单签名找出候选函数体，不依赖 `__webpack_require__.u=` 这个锚点。

    压缩后的 webpackJsonp 会把 chunk 文件名函数写成匿名独立函数
    （`function o(e){return u.p+"js/"+...}`），随后才声明 requires 对象——此时
    `.u=` 字面量**完全不存在**，只能靠「`{...}[x]` 紧跟 `+".js"`」这个签名定位。

    坑：哈希表自身可能极大（真机实测 965 条约 29,000 字符），所以**不能**按固定
    长度向前取窗口（会落进表内部）。正确做法是先从签名位置回溯找到表的 `{`，
    再以表为基准向前取一小段（那里才是前缀/分隔符字面量）。
    """
    bodies: list[str] = []
    for match in _MANIFEST_SIG_RE.finditer(js_text):
        brace = js_text.rfind("{", max(0, match.start() - 200_000), match.start())
        if brace == -1:
            continue
        # 表前取 600 字符足够覆盖 `"js/"+(...)[e]||e)+"."+` 这类前缀表达式
        start = max(0, brace - 600)
        bodies.append(js_text[start : match.end()])
    return bodies


def _count_by_confidence(candidates: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {"high": 0, "medium": 0, "low": 0}
    for item in candidates:
        counts[item["confidence"]] = counts.get(item["confidence"], 0) + 1
    return counts


def extract_entry_scripts(html: str, *, base_url: str) -> list[str]:
    """从入口 HTML 抽出**真正的入口脚本**（`<script src>` 与 `modulepreload`）。

    必须支持**无引号属性**：实测某政务站点返回的是
    `<script src=/static/config.js>`（HTML5 允许无引号），早期版本只认带引号的写法，
    导致入口脚本数恒为 0、后续 chunk 推导全部落空。

    注意：`<link rel=prefetch|preload href=*.js>` **不**算入口脚本，它们是站点
    已声明的 chunk 清单本身，见 `extract_declared_chunks()`。
    """
    urls: list[str] = []
    seen: set[str] = set()

    def add(raw: str | None) -> None:
        if not raw:
            return
        absolute = urljoin(base_url, raw.strip())
        if absolute not in seen:
            seen.add(absolute)
            urls.append(absolute)

    for match in _SCRIPT_TAG_RE.finditer(html):
        add(_attr_value(match.group(0), "src"))
    for match in _LINK_TAG_RE.finditer(html):
        tag = match.group(0)
        href = _attr_value(tag, "href")
        rel = (_attr_value(tag, "rel") or "").strip().strip("\"'").lower()
        as_value = (_attr_value(tag, "as") or "").strip().strip("\"'").lower()
        if rel == "modulepreload" or as_value == "script":
            # modulepreload 的 URL 不一定带 .js 后缀（"/assets/chunk-abc"），
            # 只在明显是静态资源时排除。
            if _is_js_href(href) or not _looks_static(href):
                add(href)
    return urls


def _looks_static(href: str | None) -> bool:
    """是否明显不是脚本（CSS/图片/字体/地图）。"""
    if not href:
        return True
    lowered = href.lower().split("?")[0]
    return lowered.endswith((".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".map"))


def extract_declared_chunks(html: str, *, base_url: str) -> list[dict[str, str]]:
    """抽出 HTML 里**已声明的 JS chunk**（`rel=prefetch|preload` 且是 .js）。

    真机价值：被测站点用 Vue CLI 生成了 962 条
    `<link rel=prefetch href=/js/chunk-*.js>`——**一个 HTML 请求就拿到的全量懒加载清单**。
    这些不需要"抓下来才知道存在"，它们已经写在 HTML 里了。

    与入口脚本的区别：入口脚本要抓回来才能读出 webpack 运行时清单；这些是清单本身。
    """
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for match in _LINK_TAG_RE.finditer(html):
        tag = match.group(0)
        rel = (_attr_value(tag, "rel") or "").strip().strip("\"'").lower()
        if rel not in {"prefetch", "preload", "modulepreload"}:
            continue
        href = _attr_value(tag, "href")
        if not _is_js_href(href):
            continue
        absolute = urljoin(base_url, (href or "").strip())
        if absolute in seen:
            continue
        seen.add(absolute)
        out.append({"url": absolute, "chunk_id": absolute.rsplit("/", 1)[-1], "via": f"html:{rel}"})
    return out


def _is_js_href(href: str | None) -> bool:
    """判断 href 是否 JS（同时排除常见静态资源）。"""
    if not href:
        return False
    lowered = href.lower().split("?")[0]
    if lowered.endswith((".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".map")):
        return False
    return ".js" in lowered


# 属性值三种合法写法：双引号 / 单引号 / 无引号
_ATTR_VALUE_TMPL = r"""{name}\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>"']+))"""

_SCRIPT_TAG_RE = re.compile(r"<script\b[^>]*>", re.IGNORECASE)
# 预加载 / modulepreload 的 JS 也算入口脚本
_LINK_TAG_RE = re.compile(r"<link\b[^>]*>", re.IGNORECASE)


def _attr_value(tag: str, name: str) -> str | None:
    """从单个标签里取属性值，兼容三种引号写法。"""
    match = re.search(_ATTR_VALUE_TMPL.format(name=name), tag, re.IGNORECASE)
    if match is None:
        return None
    return match.group(1) or match.group(2) or match.group(3)
