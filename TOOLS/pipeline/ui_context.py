# -*- coding: utf-8 -*-
"""UI 上下文抽取（ui context）—— 把一页 HTML 变成**结构化的攻击面上下文**。

为什么需要它（吸收自两个开源红队项目的共同做法）
------------------------------------------------
CyberStrike 的浏览器扩展在**触发动作前后**抓「UI 上下文」，作用域解析顺序是
**触发元素所在 form → dialog → 全页兜底**（`packages/hackbrowser/src/capture.ts: snapshotPageUI`）。
Strix 同样**从不把原始 HTML/JS 塞给模型**，只给无障碍树快照（`skills/tooling/agent_browser.md`）。
本工具把这条经验落地为确定性的一步：**离线**解析已保存的 HTML，产出 compact JSON，
并按需把表单端点与参数名写进 `endpoint_observations`（`parameter_names_json` 正是下游
`auth_logic_probe` / `x8` / `sqli_scan` 要吃的字段名）。

边界（硬性）
------------
- **纯离线**：只读本地 HTML，不发任何请求（因此不涉及出口纪律）。
- **绝不落值**：字段值（口令、验证码、CSRF token）只记录"有没有值/长度"，不记录内容。
- 不做 CSS 选择器求值、不执行 JS；只做 HTML 静态结构解析（stdlib `html.parser`）。

用法
----
    .venv/Scripts/python.exe TOOLS/pipeline/ui_context.py --html tmp/page.html --json
    .venv/Scripts/python.exe TOOLS/pipeline/ui_context.py --html tmp/page.html --out tmp/ui.json
    # 落库（表单 action 解析为绝对 URL 后写 endpoint_observations）
    .venv/Scripts/python.exe TOOLS/pipeline/ui_context.py --html tmp/page.html \
        --page-url https://app.example.com/login --target "示例目标" --store
"""

from __future__ import annotations

import argparse
import json
import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "TOOLS"))

FIELD_TAGS = {"input", "select", "textarea"}
SKIP_INPUT_TYPES = {"submit", "reset", "button", "image"}
DIALOG_ATTRS = ("role", "aria-modal")
DIALOG_ROLES = {"dialog", "alertdialog"}
CSRF_LIKE = ("csrf", "xsrf", "token", "nonce", "_token", "authenticity")
BUSINESS_HINTS = {
    "login": ("password", "passwd", "pwd"),
    "otp": ("otp", "smscode", "verifycode", "captcha", "code"),
    "payment": ("amount", "price", "money", "pay", "order"),
    "identity": ("idcard", "idno", "realname", "phone", "mobile", "email"),
    "upload": ("upload", "file", "attachment"),
}
VOID_TAGS = {
    "area",
    "base",
    "br",
    "col",
    "embed",
    "hr",
    "img",
    "input",
    "link",
    "meta",
    "param",
    "source",
    "track",
    "wbr",
}


class _Node:
    __slots__ = ("tag", "attrs", "children", "text")

    def __init__(self, tag: str, attrs: dict[str, str]) -> None:
        self.tag = tag
        self.attrs = attrs
        self.children: list[_Node] = []
        self.text = ""


class _Dom(HTMLParser):
    """只建我们需要的结构：元素树 + 文本。不做容错修复。"""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.root = _Node("#document", {})
        self._stack = [self.root]

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        node = _Node(tag, {k.lower(): (v or "") for k, v in attrs})
        self._stack[-1].children.append(node)
        if tag not in VOID_TAGS:
            self._stack.append(node)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if tag not in VOID_TAGS:
            self._stack.pop()

    def handle_endtag(self, tag: str) -> None:
        for i in range(len(self._stack) - 1, 0, -1):
            if self._stack[i].tag == tag:
                del self._stack[i:]
                return

    def handle_data(self, data: str) -> None:
        if data.strip():
            self._stack[-1].text += data


def _walk(node: _Node):
    for child in node.children:
        yield child
        yield from _walk(child)


def _text_of(node: _Node) -> str:
    parts = [node.text]
    for child in node.children:
        parts.append(_text_of(child))
    return " ".join(p.strip() for p in parts if p.strip())


def _label_index(root: _Node) -> tuple[dict[str, str], dict[int, str]]:
    """返回 (按 id 的 `for=` 标签, 按节点身份的包裹式标签)。

    包裹式 `<label>密码 <input></label>` 里的 input 往往没有 id，只能按元素身份关联。
    """
    by_id: dict[str, str] = {}
    by_node: dict[int, str] = {}
    for node in _walk(root):
        if node.tag != "label":
            continue
        text = _text_of(node)
        if not text:
            continue
        if node.attrs.get("for"):
            by_id.setdefault(node.attrs["for"], text)
        for child in _walk(node):
            if child.tag in FIELD_TAGS:
                by_node.setdefault(id(child), text)
    return by_id, by_node


def _field(node: _Node, labels: dict[str, str], wrap_labels: dict[int, str]) -> dict | None:
    tag = node.tag
    if tag == "input" and (node.attrs.get("type") or "text").lower() in SKIP_INPUT_TYPES:
        return None
    name = node.attrs.get("name") or node.attrs.get("id") or ""
    has_value = bool(node.attrs.get("value"))
    entry: dict = {
        "tag": tag,
        "type": (node.attrs.get("type") or ("select" if tag == "select" else ("textarea" if tag == "textarea" else "text"))).lower(),
        "name": name,
        "required": "required" in node.attrs,
        "disabled": "disabled" in node.attrs,
        "has_value": has_value,
        "value_len": len(node.attrs.get("value") or ""),
    }
    label = (
        wrap_labels.get(id(node))
        or labels.get(node.attrs.get("id", ""))
        or node.attrs.get("aria-label")
        or node.attrs.get("placeholder")
        or ""
    )
    if label:
        entry["label"] = label.strip()[:120]
    for attr in ("placeholder", "autocomplete", "pattern", "maxlength", "minlength"):
        if node.attrs.get(attr):
            entry[attr] = node.attrs[attr][:120]
    if entry["type"] == "hidden":
        lowered = name.lower()
        if any(marker in lowered for marker in CSRF_LIKE):
            entry["csrf_like"] = True
    return entry


def _business_hint(field_names: list[str]) -> str | None:
    blob = " ".join(field_names).lower()
    for hint, markers in BUSINESS_HINTS.items():
        if any(marker in blob for marker in markers):
            return hint
    return None


def _containers(root: _Node) -> list[tuple[str, _Node]]:
    """按 CyberStrike 的作用域顺序收集容器：form → dialog。"""
    out: list[tuple[str, _Node]] = []
    for node in _walk(root):
        if node.tag == "form":
            out.append(("form", node))
    for node in _walk(root):
        role = (node.attrs.get("role") or "").lower()
        if role in DIALOG_ROLES or node.attrs.get("aria-modal") == "true":
            out.append(("dialog", node))
    return out


def extract(html: str, *, page_url: str = "", max_fields: int = 200) -> dict:
    dom = _Dom()
    dom.feed(html)
    dom.close()
    root = dom.root
    labels, wrap_labels = _label_index(root)

    containers = _containers(root)
    claimed: set[int] = set()
    forms: list[dict] = []
    dialogs: list[dict] = []

    for kind, node in containers:
        fields: list[dict] = []
        for child in _walk(node):
            if child.tag in FIELD_TAGS:
                item = _field(child, labels, wrap_labels)
                if item and item["name"] and len(fields) < max_fields:
                    fields.append(item)
                    claimed.add(id(child))
        if not fields:
            continue
        record = {"scope": kind, "fields": fields, "field_names": [f["name"] for f in fields]}
        if kind == "form":
            action = node.attrs.get("action") or ""
            record["action"] = urljoin(page_url, action) if page_url else action
            record["method"] = (node.attrs.get("method") or "get").upper()
            if node.attrs.get("enctype"):
                record["enctype"] = node.attrs["enctype"]
            forms.append(record)
        else:
            record["dialog_label"] = node.attrs.get("aria-label") or node.attrs.get("id") or _text_of(node)[:60]
            dialogs.append(record)

    page_fields: list[dict] = []
    for node in _walk(root):
        if node.tag in FIELD_TAGS and id(node) not in claimed:
            item = _field(node, labels, wrap_labels)
            if item and item["name"] and len(page_fields) < max_fields:
                page_fields.append(item)

    all_names = [f["name"] for f in page_fields]
    for bucket in forms + dialogs:
        all_names.extend(bucket["field_names"])
    hint = _business_hint(all_names)

    return {
        "page_url": page_url,
        "scope_resolution": "form → dialog → page（同 CyberStrike snapshotPageUI 的作用域顺序）",
        "forms": forms,
        "dialogs": dialogs,
        "page_fields": page_fields,
        "business_hint": hint,
        "counts": {
            "forms": len(forms),
            "dialogs": len(dialogs),
            "page_fields": len(page_fields),
            "fields_total": sum(len(f["fields"]) for f in forms) + sum(len(d["fields"]) for d in dialogs) + len(page_fields),
        },
    }


def store(target: str, result: dict, *, db_path: str | None = None) -> int:
    """把每个表单端点写进 `endpoint_observations`（参数名进 `parameter_names_json`）。"""
    from lib.store_kit import StoreKit

    written = 0
    ctx = StoreKit(target, db_path=db_path) if db_path else StoreKit(target)
    with ctx as db:
        for form in result["forms"]:
            url = form.get("action") or result.get("page_url") or ""
            if not url:
                continue
            db.upsert(
                "endpoint_observations",
                {
                    "target_name": target,
                    "canonical_url": url,
                    "host": url.split("/")[2] if "//" in url else "",
                    "path": "/" + url.split("/", 3)[3] if url.count("/") >= 3 else "/",
                    "method": form["method"],
                    "source": "ui_context",
                    "source_id": url,
                    "source_page_url": result.get("page_url") or None,
                    "parameter_names_json": json.dumps(form["field_names"], ensure_ascii=False),
                    "business_hint": result.get("business_hint"),
                    "auth_state": "unknown",
                    "confidence": "medium",
                    "test_status": "not_tested",
                },
                key=["target_name", "canonical_url", "method", "source", "source_id"],
            )
            written += 1
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="从已保存的 HTML 抽取结构化 UI 上下文（离线，绝不落字段值）")
    parser.add_argument("--html", required=True, help="本地 HTML 文件路径")
    parser.add_argument("--page-url", default="", help="该 HTML 对应的页面 URL（用于解析表单 action）")
    parser.add_argument("--out", help="把 JSON 写到这个文件（默认只打印到 stdout）")
    parser.add_argument("--max-fields", type=int, default=200)
    parser.add_argument("--json", action="store_true", help="紧凑 JSON 输出")
    parser.add_argument("--target", help="目标名（配合 --store 落库）")
    parser.add_argument("--db", help="显式指定目标库路径")
    parser.add_argument("--store", action="store_true", help="把表单端点写入 endpoint_observations")
    args = parser.parse_args(argv)

    path = Path(args.html)
    if not path.is_file():
        print(f"HTML 不存在：{path}", file=sys.stderr)
        return 2
    result = extract(
        path.read_text(encoding="utf-8", errors="ignore"),
        page_url=args.page_url or f"file://{path.resolve().as_posix()}",
        max_fields=args.max_fields,
    )
    payload = json.dumps(result, ensure_ascii=False, indent=None if args.json else 2)
    if args.out:
        Path(args.out).write_text(payload, encoding="utf-8")
        print(f"写出 {args.out}（fields_total={result['counts']['fields_total']}）")
    else:
        print(payload)
    if args.store:
        if not args.target:
            print("--store 需要 --target", file=sys.stderr)
            return 2
        print(f"落库 endpoint_observations：{store(args.target, result, db_path=args.db)} 行")
    return 0


if __name__ == "__main__":
    sys.exit(main())
