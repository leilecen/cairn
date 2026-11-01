"""AST-backed JS call graph extraction."""

from __future__ import annotations

import gc
from dataclasses import dataclass
from pathlib import Path

import tree_sitter_javascript as tsjs
from tree_sitter import Language, Node, Parser

JS_LANGUAGE = Language(tsjs.language())
REQUEST_CALLEES = {"wx.request", "fetch", "axios", "$.ajax", "request", "service", "http"}
REQUEST_METHOD_CALLEES = {"axios.get", "axios.post", "axios.put", "axios.delete", "axios.patch"}
SKIP_CALLEES = {"if", "for", "while", "switch", "catch", "typeof", "new", "delete", "await", "return"}


@dataclass
class FunctionInfo:
    node_id: str
    kind: str
    name: str
    file: str
    line: int
    snippet: str
    body: Node


def _parser() -> Parser:
    return Parser(JS_LANGUAGE)


def _text(source: bytes, node: Node | None) -> str:
    if node is None:
        return ""
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="ignore")


def _line(node: Node) -> int:
    return node.start_point.row + 1


def _snippet(source: bytes, node: Node, limit: int = 180) -> str:
    value = _text(source, node).replace("\n", " ").strip()
    return value[:limit]


def _normalize_node_id(file_path: str, name: str) -> str:
    stem = Path(file_path).with_suffix("").as_posix()
    return f"{stem}:{name}"


def _iter_named(node: Node):
    for child in node.children:
        if child.is_named:
            yield child


def _walk_cursor(root: Node):
    """pre-order 迭代遍历：TreeCursor 单路径游走，避免深递归与反复 .children 下钻（C 层崩溃）。"""
    cursor = root.walk()
    while True:
        yield cursor.node
        if cursor.goto_first_child():
            continue
        while True:
            if cursor.goto_next_sibling():
                break
            if not cursor.goto_parent():
                return


def _walk(node: Node):
    yield node
    for child in _iter_named(node):
        yield from _walk(child)


def _member_name(source: bytes, node: Node | None) -> str:
    if node is None:
        return ""
    if node.type in {"identifier", "property_identifier", "private_property_identifier"}:
        return _text(source, node)
    if node.type == "member_expression":
        obj = _member_name(source, node.child_by_field_name("object"))
        prop = _member_name(source, node.child_by_field_name("property"))
        return f"{obj}.{prop}".strip(".")
    if node.type == "subscript_expression":
        obj = _member_name(source, node.child_by_field_name("object"))
        index = _text(source, node.child_by_field_name("index"))
        return f"{obj}[{index}]".strip(".")
    return _text(source, node)


def _function_name(source: bytes, node: Node) -> str:
    # ancestors: 直接父节点 → 根（近到远），等价原 visit 里 reversed(parent_stack)
    ancestors: list[Node] = []
    p = node.parent
    while p is not None:
        ancestors.append(p)
        p = p.parent
    if node.type == "function_declaration":
        return _text(source, node.child_by_field_name("name"))
    if node.type in {"function_expression", "arrow_function"}:
        for parent in ancestors:
            if parent.type == "variable_declarator":
                return _text(source, parent.child_by_field_name("name"))
            if parent.type == "assignment_expression":
                return _member_name(source, parent.child_by_field_name("left"))
            if parent.type == "pair":
                return _member_name(source, parent.child_by_field_name("key"))
        return ""
    if node.type == "method_definition":
        name = _member_name(source, node.child_by_field_name("name"))
        for parent in ancestors:
            if parent.type == "class_declaration":
                class_name = _text(source, parent.child_by_field_name("name"))
                return f"{class_name}.{name}" if class_name else name
            if parent.type == "pair":
                return _member_name(source, parent.child_by_field_name("key"))
        return name
    return ""


def _function_body(node: Node) -> Node | None:
    return node.child_by_field_name("body")


def _collect_functions(source: bytes, root: Node, file_path: str) -> list[FunctionInfo]:
    functions: list[FunctionInfo] = []
    seen: set[str] = set()
    # 显式栈迭代（pre-order），避免深递归；父链经由 node.parent 上溯获取
    stack: list[Node] = [root]
    while stack:
        node = stack.pop()
        if node.type in {"function_declaration", "function_expression", "arrow_function", "method_definition"}:
            name = _function_name(source, node)
            body = _function_body(node)
            if name and body is not None and name not in {"Page", "App", "Component"}:
                node_id = _normalize_node_id(file_path, name)
                if node_id not in seen:
                    seen.add(node_id)
                    functions.append(
                        FunctionInfo(
                            node_id=node_id,
                            kind="method" if node.type == "method_definition" or "." in name else "function",
                            name=name,
                            file=file_path,
                            line=_line(node),
                            snippet=_snippet(source, node, limit=220),
                            body=body,
                        )
                    )
        children = list(_iter_named(node))
        for child in reversed(children):
            stack.append(child)
    return functions


def _collect_errors(source: bytes, root: Node, file_path: str) -> list[dict]:
    errors = []
    for node in _walk_cursor(root):
        if node.type == "ERROR" or node.is_missing:
            errors.append(
                {
                    "file": file_path,
                    "line": _line(node),
                    "error": "syntax_error",
                    "snippet": _snippet(source, node),
                }
            )
    return errors


def _pair_value(source: bytes, obj: Node | None, key_name: str) -> Node | None:
    if obj is None or obj.type != "object":
        return None
    for child in _iter_named(obj):
        if child.type != "pair":
            continue
        key = child.child_by_field_name("key")
        if key is not None and _text(source, key) == key_name:
            return child.child_by_field_name("value")
    return None


def _call_callee(source: bytes, node: Node) -> str:
    return _member_name(source, node.child_by_field_name("function"))


def _call_args(node: Node) -> list[Node]:
    arguments = node.child_by_field_name("arguments")
    if arguments is None:
        return []
    return [child for child in _iter_named(arguments)]


def _request_call_info(source: bytes, call: Node, callee: str) -> tuple[str, str]:
    args = _call_args(call)
    method = "GET"
    url_expr = ""
    if callee in REQUEST_METHOD_CALLEES:
        method = callee.split(".", 1)[1].upper()
        if args:
            url_expr = _text(source, args[0]).strip("'\"`")
        return method, url_expr
    if callee == "fetch":
        if args:
            url_expr = _text(source, args[0]).strip("'\"`")
        if len(args) > 1 and args[1].type == "object":
            method_node = _pair_value(source, args[1], "method")
            if method_node is not None:
                method = _text(source, method_node).strip("'\"`").upper()
        return method, url_expr
    first = args[0] if args else None
    if first is not None and first.type == "object":
        url_node = _pair_value(source, first, "url")
        method_node = _pair_value(source, first, "method")
        if url_node is not None:
            url_expr = _text(source, url_node).strip("'\"`")
        if method_node is not None:
            method = _text(source, method_node).strip("'\"`").upper()
    elif first is not None:
        url_expr = _text(source, first).strip("'\"`")
    return method, url_expr


def build_js_callgraph(content: str, file_path: str = "<memory>") -> dict:
    # tree-sitter Node 包装对象在 Python 自动 GC 回收阶段会访问可能已释放的 C 树，
    # 深递归遍历大 JS（压缩 bundle）时触发 Windows access violation（0xC0000005）。
    # 故在解析/遍历全程禁用自动 GC，并在树仍存活时手动回收，避免崩溃。
    gc_was_enabled = gc.isenabled()
    gc.disable()
    try:
        if not isinstance(content, str):
            content = str(content or "")
        source = content.encode("utf-8")
        tree = _parser().parse(source)
        root = tree.root_node
        functions = _collect_functions(source, root, file_path)
        known_names = {item.name for item in functions}
        nodes = [
            {
                "id": item.node_id,
                "kind": item.kind,
                "name": item.name,
                "file": item.file,
                "line": item.line,
                "snippet": item.snippet,
            }
            for item in functions
        ]
        edges: list[dict] = []
        request_calls: list[dict] = []
        seen_edges: set[tuple[str, str, int]] = set()

        for function in functions:
            for node in _walk_cursor(function.body):
                if node.type != "call_expression":
                    continue
                callee = _call_callee(source, node)
                if not callee or callee in SKIP_CALLEES:
                    continue
                line = _line(node)
                if callee in REQUEST_CALLEES or callee in REQUEST_METHOD_CALLEES:
                    method, url_expr = _request_call_info(source, node, callee)
                    request_calls.append(
                        {
                            "caller": function.node_id,
                            "callee": callee,
                            "method": method,
                            "url_expr": url_expr,
                            "line": line,
                            "file": file_path,
                            "snippet": _snippet(source, node),
                        }
                    )
                    continue
                short_name = callee.split(".")[-1]
                target_name = callee if callee in known_names else short_name
                edge_key = (function.node_id, target_name, line)
                if edge_key in seen_edges:
                    continue
                seen_edges.add(edge_key)
                edges.append({"from": function.node_id, "to": target_name, "kind": "call", "line": line})

        return {
            "nodes": nodes,
            "edges": edges,
            "request_calls": request_calls,
            "errors": _collect_errors(source, root, file_path),
        }
    finally:
        gc.collect()
        if gc_was_enabled:
            gc.enable()
