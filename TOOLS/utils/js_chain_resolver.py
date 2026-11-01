"""Resolve lightweight cross-file JS caller chains."""

from __future__ import annotations

from collections import defaultdict

from utils.js_callgraph import build_js_callgraph
from utils.js_module_resolver import analyze_js_module


def build_chain_index(files: dict[str, str]) -> dict:
    modules = {}
    callgraphs = {}
    exported_by_file = defaultdict(set)
    import_aliases: defaultdict[str, dict[str, str]] = defaultdict(dict)

    for file_path, content in files.items():
        module_info = analyze_js_module(content, file_path)
        graph = build_js_callgraph(content, file_path)
        modules[file_path] = module_info
        callgraphs[file_path] = graph
        for symbol in module_info.get("symbols", []):
            if symbol["kind"].startswith("exported"):
                exported_by_file[file_path].add(symbol["name"])
            elif symbol["kind"] in {"import", "require"}:
                alias = symbol["name"].replace("{", "").replace("}", "").split(",")[0].strip()
                alias = alias.split(" as ")[-1].strip()
                import_aliases[file_path][alias] = symbol["file"]
        for node in graph.get("nodes", []):
            exported_by_file[file_path].add(node["name"].split(".")[-1])

    reverse_edges = defaultdict(list)
    for file_path, graph in callgraphs.items():
        for edge in graph.get("edges", []):
            reverse_edges[(file_path, edge["to"])].append(edge["from"].split(":")[-1])
        for node in graph.get("nodes", []):
            short = node["name"].split(".")[-1]
            reverse_edges[(file_path, short)]

    return {
        "modules": modules,
        "callgraphs": callgraphs,
        "exported_by_file": exported_by_file,
        "import_aliases": import_aliases,
        "reverse_edges": reverse_edges,
    }


def resolve_request_chain(index: dict, file_path: str, request_call: dict) -> list[str]:
    caller = request_call["caller"].split(":")[-1]
    chain = [caller]
    reverse_edges = index["reverse_edges"]
    import_aliases = index["import_aliases"]
    exported_by_file = index["exported_by_file"]

    local_callers = reverse_edges.get((file_path, caller), [])
    if local_callers:
        chain.insert(0, local_callers[0])

    for importer, aliases in import_aliases.items():
        for alias, imported_file in aliases.items():
            if imported_file != file_path:
                continue
            if alias == caller or caller in exported_by_file[file_path]:
                import_callers = reverse_edges.get((importer, alias), []) or reverse_edges.get((importer, caller), [])
                if import_callers:
                    chain.insert(0, import_callers[0])
                break
    return chain
