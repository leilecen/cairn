"""Best-effort JS module import/export resolver."""

from __future__ import annotations

import posixpath
import re
from pathlib import Path, PurePosixPath
from typing import Any

IMPORT_RE = re.compile(r"import\s+(?P<what>.+?)\s+from\s+['\"](?P<path>[^'\"]+)['\"]")
REQUIRE_RE = re.compile(
    r"\b(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)\s*="
    r"\s*require\(\s*['\"](?P<path>[^'\"]+)['\"]\s*\)"
)
EXPORT_FUNC_RE = re.compile(r"export\s+function\s+([A-Za-z_$][\w$]*)")
EXPORT_CONST_RE = re.compile(r"export\s+(?:const|let|var)\s+([A-Za-z_$][\w$]*)")
MODULE_EXPORTS_RE = re.compile(r"module\.exports\s*=\s*\{(?P<body>.*?)\}", re.DOTALL)
EXPORTS_MEMBER_RE = re.compile(r"exports\.([A-Za-z_$][\w$]*)\s*=")


def _is_bare_module(import_path: str) -> bool:
    return not import_path.startswith((".", "/")) and PurePosixPath(import_path).suffix != ".js"


def normalize_import_path(file_path: str, import_path: str) -> str:
    if _is_bare_module(import_path):
        return import_path
    base = PurePosixPath(file_path).parent
    has_trailing_slash = import_path.endswith("/")
    candidate = posixpath.normpath(str(PurePosixPath(base, import_path)))
    if not candidate.endswith(".js"):
        if has_trailing_slash:
            candidate = f"{candidate}/index.js"
        elif PurePosixPath(candidate).suffix == "":
            candidate = f"{candidate}.js"
    return str(PurePosixPath(candidate))


def analyze_js_module(content: str, file_path: str) -> dict:
    imports = []
    exports = []
    symbols = []
    resolution_errors: list[dict[str, Any]] = []

    for match in IMPORT_RE.finditer(content):
        normalized = normalize_import_path(file_path, match.group("path"))
        imports.append(normalized)
        symbols.append({"name": match.group("what").strip(), "file": normalized, "kind": "import"})
    for match in REQUIRE_RE.finditer(content):
        normalized = normalize_import_path(file_path, match.group("path"))
        imports.append(normalized)
        symbols.append({"name": match.group("name"), "file": normalized, "kind": "require"})
    for pattern in (EXPORT_FUNC_RE, EXPORT_CONST_RE, EXPORTS_MEMBER_RE):
        for match in pattern.finditer(content):
            exports.append(match.group(1))
            symbols.append({"name": match.group(1), "file": file_path, "kind": "exported_function"})
    module_exports = MODULE_EXPORTS_RE.search(content)
    if module_exports:
        names = re.findall(r"([A-Za-z_$][\w$]*)\s*[:,]", module_exports.group("body"))
        exports.extend(names)
        for name in names:
            symbols.append({"name": name, "file": file_path, "kind": "exported_member"})
    return {
        "modules": [{"file": file_path, "imports": sorted(set(imports)), "exports": sorted(set(exports))}],
        "symbols": symbols,
        "resolution_errors": resolution_errors,
    }


def resolve_module_graph(root_dir: str) -> dict:
    root = Path(root_dir)
    modules = []
    symbols = []
    errors = []
    discovered_files = {path.relative_to(root).as_posix() for path in root.rglob("*.js")}
    for js_file in root.rglob("*.js"):
        rel = js_file.relative_to(root).as_posix()
        try:
            analysis = analyze_js_module(js_file.read_text(encoding="utf-8", errors="ignore"), rel)
        except Exception as exc:
            errors.append({"file": rel, "error": f"{type(exc).__name__}: {exc}"})
            continue
        modules.extend(analysis["modules"])
        symbols.extend(analysis["symbols"])
        errors.extend(analysis["resolution_errors"])
    for module in modules:
        for imported in module["imports"]:
            if imported in discovered_files:
                continue
            kind = "bare_module" if _is_bare_module(imported) else "missing_file"
            errors.append({"file": module["file"], "import": imported, "error": kind})
    return {"modules": modules, "symbols": symbols, "resolution_errors": errors}
