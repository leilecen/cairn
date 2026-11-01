import sys
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))

from utils.js_module_resolver import analyze_js_module, normalize_import_path, resolve_module_graph


def test_normalize_import_path_supports_extensionless_and_index():
    assert normalize_import_path("pages/home/index.js", "../../utils/request") == "utils/request.js"
    assert normalize_import_path("pages/home/index.js", "../../api/") == "api/index.js"


def test_analyze_js_module_extracts_imports_requires_and_exports():
    content = """
    import { getUser } from '../../api/user'
    const request = require('../../utils/request')
    export function load() {}
    exports.save = function() {}
    """
    result = analyze_js_module(content, "pages/home/index.js")
    assert "../../api/user" not in result["modules"][0]["imports"]
    assert "api/user.js" in result["modules"][0]["imports"]
    exported = {item["name"] for item in result["symbols"] if item["kind"].startswith("exported")}
    assert "load" in exported
    assert "save" in exported


def test_resolve_module_graph_walks_directory(tmp_path):
    root = tmp_path / "pkg"
    (root / "pages").mkdir(parents=True)
    (root / "pages" / "index.js").write_text("import api from '../api';", encoding="utf-8")
    (root / "api.js").write_text("export const ping = 1;", encoding="utf-8")
    result = resolve_module_graph(str(root))
    assert len(result["modules"]) == 2
    assert result["resolution_errors"] == []


def test_resolve_module_graph_records_unresolved_imports(tmp_path):
    root = tmp_path / "pkg"
    root.mkdir()
    (root / "index.js").write_text(
        "import missing from './missing';\nconst vue = require('vue');",
        encoding="utf-8",
    )
    result = resolve_module_graph(str(root))
    errors = {(item["import"], item["error"]) for item in result["resolution_errors"]}
    assert ("missing.js", "missing_file") in errors
    assert ("vue", "bare_module") in errors
