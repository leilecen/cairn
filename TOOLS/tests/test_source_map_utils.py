import json
import sys
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))

from utils.source_map_utils import detect_source_map_url, is_same_origin_or_scope, parse_source_map_text


def test_detect_source_map_from_comment():
    content = "console.log('x');\n//# sourceMappingURL=app.js.map"
    assert detect_source_map_url(content, "https://example.com/static/app.js") == "https://example.com/static/app.js.map"


def test_detect_source_map_from_header():
    assert (
        detect_source_map_url("console.log('x')", "https://example.com/static/app.js", {"SourceMap": "app.js.map"})
        == "https://example.com/static/app.js.map"
    )


def test_same_origin_guard():
    assert is_same_origin_or_scope("https://example.com/app.js", "https://example.com/app.js.map") is True
    assert is_same_origin_or_scope("https://example.com/app.js", "https://cdn.example.net/app.js.map") is False


def test_parse_source_map_text():
    payload = json.dumps({"sources": ["src/a.js"], "sourcesContent": ["export const x = 1;"]})
    entries = parse_source_map_text(payload)
    assert entries == [{"source": "src/a.js", "content": "export const x = 1;"}]
