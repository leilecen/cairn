import sys
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))

from utils.js_chain_resolver import build_chain_index, resolve_request_chain


def test_resolve_request_chain_crosses_import_boundary():
    files = {
        "pages/home/index.js": """
        import { getUser } from '../../api/user'
        function onLoad() { getUser() }
        """,
        "api/user.js": """
        export function getUser() {
          return request({ url: '/api/user/info', method: 'POST' });
        }
        """,
    }
    index = build_chain_index(files)
    request_call = index["callgraphs"]["api/user.js"]["request_calls"][0]
    assert resolve_request_chain(index, "api/user.js", request_call) == ["onLoad", "getUser"]
