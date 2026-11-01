import sys
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))

from utils.js_callgraph import build_js_callgraph


def test_build_js_callgraph_links_page_to_wrapper_and_request():
    content = """
    const api = {
      getUser() {
        return request({ url: baseURL + '/api/user/info', method: 'POST' });
      }
    };

    Page({
      onLoad() {
        api.getUser();
      }
    });
    """
    graph = build_js_callgraph(content, "pages/user/index.js")
    node_ids = {node["id"] for node in graph["nodes"]}
    assert "pages/user/index:getUser" in node_ids
    assert "pages/user/index:onLoad" in node_ids
    assert any(edge["from"] == "pages/user/index:onLoad" and edge["to"] == "getUser" for edge in graph["edges"])
    assert any(call["callee"] == "request" and call["method"] == "POST" for call in graph["request_calls"])


def test_build_js_callgraph_handles_web_wrappers_and_arrow_functions():
    content = """
    const getOrder = () => axios.get('/api/order/detail');
    const load = async () => {
      await getOrder();
      return fetch('/api/order/list', { method: 'POST' });
    };
    """
    graph = build_js_callgraph(content, "src/orders.js")
    assert any(edge["from"] == "src/orders:load" and edge["to"] == "getOrder" for edge in graph["edges"])
    callees = {call["callee"] for call in graph["request_calls"]}
    assert "axios.get" in callees
    assert "fetch" in callees


def test_build_js_callgraph_keeps_partial_results_for_bad_js():
    content = """
    function broken() {
      wx.request({ url: '/api/demo', method: 'GET' });
    // missing closing brace on purpose
    """
    graph = build_js_callgraph(content, "app.js")
    # 残缺 JS 不抛异常：结构字段保持空列表（部分结果），同时**显式记录**语法错误。
    assert graph["nodes"] == []
    assert graph["edges"] == []
    assert graph["request_calls"] == []
    assert [e["error"] for e in graph["errors"]] == ["syntax_error"]
    assert graph["errors"][0]["file"] == "app.js"
