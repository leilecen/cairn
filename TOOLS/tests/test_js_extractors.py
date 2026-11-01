import sys
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))

from utils.js_extractors import (
    extract_all_signals,
    extract_request_signals,
    extract_route_signals,
    fold_static_url_parts,
    score_signal,
)


def test_fold_static_url_parts_restores_base_plus_path():
    content = "const baseURL='https://example.com'; const userApi = baseURL + '/api/user';"
    constants = fold_static_url_parts(content)
    assert constants["baseURL"] == "https://example.com"
    assert constants["userApi"] == "https://example.com/api/user"


def test_extract_request_signals_handles_fetch_and_axios():
    content = """
    const baseURL = 'https://example.com';
    fetch(`${baseURL}/api/user/${id}`, { method: 'POST', headers: { Authorization: token } });
    axios.get('/api/order/detail');
    """
    signals = extract_request_signals(content, "https://example.com/app.js")
    paths = {signal["path"] for signal in signals}
    assert "https://example.com/api/user/{dynamic}" in {signal["url"] for signal in signals}
    assert "/api/order/detail" in paths or "https://example.com/api/order/detail" in {signal["url"] for signal in signals}


def test_extract_route_signals_finds_routes_and_dynamic_imports():
    content = "router.push('/admin/users'); const page = import('./pages/detail.js');"
    signals = extract_route_signals(content)
    kinds = {signal["signal_type"] for signal in signals}
    assert "route_entry" in kinds
    assert "dynamic_import" in kinds


def test_extract_all_signals_scores_admin_post_high():
    content = "axios.post('/api/admin/users', { userId, tenantId, sign, timestamp });"
    signals = extract_all_signals(content, "https://example.com/app.js")
    top = max(signals, key=lambda item: item["risk_score"])
    assert top["risk_score"] >= 70
    assert score_signal(top) >= 70


def test_expand_url_handles_backslash_replacement_values():
    content = r"""
    const assetRoot = 'C:\xwechat\radium';
    const api = assetRoot + '/api/user';
    wx.request({ url: api, method: 'POST', data: { userId } });
    """
    signals = extract_request_signals(content)
    assert any(signal["url"] == r"C:\xwechat\radium/api/user" for signal in signals)
