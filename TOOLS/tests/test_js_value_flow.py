import sys
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))

from utils.js_value_flow import fold_request_value_flow


def test_fold_request_value_flow_handles_template_concat_and_storage():
    content = """
    const base = 'https://api.example.com';
    const config = { baseURL: base };
    const token = wx.getStorageSync('token');
    request({
      url: `${config.baseURL}/order/${orderId}`,
      data: { orderId, token, userId: profileId }
    });
    """
    flow = fold_request_value_flow(
        content,
        "`${config.baseURL}/order/${orderId}`",
        "{ orderId, token, userId: profileId }",
        file_path="demo.js",
        line=4,
    )
    assert flow["url"] == "https://api.example.com/order/{dynamic}"
    assert any(source["expr"] == "config.baseURL" for source in flow["url_sources"])
    assert any(param["name"] == "token" and param["source"].startswith("function_param") for param in flow["params"]) or any(
        param["name"] == "token" for param in flow["params"]
    )
