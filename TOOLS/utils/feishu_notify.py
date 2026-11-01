"""飞书 Bot 消息推送（HTTP API）。

通过飞书开放平台 API 直接发送消息，使用 Bot 身份（手机有推送通知）。

用法（Python import）:
  from utils.feishu_notify import send_message

  send_message("漏洞确认: target=xxx, type=IDOR, severity=High")

CLI 用法:
  uv run python TOOLS/utils/feishu_notify.py --msg "hello world"

环境变量:
  FEISHU_BOT_TOKEN  飞书 tenant_access_token（必填）
  FEISHU_CHAT_ID    目标群 chat_id（必填，除非调用时显式传入）
"""

import argparse
import json
import os
import sys

import requests

# 默认配置
CHAT_ID = os.environ.get("FEISHU_CHAT_ID", "")
TENANT_ACCESS_TOKEN = os.environ.get("FEISHU_BOT_TOKEN", "")

API_URL = "https://open.feishu.cn/open-apis/im/v1/messages"


def send_message(text: str, chat_id: str | None = None) -> dict:
    """向飞书群发送纯文本消息。

    Args:
        text: 消息文本内容。
        chat_id: 目标群 chat_id，覆盖 FEISHU_CHAT_ID 环境变量。

    Returns:
        飞书 API 返回的 JSON dict，含 code/msg/data 等字段。

    Raises:
        RuntimeError: FEISHU_BOT_TOKEN 或目标 chat_id 未配置时抛出。
        requests.RequestException: 网络或 API 错误时抛出。
    """
    if not TENANT_ACCESS_TOKEN:
        raise RuntimeError("FEISHU_BOT_TOKEN 未设置，无法发送飞书消息。请通过环境变量 FEISHU_BOT_TOKEN 配置 tenant_access_token。")

    target_chat = chat_id or CHAT_ID
    if not target_chat:
        raise RuntimeError("目标 chat_id 未设置。请通过 --chat-id 参数或环境变量 FEISHU_CHAT_ID 配置。")

    # 转义消息文本中的特殊字符（双引号、反斜线、换行等）
    safe_text = text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")

    body = {
        "receive_id": target_chat,
        "msg_type": "text",
        "content": json.dumps({"text": safe_text}, ensure_ascii=False),
    }
    headers = {
        "Authorization": f"Bearer {TENANT_ACCESS_TOKEN}",
        "Content-Type": "application/json",
    }

    resp = requests.post(
        API_URL,
        params={"receive_id_type": "chat_id"},
        json=body,
        headers=headers,
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="飞书 Bot 消息推送（HTTP API）",
    )
    parser.add_argument("--msg", "-m", required=True, help="消息文本内容")
    parser.add_argument("--chat-id", help="目标群 chat_id，覆盖默认值")
    args = parser.parse_args()

    try:
        result = send_message(text=args.msg, chat_id=args.chat_id)
    except RuntimeError as e:
        print(f"[feishu_notify] 配置错误: {e}", file=sys.stderr)
        sys.exit(1)
    except requests.RequestException as e:
        print(f"[feishu_notify] 请求失败: {e}", file=sys.stderr)
        sys.exit(1)

    code = result.get("code", -1)
    if code == 0:
        print(f"[feishu_notify] 发送成功: message_id={result.get('data', {}).get('message_id', '?')}")
    else:
        print(f"[feishu_notify] 发送失败: code={code} msg={result.get('msg', '?')}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
