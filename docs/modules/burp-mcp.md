# Burp MCP 模块

> **何时读**：需要用到 Burp 的代理历史、请求差异、Repeater/Intruder、Scanner、GraphQL、Collaborator OOB，或需要判断某个 Burp 能力该在哪个阶段调用时。
> 本文件是 Burp MCP 的模块说明真源。**工具名与参数的最终真源是运行中的 MCP 服务端**：以每次 `initialize → tools/list` 返回的工具清单为准，本文件列出的名字只是常见起点，不作为契约。
> 目标侧发包纪律见 [`egress-traffic-shaping.md`](egress-traffic-shaping.md)（硬约束 9）。

## 适用场景

- 使用 Burp MCP 做流量分析、发包、主动扫描、历史查询、GraphQL 侦察、Collaborator OOB
- 需要知道某个 Burp 工具该在什么阶段调用

## 加载规则

- 只有当任务明确涉及 Burp、代理历史、主动扫描、GraphQL、Collaborator、降噪模式时再加载
- 每次使用前先确认 Burp 侧的 scope 与当前 project，避免把其他项目的流量混进本轮目标

## 出口纪律（先读这一条）

Burp MCP 的以下动作**都是目标侧发包**，受硬约束 9 约束：

| 动作 | 出口形态 |
|---|---|
| `send_http1_request` / `send_http2_request` | 单请求手发，等价于 Repeater 手工发送 → 符合「逐条手发优先」 |
| `create_repeater_tab` / `send_to_intruder` | 只投递到 Burp UI，**发包由人在 Burp 里点**；批量变体必须过操作员门控 |
| `start_active_scan` | 主动扫描 = 高请求量动作，**必须先过操作员门控**，并限定 scope 与预算 |

派生要求：

- 脚本侧不要为了「批量」而走 Burp MCP；脚本的目标侧请求统一经受管出口 `TOOLS/utils/egress.py`。
- `mode=burp` 是 Egress 的备选出口模式：需要请求差异 / GraphQL / Collaborator / 复杂复核时，由操作员切到 `EGRESS_MODE=burp` 并启动 Burp，见 [`egress-traffic-shaping.md`](egress-traffic-shaping.md) §2。
- 原始请求/响应、Cookie、Authorization 只留在 Burp 或证据层，不进对话与 `worker_result`。

## 插件感知

装了以下插件时，部分能力会被自动增强（插件不在仓库内，属 Burp 侧环境）。

### A 类：对 `send_http1_request` 自动生效

- Bypass WAF
- Knife
- 403 Bypasser
- autoDecoder
- captcha-killer
- Content Type Converter

### B 类：对 `start_active_scan` 自动生效

- Active Scan++
- HTTP Request Smuggler
- FastjsonScan
- ShiroScan
- Struts RCE
- Retirejs
- Java Deserialization Scanner
- Upload Scanner

## 常用入口（按用途分组）

> 名字以服务端 `tools/list` 为准；下面按用途列出常用项，便于判断「这件事该找哪个工具」。

### 基础信息

- `get_burp_info`
- `exporter_stats`

### 发包

- `send_http1_request`
- `send_http2_request`
- `create_repeater_tab`
- `send_to_intruder`

### 历史与证据

- `list_security_candidates`
- `list_proxy_http_history`
- `get_proxy_http_history`（实时 regex 过滤）
- `get_proxy_http_detail`
- `diff_proxy_responses`
- `get_export_noise_mode` / `set_export_noise_mode`

### 扫描

- `manage_scope`
- `get_site_map`
- `start_active_scan`
- `list_scanner_issues`
- `get_scanner_issue_detail`

### OOB

- `generate_collaborator_payload`
- `get_collaborator_interactions`

### GraphQL

- `graphql_introspect`
- `graphql_list_types`
- `graphql_describe_type`
- `graphql_query`

## 常用工作流

### 主动扫描（需门控）

```text
1. 操作员确认：目标在委托 targets 内、扫描预算与停止条件明确
2. manage_scope(action="add", url="https://{target}")
3. start_active_scan(url="https://{target}/api?id=1")
4. 等待扫描完成（分钟级；不要轮询过密）
5. list_scanner_issues → get_scanner_issue_detail
```

### 历史降噪

```text
1. get_export_noise_mode
2. set_export_noise_mode(mode="balanced", inScopeOnly=true)
3. list_proxy_http_history / get_proxy_http_detail
```

推荐：

- 常规业务/API：`balanced`
- 浏览器噪音特别大：`strict`
- CORS/PWA/service worker：`off`

### Collaborator SSRF

```text
1. generate_collaborator_payload
2. .venv\Scripts\python.exe TOOLS\pipeline\ssrf_scan.py --target "{target}" \
     --collaborator-url <payload URL> --collaborator-payload-id <id>
3. 10-30 秒后 get_collaborator_interactions(payloadId=...)
```

`ssrf_scan.py` 的 `--target` 必填；`--delay` 只映射进 Egress `PacingPolicy.min_gap_ms`（**只会让节奏更慢**），不是提高速率的手段。

### GraphQL

```text
1. graphql_introspect
2. graphql_list_types
3. graphql_describe_type
4. graphql_query
```

## 关键策略

- 业务/API 复核优先用 `list_security_candidates`
- 通用调试再用 `list_proxy_http_history`
- 需要实时 regex 过滤时再用 `get_proxy_http_history`
- 响应确认优先 `diff_proxy_responses`
- `Retirejs` 只有扫 `.js` 响应体才触发
- 含参数的 URL 最利于主动扫描插件覆盖
- **发现 → 候选 → 确认三段式**：Burp 的 scanner issue 与候选列表都只形成 candidate / evidence ref，不直接记为 confirmed finding

## DB 可追溯性

在做 Repeater 或 Collaborator 操作前：先确认存在已接受（或已开启）的 `operator_inbox` 动作卡片，并创建/关联一条 `burp_actions` 记录；用队列 helper 标记 `sent` / `failed` / `skipped`，重复发送必须复用已有 evidence ref。**compact 动作卡片输出里永不出现原始 header、body、Cookie 或 Authorization。**
