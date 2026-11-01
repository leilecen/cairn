# 浏览器侧侦察（Chrome DevTools MCP）

> **何时读这份**：要用浏览器读取已授权页面的 DOM、脚本资源、网络请求、控制台或运行时线索，恢复"页面 → JS → API → 认证边界"事实链时。
> 本模块只负责**事实恢复**，不做漏洞确认或报告提交。术语见 [`docs/GLOSSARY.md`](../GLOSSARY.md)。

浏览器流量就是目标侧流量，导航与请求同样受出口纪律约束（硬约束 9，真源 [`egress-traffic-shaping.md`](egress-traffic-shaping.md)）。

## 1. 配置

| harness | 位置 | 启动方式 |
| --- | --- | --- |
| Claude Code / DSH | 项目根 `.mcp.json` 的 `chrome-devtools`（**入库**） | `npx -y chrome-devtools-mcp@latest --no-usage-statistics --no-performance-crux --redact-network-headers --browserUrl http://127.0.0.1:9222`（复用已存在的 CDP 端点） |
| Codex | `.codex/config.toml` 的 `[mcp_servers.chrome-devtools]`（**本机文件，`.gitignore` 已忽略，不入库**） | 同样三个参数，但**不带** `--browserUrl`，由 MCP 自己拉起浏览器 |

工具名与参数随版本迭代；**以每次 `initialize` → `tools/list` 返回的实际能力为准**，不要照抄本文里的名字。

## 2. 两种模式（别把 L3 的前置条件搬到 L0/L1）

**模式 A —— L0/L1 只读侦察（默认）**：前置条件只有 `target_name`、完整 URL、该资产 `scope_status=in_scope`。**不需要 `work_item_id`**，L0/L1 也不创建 `work_items`。产出只写事实表与证据层；不派发 lane worker、不写 `scan_state`。没有明确范围、登录授权或页面归属时，写 `operator_inbox` 并停止。

**模式 B —— L3 深测**：额外前置条件为 active manual focus（`hunt_sessions.system_id`）、`system_id`、`work_item_id` 与 action-card 引用（派发契约见 [`src-pipeline.md`](src-pipeline.md) §5），走 lane worker 生命周期并回写 `worker_result`。

两种模式都**不得**自行从搜索结果扩展目标集合。

## 3. 单页流程

1. `list_pages` 列出页面 → `select_page` 选择目标页；没有页面时只用 `new_page` 打开给定 URL。
2. 页面稳定后采集：`take_snapshot`（页面结构、链接、表单、入口、脚本标签）；`list_network_requests`（`Document`/`Script`/`XHR`/`Fetch`/`WebSocket` 摘要）；`get_network_request`（只对高价值脚本/API 取正文，原文写 `tmp/recon/<case>/` 并登记 `evidence_refs`）；`evaluate_script`（只读提取 `document.scripts`、资源时序、公开配置、API 前缀、框架标志）；`list_console_messages` / `take_screenshot`（仅在能解释页面/API 行为或需要操作员确认时）。
3. 脚本资源去重后记录 URL、来源页面、状态、类型、大小、source map 线索与证据引用。
4. 脚本正文交给 JS 工具链：采集/还原的唯一入口是 `TOOLS/pipeline/js_recon.py`（契约见 [`js-analysis-toolchain.md`](js-analysis-toolchain.md)），再由 `js-reversing-helper` 处理单个 `js_files` 或 `js_signal_clusters` subject。
5. **页面 HTML 落地后立即过 `ui_context.py`**（离线表单/字段上下文，不发包）：
   `.venv/Scripts/python.exe TOOLS/pipeline/ui_context.py --html <落盘HTML> --page-url <页面URL> --target "<目标名>" --store`
   产出写进 `endpoint_observations.parameter_names_json`，是 `auth_logic_probe` / `sqli_scan` 的参数名来源。
   该步已写入 lane 契约（`TOOLS/db/lane_templates.py` 的 `LANE_TO_OFFLINE_TOOL`）：`quick_scout` / `entry_explore` /
   `entry_probe` / `preauth_probe` / `logic_probe` / `semantic_profile` 的 subagent prompt 会自动带上这条命令，
   **不需人工记得调**。它只做静态解析，绝不记录字段值。

> `js-reversing-helper` 是 **agent 定义**（`.claude/agents/js-reversing-helper.md`，lane `js_reverse` 的 worker），不是 skill；对应 skill 名是 `js-recon`。

## 4. 交互与安全边界

- 默认只读：允许导航、等待、快照、网络观察、脚本静态/运行时读取与截图。
- 不点击提交、保存、删除、支付、邀请、上传、导出等状态改变控件；不输入账号、密码、验证码；不绕过认证（硬约束 5）。出现敏感读取、账号边界、高危信号或授权不确定时立即 block；不执行弱口令、越权、并发、高负载或漏洞 PoC。
- 需要复用操作员已登录的浏览器时才接 `--browserUrl` / `--auto-connect`，且必须先由操作员明确启动与授权，并记录 `auth_blocker` / operator gate；不要擅自接入操作员日常 profile。
- 中间文件一律放 `tmp/recon/`，文件名不得含 Cookie、Authorization 或其他密钥；页面查询参数、请求头与响应体在写入 compact 摘要前必须脱敏（硬约束 3）。

## 5. 验收标准

合格结果必须**同时**包含：当前页面与范围证据；去重后的脚本/网络资源清单；至少一组"页面 → 脚本或 API"的可追溯关系；`covered` / `unknown` / `blocked` 覆盖状态；可复核的 evidence refs，以及下一步 `js_reverse` 或 operator action。

只看到空白页、单个 200 状态或浏览器成功启动，都不能作为侦察完成依据。
