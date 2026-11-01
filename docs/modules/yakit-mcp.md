# Yakit MCP 模块

> **何时读**：需要用 Yakit 读被动流量 / 风险 / 指纹 / SSA / Yak 脚本，或要操作 MITM / Web Fuzzer / 插件时。
> 本文件是 Yakit MCP 的模块说明真源；**工具名与参数的最终真源是运行中的 MCP 服务端**：以每次 `initialize → tools/list` 返回的清单为准。
> 出口形态与发包纪律的真源是 [`egress-traffic-shaping.md`](egress-traffic-shaping.md)（硬约束 9）：`EGRESS_MODE` 默认 `yakit`，即目标侧请求默认经本机 Yakit MCP 的 `do_http_request` 发出，客户端是 `TOOLS/utils/yakit_mcp.py`（SSE + JSON-RPC）。

## 当前定位

Yakit MCP 是本项目默认的被动采集与分析辅助工具。稳定时优先使用 Yakit 完成流量、风险、指纹、端口、Codec 和 SyntaxFlow/SSA 结果的读取；Burp MCP 保留为请求差异、GraphQL、WebSocket、Collaborator 和复杂复核的补充工具。

因此「Egress 发出去的请求」会出现在 **Yakit 当前项目库**中，可用 `query_http_flow` 复核；反过来，凡是要对目标发包的脚本都必须经 Egress，不得绕过。

本模块只依赖 Yakit 官方 MCP，不在项目内增加代理层、缓存层或自定义 MCP 代码。Yakit MCP 会快速迭代，工具名称和参数以每次 `initialize → tools/list` 返回的实际能力为准。

## 默认配置与稳定性约束

**MITM filter 由 Yakit 侧持有，本文件不复制它的当前取值。** 判断方式：调 `get_mitm_filter` 读取实际配置；`egress.py --preflight` 会额外报告 Yakit MCP 与 MITM 端口是否就绪。

通常的过滤口径（**核验方式见上，不要把它当快照**）：排除打包后的静态 JS 与常见静态资源扩展名（`.css/.jpg/.jpeg/.png/.gif/.svg/.ico/.mp3/.mp4/.woff/.woff2/.ttf/.otf/.eot/.map/.wasm`）、排除 `image/*`、`audio/*`、`video/*`、`font/*`、`application/wasm` 等 MIME、排除 `OPTIONS` 与 `CONNECT`。

这些规则只降低无价值流量写入，**不包含目标域名白名单**；切换目标时仍需由操作员确认当前 Yakit project。

AI 使用 Yakit 时必须遵守：

- 同一 Yakit session 不并行发起多个 MCP 调用；优先串行、低频查询。
- `query_http_flow` 默认只查当前 MITM 流量，不使用 `sourceType="all"`，不翻页扫全库。
- 优先使用 `query_new_risks(afterId=...)` 和 `afterId/afterUpdatedAt` 增量条件。
- `full=false` 不能保证响应体一定很小；主模型只消费 ID、URL、方法、状态码、类型、长度、时间、标签等 compact 字段。
- 不因一次空结果判断“没有流量”或“没有漏洞”；先确认 current project/database 和 capture 状态。
- 收到 `Invalid session ID`、EOF 或连接重置时，重新执行 `initialize → tools/list → get_current_database_context`，不得复用旧 session。
- 当前 project 变化、MITM filter 变化或 Yakit 重启后，暂停自动查询并重新确认环境。

## 适用场景

- 当前目标已确认且 Yakit project 已由操作员确认；或操作员明确说“用 Yakit / 走 Yakit / 查 Yakit / 用 Yakit 插件”。
- 读取 Yakit 当前项目中的 HTTP 流量、风险、端口、指纹、Payload、Yak 脚本、MITM 规则或被动插件结果。
- 将单个已确认请求送入 Yakit Web Fuzzer，或在授权范围内使用 Yakit 的爬虫、端口扫描、混合扫描、Codec、OOB/反连辅助能力。

## 加载规则

- 默认流程仍由项目黑板和 dispatcher 控制；对已确认的当前 Yakit project，AI 可以默认读取 Yakit 的被动和分析结果。
- 不把 Yakit 的主动扫描、发包、MITM 修改和高危辅助能力视为默认能力。
- 每次使用前先确认当前 Yakit 项目库，避免把其他项目的流量、风险或插件结果混入当前目标。

## AI 默认可用能力

以下能力在目标、项目和授权范围已经明确后，可以由 AI 默认使用：

- `get_current_database_context`、`list_project_databases`：确认项目和数据库。
- `query_http_flow`：读取当前 MITM 流量的 compact 摘要；默认不查全库、不翻页。
- `query_new_risks`、`query_risks`：读取增量或有限页风险摘要。
- `query_risk`：只在已有风险 ID/hash 且需要单条复核时使用。
- `query_ports`、`query_fingerprint`：读取已有端口和指纹事实，不自动启动扫描。
- `get_mitm_filter`、`get_current_rules`、`get_global_hotpatch_config`：读取当前配置。
- `query_yak_script`、`list_yak_script_group`、`static_analyze_yak_script`：读取或静态分析已有脚本。
- `codec_method_details`、`exec_codec`：只做本地编解码/格式转换，不向目标发包。
- 已明确提供且在授权范围内的本地源码，可使用 `ssa_compile`、`ssa_query`、`syntaxflow_scan` 做离线静态分析；路径或授权不明确时先沟通。

默认读取结果只能形成 candidate、evidence ref 或 compact summary，不能直接形成 confirmed finding。

## 必须与操作员沟通的能力

下列动作在执行前必须明确说明目标、范围、影响和停止条件，并等待操作员确认：

- 切换 Yakit project、启动/停止 MITM、下载或安装证书、修改系统代理。
- 修改 MITM filter、replacer rule、global hotpatch 或启停插件。
- `web_crawler`、`port_scan`、`hybrid_scan`、`subdomain_collection` 和任何主动扫描。
- `http_fuzzer`、`create_web_fuzzer_tab(s)`、批量发包、状态改变请求和漏洞验证。
- `require_dnslog_domain`、OOB、`start_facades`、反连辅助和 Collaborator 类验证。
- `exec_yak_script`、`generate_yso_bytes`、`yso_dump`、`generate_reverse_shell_command`。
- `save_*`、`update_*`、`delete_*` 等会修改或删除 Yakit 数据的动作。
- High/Critical 风险、敏感数据读取、登录态、角色边界、越权边界和高危 PoC。

如果操作员只说“用 Yakit 查一下”，默认只做项目确认和只读查询，不自动发包、不切 project、不改 MITM 配置。

## 当前项目确认

优先使用：

- `get_current_database_context`
- `list_project_databases`

规则：

- 若当前项目不是本轮目标，先提示操作员切换/确认项目。
- 不要把 Yakit 中其他项目的 HTTP 流量、风险、端口或扫描结果写入当前目标 DB。

## 工具分类

Yakit MCP 暴露的工具会随 Yakit 版本和 MCP 服务端变化，不要把下列列表理解成完整清单。需要新能力时先按关键词查找 `mcp__yakit` 工具。

### HTTP 流量

- `query_http_flow`
- `set_tag_for_http_flow`
- `delete_http_flow`

规则：

- 默认只查询当前 MITM/capture 流量。
- 不要用分页 limit 或 total count 声称“已读取 N 条完整记录”。
- 除非操作员明确要求，不要翻页扫全库，不要读取无关来源。
- 原始请求/响应、Cookie、Authorization、HTML/JS 大块内容只作为证据引用，不写入 compact 结果。

### 风险与发现

- `query_risks`
- `query_new_risks`

用途：

- 读取扫描、MITM、被动插件、OOB 或 SSA/SyntaxFlow 产生的风险记录。
- 用于候选复核、证据归档、报告前整理。

规则：

- High/Critical、敏感读取、认证边界不明、破坏性验证必须升级给操作员。
- 不把 Yakit 风险直接记为 confirmed finding；先按项目复核流程转为 candidate。

### Yak 脚本与插件

- `query_yak_script`
- `download_online_yak_script`
- `list_yak_script_group`
- `create_yak_script_group`
- `rename_yak_script_group`
- `static_analyze_yak_script`
- `set_group_for_yak_script`

插件边界：

- 被动扫描/MITM 插件若已在 Yakit UI 中启用，主模型可以通过 MCP 消费其流量、风险结果和规则状态。
- MCP 不等同于可任意运行 Yakit UI 中的所有插件；只有已暴露为 MCP tool 的能力才可直接调用。
- 查询、下载、分组、静态分析 Yak 脚本属于低风险管理动作。
- 启停插件、主动扫描、端口扫描、爬虫、批量发包、漏洞验证必须先确认授权范围和风险级别。

### MITM 与热加载

- `start_mitm_v2`
- `download_mitm_cert`
- `get_mitm_filter`
- `set_mitm_filter`
- `get_current_rules`
- `query_mitm_replacer_rules`
- `set_current_rules`
- `query_hotpatch_template_list`
- `create_global_hotpatch_template`
- `enable_global_hotpatch`
- `disable_global_hotpatch`

规则：

- 修改 MITM filter、replacer、global hotpatch 前，先读取当前配置并说明会改变什么。
- 不在未确认授权范围时扩大拦截范围。
- 不把热加载脚本用于破坏性修改、敏感数据外带或绕过授权边界。

### Web Fuzzer

- `create_web_fuzzer_tab`

规则：

- 仅把单个已确认请求送入 Fuzzer。
- 变体发包、批量测试、状态改变请求、高危 PoC 必须先确认授权和风险。
- HTTP 请求证据中不要保存 Cookie、Authorization 等敏感头的明文。

### 爬虫、端口、混合扫描

- `web_crawler`
- `port_scan`
- `hybrid_scan`
- `query_fingerprint`
- `create_fingerprint`
- `delete_fingerprint`
- `delete_ports`
- `subdomain_collection`

规则：

- 这些属于主动能力，不因“用 Yakit”而自动执行。
- 必须限定授权目标、端口/路径、并发、深度、超时和是否入库。
- 禁止 C 段扩展、弱口令/爆破、高并发或破坏性动作，除非操作员明确授权且**在委托 `intensity` 与 `excluded` 范围内**（见硬约束 5 与 `docs/modules/engagement-authorization.md`；弱口令另有 `weak-password-boundary` skill）。

### Codec、Payload、辅助工具

- `codec_method_details`
- `exec_codec`
- `query_payload`
- `save_payload`
- `create_payload_folder`
- `rename_payload_folder`
- `rename_payload_group`
- `update_one_payload`
- `update_payload_file_content`
- `delete_payload`
- `yakdoc_get_all_library_names`

规则：

- `exec_codec` 前先调用 `codec_method_details`。
- Payload 管理默认只读；新增、更新、删除 payload 前确认目标用途。

### OOB 与反连

- `require_dnslog_domain`
- `get_global_reverse_server`
- `generate_reverse_shell_command`

规则：

- DNSLog/OOB 域名可用于低风险验证，但必须记录 token 与证据引用。
- 反连地址查询可以只读。
- 生成 reverse shell 命令属于高危辅助能力；不得对目标执行，除非操作员明确授权高危 PoC。

### 代理与系统设置

- `get_system_proxy`
- `set_system_proxy`

规则：

- 读取系统代理是低风险。
- 修改系统代理会影响全局网络环境，必须先确认并说明恢复方式。

## 常用工作流

### 查询当前 Yakit 项目

```text
1. get_current_database_context
2. list_project_databases(limit=5)
3. 若 current project 与目标不一致，暂停并请操作员确认
```

### 被动插件结果消费

```text
1. get_current_database_context
2. query_http_flow(pagination={limit: 20, page: 1, order: "desc", orderby: "updated_at"})
3. query_risks(pagination={limit: 20, page: 1, order: "desc", orderby: "updated_at"})
4. 只输出 compact 摘要和 evidence_refs，不输出原始敏感内容
```

### 单请求送入 Web Fuzzer

```text
1. query_http_flow(includeId=[id], full=false)
2. 操作员确认该请求可用于 Fuzzer
3. create_web_fuzzer_tab(request=..., isHttps=...)
```

### MITM 过滤调整

```text
1. get_mitm_filter
2. 说明拟新增/修改的 include/exclude 条件
3. 操作员确认后 set_mitm_filter
```

## 关键策略

- Yakit 是本项目默认的被动/分析辅助入口，但不替代黑板队列、scope gate、operator gate 和证据回写流程。
- Burp MCP 不再作为 Yakit 的默认替代路径；只有 Yakit 不具备所需能力、结果需要差异复核，或操作员明确要求 Burp 时才切换。
- 先确认项目库，再读取流量/风险。
- 被动插件结果可消费，主动扫描/发包/启停插件需门控。
- 只把 compact 结论、证据引用 ID、下一步动作写入 worker_result。
- 原始 HTTP、Cookie、Authorization、HTML/JS、完整请求响应只能进事实表或 evidence_refs，不进摘要字段。
