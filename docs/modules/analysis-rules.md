# 分析规则模块

> **何时读**：要把大段原始噪音（Burp 历史、SQL 结果、大 JS/HTML）交给 AI 之前，或需要候选查询 / ETL 路由 / 精读顺序时。
> 本文件是 **compact 分析口径**的真源；工具链的版本与二进制契约真源在 [`js-analysis-toolchain.md`](js-analysis-toolchain.md)，本文件只列命令形态，两处必须逐项一致。
> 术语（ETL 路由 / 候选 / 证据引用 / lane）见 [`docs/GLOSSARY.md`](../GLOSSARY.md)。

## 适用场景

- 需要处理 Burp 历史、SQL 结果集、大 JS/HTML
- 需要候选查询、ETL、LSP 精读、浏览器 token 控制

## 加载规则

- 只有在任务涉及数据降噪、ETL、JS 逆向精读、候选筛选时再加载

## ETL 铁律

- AI 不直接读大段原始噪音数据
- Burp 历史、DB 结果、大 JS/HTML 先交给 `etl_analyzer.py`

## `etl_analyzer.py` 任务

| task | 用途 |
| --- | --- |
| `filter_burp` | 过滤 Burp 历史 |
| `filter_db` | 过滤 SQL 结果 |
| `analyze_js` | 分析大 JS / HTML |
| `extract_endpoints` | 提取端点 |
| `classify_business` | 分类业务接口 |
| `analyze_flow` | 识别流程链 |
| `generate_variants` | 生成测试变种 |
| `diff_responses` | 对比响应 |

## CLI 示例

执行位置：**仓库根目录**；解释器统一 `.venv/Scripts/python.exe`（本机 shell 无全局 `uv`）。`--cache-db` 传目标库路径，按 `AGENTS.md` 硬约束 1 显式指定，不猜目标。

```bash
.venv\Scripts\python.exe TOOLS\utils\etl_analyzer.py --task filter_burp --cache-db dbs/<target>.db --data "$(cat tmp/<case>/burp.json)"
.venv\Scripts\python.exe TOOLS\utils\etl_analyzer.py --task analyze_js --cache-db dbs/<target>.db --data "$(cat tmp/<case>/file.js)"
.venv\Scripts\python.exe TOOLS\utils\etl_analyzer.py --task filter_db --cache-db dbs/<target>.db --data "$(cat tmp/<case>/query_result.txt)"
```

## 候选查询

- 默认先查 `review_candidates`（它是 `schema.sql` 里的**视图**，不是事实表）
- 命令入口（仓库根目录）：

```bash
.venv\Scripts\python.exe TOOLS\db\candidate_query.py --target "{target}" --limit 5 --json
```

- 可选 `--offset`；`--target` 必填（按 `dbs/{target}*.db` 匹配，不猜目标）
- 只有需要回写状态、补证据、追溯源字段时才读原表

## Blackboard 分析协议（v1）

黑板协作启用后，分析类脚本和 subagent 不直接在对话里保存进度，统一写 DB 协议：

- 任务领取和状态流转走 `TOOLS/db/work_queue.py`
- 事实到任务的首轮映射走 `TOOLS/db/blackboard_seed.py`
- 主 session 态势读取走 `TOOLS/db/blackboard_view.py`
- Burp Repeater 投递记录走 `TOOLS/db/burp_action_queue.py`
- 极简证据整理走 `TOOLS/db/evidence_pack.py`

必须遵守的事件协议：

- `work_item`: 本轮唯一工作单元
- `heartbeat`: 表示还在推进，避免任务被回收
- `partial_result`: 已有局部发现，哪怕还没完成也要写
- `operator_inbox`: 登录、A/B 账号、截图、授权确认、高危确认统一走这里

分析边界：

- 可以自动写 `signal`、`hypothesis`、`replay_result`、`finding_candidate`
- 没有证据引用的 hypothesis 不能直接晋级成可确认结论
- `high_risk`、批量枚举、真实交易、RCE/SQLi 写入、webshell 上传必须暂停
- 涉及敏感读取或单次状态变更时，要同时留下 operator 提醒和 evidence refs

Burp / 证据规则：

- 复核阶段才批量写 `burp_actions`
- `high_risk` action 不自动投递
- 发送到 Repeater 后必须补 `evidence_refs(evidence_type='repeater_tab')`
- 需要视觉证据时，立即写 `operator_inbox(kind='screenshot_needed')`，不要等报告阶段再补

## JS 逆向规则

JS 分析采用**新工具链**（唯一详细事实源见 [`js-analysis-toolchain.md`](js-analysis-toolchain.md)）：采集层 URLFinder / jsluice / x8，还原层 webcrack / Retire.js / gitleaks / source map 还原。

旧 Python 管线（`js_intel.py` collect/extract/promote、`js_analyzer.py`、`js_reverse_cli.py`、`runtime_trace_ingest.py`、`h5_asset_expander.py`）**已退役**（2026-10-17）：5 个模块与只服务它们的 6 个旧测试文件已移到 `TOOLS/legacy/js/`，不再写入文档与命令（`AGENTS.md` 的退役清单同源，改动时两处一起改）。`TOOLS/utils/js_callgraph.py` / `js_module_resolver.py` **仍然活跃**（被 `utils/js_chain_resolver.py`、`TOOLS/wechat_api_analyzer.py` import），不在退役清单里；旧文档里「文件已不存在」的说法是错的。

统一边界（所有工具）：只消费已观测/已加载脚本与 source map；不枚举 chunk URL、不批量探测未知静态资源、不自动访问还原产物中的新 URL。还原产物写 `tmp/js_reverse/<case>/` 并登记 evidence ref，经 `js_reverse` 管线喂 `js_value_flow`/`js_attack_surface`，不直接写 suspicious_point。

标准工作流（js_reverse 场景）：

```text
已观测 script（browser_script|login_page）
  → URLFinder 轻爬 / jsluice urls+secrets（采集）
  → 高分短片段精读
  → webcrack 反混淆还原 + source map 还原（还原层）
  → gitleaks（--no-git，还原源码扫密钥）+ Retire.js（已知漏洞库）
  → 还原产物/命中写 tmp/js_reverse/<case>/ + js_signals/evidence_refs
  → 经 js_reverse 管线喂 js_value_flow / js_attack_surface → hypothesis
```

工具健康检查与命令契约（真实二进制对齐）。执行位置：**仓库根目录**（`TOOLS/bin` 已在 PATH）；产物落点见各条说明，默认落 `tmp/`。

- URLFinder：`TOOLS/bin/urlfinder.exe -h`（banner `Update: 2026.6.16`；**无 `--version`**）→ 输出逐行 URL 到 stdout，落 `tmp/recon/<case>/`
- jsluice：`TOOLS/bin/jsluice.exe urls <file>`（**NDJSON 逐行对象**，不支持 `--json`/`--format`）；`secrets` 子命令查密钥；产物落 `tmp/js_reverse/<case>/`
- x8：`TOOLS/bin/x8.exe --version`（`x8 4.3.0-main`），JSON 输出 `found_params:[{name,...}]`
- webcrack：`TOOLS/js-tools/node_modules/.bin/webcrack.cmd <file> -o tmp/js_reverse/<case>/webcrack/`（`--version` → `2.16.0`）
- Retire.js：`retire --path <dir> --outputformat json`；输出顶层 `data:[{file,results:[...]}]` 且 `identifiers.CVE` 大写；检出漏洞 exit code=1 属正常；`{"data": []}` = 扫了没命中
- gitleaks：`TOOLS/bin/gitleaks.exe version` → `8.30.1`；必须 `detect --source <dir> --no-git`；`File` 字段相对运行 cwd

> 这些是 Go / npm 二进制，**不要用 `uv run` 或 `.venv/Scripts/python.exe` 包它们**；只有 Python 脚本（`js_recon.py` 等）才用虚拟环境解释器。版本与契约的**真源**是 [`js-analysis-toolchain.md`](js-analysis-toolchain.md) §2/§3，本节摘录，改动时两处一起改。

LSP / 精读顺序：

```text
1. jsluice/URLFinder 静态抽取 + 聚类（js_signal_clusters）
2. documentSymbol(filePath)
3. workspaceSymbol / findReferences
4. 只读 20-50 行精确片段
5. 必要时再喂给 etl_analyzer(task=analyze_js)
```

- 禁止一次性读 2000+ 行打包产物
- 禁止把完整 source map、完整 wxapkg 解包源码直接喂给 AI
- JS 情报先入 `js_signals` / `js_signal_clusters`，不要直接把所有发现写进 `suspicious_points`

## JS Reverse Pipeline

被动逆向阶段：

1. jsluice / URLFinder 提取 URL 与 secrets，写 `js_signals` / `js_signal_clusters`
2. webcrack 反混淆还原 + source map 还原（`tmp/js_reverse/<case>/`）
3. gitleaks（`--no-git`）扫还原源码密钥 + Retire.js 比对已知漏洞库
4. `TOOLS/utils/js_value_flow.py` 折叠 URL / 参数来源，未知值保留 `{dynamic}`
5. `TOOLS/js_attack_surface.py` 产出验证假设（`build_attack_surface` / `attack_surface_markdown`），**这两个是库模块、没有独立 CLI**；旧 CLI `TOOLS/js_reverse_cli.py attack-surface` 已随模块退役（现在在 `TOOLS/legacy/js/`），改为按库调用或在 `tmp/` 下写一次性脚本

**验证路由**：产出的假设按 lane 派发（`logic_probe` / `vuln_review` / `hypothesis`，见 `TOOLS/db/lane_templates.py`），payload 与利用方法必须先读 `src-hunter` 对应 playbook（硬约束 10），发现写 `suspicious_points` / `finding_candidate`。**不要路由到已归档 skill**：`business-logic-hunt` / `manual-replay` / `vuln-review` / `src-report` / `vuln-auditor` / `stealth-scanner` / `soft-target`（单数）均在 `.agents/skills/.archived/`。

主动验证阶段：

- 只有 attack-surface 已说明参数、认证材料、前置条件后，才进入 replay / probe / 发包验证
- 静态 JS 发现本身不是漏洞结论

操作员检查清单：

- 先看 `summary`
- 再看 `chains`
- 最后看 `attack-surface`
- 遇到高危签名/支付/上传链路，先暂停并确认授权范围

## JS 情报边界

- 允许：抓取已加载 JS、同源 source map、Burp/HAR 已见脚本、本地 wxapkg 解包源码
- 允许：把空白页、停维页、无可点击功能页加载的同站点 JS 写入 `js_files`，并通过 `page_url/source_kind` 保留资产归属
- 允许：解析 `SourceMap` / `X-SourceMap` header、注释型 `sourceMappingURL`、浏览器或 HAR 中已经观测到的动态脚本 URL
- 不允许默认执行：对 JS 中新发现但从未访问过的接口直接发包
- 不允许默认执行：为了补全 JS 情报而主动跑登录态浏览器、枚举 chunk URL、批量探测未知静态资源
- `needs_auth` / `needs_signature` cluster 保留在 JS 情报层，等待后续认证或签名分析
- `js_signals` 是低成本事实层；`js_signal_clusters` 是候选决策层；`suspicious_points` 只接收晋级结果
- Burp 业务候选不承接 JS 文件列表；Retire.js、source map、接口提取走 JS 情报层。

## Source Map / 动态脚本约束

- source map 只处理三类来源：文件尾注释、HTTP 响应头、CDP 或 HAR 中已出现的 `sourceMapURL`
- 动态脚本只接收两类来源：浏览器运行期已加载脚本、Burp/HAR 已记录脚本
- 遇到 `sourceMapURL` 指向跨域或未访问资源时，默认只记元数据，不额外发起抓取

## 浏览器 Token 约束

- 默认用 `browser_snapshot`
- 只在需要视觉证据时用 `take_screenshot`
- 不截整页，优先截具体元素
- 登录完成后及时关闭无关 tab
