# L3 认知闭环与 work item 管线

> **何时读这份**：要在 L3 人工深测里跑认知闭环（焦点控制 / `sprint_tick` / `dispatcher` / lane worker 派发与回写 / 覆盖账本）时。
> **L0/L1 广度侦察不读这份**，走 [`asset-recon.md`](asset-recon.md)。
> 术语（黑板 / tick / lane / lane worker / work item / 认知闭环 / 覆盖账本）见 [`docs/GLOSSARY.md`](../GLOSSARY.md)。
> 授权门控的唯一事实源是 [`engagement-authorization.md`](engagement-authorization.md)；本文只引用 `AGENTS.md` 的硬约束**编号**，不复制正文。

## 1. 分层边界

| 层 | 允许 | 禁止 |
| --- | --- | --- |
| L0/L1 广度侦察 | `db_admin init`、`recon_doctor`、`init_scan --baseline`、`v3_chain`、`human_brief` | `sprint_tick`、worker queue、`work_items`、`pages`、`scan_state` |
| L3 人工深测（本文） | `sprint_tick`、`dispatcher`、worker queue、认知闭环 | 无 active focus 时派发测试类 lane |

L3 的三个前置条件**全部成立**才可运行 `sprint_tick`：① 操作员已确认 active manual focus；② engagement / risk gate 通过；③ 存在 `system_asset_links`。

每轮最多两个**单一** work item 的 lane worker（见 `AGENTS.md` 的「v4.6 运行分层」；实现上限见 §6）。

## 2. 命令口径

```bash
# 执行位置：仓库根目录。下面各行把 <TARGET>/<DB> 替换成实际值。
.venv/Scripts/python.exe TOOLS/db/<脚本>.py --target "<TARGET>" --db <DB> [args]
```

- 本机无全局 `uv`。**文档里写 `uv run python` 的地方，等价位就是 `.venv/Scripts/python.exe`**（硬约束 4）。
- 目标必须显式传入（`--target` 或 `--file`）；禁止用环境变量推断目标（硬约束 1）。
- 目标侧发包一律走受管出口 `TOOLS/utils/egress.py`（硬约束 9，真源 [`egress-traffic-shaping.md`](egress-traffic-shaping.md)）。本文所有命令都是本地读写，不发目标侧请求。

## 3. 焦点：先确认主攻系统

`target_systems` 是面向操作员的系统身份层；`hunt_sessions.system_id` 是唯一的焦点事实源。**框架不会自动选焦点。**

```bash
# 1) 评分并查看候选（只排序，不选择）
.venv/Scripts/python.exe TOOLS/db/soft_target_scorer.py --target "<TARGET>" --db <DB> \
    --list-ranked --top 30

# 2) 操作员明确选定后，标记 focused（会创建/复用 entry_probe work item）
.venv/Scripts/python.exe TOOLS/db/soft_target_scorer.py --target "<TARGET>" --db <DB> --focus-id <id>

# 3) 目标失败或需要换方向：标记并保留证据，然后等操作员再选
.venv/Scripts/python.exe TOOLS/db/soft_target_scorer.py --target "<TARGET>" --db <DB> \
    --fail-id <id> --reason "<原因>"
.venv/Scripts/python.exe TOOLS/db/soft_target_scorer.py --target "<TARGET>" --db <DB> \
    --park-id <id> --reason "<原因>"
```

- `--focus-id` / `--fail-id` / `--park-id` 写入 `soft_targets` / `soft_target_events`；fail/park 只返回剩余候选排序，**不得**自动 focus 下一个。
- 每轮先读 `human_brief`，把它当作对操作员输出的唯一形态：系统显示名、完整 `canonical_url`、readiness、`operator_actions`、`operator_choices`、下一更新时间。

```bash
.venv/Scripts/python.exe TOOLS/db/human_brief.py --target "<TARGET>" --db <DB> --json
```

- 无 active focus 时 `human_brief.current_system` 为 `null`、`focus_session` 为 `null`，只展示候选与未恢复原因。**不得把 hostname 或 work item 内部代号当成系统焦点。**
- 焦点激活与切换由 `TOOLS/db/focus_control.py` 在单事务中完成（`activate-focus` / `accept-switch` / `pause-focus` / `renew-focus`，`--actor operator`）。AI 只能生成 switch proposal，不能自己接受。

## 4. 一轮 L3 循环

```text
sprint_tick → 读 human_brief → 处理 operator_inbox → dispatcher 生成 compact 派发计划
→ 派发 ≤2 个单一 work item 的 lane worker → claim → heartbeat → partial → complete/block
→ 主 session 收割 agent_events → 更新假设/unknown/coverage → 记 decision event
```

```bash
# 一轮主入口：seed + reclaim + v3 chain facts + compact 视图 + 候选门控
.venv/Scripts/python.exe TOOLS/db/sprint_tick.py --target "<TARGET>" --db <DB> --json

# 只读派发计划（默认 --limit 2；不读取原始 HTML/JS/Burp 大块数据）
.venv/Scripts/python.exe TOOLS/db/dispatcher.py --target "<TARGET>" --db <DB> [--limit N]
```

- `sprint_tick` 包装 `TOOLS/db/blackboard_tick.py`，先 seed 可用工作项，再回收过期租约，然后汇总 `attack_threads`、B-class 候选、pivot pressure 与 `operator_inbox`。非 sprint 场景只有调试时才直接调 `blackboard_tick.py` / `blackboard_view.py`。
- `dispatcher.py` 是**只读**的：它给出 adapters 与 compact prompt 上下文，Python 侧不调用运行时 agent。派发动作由主 session 按计划执行。
- 派发计划只覆盖 `queued` / `partial` 状态；`summary` / `prompt_context` 截断到 360 字符，原始 HTML/JS/Burp 正文不读。
- 主 session 派发后继续做决策、验收与收割；完成由 runtime 通知，不要"全部堆给一个 subagent 串行 + 主 session 干等"。

## 5. lane 与 work item 契约

lane 是 work item 的执行通道，每个 lane 绑定一个 worker agent 定义（`.claude/agents/<name>.md`，由 `.agents/` 真源同步生成）。lane 白名单的真源是 `TOOLS/db/lane_templates.py`（`SUPPORTED_LANES`）与 `TOOLS/db/system_contract.py`（`COLLECTION_LANES`）。

| 分类 | lane | 说明 |
| --- | --- | --- |
| 收集/归类（不依赖 focus 锁） | `asset_ingest` `source_intel` `quick_scout` `entry_explore` `entry_probe` `network_profile` `origin_verify` `js_reverse` `semantic_profile` `asset_triage` | 只消费已观测事实或做有界被动观察；仍需过 scope / risk gate |
| 测试/验证（需 active focused eligible system） | `preauth_probe` `logic_probe` `replay` `vuln_review` `evidence_pack` `report_audit` `postexp` `cognitive_experiment` `hypothesis` | 派发前经 engagement / risk / cognitive gate |
| 操作员/主 session 决策 | `operator_task` | 无独立 agent 定义，不做运行时派发 |

work item 必填字段与状态机（DDL 真源 `TOOLS/db/schema.sql` 的 `work_items`，列级说明见 [`db-schema-reference.md`](db-schema-reference.md)）：

- 必填：`target_name`、`lane`、`subject_table`、`subject_id`；`status` ∈ {queued, claimed, partial, blocked, done, failed, cancelled}。
- 派发契约（`lane_templates.REQUIRED`）：`objective`、`expected_output`、`timebox_minutes`、`heartbeat_minutes`、`risk_class`、`scope_boundary`。
- `risk_class` ∈ {safe_passive, safe_replay, sensitive_read, state_changing, high_risk}。

配额与门控：

- `safe_passive` / `safe_replay` 可自动推进。
- `sensitive_read` / `state_changing` 可少量验证，但必须留审计并提醒操作员。
- `high_risk` 必须暂停并写入 `operator_inbox(kind='confirm_high_risk')`。
- confirmed finding、正式提交、账号/授权边界不明仍由操作员确认（硬约束 5）。
- `quick_scout` 若 `subject_table='pages'` 且 subtype 不是 `explicit_single_page`，被 scope gate 停车，不做宽泛爬取。

每个 worker 的派发契约必须携带 `system_id`、`work_item_id`、完整 URL 与 action-card 引用。缺字段时只能是 non-blocking incomplete，不得伪造可执行步骤。

## 6. worker 回写契约

worker 生命周期四态：`claim → heartbeat → partial → complete/block`。

```bash
.venv/Scripts/python.exe TOOLS/db/work_queue.py create  --target "<TARGET>" --db <DB> \
    --lane <lane> --subject-table <表> --subject-id <id> [--risk-class ...]
.venv/Scripts/python.exe TOOLS/db/work_queue.py claim   --target "<TARGET>" --db <DB> --agent-id <id> [--lanes a,b]
.venv/Scripts/python.exe TOOLS/db/work_queue.py heartbeat --work-item-id <id> --agent-id <id> --db <DB>
.venv/Scripts/python.exe TOOLS/db/work_queue.py partial   --work-item-id <id> --agent-id <id> --db <DB> --summary "<...>"
.venv/Scripts/python.exe TOOLS/db/work_queue.py complete  --work-item-id <id> --agent-id <id> --db <DB> --summary "<...>"
.venv/Scripts/python.exe TOOLS/db/work_queue.py block     --work-item-id <id> --agent-id <id> --db <DB> --summary "<...>"
```

`partial` / `complete` / `block` 的结果统一写入 `agent_events.payload_json.worker_result`，由 `TOOLS/db/worker_result.py` 归一化。固定字段：

| 字段 | 取值 |
| --- | --- |
| `status` | `done` / `partial` / `blocked` |
| `conclusion` / `summary` | 一句话结论或进展摘要 |
| `evidence_refs` | 证据引用 ID 列表（输入别名 `evidence_ids`） |
| `confidence` | `low` / `medium` / `high` / `unknown` |
| `blocker` / `block_reason` | 阻塞类型与原因，非阻塞可为空 |
| `next_action` | 下一步建议动作 |
| `outcome` | `supports` / `refutes` / `inconclusive` / `blocked` / `not_run`；`supports`/`refutes` 缺 `evidence_refs` 时强制降级为 `inconclusive` |
| 可选 | `risk_level`、`upgrade_request`、`coverage_updates`、`insight_proposals` |

硬性边界：

- 主 session 只消费 `blackboard_view.recent_worker_results`（或 `sprint_tick.blackboard.view.recent_worker_results`）里的 compact `payload`，不读原始 `payload_json`（硬约束 3）。
- `worker_result` **禁止**包含原始 HTML/JS bundle、Burp 历史、完整 HTTP、Cookie/Authorization。原始证据写事实表或 `evidence_refs.ref_json`，摘要里只放引用 ID 和结论。`worker_result.py` 对疑似原始/过长文本做 redaction 与截断。
- worker 必须使用主 session 传入的稳定 `agent_id`；未传入时用 `{target_name}:{agent_name}:{short_instance_id}`，同一生命周期内不变。
- worker 不自行确认高危结论、不自行升级模型，只能回传 `upgrade_request` 或 `blocked`。

并发上限（`TOOLS/db/dispatcher.py`）：

- 每轮派发总数默认 `--limit 2`；测试类 lane 的并发子上限固定为 2，与总数上限无关。
- 同一 lane 少量（≤3 个）work item 复用同一个 subagent 串行喂；串行链超过 3 个就为同 lane 开第二个 subagent 分摊。

## 7. 黑板表职责

| 表 | 职责 |
| --- | --- |
| `work_items` | 主 session 与 worker 共享的任务黑板 |
| `agent_events` | heartbeat / partial / blocker / done 事件流，`worker_result` 的载体 |
| `operator_inbox` | 需要操作员确认、登录、截图、授权边界的待办（结构化 action card） |
| `burp_actions` / `browser_actions` | 复核阶段允许自动投递到 Repeater / 浏览器的动作队列 |
| `evidence_refs` | 请求、响应、diff、截图、Repeater tab 等证据索引；库里只存指针 |
| `coverage_ledger` | 按 `item_key × category` 记 covered / unknown / uncovered / blocked |
| `attack_threads` / `attack_thread_events` | 一条攻击线索（假设 → 实验 → 结论）的聚合视图 |
| `experiments` / `decision_events` | 认知闭环的实验定义、控制项与主 session 决策记录 |
| `hunt_sessions` / `target_systems` / `system_asset_links` | 焦点、系统身份与系统↔资产关联 |
| `insights`（`inspirations`）/ `experience_entries` | 灵光→线索的晋级链与可复用经验 |

辅助脚本：

| 脚本 | 用途 |
| --- | --- |
| `TOOLS/db/blackboard_seed.py` | 幂等 seed 可用工作项 |
| `TOOLS/db/blackboard_view.py` | compact 视图 |
| `TOOLS/db/dispatch_guard.py` | 派发前可用性判定（含 human focus gate） |
| `TOOLS/db/coverage_guard.py` | 覆盖账本佐证，支撑"已穷尽"声明 |
| `TOOLS/db/evidence_pack.py` | 极简证据包 |
| `TOOLS/db/business_flow_view.py` | 业务状态机图谱读取（`migrations/035_business_state_machine.sql`），`--seed-templates` 幂等 seed 启发式提醒 |
| `TOOLS/db/butian_docx_report.py` | 从 findings 生成 Word 报告（依赖 `officecli`） |
| `TOOLS/src_cli.py` | 对 `soft-targets` / `sprint-tick` / `work` / `report` 的统一薄封装 |

## 8. 灵光与经验的晋级纪律

- worker 产出的是 compact `insight_proposals`；主 session 用 `TOOLS/db/insight_capture.py --target <T> --db <DB> accept` 接受一条，并**原子地**创建同系统的安全验证 work item。
- 只有带 evidence refs 的终态验证结果，才能把该 insight 标为 verified 或 refuted。
- 经验库 `experience_entries` 的写入与复用由 `TOOLS/db/experience_store.py` 管理；L3 复用需要显式的 focused work-item 查找/采纳，且该 work item 必须终态并携带 `worker_result.evidence_refs`（`effectiveness` 才可更新）。
- 操作员专属的收割动作是 `experience_store --target <T> --db <DB> harvest`。

## 9. 停止条件

- 声称"攻击面穷尽"前必须逐项核对 `coverage_ledger` 的 `unknown` / `uncovered` / `blocked`，列出每个未测项及阻塞原因（硬约束 6）。
- 账号或手机号缺失只阻塞相应路径；未认证攻击面（公开接口、登录前功能、JS 分析出的接口、静态资源、swagger/actuator/docs 等）继续按委托范围推进，不整体停摆。
- 每轮输出"下一步自动推进：{无需账号的攻击面}"+"等账号就绪后：{清单}"；新线索照常写回 DB 并生成 work item。
- 需要 Repeater / Collaborator 的动作先写 `operator_inbox` action card 与 `burp_actions`/`browser_actions`，再调用外部工具；回填必须通过 evidence ref 追溯到 card/action。
- worker blocked 时立即清 lease，主 session 继续输出 human brief，不长期等待单个 worker。

## 10. 已归档，勿调用

- 7 个管线 skill 已归档：`stealth-scanner`、`vuln-review`、`src-report`、`vuln-auditor`、`business-logic-hunt`、`manual-replay`、`soft-target`（单数）。目录见 `.agents/skills/.archived/`。
- 旧 run_scan 链已归档到 `TOOLS/legacy/`：`run_scan.py`、`bfs_crawl.py`、`probe_runner.py`、`api_fuzz.py`、`brutescan.py`、`framework_exploit.py`、`upload_scan.py`、`reflect.py`、`reflect_map.py`、`entry_family_enumerator.py`。
- 旧 Python JS 管线已退役到 `TOOLS/legacy/js/`（2026-10-17）：`js_intel.py`、`js_analyzer.py`、`js_reverse_cli.py`、`runtime_trace_ingest.py`、`h5_asset_expander.py`（连同只服务它们的 6 个测试文件）。JS 分析的唯一真源是 [`js-analysis-toolchain.md`](js-analysis-toolchain.md)，唯一入口是 `TOOLS/pipeline/js_recon.py`。
- `pages` 表是旧爬取链的遗留事实表：当前活跃代码只读它，`init_scan --baseline` 显式 `enqueue_pages=False` 不写它。新的事实写入走 `target_assets` / `endpoint_observations` / `entry_observations`。

## 11. 相关文档

| 主题 | 文档 |
| --- | --- |
| 授权门控、拒绝边界、强度等级 | [`engagement-authorization.md`](engagement-authorization.md) |
| L0/L1 资产录入、公开情报、FOFA relay、归属门控 | [`asset-recon.md`](asset-recon.md) |
| 出口形态与发包纪律 | [`egress-traffic-shaping.md`](egress-traffic-shaping.md) |
| JS 采集/还原与接口地图 | [`js-analysis-toolchain.md`](js-analysis-toolchain.md) |
| 落库助手与探测方法学 | [`probe-and-store-toolkit.md`](probe-and-store-toolkit.md) |
| 列级表结构 | [`db-schema-reference.md`](db-schema-reference.md) |
| 调用关系全景 | [`../architecture-call-graph.md`](../architecture-call-graph.md) |
| 浏览器侧侦察 | [`chrome-devtools-recon.md`](chrome-devtools-recon.md) |
