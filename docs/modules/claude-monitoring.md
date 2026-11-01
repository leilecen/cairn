# Claude Code 会话监控与交接

> **何时读**：要复盘 Claude Code 会话、生成 handoff、检查成本与 hook 记录，或要看认知决策反馈时。
>
> **范围说明（重要）**：本模块只覆盖 **Claude Code** 这一种 harness（`.claude/settings.local.json` 的 hooks + `TOOLS/db/claude_monitor.py`）。当前主 session 跑在 **DSH** 上，DSH 侧的会话拆分、subagent 派发、成本 compact 与 pwsh/bash 执行口径由 `dsh-session-ops` 与 [`dsh-shell-escape.md`](dsh-shell-escape.md) 覆盖，**本文件不描述 DSH 的会话机制**。
>
> **分层对齐**：本文件提到的 `sprint_tick` / `work_queue` 类事件属 **L3 认知闭环**（`AGENTS.md` v4.6 运行分层）。**L0/L1 广度侦察阶段不会出现这些类别**——L0/L1 不运行 `sprint_tick`、不创建 worker queue。看 hook 记录时按当时所处层级解释：L0/L1 会话里没有 `sprint_tick` / `work_queue` 类别是**正常的**，不是漏采。
> 术语（认知闭环 / tick / work item）见 [`docs/GLOSSARY.md`](../GLOSSARY.md)。

## 目标

Claude Code 每次工作后留下两类互补记录：

- `metrics/costs.jsonl`：token、模型和成本元数据；
- `metrics/claude-sessions.jsonl`：工具生命周期、失败类型、耗时、测试计数、文件路径和 compact session note；

## DB-first 人机焦点交接

Stop/SessionEnd 交接时，如果显式提供 target DB，优先从 `human_brief`、active `hunt_sessions`、readiness 和 open action cards 重建当前状态。session note 与 DB 焦点不一致时以 DB 为准，并把旧 note 标记为 stale；不得从 transcript、完整命令、原始 HTTP 或敏感头恢复状态。

反馈应关注 `focus_db_conversation_divergence`、`testing_before_recon_ready`、`operator_task_without_action_card`、`burp_call_without_burp_action`、`handoff_stale_work_item` 和 `broad_queue_after_focus`。反馈只生成 compact remediation，不自动修改焦点或数据库。
- `metrics/claude-handoffs/{session_id}.json`：单会话交接；
- `metrics/claude-handoffs/latest.json`：最近一次 Stop/SessionEnd 快照。

交接用于回答“Claude 做了什么、验证了吗、卡在哪里、系统流程应该怎么改”，不是新的原始证据仓库。

## 自动采集

`.claude/settings.local.json` 将下列事件直接交给 `TOOLS/db/claude_monitor.py record-hook`：

```text
SessionStart
UserPromptSubmit
PostToolUse
PostToolUseFailure
PermissionDenied
SubagentStart
SubagentStop
Stop
SessionEnd
```

`Stop` 生成可随时读取的中间快照，`SessionEnd` 生成最终快照。SessionEnd hook 设置了 10 秒超时，避免 Claude Code 默认的短结束预算中断 Python 启动。事件和字段语义以 [Claude Code hooks reference](https://code.claude.com/docs/en/hooks) 为准。

自动事件只保存白名单字段：

```text
session_id / event_name / recorded_at
agent_id / agent_type / model / effort
tool_name / tool_category / command_kind
status / error_type / duration_ms
input_bytes / output_bytes / sensitive_field_count
workspace-relative files
pytest passed/failed/errors/skipped 计数
```

Shell 只记录类别（如 `test`、`git_read`、`network_probe`，L3 会话下另有 `sprint_tick`、`work_queue`），**不记录完整命令**。

## Claude Code 结束前的 session note

自动轨迹无法可靠表达实现意图。Claude Code 在完成一次有实质工作的会话后、最终回复前，必须写一条 compact note。`SessionStart` 上下文会给出当前 `claude_session_id`，直接作为参数使用，不设置环境变量：

```text
uv run python TOOLS/db/claude_monitor.py note \
  --session "<claude_session_id>" \
  --target "<目标名或代码模块>" \
  --summary "<完成了什么及当前结论>" \
  --decision "<关键选择及原因>" \
  --blocker "<仍未解决的问题>" \
  --next-action "<建议下一步>" \
  --work-item "<可选 work_item_id>"
```

`--decision`、`--blocker`、`--next-action` 和 `--work-item` 可重复。无内容的类别可以省略。只写结论，不写 HTTP 原文、凭据、代码块、长错误日志或工具输出。

## 交给 Codex 复盘

默认读取最近会话：

```text
uv run python TOOLS/db/claude_monitor.py handoff --json
uv run python TOOLS/db/claude_monitor.py feedback --json
```

指定历史会话：

```text
uv run python TOOLS/db/claude_monitor.py handoff --session "<session_id>" --json
```

用户只需说“复盘上一次 Claude Code 会话”。Codex 应先读取 compact handoff，再按其中的文件列表检查实际 diff 和定向测试；只有 compact 信息不足且用户明确同意时，才考虑读取 Claude transcript。

内置反馈规则目前覆盖：

- 缺少 session note；
- 同类工具错误重复；
- 修改文件但没有测试；
- 测试未通过；
- 单次工具输出过大；
- 权限拒绝；
- 缺少 target/work_item；
- 只有 Stop 快照、尚未 SessionEnd。

这些规则只提出复盘线索，不自动改代码或调整权限。

## 隐私与容量边界

禁止落盘：

- user prompt、assistant response、subagent 最终正文；
- 完整 Bash/PowerShell 命令；
- `tool_input` / `tool_response` / transcript；
- HTML、JS bundle、Burp/HTTP 请求响应；
- Cookie、Authorization、Token、密码和 headers。

监控器可以在内存中读取 hook payload 来计算类别、字节数和测试计数，计算后立即丢弃原文。session note 使用长度限制和凭据/URL 查询参数脱敏。工作区外的文件只记录为 `<outside-workspace>`。

## 认知闭环复盘

认知型会话还应记录 focused session、假设、experiment、选择理由和 unknown 变化：

```text
uv run python TOOLS/db/claude_monitor.py decision --session "<session>" --decision-type dispatch --chosen-action "<action>" --rationale "<reason>"
uv run python TOOLS/db/claude_monitor.py handoff --json
uv run python TOOLS/db/claude_monitor.py feedback --json
```

handoff 保持旧 v1 可读，并额外输出 `cognitive_summary`、`decision_notes`；只保存 ID、计数、枚举和脱敏摘要。

## 自检

```text
uv run pytest TOOLS/tests/test_claude_monitor.py -q
uv run python TOOLS/db/claude_monitor.py handoff --json
```

若 `handoff` 提示没有记录，先确认 Claude Code 已重新加载 `.claude/settings.local.json`，再开启一个新会话；当前已经运行中的 Claude Code 进程可能仍使用旧 hook 配置。
