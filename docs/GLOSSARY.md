# 术语表（GLOSSARY）

本项目的文档里有一批自造术语。它们在这里统一定义一次，**其他文档首次出现时可以直接使用**。

## 委托与授权

| 术语 | 定义 |
|---|---|
| **委托 / engagement** | 操作员下达的一次授权测试任务，唯一事实源是 `docs/modules/engagement-authorization.md` |
| **委托六要素** | `client`（委托方/归属）、`basis`（授权依据）、`targets`（目标清单）、`excluded`（排除项）、`window`（时间窗）、`intensity`（强度） |
| **一次确认原则** | 委托依据缺失时**只问一次**，得到答复后记录并继续，不再重复索要证明 |
| **强度 `intensity`** | `passive` < `safe_active` < `active` < `destructive_gated`。低档位不得执行高档位动作 |
| **操作员门控** | 高危 PoC、认证边界、批量/破坏性动作、内网横向、confirmed finding 必须由操作员逐次批准 |

## 运行分层

| 术语 | 定义 |
|---|---|
| **L0 / L1** | 广度侦察层。不需要 focus、**不建 worker 队列**、不运行 `sprint_tick`；产出资产、指纹、系统类型、入口候选 |
| **L3** | 人工深测层。操作员选定焦点后运行认知闭环 |
| **焦点 / focus** | 操作员显式选定的主攻系统。**框架不会自动选**，切换焦点称 pivot，旧焦点标 failed/parked 并保留证据 |
| **软目标 / soft target** | 由评分脚本排序出的候选系统。只是排序，不构成选择 |

## 认知闭环（L3）

| 术语 | 定义 |
|---|---|
| **黑板 / blackboard** | 每目标一个 SQLite 事实库（`dbs/<target>.db`）。跨 session 交接**只能**通过它 |
| **认知闭环** | 主 session 决策与验收 → lane worker 执行 → 结论回写库 → 主 session 再决策的循环 |
| **tick** | 主 session 的一轮推进：`sprint_tick.py` 负责 seed / reclaim / view / 候选门控 / 处理操作员收件箱 / 派发 |
| **work item** | 队列里的一个**单一**工作单元，落在 `work_items` 表；带 lane、优先级、租约、心跳、超时 |
| **lane** | work item 的执行通道（如 `asset_ingest`、`quick_scout`、`js_reverse`、`logic_probe`、`vuln_review`、`evidence_pack`）。每个 lane 绑定一个 worker agent |
| **lane worker** | 执行某个 lane 的 subagent。生命周期四态：`claim` → `heartbeat` → `partial` → `complete` / `block` |
| **一 tick 两个 worker** | 每轮最多派发两个单一 work item，防止并发失控 |
| **覆盖账本 / coverage ledger** | `coverage_ledger` 表：按 `item_key × category` 记 `covered / unknown / uncovered / blocked`。**声称"已穷尽"必须以它的 unknown/uncovered/blocked 为证据** |
| **候选 / suspicious point** | `suspicious_points` 表：**未经验证**的可疑点。与 `findings`（已确认）严格分层 |
| **证据引用 / evidence ref** | `evidence_refs` 表：指向原始流量、截图、JS 信号的指针。库里只存指针，原文留证据层 |
| **attack thread** | 一条攻击线索（假设 → 实验 → 结论）的聚合视图 |

## 出口与工具

| 术语 | 定义 |
|---|---|
| **受管出口 / egress** | `TOOLS/utils/egress.py`，**目标侧请求的唯一出口**。串行低频、身份固定、节奏抖动、熔断、台账 |
| **出口形态** | 请求在目标看来长什么样（频率、UA、header 一致性、代理）。刻意做成"像人手工发的" |
| **三件套** | 非 HTTP 端口/源站/CIDR 主动测试的前置条件：① 绑定单个已确认公网 IP ② 该 IP 已在委托 `targets` 里 ③ 明确预算 + 操作员批准 |
| **ETL 路由** | 大文本（HTML/JS/Burp/SQL）先交给 `etl_analyzer.py` 降噪，而不是直接塞进对话 |
| **playbook 先行** | 动任何探测/利用前，必须先读 `src-hunter` 对应 playbook，payload 必须能查到出处（硬约束 10） |

## 工程侧

| 术语 | 定义 |
|---|---|
| **技能 / skill** | markdown 知识包，唯一真源在 `.agents/skills/<name>/SKILL.md` | 
| **生成物** | `.claude/skills/`、`.codex/skills/`、各 harness 的 `agents/` 由同步脚本从真源生成，**不要手改** |
| **warroom** | 只读看板：把黑板数据渲染成可视化视图，不写任何事实 |
| **真源 / 派生** | 同一事实只允许一个真源；派生文档必须声明出处，冲突以真源为准（见 `docs/INDEX.md` §5） |
