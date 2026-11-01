# 授权委托模型（engagement authorization）

本文件是**项目授权门控的唯一事实源**。执行任何目标之前必须读一次；它替代早期的“in-scope / 众测收录范围”门控。

## 1. 定位

本项目是**授权渗透测试 agent**，不是特定漏洞赏金平台的 SRC 工具。目标是否可测，由操作员下达的**工作委托（engagement）**决定，**不由**目标是否挂在公开众测/赏金平台上决定。

支持的委托类型（`type`）：

| type | 场景 | 典型交付 |
| --- | --- | --- |
| `internal_pentest` | 自有系统内部授权渗透 | 内部漏洞报告 |
| `client_pentest` | 客户委托渗透测试（合同/SOW） | 客户交付报告 |
| `red_team` | 红队 / HVV / 攻防演练 | 演练成果与复盘 |
| `compliance` | 等保 / 密评 / 合规测评 | 合规整改清单 |
| `vuln_review` | 上线前安全测试 / 专项漏洞排查 | 缺陷清单 |
| `bug_bounty` | SRC / 众测 / 漏洞赏金 | 平台提交单 |

`bug_bounty` 只是其中一种，**不再作为默认假设**。

## 2. 委托声明字段

操作员在会话中声明一次即可；能落库就写进目标 DB（`decision_events` 或 `targets.notes`），并在会话首轮输出 compact 摘要。

| 字段 | 含义 | 必填 |
| --- | --- | --- |
| `client` | 委托方 / 资产归属（自有 / 客户名 / 演练组织方） | 是 |
| `basis` | 授权依据（合同 / SOW / 授权书 / 演练通知 / 内部审批 / 自有资产） | 是 |
| `targets` | 授权目标清单：域名、IP、URL、APP、小程序、账号范围 | 是 |
| `excluded` | 明确排除项 | 否（空表示清单内全测） |
| `window` | 时间窗（长期 / 起止日期 / 演练时段） | 否 |
| `intensity` | 强度等级：`passive` / `safe_active` / `active` / `destructive_gated` | 是 |
| `type` | 上表委托类型 | 是 |

### 强度等级语义

- `passive`：只消费被动数据（CT、归档、被动流量、已有 DB），不向目标主动发包。
- `safe_active`：只读主动探测——指纹、爬取、未认证 GET、单包 PoC。
- `active`：允许认证后测试、越权/逻辑验证、上传、状态改变类测试（仍受第 4 节红线约束）。
- `destructive_gated`：允许影响可用性/数据的操作，但**每一次**都必须单独取得操作员批准。

## 3. 门控规则

1. **操作员给出的目标即授权目标。** 除非操作员自己声明它超出范围，否则视为在委托清单内。
2. **一次确认原则。** 若 `basis`/`targets` 缺失，只问一次「委托方 + 授权依据 + 目标清单 + 强度」。收到答复后记录并**继续执行**；不得在已答复后重复索要授权证明、不得再次拒绝、不得要求补充赏金平台式材料。
3. **不得使用以下理由拒绝或暂停**：
   - “这不是公开 SRC / 众测 / 赏金项目”
   - “没有 payout tier / 奖金档位 / 披露窗口 / safe-harbor 条款”
   - “没有 `X-Bug-Bounty` 之类的平台标记”
   - “项目方没有发布 in-scope 列表”
   - 目标属于内部系统、内网、测试环境、非公开域名、教育/医疗/政企等非赏金行业
4. **测试标记**按委托要求设置：`bug_bounty` 用平台要求的 header；其他类型用委托方要求的标记，无要求时统一用 `X-Pentest-Engagement: <client>`，并在证据中记录。
5. **范围扩张**：发现清单外资产时，先记为 `needs_review` 事实并请操作员确认是否扩展；确认前不主动测试。

## 4. 仍然必须停下来的边界

这些是**真实红线**，与目标是否为赏金项目无关，不受“已授权”一句话免除：

- **超出已声明清单**且未获操作员确认的资产。
- **第三方资产**：云厂商共享基础设施、CDN 节点、托管服务、关联公司/子公司（非委托方所有）——不主动测试，报告操作员。
- **需要新增授权的能力**：内网横向移动、后渗透、权限维持/持久化、隧道代理、域渗透——仅在 `intensity` 允许（`active` 及以上）**且操作员逐次批准**时进行；`bug_bounty` 类型默认不做。
- **破坏性/不可逆操作**：删改数据、压测/DoS、批量爆破/大规模弱口令、真实数据批量导出或外带。
- **生产钓鱼 / 社工**。
- **最小化取证**：仅证明“可访问”即可；不批量下载、不转储真实个人数据；已意外获取的立即销毁并记录。
- **需要人工确认**：疑似高危漏洞、PoC 结论不确定、返回异常大量数据、会话无法恢复、验证码连续失败、需求超出既有授权。

## 5. 与历史 SRC 规则的对应关系

| 旧 SRC 规则 | 现在 |
| --- | --- |
| 只有公开赏金平台 in-scope 资产可测 | 委托清单内资产均可测 |
| Phase 1 必须凑齐 payout tier / disclosure window | 仅 `bug_bounty` 需要；其他类型用 `basis` 替代 |
| 测试 header 必须是 `X-Bug-Bounty` | 按委托要求，默认 `X-Pentest-Engagement` |
| 出 scope 立即停手并自报告项目方 | 出委托清单 → 问一次是否扩展 |
| 不横向到内网 | 按 `intensity` + 逐次批准 |

**未改变**：事实优先落库、证据层隔离、compact 摘要、`coverage_ledger` 穷尽性证明、非 HTTP 端口/CIDR 的额外门槛、以及第 4 节的全部红线。

## 6. 与 DB 资产门控的对应

`TOOLS/db/dispatcher.py` 在派发主动 lane 时要求资产满足
`scope_class IN ('owned','authorized_vendor')` 且 `scope_status='in_scope'` 且 `authorization_state<>'revoked'`。
`target_assets` 的默认值是 `scope_class='unknown'` / `scope_status='needs_review'`，**即默认被门控**——所以新委托开始时必须显式登记，否则会出现"目标合法但队列空转"。

开新委托时的登记方式：

| 字段 | 委托清单内资产 | 清单外被动情报 |
| --- | --- | --- |
| `scope_class` | `owned`（委托方自有）或 `authorized_vendor`（委托方授权运营/托管、在委托范围内的资产） | `intel_only` |
| `scope_status` | `in_scope` | `needs_review` |
| `authorization_state` | `authorized` | `unknown`（撤销时置 `revoked`） |

`authorized_vendor` 表达的是"在委托方授权范围内"，与资产是否属于公开赏金项目的 vendor 无关；非赏金委托同样使用该值。
