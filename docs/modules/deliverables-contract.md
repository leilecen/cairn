# 交付契约（deliverables contract）

> **给谁看**：要产出 `reports/` 交付物的人或 agent、把 `findings` 交给客户/平台之前做最后一道检查的人。
> **真源关系**：本文是**交付口径**的真源；**事实**以 `dbs/<target>.db` 为准（`findings` / `suspicious_points` / `evidence_refs`），冲突时**以库为准**。
> **不是**：本文不规定怎么打、不复制 `AGENTS.md` 的硬约束正文（只引用编号）。
> **最后更新**：2026-10-17（依据：177 份既有报告的实际章节结构 + `TOOLS/db/dispatcher.py` 19 个 lane + `TOOLS/db/worker_result.py` 的字段契约）。

---

## 0. 一页速查

| 交付物 | 落点 | 谁产出 | 入库？ |
|---|---|---|---|
| 逐目标事实 | `dbs/<target>.db` | 所有 worker / 脚本（经 `store_kit`） | ✅ 唯一权威 |
| 证据原件（原始流量/JS/截图） | `tmp/<case>/` 或 DB 的 `evidence_refs` 引用 | 执行者 | ❌ 不入库 |
| 客户/平台交付报告 | `reports/<client>/` 或 `reports/<domain>/` | `src-reporter` / 人工 | ❌ 不入库 |
| 内部工作记录（侦察进度、排序、阻塞分级） | `reports/<target>/` 同名文件 | 执行者 | ❌ 不入库 |
| 操作员决策卡 | DB `operator_inbox` | `create_action_card` | ✅ 结构化 |

**三条铁律**

1. **库里没有的结论不算发现**。报告里的每条结论必须能指回 `findings.id`（已确认）或 `suspicious_points.id`（未确认/待验证）。
2. **未确认的要单列，不许混进漏洞清单**。既有 177 份报告里 11 份专门有「无法确认的漏洞（附录）／信息不足」章节——这是硬口径，不是可选项。
3. **交付前必须有证伪记录**。没有"我试过什么、为什么排除"的报告，等于无法复核。

---

## 1. 发现的分级（决定它进哪一章）

沿用 `TOOLS/db/worker_result.py` 的枚举，不要另造词：

| 级别 | 判定 | 落在报告哪一章 | 能否对外提交 |
|---|---|---|---|
| **已确认** | 有可复现证据 + 影响面明确 + 已排除误报 | 「一、有攻击依据的漏洞」 | ✅ |
| **待授权验证** | 证据指向漏洞，但触发需要操作员批准的动作（高危 PoC、批量读取、认证边界） | 「二、待授权验证」 | ⚠️ 需操作员放行 |
| **无法确认** | 信息不足（缺账号/缺权限/缺响应差异） | 「附录：无法确认的漏洞」 | ❌ 不作为漏洞提交 |
| **已证伪** | 测过、不成立 | 「附录：已证伪项」 | ❌ 但要写出来 |

`risk_level` 取值固定为 `low | medium | high | critical | unknown`（`worker_result.VALID_RISK_LEVELS`）；`confidence` 固定为 `low | medium | high | unknown`（`VALID_CONFIDENCE`）。**不要**在报告里写「中高危」「疑似严重」这类自造档位。

---

## 2. 单条发现的最小字段集

内部记录（DB / evidence pack）与对外报告**都**至少要能回答下面 6 个问题。缺任何一条，这条发现只能待在「无法确认」。

| 字段 | 回答什么 | DB 落点 | 报告里的章节（按既有惯例） |
|---|---|---|---|
| `type` + `url` + `param` | 打的是什么 | `findings.type/url/param/method` | 漏洞总览表 |
| `title` | 具体到端点/参数（写「XSS」不算） | `findings.title`（043 迁移新增） | 报告标题 |
| `payload` | 怎么打的 | `findings.payload` | 复现步骤 |
| `evidence` | 看到了什么（脱敏摘要，非原文） | `findings.evidence` + `evidence_refs` | 证据 / PoC |
| `risk` + `cvss` | 多严重（`cvss` 目前是自由 TEXT，写向量串如 `CVSS:3.1/AV:N/...`） | `findings.risk/cvss` | 影响范围 |
| `remediation` | 怎么修 | `findings.remediation` | 修复建议 |
| **前置条件** | 需不需要登录/什么角色/要不要内网 | `findings.preconditions` | 前置条件 |
| **证伪记录** | 我试过什么、为什么不是误报 | `findings.counterevidence` | 反证（为什么不是误报） |
| **置信度理由** | 为什么信这个结论 | `findings.confidence_rationale` | 置信度理由 |
| **改级条件** | 什么新事实会让我上调/下调 | `findings.severity_change_conditions` | 什么情况下该改这个等级 |

后 4 项（及 `title`）是 2026-10-20 吸收两份开源评估后新增的，见 `migrations/043_report_fields.sql`。它们直接决定报告"可不可复核"：只写"是什么"而不写"我排除了什么"，客户侧无法判断真假。

**前置条件**必须显式写（既有报告里 29 处用到这个词）：需要登录态？需要特定角色？需要内网？需要某个参数组合？没有前置条件的漏洞描述在客户侧会被直接判为"不可复现"。

---

## 2.1 定级与反高估（按 triage 视角）

> 规则真源：`TOOLS/lib/finding_grader.py`；方法论正文见 `.agents/skills/src-hunter/references/methodology/03-evidence-discipline.md` §11。

**你不是扫描器，是 triager。** 等级反映攻击者实际能做什么。工具会给出「该类别建议上限」并标出高估：

| 情形 | 上限 |
|---|---|
| CORS 配置错误 / 缺失安全头 / 自 XSS / 自 CSRF | **low** |
| 盲 SSRF、上传但未证明执行、CSRF（默认） | **medium** |
| IDOR / XSS / SSTI / XXE / JWT | **high** |
| SQLi / 认证绕过 / RCE / 账号接管 | **critical**（需证据支撑） |

降级矩阵：需同权限攻击者 −1 档；需 admin −2 档（≤medium）；仅本人影响 → low；仅理论无 PoC −1 档；被浏览器默认缓解 −1 档；WAF 后未演示绕过 −1 档；仅非生产 → info。

**否定结论不是发现**：「未发现」「待验证」「疑似」这类措辞会被 `validate_finding_quality()` 直接判为不可交付，应进「无法确认/已证伪」附录。

---

## 2.2 交付前用工具自检（别靠记忆）

```powershell
# 逐条质量门：缺证据/缺证伪/缺前置条件/标题笼统/高估 → 逐条列出
.venv/Scripts/python.exe TOOLS/db/report_summary.py --db dbs/<target>.db --target "<目标名>" --check

# 生成目标级汇总报告（执行摘要数据 / 漏洞总表 / 定级异常 / 覆盖度与未测清单）
.venv/Scripts/python.exe TOOLS/db/report_summary.py --db dbs/<target>.db --target "<目标名>"
```

汇总报告里的「执行摘要」「修复优先级」「评估局限」三节留空由人/模型撰写——模板不假装会思考，其余章节是数据库事实的确定性输出，可直接复核。

---

## 3. 报告的章节骨架（按既有 177 份归纳，不另起炉灶）

**A. 渗透测试/漏洞报告**

```
基本信息              ← 目标、委托方{client}、时间窗、强度、测试账号、测试标记
一、执行摘要          ← 结论先行：几条已确认、最高风险、是否可上线
二、有攻击依据的漏洞  ← 逐条：漏洞描述 / 复现步骤 / PoC / 影响范围 / 修复建议 / 证伪说明
三、待授权验证        ← 有证据但需要放行的项
四、无法确认的漏洞（附录）  ← 信息不足，逐条写清缺什么
五、已证伪项（附录）  ← 测过不成立，写清排除理由
六、结论与下一步
七、信息收集局限      ← 没覆盖到的面、被 WAF 拦住的、拿不到的账号
```

**B. 指纹/Nday 报告**（`web-fingerprint-nday` 技能固化）：

```
一、网络基础设施  二、安全防护层  三、技术栈指纹  四、API 端点发现
五、认证系统分析  六、供应链信息  七、信息收集局限
```

**C. 内部工作记录**（`hunt_log` / `recon_progress` / `soft_target_ranking` / 阻塞分级）
不是交付物，但要留在同目录便于复盘；命名用 `<target>_<用途>_<YYYY-MM-DD>.md`。

---

## 4. 落点与命名

| 场景 | 路径 | 例子 |
|---|---|---|
| 客户委托（有委托方名） | `reports/<client>/` | `reports/{client}/2026-10-17-{target}-渗透测试报告.md` |
| 按域名组织 | `reports/<root-domain>/` | `reports/example.com/example.com_技术指纹报告_2026-10-17.md` |
| 单条紧急发现 | `reports/` 根 | `2026-10-17-{client}-{威胁关键词}.md` |

- 日期一律 `YYYY-MM-DD`；文件名**不出现**真实凭据、完整 Cookie、身份证/手机号。
- 一个目标一个目录，**不要把两个委托方混进同一目录**（既有目录结构就是这么分的）。
- 报告之间的交叉引用用相对路径；引用证据用 evidence ref（如 `ev_xxxx`），不要贴原文。

---

## 5. 脱敏与最小化（硬性）

| 内容 | 报告里怎么写 |
|---|---|
| 凭据（口令/token/key） | 只写"存在凭据泄露，类型=X，长度≈N"，**不写值**；样例掩码 `ad***n` |
| 个人数据（姓名/手机/身份证/住址） | 只写字段名 + 命中条数的**量级**（如"≤10 条样例"），不批量罗列 |
| 内网 IP / 主机名 | 保留网段级别（`10.x.x.x`），主机名脱敏 |
| 原始 HTTP/JS/HTML | 只进 `tmp/` 或证据层；报告里给 `evidence_ref` |
| 委托方名称 | 出现在 `reports/<client>/` 与报告正文没问题，**但不得进入任何入库文件**（`docs/`、`TOOLS/`、`.agents/`） |

对应硬约束：取证最小化见 `AGENTS.md`「拒绝边界」；入库脱敏见 `docs/INDEX.md` §4/§7 第 4 项。

---

## 6. 交付前检查清单（逐条打勾，别凭印象）

```
[ ] 报告的每条结论都能指回 findings.id 或 suspicious_points.id
[ ] 「待授权验证」「无法确认」「已证伪」三章该有的都有（没有就写"无"）
[ ] 每条发现都有：前置条件 + 复现步骤 + 证据引用 + 修复建议
[ ] cvss 是向量串或明确写 unknown；risk 用 low/medium/high/critical/unknown
[ ] 不含凭据明文、完整 Cookie、批量个人数据、内网真实主机名
[ ] 报告里的时间窗/强度/测试标记与委托声明一致（见 engagement-authorization.md）
[ ] 文件名/报告内不含真实委托方凭据；入库文件零委托方标识
[ ] 复核：换一个人只看报告能否独立复现（不能 → 补 PoC 或降到"无法确认"）
```

---

## 7. 与其它文档的边界

| 想知道 | 看 |
|---|---|
| 目标能不能打、强度、测试标记 | `docs/modules/engagement-authorization.md` |
| 事实表结构（`findings` / `suspicious_points` 各列含义） | `docs/modules/db-schema-reference.md`（DDL 真源是 `schema.sql`） |
| 怎么落库（禁止裸 SQL） | `docs/modules/probe-and-store-toolkit.md` |
| worker 回写格式、lane 契约 | `docs/modules/src-pipeline.md`、`.agents/agents/_CONTRACT.md` |
| 指纹/Nday 两份报告的固定结构 | `src-hunter` 的 `web-fingerprint-nday` 技能 |

> 本文与 `web-fingerprint-nday` 技能的分工：**结构**（本文）vs **怎么识别指纹/怎么检索 Nday**（技能）。两边冲突时，结构以本文为准，方法以技能为准。
