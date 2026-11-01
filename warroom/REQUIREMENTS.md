# SRC 作战室 Dashboard 需求文档（v2 · VSCode 风格）

**版本**: 2026-08-15 · v2
**状态**: 需求定稿 · 前端待实现（后端已完成）
**正式落库**: 本文件与 `local/archive/specs/2026-08-15-warroom-dashboard-v2-design.md` 内容一致（spec 为正式版）；分步实施见 `local/archive/plans/2026-08-15-warroom-dashboard-v2-implementation-plan.md`。
**给实现 AI 的说明**: 本文档是前端实现的唯一需求来源。后端 API 已存在且已实测（`warroom/server.py`），**不要重写后端**，只实现前端并按本文档数据契约消费 API。

---

## 0. 项目背景与目标

操作员在 AI 跑渗透（侦察/验证/漏洞挖掘）期间，需要一个**本地只读实时看板**，不打断 AI 就能掌握：

- 当前渗透目标（主攻资产）
- 待测队列（附 URL，可点击打开）
- 系统资产 + 指纹（信息收集成果）
- 已发现漏洞成果
- 当前资产的**堵点与进展**（本版新增，重点）

**定位**：只读观察台，纯本地（127.0.0.1），不做任何写操作、不做漏洞提交、不替代 `sprint_tick` 文本输出。

**既有资产（勿重写）**：

| 文件 | 说明 |
|---|---|
| `warroom/server.py` | 后端已完成：目标列表 + 5 组 API，纯 Python stdlib，已实测通过 |
| `local/archive/specs/2026-08-11-warroom-dashboard-design.md` | v1 设计文档（五视图原始构想 + 视觉方向，可参考） |
| `dbs/*.db` | 每目标一个 SQLite 黑板（13 个），数据源 |

**需要实现**：`warroom/web/` 前端（当前为空）。

---

## 1. 布局（核心要求：VSCode 风格）

整体仿 VSCode 的 IDE 布局，不是普通网页卡片流。四层结构：

```
┌─────────────────────────────────────────────────────────────────────────┐
│ 顶栏:  [目标▾  {client}]            [主攻资产▾  srmminio.example-client.com] │
├──────┬─────────────────────────────┬─────────────────────────────────────┤
│ 活动栏│  侧边栏（随视图切换）         │ 编辑器区（标签页，可开多个）           │
│ (图标)│                             │                                     │
│  👁  │  ▸ 当前资产 · 堵点/进展(常驻)  │  ┌───────────────────────────────┐  │
│  🗂  │    进展: 3 done · 2 partial  │  │ [态势] [资产] [队列] [漏洞] ... │  │
│  📋  │    ▸ 堵点: 2 blocked         │  │                               │  │
│  🛡  │    ▸ 待办: 1 operator        │  │   当前标签页内容              │  │
│  💰 │    ──────────────            │  └───────────────────────────────┘  │
│  ⏱  │  ▸ 资产列表(当前视图)         │                                     │
│     │  ▸ 待测队列(当前视图)         │                                     │
├──────┴─────────────────────────────┴─────────────────────────────────────┤
│ 状态栏: 目标={client} │ 队列 48 queued │ 漏洞 3 │ 上次刷新 14:32:05          │
└─────────────────────────────────────────────────────────────────────────┘
```

### 1.1 顶栏（Top Bar）

- **左侧**：目标切换下拉（列出 `/api/targets` 全部目标，显示 `target` 名）。切换后**全应用数据源切换**。
- **右侧**：主攻资产（当前聚焦资产名 + 下拉可手动切换主攻）。主攻来源：`/api/view` → `overview.soft_targets` 中 `status=focused/active` 优先，其次 rank 最高。
- **不要**显示"SRC 作战室"等标题文字（顶栏只放这两个控件 + 右侧刷新按钮）。

### 1.2 活动栏（Activity Bar，最左侧图标列）

- 竖直图标列，点击切换侧边栏 + 编辑器默认视图。图标建议（lucide-react）：
  - 👁 态势（`Gauge` / `Activity`）
  - 🗂 状态机（`Workflow`）
  - 🛡 资产网（`Network` / `Server`）
  - 📋 利用链（`Link` / `GitBranch`）
  - ⏱ 时间线（`History`）
  - 💰 漏洞（`Bug` / `ShieldAlert`）
- 当前激活项高亮（VSCode 式左侧竖条指示）。

### 1.3 侧边栏（Sidebar，随视图切换 + 常驻堵点块）

- **常驻顶部**：「当前资产 · 堵点/进展」块（数据 `/api/blockers`），**任何视图下都可见**：
  - 进展区：最近 worker 结论（`progress[]`，显示 status glyph + conclusion + 时间）
  - 堵点区：`blocked_items[]`（lane + title + blocker_reason）+ `operator_inbox[]`（kind + title）+ `coverage_blocked[]`（item_key + status），带计数
  - 点击某项 → 编辑器区打开对应详情标签页（如有 URL 则详情内可打开）
- 视图相关列表（如资产列表 / 待测队列）显示在堵点块下方，随活动栏切换。

### 1.4 编辑器区（Editor，标签页）

- 标签页可开多个、可关闭、可切换（VSCode 行为）。
- 五视图 + 各详情页均以标签页打开。
- 数据 15s 轮询刷新（TanStack Query `refetchInterval`）。

### 1.5 状态栏（Status Bar）

- 底部细条：目标名、KPI 摘要（queued/active/blocked/done）、漏洞数、上次刷新时间、后端错误提示（如有）。

---

## 2. 视图（6 个标签页视图，全部保留）

> 五视图沿用 v1 设计（见 `local/archive/specs/2026-08-11-warroom-dashboard-design.md` §5），本版新增「堵点/进展」侧边栏块。数据源均为对应 API。

### 2.1 态势 Overview（活动栏 👁）
- KPI 条：queued / active / partial / blocked / done / operator（`overview.work_summary`）
- 主攻资产卡（`overview.soft_targets`，含聚焦状态）
- 覆盖率（`overview.attack_surface` → profiles / coverage_counts）
- 最近 worker 结果（`overview.worker_results`）
- 操作员待办（`overview.operator_inbox`）
- 下一步建议（`overview.next_actions`）

### 2.2 状态机 State（活动栏 🗂）
- 四层流：system → session → thread → experiment（`state.*`）
- 每层节点按状态着色（active/ok/blocked/off），回答"现在卡在哪一层"

### 2.3 资产网 Assets（活动栏 🛡）
- `target_assets` 列表（asset_value/asset_type/port/live_status/scope_status/**tech_stack 指纹**）
- 信息收集计数：endpoint_observations / js_files（`assets.counts`）
- 资产可点击 → 打开该资产详情标签页（含其下队列/指纹/相关 findings）

### 2.4 利用链 Chain（活动栏 📋）
- 线索→漏洞管线：attack_threads → suspicious_points → findings（`chain.*`）
- 五列传送带式展示（v1 设计 §5.4），每行一个 thread，hover 高亮
- findings 项 URL 可打开

### 2.5 时间线 Timeline（活动栏 ⏱）
- past（recent_events + worker_results）→ NOW → future（next_actions + cognitive next）（`timeline.*`）

### 2.6 漏洞成果（活动栏 💰，/api/findings）
- findings 列表：risk 着色（Critical/High 红、Medium 琥珀）、type、url（可开）、param、review_status、confirmed_at

---

## 3. 数据契约（后端 API — 已存在，前端只消费）

Base URL 同源（前端由 server.py 托管，`/api/*` 同 host）。

| 端点 | 返回 | 说明 |
|---|---|---|
| `GET /api/targets` | `{targets:[{db,target}]}` | 全部目标（UI 下拉） |
| `GET /api/view?target=X` | `{overview,state,chain,timeline,recon}` | 五视图聚合数据 |
| `GET /api/queue?target=X` | `{items:[{id,lane,subtype,title,status,url,priority,claimed_by,summary,next_action,blocker_reason}]}` | 待测队列（queued/claimed/partial） |
| `GET /api/assets?target=X` | `{assets:[{asset_value,asset_type,port,protocol,live_status,scope_status,tech_stack,resolved_ip,source,...}],counts}` | 资产 + 指纹 |
| `GET /api/findings?target=X` | `{findings:[{id,type,url,param,method,risk,review_status,confirmed_at,report_file,audit_status}]}` | 漏洞成果 |
| `GET /api/blockers?target=X` | `{blocked_items,operator_inbox,coverage_blocked,progress,counts}` | 当前资产堵点/进展 |

**字段要点**：
- `overview.work_summary`：`{queued,claimed,partial,blocked,done,failed,cancelled}`
- `overview.soft_targets`：**两种形态**——有排序时为 `{results:[...], selection_required:bool}`；无可用目标时为 `{empty:true, results:[], message:"..."}`（前端需兼容空态，显示"未聚焦"占位）。有数据时每项含 `status`（focused/active/...）、`asset_value`、`rank`
- `queue.items[].url`：**可能是相对路径**（如 `/api/uploader/v2/init`，来自 endpoint_observations.path）。前端打开 URL 时：若以 `http` 开头直接开；否则**用当前主攻资产 host 拼接**（`https://{主攻资产}{path}`）后在新标签页打开；若主攻资产也未设，则该 URL 项只显示不可点。

---

## 4. 交互细节

1. **目标切换**：顶栏下拉 → 全局状态（Context/Zustand 均可）更新 `target` → 所有查询自动带新 target 重取 → 标签页保留但内容刷新。
2. **主攻资产切换**：顶栏右侧下拉 → 更新主攻 → 影响：URL 拼接、堵点块上下文、资产详情。
3. **待测队列 URL 点击**：**直接浏览器新标签页打开**（见 §3 相对路径拼接规则）。
4. **侧边栏堵点/进展块**：任何视图下可见；展开/折叠某项详情；点击打开对应标签页。
5. **轮询**：所有数据 15s 自动刷新（TanStack Query `refetchInterval: 15000`）；状态栏显示"上次刷新"时间；请求失败不打断 UI，状态栏显示错误。
6. **标签页**：可开多个、关闭、拖拽排序非必须（可后续加）。

---

## 5. 技术栈（前端，固定）

| 层 | 选型 |
|---|---|
| 框架 | React 19 + TypeScript + Vite 5（独立工程 `warroom/web/`，**勿动根目录 node_modules/package.json**） |
| 样式 | Tailwind CSS v4（或纯 CSS Modules，二选一；本需求不强制组件库） |
| 状态 | TanStack Query（服务端状态）+ React Context 或 Zustand（目标/主攻全局状态） |
| 图 | @xyflow/react（资产网/状态机；v1 允许径向示意） |
| 图标 | lucide-react |
| 动效 | framer-motion（入场微动，可选） |

**构建产物**：`warroom/web/dist/`（server.py 从该目录托管静态文件；`dist/index.html` 存在则直接可用）。

**开发方式**：`cd warroom/web && npm install && npm run dev`（Vite dev server，需代理 `/api` → `127.0.0.1:8787`，见 vite.config.ts `server.proxy`）。

---

## 6. 隐私与安全硬边界（不可违反）

| 表 | 规则 |
|---|---|
| `auth_credentials` / `auth_sessions` / `runtime_requests` / `burp_actions` | **零端点**：前端不得请求、后端无读取路径 |
| `evidence_refs` | 前端只消费 id/title 级别摘要，**不显示 ref_json / 原始证据** |
| 原始正文 | HTML、JS bundle、完整 HTTP 请求/响应、Cookie、Authorization **永不进入前端渲染** |

后端已按此实现；前端**不得**尝试访问上述表或字段，也不得新增任何写请求（无 POST/PUT/DELETE）。

---

## 7. 验收标准

1. `uv run python warroom/server.py` 启动后 `127.0.0.1:8787` 可打开（前端已构建）。
2. 布局为 VSCode 风格（顶栏左目标右资产 / 活动栏 / 侧边栏 / 编辑器标签页 / 状态栏），**无"SRC 作战室"标题**。
3. 目标下拉切换：13 个目标全部可切，切换后全部视图数据源切换。
4. 五视图 + 堵点/进展块全部渲染，数据来自真实 API（非 mock），无 console error、无横向溢出。
5. 待测队列 URL 点击 → 浏览器新标签页打开目标（相对路径正确拼接）。
6. 15s 自动刷新生效；状态栏显示目标/KPI/刷新时间。
7. 隐私检查：`grep` 前端源码无 `auth_credentials|auth_sessions|runtime_requests|burp_actions|ref_json` 请求代码。
8. 侧边栏堵点/进展块在任意视图可见，blocked/inbox/coverage 计数正确。

---

## 8. 已确认的决策记录（本版定稿时用户确认）

| 项 | 决策 |
|---|---|
| 布局 | VSCode 风格（非卡片流） |
| 顶栏 | 左=目标切换；右=主攻资产(显示+可切换)；**无标题文字** |
| 视图 | 五视图全保留 + 新增「当前资产堵点/进展」 |
| 堵点/进展 | 侧边栏常驻块：进展(done/partial/最近 worker) + 堵点(blocked+reason/inbox/coverage blocked) |
| 队列 URL | 点击直接开浏览器 |
| 目标切换 | UI 内下拉切换任意目标（不用 CLI 参数绑定） |
| 启动 | 按需启动（不用时不开） |
| 技术栈 | React 19 + Vite + Tailwind + TanStack Query + @xyflow/react + lucide-react |

---

## 9. 实现建议顺序（供实现 AI）

1. `warroom/web/` 初始化 Vite + React + TS 工程，vite.config.ts 配 `/api` 代理。
2. 全局状态（target / 主攻资产）+ `/api/targets` 拉取 + 顶栏。
3. VSCode 布局壳（活动栏/侧边栏/编辑器/状态栏）——先出空壳。
4. 侧边栏「堵点/进展」块（`/api/blockers`）——本版新增，优先接通。
5. 五视图逐个接通（Overview → Assets → Findings → Chain → Timeline → State）。
6. 交互收尾（URL 拼接、轮询、标签页、状态栏）。
7. 按 §7 验收标准逐条自测。
