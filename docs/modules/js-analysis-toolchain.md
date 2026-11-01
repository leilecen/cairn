# JS 分析工具链

> **何时读**：要对站点**已观测/已加载**的 JS 做接口、密钥、混淆还原或 source map 分析，或要把 JS 信号落库、喂给 `js_reverse` lane 时。
> 本文件是 JS 分析的**唯一详细事实源**；skill `js-recon` 只讲「怎么跑、怎么落库、边界在哪」，不重复执业口径。
> 执行位置统一为**仓库根目录**，解释器 `.venv/Scripts/python.exe`（本机 shell 无全局 `uv`）。
> 下面所有工具版本号都是 **2026-10-17 在真实二进制上重新核对过**的（§2/§3 各表给出核对命令）；安装来源、SHA256 与漂移修正过程属本地一次性证据，存 `tmp/`，不写进本文件（见 §12）。

## 0. 两条底线（先读这段）

1. **原始 JS / HTML / HAR / Cookie 永不进对话**：只留在 `tmp/` 或证据层；进上下文、进 `worker_result` 的只有结构化信号摘要。
2. **不对目标做「JS 普查」**：输入只能是已观测/已加载、且已落盘的脚本与 source map（§6 边界）。

---

## 1. 两层契约：确定性采集/还原层 + 摘要式分析层

| 层 | 谁执行 | 用 LLM 吗 | 输入 | 输出 |
| --- | --- | --- | --- | --- |
| ① **采集/还原层** | 浏览器/代理捕获把脚本落盘，`TOOLS/pipeline/js_recon.py` 串起确定性二进制 | **不用**（纯工具链、可重放、无模型调用） | 本地 JS 文件（`js_files.local_path`，或 `--file` 指定的已落盘文件） | `tmp/js_reverse/<case>/` 产物 + `js_signals` / `js_signal_clusters` 结构化信号 |
| ② **分析层**（`js_reverse` lane / 主 session） | agent 读**信号摘要** | 用（只读摘要，不读原文） | `js_signals` 行、`js_signal_clusters` 行、`summary.json` 的 blockers/warnings、必要时按 `evidence_location` 取的**短片段** | 可证伪假设 → 经 `coverage_guard` 后写 `suspicious_points`；`worker_result` 只写 compact 结论 + evidence ref |

① 的固定顺序（`js_recon.py` 一条命令内）：**已落盘脚本 → jsluice（urls/secrets）→ webcrack（反混淆还原）→ gitleaks（`--no-git`，扫还原产物）→ Retire.js（已知漏洞库）→ 登记 sourceMappingURL 线索 → 落库**，产物全部落 `tmp/js_reverse/<case>/`。

契约的三条推论（违反即为流程违规）：

1. ① 的每条结论都能由「同一条命令 + 同一个输入文件」重放；② 的每条结论必须能指回 `js_signals.id` 或 `<case>` 下的 evidence ref。
2. ② **不许**把 bundle 读进上下文；需要看代码时只读**短片段**（按 `evidence_location` 定位），看完即弃。
3. `js_recon.py` **不向目标发任何请求**：它只读本地文件。缺脚本时走浏览器/代理捕获补 `local_path`，而不是让分析层去抓。

### 1.1 为什么是这两层：与 Strix / CyberStrike 的对照

调研过的两个开源红队项目（结论直接决定了本管线的形态）：

| 维度 | Strix | CyberStrike | 本项目 |
| --- | --- | --- | --- |
| 静态 JS 分析 | **不做**。端点靠 `katana -jc/-jsl` 发现（内部就是 jsluice），源码分析走 `semgrep` | 不自建 JS 解析器 | 不自建解析器：URL/密钥提取交给 jsluice（真 tree-sitter AST），还原交给 webcrack / Retire.js / gitleaks |
| 给模型的页面上下文 | CDP 直连的 `agent-browser`，**只给无障碍树快照**（`@eN` 引用，约 200–400 token），**不给原始 HTML/JS** | 浏览器扩展在**触发动作前后**抓 UI 上下文：以触发元素所在 **form/dialog** 为范围收集表单字段与标签（`src/capture.ts` 的 `snapshotPageUI`，作用域解析顺序 **form → dialog → 全页兜底**）；另有请求捕获（`src/ingest.ts`）与页面 diff | 捕获层落 `local_path` + `js_files`；分析层只吃信号摘要；浏览器侧 UI/网络捕获见 `docs/modules/chrome-devtools-recon.md` |
| 流量/产物治理 | 透明代理（Caido）统一抓页面流量 | 扩展侧请求捕获 + 页面 diff | 受管出口 `egress.py`（Yakit/Burp）+ 浏览器已观测流量；产物落 `tmp/` |
| **共同点** | —— | —— | **都不自建 JS 解析器；都是「浏览器/代理侧捕获 → 结构化 compact 上下文 → 喂 LLM」，绝不把原始 JS/HTML 塞进对话** |

对照结论：把「解析」放进确定性工具链、把「读数」压到摘要量级，是三条路线唯一的共同设计选择。**token 账的参考量级是「每次喂 LLM 几百 token 的结构化上下文」，不是几十 KB 源码**；本管线的对应实现就是 `js_signals` / `js_signal_clusters` 摘要 + `summary.json`。

---

## 2. 采集层（广度）

| 工具 | 版本 | 位置 | 核对命令（2026-10-17 实测） | 真实契约要点 |
| --- | --- | --- | --- | --- |
| URLFinder | 2026.6.16 | `TOOLS/bin/urlfinder.exe` | `TOOLS\bin\urlfinder.exe -h` → banner `Update: 2026.6.16 \| 已是最新版本`（**无 `--version`**） | `-u <url> -m <1\|2\|3>`；**吃 URL，不吃本地文件**；输出逐行 URL |
| jsluice | go install 锁定 main（`@0ddfab1`） | `TOOLS/bin/jsluice.exe` | `TOOLS\bin\jsluice.exe --help` → `rc=0`（**无数字版本**） | `urls <file>` 输出 **NDJSON 逐行对象**（非数组、不支持 `--json`/`--format`）；`secrets <file>` 查密钥 |
| x8 | 4.3.0-main | `TOOLS/bin/x8.exe` | `TOOLS\bin\x8.exe --version` → `x8 4.3.0-main` | JSON 输出 `found_params:[{name,...}]`（不是 `params`） |

- 采集层是**默认轻爬**，**不默认双跑 katana**；katana 仅对聚焦 SPA 系统显式 `--headless`。
- **`js_recon.py` 本身不调用 urlfinder / x8**：这两个是手工/离线适配器可用的二进制（命令构造与输出归一化见 §8 的 `build_urlfinder_command` / `build_x8_command`）。入口实际调用的工具见 §4。

### 2.1 表单/字段上下文 —— `TOOLS/pipeline/ui_context.py`

JS 信号回答「**有哪些接口**」，表单回答「**怎么调它**」。两者互补，且表单是唯一能给出**参数名**的静态来源。

```bash
# 只看结果（离线，不发请求）
.venv/Scripts/python.exe TOOLS/pipeline/ui_context.py --html tmp/recon/<case>/page.html \
    --page-url "https://<host>/<path>" --json
# 落库：表单 action 解析为绝对 URL，字段名进 endpoint_observations.parameter_names_json
.venv/Scripts/python.exe TOOLS/pipeline/ui_context.py --html tmp/recon/<case>/page.html \
    --page-url "https://<host>/<path>" --target "{target}" --store
```

契约：

| 项 | 规则 |
| --- | --- |
| 作用域 | **form → dialog → page**（吸收自 CyberStrike `snapshotPageUI`）；`page_fields` 只收表单/弹窗之外的散字段 |
| 字段元数据 | `tag/type/name/required/disabled/label/placeholder/pattern/maxlength`；label 解析顺序：包裹式 `<label>` → `<label for=id>` → `aria-label` → `placeholder` |
| **值处理** | **绝不记录字段值**：只记 `has_value` 与 `value_len`；名字像 CSRF 的 hidden 字段打 `csrf_like: true` |
| 输出 | compact JSON（`forms`/`dialogs`/`page_fields`/`business_hint`/`counts`），`business_hint` 由字段名规则推断（login/otp/payment/identity/upload） |
| 落库 | `endpoint_observations`，`source='ui_context'`，`parameter_names_json` = 字段名数组；`UNIQUE(target_name,canonical_url,method,source,source_id)` 保证重复跑幂等 |
| 网络 | **零发包**（纯离线解析），因此不涉及出口纪律 |

为什么值得单列一步：`parameter_names_json` 正是 `auth_logic_probe` / `x8` / `sqli_scan` 的输入；没有它，参数变体测试只能靠猜。测试见 `TOOLS/tests/test_ui_context.py`（含「值不外泄」与落库幂等两条回归）。

## 3. 还原层（深度）

| 工具 | 版本 | 位置 | 核对命令（2026-10-17 实测） | 真实契约要点 |
| --- | --- | --- | --- | --- |
| webcrack | 2.16.0 | `TOOLS/js-tools/`（npm，`package.json` + lock 锁定） | `TOOLS\js-tools\node_modules\.bin\webcrack.cmd --version` → `2.16.0` | `webcrack <file> -o <outdir>`；产物 = 输出目录文件清单（字符串解码 + unminify）；**stderr 会带 Node 的 `UNDICI-EHPA` 实验性告警，与结果无关**；`isolated-vm` 原生脚本因 npm allow-scripts 策略未执行，不影响已测功能 |
| Retire.js | 5.4.3 | `TOOLS/js-tools/`（npm） | `TOOLS\js-tools\node_modules\.bin\retire.cmd --version` → `5.4.3` | `retire --path <dir> --outputformat json`；顶层 **`data:[{file,results:[...]}]`** 且 `identifiers.CVE` 大写；**检出漏洞 exit code=1 属正常**（解析不依赖 exit code）；`{"data": []}` 是「扫了没命中」不是失败 |
| gitleaks | 8.30.1 | `TOOLS/bin/gitleaks.exe` | `TOOLS\bin\gitleaks.exe version` → `8.30.1`（**不是 `--version`**） | **必须 `detect --source <dir> --no-git`**：不加 `--no-git` 会向上找到工作区 `.git` 扫整个仓库历史；`File` 字段是相对运行 cwd 的路径 |
| source map 还原 | ——（复用） | `TOOLS/utils/source_map_utils.py` | 纯 Python，随主套件回归 | `detect_source_map_url`（注释/响应头）→ `parse_source_map_text`（sources + sourcesContent）→ `plan_sourcemap_reconstruction`（剥离 `webpack:///` 前缀、拒绝路径穿越）；只处理三类来源：文件尾注释、HTTP 响应头、CDP/HAR 已见 `sourceMapURL` |

三处真实契约漂移（已在真实二进制上对齐）：① retire `data[]` + `identifiers.CVE` 大写；② gitleaks 必须 `--no-git`；③ gitleaks `File` 相对 cwd。

---

## 4. 入口与真实命令

**唯一入口：`TOOLS/pipeline/js_recon.py`**（一条命令串起采集 + 还原 + 落库，不发目标请求）。

| 用途 | 命令（仓库根目录） |
| --- | --- |
| 单文件采集+还原+落库（推荐） | `.venv\Scripts\python.exe TOOLS\pipeline\js_recon.py --target "{target}" --js-id {js_files.id}` |
| 只分析本地文件（不落库） | `.venv\Scripts\python.exe TOOLS\pipeline\js_recon.py --file tmp/recon/<case>/app.js --case <case>` |
| 晋级到 `suspicious_points`（默认关闭） | 追加 `--promote --min-score 70`，**先过 `TOOLS/db/coverage_guard.py`** |
| 完整摘要 JSON（排障） | 追加 `--json` |

`js_recon.py` 的**真实参数**（按 argparse 逐项核对）：`--target` / `--db` / `--js-id` / `--file` / `--case` / `--skip`（逗号分隔，可跳 `jsluice,webcrack,gitleaks,retire`）/ `--promote` / `--min-score`（默认 70）/ `--timeout`（默认 120s）/ `--json`。

**入口内部实际调用**：jsluice（`urls` + `secrets`）→ webcrack → gitleaks → Retire.js → sourceMappingURL 线索登记 → 落库。单个工具失败**只记 blocker 不中断**；`summary.json` 一定写。

**产物（`tmp/js_reverse/<case>/`）**

| 文件 | 内容 |
| --- | --- |
| `jsluice_urls.ndjson` | jsluice `urls` 原始 NDJSON（逐行对象） |
| `jsluice_secrets.json` | jsluice `secrets` 归一化结果（**只留 kind/severity/file，不留密钥原文**） |
| `webcrack/` | 反混淆还原产物（随后作为 gitleaks/Retire.js 的 `scan_dir`；没有还原产物时 `scan_dir` = 原 JS 所在目录） |
| `gitleaks.json` | gitleaks 报告（`--no-git`） |
| `retire.json` | Retire.js 原始输出 |
| `summary.json` | compact 摘要：`tools` / `signal_count` / `restored_count` / `source_map_url` / **`blockers`** / **`warnings`** |

**运行约定**

- 所有入口必须显式传入 `--target`（或 `--db`）；目标不存在时失败，不回退到第一个目标或私有默认库（`AGENTS.md` 硬约束 1）。
- `js_files` 缺少新版可选列时按能力降级；source map、H5 和旧 schema 不得因 `KeyError` 崩溃。
- 退出码：`0` 无 blocker；`4` 有 blocker（**不等于失败**，看 `summary.json`）；`1/2` 是输入错误（文件不存在 / 参数缺失）。
- CLI 在 Windows 和重定向管道中统一输出 UTF-8；原始 JS/HAR 不进 stdout、对话或 `worker_result`。SQLite `bytes` 值输出 JSON 前按 UTF-8 解码，非法字节用替换字符。
- **`gitleaks` 0 命中 ≠ 没有密钥**：本机 8.30.1 对 AWS key / PEM / `ghp_` 实测全 0 命中，此时 `summary.json` 会带 `gitleaks_zero_findings` 警告，**以 `jsluice secrets` 为准**。
- 运行期记录里的 `postData: null` 必须视为空 body；敏感 header 只保存脱敏后的 compact 元数据。

---

## 5. 落库：表与字段（DDL 真源 `TOOLS/db/schema.sql`）

| 表 | 关键字段 | 谁写 | 约束/状态 |
| --- | --- | --- | --- |
| `js_files` | `url`、`page_url`、`local_path`、`content_hash`、`source_kind`、`source_map_url`、`source_map_status`、`extraction_status`、`signal_count`、`analyzed_at` | 采集层落盘；`js_recon.py` 收尾更新 | `url` UNIQUE；`source_kind` 默认 `web_script`（另有 `source_map_source` / `login_page` 等值）；`extraction_status`：`pending` → `extracted` |
| `js_signals` | `id`(TEXT PK)、`target_id`、`js_file_id`、`source_kind`、`signal_type`、`method`、`url`、`path`、`host`、`params_json`、`evidence_snippet`、`evidence_location`、`caller_hint`、`page_route`、`confidence`、`risk_score`、`status`、`promoted_sp_id` | `js_recon.py` → `utils/js_signal_store.insert_js_signal` | **UNIQUE(js_file_id, signal_type, method, path, evidence_location)** —— 同一条信号重跑是幂等（记为 duplicate，不是新增）；`source_kind` 由入口写 `toolchain` |
| `js_signal_clusters` | `id`(TEXT PK)、`target_id`、`fingerprint`、`canonical_method`、`canonical_url`、`signal_types_json`、`source_count`、`best_confidence`、`best_risk_score`、`representative_signal_id`、`status` | `upsert_js_cluster` | **UNIQUE(target_id, fingerprint)**；`status` 现行写入值：`new` / `clustered`（best_risk_score ≥ 70）/ `promoted`。（`session_dash.py` 与 `blackboard_seed.py` 还识别 `needs_auth` / `needs_signature` 两个**历史状态**，当前管线不写） |
| `js_asset_links` | `js_file_id`、`asset_id`、`relation`、`confidence`、`evidence_ref` | 归属关联脚本 | PK(js_file_id, asset_id) |
| `endpoint_observations` | `js_file_id`、`js_signal_id`、`canonical_url`、`method`、`source`、`auth_state`、`evidence_refs_json` | 端点观测登记 | 与 JS 信号的对外承接表 |
| `suspicious_points` | `source`、`risk`、`test_status`、`reasoning`、`risk_score` | 仅 `--promote` 且过 `coverage_guard` | `source='js_intel'` 是**历史数据枚举值**（不是模块引用），随迁移 `migrations/020_js_intelligence.sql` 一起存在，**不要改值** |

**入口实际写入**（`store_signals`）：信号 → `js_signals`（`source_kind='toolchain'`）→ 聚合 `js_signal_clusters` → 回填 `js_files.extraction_status='extracted'`、`analyzed_at`、`signal_count`（= 该文件的**事实行数**，用插入前后计数差得出，不是本次尝试数）、`source_map_url`（仅在非空时覆盖）。`--promote` 时按 `--min-score`（默认 70）把 cluster 晋级成 `suspicious_points` 并回写 `status='promoted'` / `promoted_sp_id`。

`signal_type` 现行取值：`js_endpoint`（jsluice urls）、`secret_candidate`（jsluice secrets / gitleaks）、`vulnerable_lib`（Retire.js）、`source_map`（sourceMappingURL 线索）。

---

> **接口穷举的方向与泛化要求**另见 [`endpoint-collection.md`](endpoint-collection.md)（设计稿）：
> 本文管「已拿到的 JS 怎么采集/还原/落库」，那份管「还有哪些来源能把接口找出来、
> 以及怎么证明换目标也有效」。两者不重复：本文是行为真源，那份是来源扩展计划。

## 6. 边界（硬约束，与 `AGENTS.md`「统一边界」同源）

- **只消费已观测/已加载脚本与 source map**：入口输入必须是已落盘的本地文件（`js_files.local_path` 或 `--file`）。
- **不猜路径、不批量探测未知静态资源、不自动访问还原产物中的新 URL**（还原产物里出现的新 URL 是**线索**，不是采集目标；要访问必须经出口治理与会话/委托门控）。
  - 允许：读**站点自己声明的清单**并按清单抓取——包括 HTML 明文引用、入口 JS 里明文 `import()` / `__vitePreload`、以及 webpack `__webpack_require__.u` 的哈希模板（`TOOLS/utils/js_chunk_manifest.py` 解析）。
  - 禁止：字典扫描、后缀探测、目录列举等**猜测**行为。判定标准是「站点声明了它」还是「我猜它可能有」。
- **不向目标发新请求**：`js_recon.py` 全程只读本地文件。
- **密钥绝不留原文**：jsluice `secrets` 的 `data`、gitleaks 的 `Secret/Match` 一律丢弃，只留 rule/kind + 位置。
- **晋级前必过门控**：`--promote` 默认关闭；写 `suspicious_points` 前先跑 `TOOLS/db/coverage_guard.py` 查历史负结论。
- **单个 subject 一个 work_item**；不做「全站 JS 普查」「批量分析未处理 js_files」（`blackboard_seed.py` 的 `js_reverse` 计划器按 `js_files.id` 逐条派发，上限 15 条/次）。

---

## 7. 认证面发现（第二阶段）

`js_recon.py` 只吃**已观测**的单个脚本、不跟随 import；而登录表单几乎总在 **lazy chunk** 里，浏览器在 SSO 强制跳转下可能**永远不加载这个 chunk**（因此它进不了 `js_files`，属管线的结构性漏检）。下面两步补齐这个缺口，并回答「这系统怎么登录、有没有默认凭据、SSO 是不是只挡了 UI、未认证能走到哪一步」。这两步会**发包**，因此不属于 §1 的确定性层，必须走 `egress.py` 与委托 `intensity` 门控。

### 7.1 `auth_surface` —— 认证面与默认凭据线索

| 用途 | 命令（仓库根目录） |
| --- | --- |
| 认证面发现（在线） | `.venv\Scripts\python.exe TOOLS\recon\auth_surface.py --target "{target}" --url https://<host>/` |
| 零发包回归 / 离线复算 | `... auth_surface.py --url https://<host>/ --offline-dir tmp/<case>/evidence` |
| 落库（`suspicious_points` + `endpoint_observations`） | 追加 `--store`（需 `--target`） |

产出五类 finding：

1. `default_credential` —— 表单默认值/赋值里的弱口令线索。要求**键名 + 弱值成对**（`account:"admin"` 与 `password:"<weak>"` 邻近），所以 base64/md5 字符表里的 `123456` 不会误报；
2. `sso_ui_gate_only` —— `openSso` + `casBaseUrl` + `location.href` 同现 = SSO **只在 UI 层**遮蔽；
3. `local_login_endpoint` —— 本地登录/短信/注册/扫码接口线索；与 2 同现即**认证旁路候选**（UI 跳 SSO ≠ 后端关本地认证）；
4. `runtime_config_dead_code` —— HTML 引用了 `*.config.js`，但产物内联了 env（`DEV:!0`/sandbox）→ 改配置不生效；
5. `hardcoded_http_service` —— 跳转 `service` 硬编码 `"http://" + location.host` → 登出/会话失效撞 https 端口的 400。

边界与预算（与 `js_recon` 同一套边界）：

- 只消费 HTML 明文引用的资源 + 入口 JS 里明文 `import()` / `__vitePreload` 的 chunk；**不枚举、不爆破路径**。
- chunk 展开有**命名白名单 + 权重排序**（`LoginForm` > `Login` > `oauth/third/mobile`）与预算 `--max-chunks`（默认 12），另有 `--max-assets`（默认 8）、`--all-chunks`、`--all-assets`。
- **CSS/图片默认跳过**：它们会挤占资产预算（曾出现两个 CSS 合计近 1 MB、吃掉 8 个资产预算里的 2 个）；确需时用 `--all-assets`。
- **大产物必须走 save-packet**：Yakit 文本通道 >10KB 会截断，截断会让 chunk 展开**静默返回 0**。工具识别截断标记与 `Content-Length` 差异并自动全量重取；取不全时写进 `coverage_warnings`：**空结果不许当作「没发现」**。

回归与验收：

- `.venv\Scripts\python.exe -m pytest TOOLS\tests\test_auth_surface.py -q`，fixture 取自 `TOOLS/tests/fixtures/auth_surface/`（本项目真实证据脱敏后固化）。
  两条关键回归：入口 bundle 里 charset 的 `123456` **必须零命中**；没有出厂口令的产品必须报「不猜」而不是漏报。
- 真机验收判据（不记具体站点）：能自动识别框架指纹 → 从 chunk 候选中按白名单取少数几个 → 命中登录表单 chunk → 报出默认凭据线索 + 上述结构性缺陷。**请求数必须是可控的个位数**。

默认凭据线索的**验证**与尝试上限不在本文件，按 `weak-password-boundary` skill 与委托 `intensity` 执行。

### 7.2 `auth_logic_probe` —— 未认证可达性

`auth_surface` 之后的第二问：**这些认证接口，未认证到底能走到哪一步？**

| 用途 | 命令（仓库根目录） |
| --- | --- |
| 逻辑面探测（在线） | `.venv\Scripts\python.exe TOOLS\recon\auth_logic_probe.py --target "{target}" --url https://<host>/ --from-auth-surface tmp/auth_surface/<slug>.json` |
| 零发包回归 / 复算 | `... --offline-dir tmp/auth_logic/<slug>`（配 `manifest.json` 把 probe_id 映射到真实回包文件名） |

判定口径：返回带 `success/code/message` 的业务 JSON = **未认证可达**；`401/403` 或含「Token 失效/请重新登录」= **需鉴权**；`502/503/504` = **后端不可用**（记 blocked，不许记成「没发现」）；`404` = 不存在。

产出四类 finding：`missing_auth_on_protected_endpoint`（本应鉴权却未认证可达，high）、`user_enumeration_oracle`（存在性校验的测试值/对照值语义不同，medium）、`auth_backend_unavailable`（info，用于把环境阻塞与「安全」区分开）、以及逐条 verdict 清单。

**内建安全（不可用参数关闭）**：

1. 只发**空 body** 或**明显无效占位参数**（`zz-nonexist-<rand>`）——不做任何口令/账号猜测；
2. **状态改变类**（注册/短信/改密/第三方建号/导入导出/上传/强制下线）默认 **skip 并记录原因**，只有显式 `--i-approve-state-change`（操作员门控）才执行；
3. 存在性校验固定 **2 个请求**（1 测试值 + 1 对照），不做批量枚举；
4. 全部经 `egress.py` 串行发出，逐条记台账；`--offline-dir` 零发包。

回归与验收：`.venv\Scripts\python.exe -m pytest TOOLS\tests\test_auth_logic_probe.py -q`。关键回归：真实 401 组**不得**被误报成「未认证可达」；状态改变类**必须**默认跳过；`checkOnlyUser` 的测试/对照差异必须识别为枚举 oracle。

---

## 8. 适配器契约（离线层）

`TOOLS/recon/phase_a_adapters.py` 只负责**构造命令**与**解析已捕获的 fixture**，不调用真实二进制（运行时相位由操作员批准）。`js_recon.py` 复用它的 `build_*` / `parse_*`，不自己拼命令行。

- **命令构造**：`build_urlfinder_command` / `build_jsluice_command` / `build_x8_command` / `build_webcrack_command` / `build_retirejs_command` / `build_gitleaks_command`。
- **输出归一化**：`parse_urlfinder_fixture` / `parse_jsluice_fixture` / `parse_x8_fixture` / `parse_webcrack_fixture` / `parse_retirejs_fixture` / `parse_gitleaks_fixture`。
- **健康检查注入**：`health_contract(tool, binary_path=..., expected_version=...)`，runner 由调用方注入。
- **source map 规划**：`plan_sourcemap_reconstruction`。
- **安全约束**：`parse_gitleaks_fixture` **绝不输出 Secret/Match 原文**（只保留 rule/file/line/commit 前缀）；URL 归一化拒绝含凭据的 URL。
- **测试**：`.venv\Scripts\python.exe -m pytest TOOLS\tests\test_phase_a_adapters.py -q`。
- **端到端漂移验证**：真实二进制输出 → `parse_*` 全绿，临时脚本落 `tmp/`（不入库）。

---

## 9. 标准工作流（`js_reverse` 场景）

```text
已观测 script（browser_script | login_page）落盘 → js_files.local_path
  → js_recon.py --target ... --js-id <id>                     ← ① 确定性层，无 LLM
      jsluice urls+secrets → webcrack 反混淆 → gitleaks(--no-git) → Retire.js → sourceMap 线索
      → tmp/js_reverse/<case>/（summary.json）+ js_signals / js_signal_clusters
      → js_files.extraction_status='extracted'
  → ② 分析层：读信号摘要（cluster 按 best_risk_score 排序）→ 高分短片段精读
  → 需要登录面时走 §7（auth_surface → auth_logic_probe，发包、受门控）
  → 晋级前过 coverage_guard 查历史负结论 → suspicious_points（--promote）
```

`TOOLS/js_value_flow.py` / `TOOLS/js_attack_surface.py` 是**库模块**（`build_attack_surface`、`attack_surface_markdown`），**没有独立 CLI**：按库调用（`from js_attack_surface import build_attack_surface`）或在 `tmp/` 下写一次性脚本。`js_value_flow` 折叠 URL/参数来源（未知值保留 `{dynamic}`）。

---

## 10. 已退役的旧 JS 管线（`TOOLS/legacy/js/`）

2026-10-17 的**第一层收敛**把这 5 个模块连同只服务它们的 6 个测试文件（33 个用例）移出活跃目录：

| 模块 | 退役前位置 | 现状 | 承接者 |
| --- | --- | --- | --- |
| `js_intel.py` | `TOOLS/js_intel.py` | `TOOLS/legacy/js/js_intel.py`（退役） | `pipeline/js_recon.py`（一条命令） |
| `js_analyzer.py` | `TOOLS/js_analyzer.py` | `TOOLS/legacy/js/js_analyzer.py`（退役） | `pipeline/js_recon.py` + `utils/js_signal_store.py` |
| `js_reverse_cli.py` | `TOOLS/js_reverse_cli.py` | `TOOLS/legacy/js/js_reverse_cli.py`（退役） | **无 CLI 替代**：`js_attack_surface.py` / `js_value_flow.py` 按库调用 |
| `runtime_trace_ingest.py` | `TOOLS/runtime_trace_ingest.py` | `TOOLS/legacy/js/runtime_trace_ingest.py`（退役） | 浏览器侧捕获（`docs/modules/chrome-devtools-recon.md`）+ `pipeline/js_recon.py` |
| `h5_asset_expander.py` | `TOOLS/h5_asset_expander.py` | `TOOLS/legacy/js/h5_asset_expander.py`（退役） | `wechat_api_analyzer.py` + `pipeline/js_recon.py` |

- 搬迁保行为：`PROJECT_ROOT` / `TOOLS_DIR` / 默认缓存根等路径锚点按新层级回推，**解析到与搬迁前完全相同的目录**；`runtime_trace_ingest.py` 自行补 `TOOLS/` 到 `sys.path`。归档目录另有 [`TOOLS/legacy/js/README.md`](../../TOOLS/legacy/js/README.md) 记录细节，`_tests/conftest.py` 只补 `sys.path`（不改断言）。
- **不再被扫到**：`pyproject.toml` 的 `ruff extend-exclude` 与 `pytest norecursedirs` 都包含 `TOOLS/legacy`。（mypy 的 `exclude` 目前**没有** `TOOLS/legacy`，属已知残留，见 §11。）
- **不再是入口**：任何文档、skill、work_item 文案都不得再把它们写成可用命令；需要既有 `js_files` 数据时，在 `tmp/` 下写一次性只读脚本（显式 `--target`，目标不存在时失败）。
- `TOOLS/utils/js_callgraph.py` 与 `TOOLS/utils/js_module_resolver.py` **仍然活跃**（被 `utils/js_chain_resolver.py`、`TOOLS/wechat_api_analyzer.py` import），**不在退役清单里**；`TOOLS/utils/js_*.py` 全部是活跃库模块。

---

## 11. 验收标准

**回归（每条都要贴真实输出）**

```bash
# 主套件：必须 0 failed
.venv\Scripts\python.exe -m pytest TOOLS/tests -q
# 入口自身
.venv\Scripts\python.exe -m pytest TOOLS/tests/test_js_recon.py -q
# 离线适配器契约
.venv\Scripts\python.exe -m pytest TOOLS/tests/test_phase_a_adapters.py -q
# 归档用例（不被收集，仅在显式指定时运行；应 0 error）
.venv\Scripts\python.exe -m pytest TOOLS/legacy/js/_tests -q
```

**退役收敛验收**（2026-10-17 实跑）

- 主套件：**1155 passed / 1 skipped / 0 failed**。账目对得上：收敛前基线 1180 passed，**−33**（随 5 个退役模块归档的用例）+ **+9**（同日并行落地的 `TOOLS/tests/test_ui_context.py`，与本轮无关）− **1**（同日并行删掉 `TOOLS/schema.sql` 后，`test_blackboard_schema.py` 的 `parametrize` 从两个 schema 路径减到一个）= 1155。
- 归档用例显式运行：**33 passed**（路径锚点保行为成功，不是「跑不了」）。
- `TOOLS/legacy/js/` 下 5 个模块 + `_tests/conftest.py`：`py_compile` 全过；在只注入归档目录的干净环境里 `import` 全部成功。
- 全仓 `git grep` 5 个模块名：活跃目录（`TOOLS/` 非 legacy、`AGENTS.md`、`docs/modules/`）**无命令性引用**；`pyproject.toml` 里 `"TOOLS/js_analyzer.py" = ["S501","S603","S607"]` 一条 per-file-ignores 已成悬空项（ruff 容忍不匹配的 pattern，但应在下次改 `pyproject.toml` 时删掉，见下）。

> **跑套件的陷阱**：不要在 shell 里设 `PYTHONIOENCODING=utf-8` 再跑 pytest。若设了，子进程按 UTF-8 输出、父进程按本机 locale（gbk）解码，`subprocess` 读线程会抛 `UnicodeDecodeError`，表现为 `test_blackboard_tick` / `test_blackboard_view` / `test_human_brief` 三个 CLI 子进程用例假失败（实测 3 failed；去掉该环境变量后 0 failed）。

**已知残留（刻意不改，改前先确认）**

- `mypy` 的 `exclude` 未含 `TOOLS/legacy`：`pyproject.toml` 不在本轮改动清单里，且 `legacy` 代码已冻结。
- `suspicious_points.source='js_intel'` 是历史数据枚举（`migrations/020_js_intelligence.sql`、`utils/js_signal_store.py`、`db/schema.sql` 的视图），**不是模块引用**，不要改名。
- `docs/archive/**` 与 `TOOLS/legacy/README.md` 里的旧路径属历史留档。

---

## 12. 维护约定

- 版本、位置、二进制契约、健康检查命令以本文件为准；**改这里就要同时改 `docs/modules/analysis-rules.md` 的「工具健康检查与命令契约」小节**（两处必须逐项一致）。
- 安装来源、SHA256 校验值、漂移修正过程是**本地一次性证据**，写 `tmp/` 下的记录文件并从 `tmp/` 引用，不复制进本文件（历史归档在仓库外 `local/archive/`，不入库）。
- 手工分步跑二进制时的正确形态与陷阱见 skill `js-recon`；本文件只维护契约与入口。
- 工具链扩容的判据：**确定性、可重放、无模型调用**才能进 §1 的 ① 层；任何需要「读原文才能判断」的步骤都属 ② 层，必须走信号摘要 + 门控。
