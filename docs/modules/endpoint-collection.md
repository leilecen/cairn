# 接口穷举（Endpoint Collection）设计与开发文档

> **这份文档是什么**：接口收集能力的设计稿与开发计划，用于指导后续实现。
> **不是**现行行为真源——现行 JS 采集/还原行为见 [`js-analysis-toolchain.md`](js-analysis-toolchain.md)。
> 本文与它冲突时以 `js-analysis-toolchain.md` 为准；本文描述的 Source 协议落地后，再由它接管终态真源地位。
>
> 登记：`docs/INDEX.md` §1；缺口跟踪：§6 缺口 14/15。

---

## 1. 目标与非目标

### 1.1 唯一目标

**把一个授权目标的接口收集"全"**，并且**换一个目标同样有效**。

"全"的判据不是数量好看，而是能回答三个问题：

1. **该站有哪些接口**（含从未被任何页面加载过的）
2. **每个接口要什么参数**（含 UI 上看不到的隐藏参数）
3. **哪个来源漏了、为什么漏**（可解释，而不是"大概齐了"）

### 1.2 硬要求：泛化

**任何"只在某个目标上调通"的实现都算失败。** 当前代码里已存在这类苗头，必须在 P0 阶段清除（见 §3.2）。

### 1.3 非目标（明确不做，避免范围蔓延）

| 不做 | 理由 |
|---|---|
| 接口的漏洞判定/利用 | 本能力只负责"看见"，判定是 playbook 与后续阶段的事 |
| 字典爆破路径 | `AGENTS.md` 硬约束：不猜路径。只读站点**声明**的清单 |
| 全站并发扫描 | 受 `egress.py` 串行低频约束（硬约束 9） |
| 取代 Yakit/Burp 的流量能力 | 它们是**来源之一**（S7），不是被取代对象 |
| 目标专用字典固化到代码 | 允许放 `TOOLS/dicts/<client>/`，但不得进入通用路径 |

---

## 2. 现状盘点

### 2.1 已有能力

| 能力 | 入口 | 产出 |
|---|---|---|
| HTML 已声明 chunk（`rel=prefetch/preload`） | `TOOLS/utils/js_chunk_manifest.py` `extract_declared_chunks()` | 候选 URL 列表 |
| 打包器运行时清单（webpack `u` 模板 / 签名扫描 / Vite `mapDeps`） | 同上 `parse_chunk_manifest()` | 候选 URL + 置信度 |
| 受管抓取（同源门/预算门/不猜门） | `TOOLS/pipeline/chunk_discover.py` | `tmp/chunks/<case>/js/` |
| JS 采集与还原（jsluice/webcrack/gitleaks/source map） | `TOOLS/pipeline/js_recon.py` | `js_signals` / `js_signal_clusters` |
| 静态 API 路径正则（17 组） | `TOOLS/utils/js_extractors.py` | `API_PATH_RE` 等 |
| 离线表单字段上下文 | `TOOLS/pipeline/ui_context.py` | `endpoint_observations.parameter_names_json` |
| Source map 解析（含 `sourcesContent`） | `TOOLS/utils/source_map_utils.py` | 原始模块文本列表 |
| 认证面 / 未认证可达性 | `TOOLS/recon/auth_surface.py` / `auth_logic_probe.py` | `suspicious_points` |

### 2.2 结构性缺口

| 缺口 | 后果 |
|---|---|
| **无 OpenAPI/Swagger 发现** | 最权威的接口清单（`/v2/api-docs`、`/v3/api-docs`、`/doc.html`）完全没读 |
| **Source Map 只用于还原，不用于提端点** | `sourcesContent` 里有**未压缩原始源码**，路径与参数最完整，价值被闲置 |
| **无路由表提取** | SPA 的 `vue-router`/`react-router` 定义里有全部路由（含未加载页面），不知道它们存在就无法触发 |
| **无前端配置常量提取** | 实测一站 `config.js` 直接给出 API 基址与 SSO 配置，属最高性价比来源 |
| **无运行时录制** | 浏览器实际发出的 XHR/fetch/WS/SSE 一条都没进库 |
| **无 WS 帧捕获** | ARTEX 注释点明"fetch/XHR 拦截看不到 WS"，我们只有静态 `ws://` URL 提取 |
| **无端点归一化** | `/users/1` 与 `/users/2` 算两条，接口数虚高且无法回答"这个端点谁能访问" |
| **无来源审计** | 只知道总数，不知道"哪个来源漏了、为什么漏"——这是泛化的致命缺陷 |

### 2.3 已踩过的坑（三次真机教训，必须写进回归）

| 坑 | 现象 | 教训 |
|---|---|---|
| 无引号 HTML 属性 | `<script src=/static/config.js>`（HTML5 合法）→ 入口脚本恒为 0 | 解析器必须覆盖三种合法引号写法 |
| Yakit 文本通道截断 | 20,443 B 的入口页在 9,923 字符处截断，`</html>` 都没有 | 大产物必须走 save-packet；**空结果不许当"没发现"** |
| 哈希表极大时固定窗口失效 | 965 条 hash ≈ 29,000 字符，3,000 字符窗口落在表内部 → 0 个 | 窗口必须相对结构定位，不能按固定长度 |
| 压缩后锚点消失 | Vue CLI 无 `__webpack_require__.u=` 字面量 | 必须按**清单签名**定位，不能依赖符号名 |
| 用真实目标当唯一验证 | 单测全绿但换真实 bundle 就失效 | 必须有合成 fixture 矩阵（§8） |

---

## 3. 泛化的定义与反模式

### 3.1 泛化的三条判据

1. **输入泛化**：不假设打包器、框架、符号名、属性引号写法、表规模、压缩形态。
2. **失败可解释**：某来源不适用时，输出"为什么"（缺什么输入/探测失败/格式不认识），而不是静默 0。
3. **可独立验证**：每个来源都能用**合成样本**在 CI 里验证，不需要真实目标。

### 3.2 必须清除的反模式（现存）

| 反模式 | 现状 | 清除方式 |
|---|---|---|
| 数值阈值写在解析逻辑里（如哈希长度门 `{6,16}`） | 已修，但同类风险仍在（`MAX_CANDIDATES`、窗口长度） | 收敛为**具名常量 + 注释出处**，并在 fixture 里覆盖边界值 |
| 锚定具体符号名（`__webpack_require__.u`） | 已加签名扫描兜底 | 要求每个来源至少有**一个不依赖符号名**的兜底路径 |
| 用单个真实目标调参 | 存在（真实目标的形态影响了实现） | P0 建立 fixture 矩阵后，**禁止**用真实目标作为唯一验证手段 |
| 目标特征进通用代码 | 未发生，但 `auth_surface.AUTH_CHUNK_TOKENS` 是同类形状 | 目标专用词表放 `TOOLS/dicts/<client>/`，通用代码只读配置 |

### 3.3 一条必须坚持的边界

**"读声明" ≠ "猜路径"**：

- ✅ 允许：`robots.txt`、`sitemap.xml`、`manifest.json`、OpenAPI 文档、打包器清单、source map、路由表、页面已加载的 JS
- ❌ 禁止：目录字典、后缀探测、id 遍历、`/.git/config` 之类猜想

判据：**站点自己声明了它**（文件里写着 / 代码里编译进去了）→ 允许；**我按经验猜它可能有** → 禁止。

---

## 4. 架构

### 4.1 五层

```
L4 落库   endpoint_observations / endpoint_source_runs
              ▲
L3 归一化  端点身份 key_hash + template_path（/users/1 → /users/{id}）
              ▲
L2 富化    参数名 / 角色可见性 / 状态码（可选，不阻塞清单）
              ▲
L1 解析    Source 纯函数：text → [Candidate]        ← 可完全离线测试
              ▲
L0 来源    S1…S9 每个都是「哪里能读到清单」        ← 部分需要发包
```

**关键分层原则**：**L1 解析必须与网络完全解耦**。凡"给定一段文本就能算出候选"的逻辑，一律纯函数、无 I/O。这样 §8 的 fixture 矩阵才能离线跑满。

### 4.2 Source 协议（新增 `TOOLS/lib/endpoint_source.py`）

```python
SourceKey = str  # "s1.html.prefetch" / "s2.webpack.manifest" / ...

@dataclass(frozen=True)
class Candidate:
    url: str                          # 绝对 URL
    method: str | None = None         # 静态来源通常未知
    param_names: tuple[str, ...] = ()
    confidence: Literal["high", "medium", "low"] = "medium"
    via: SourceKey = ""               # 来源标识，落库审计用
    evidence: dict[str, Any] = field(default_factory=dict)  # 命中位置/正则/行号

@dataclass
class DiscoveryResult:
    candidates: list[Candidate]
    stats: dict[str, int]             # scanned / hits / deduped
    warnings: list[str]               # 必须对人可见，不许静默
    skipped_reason: str | None = None # 不适用时说明原因

class EndpointSource(Protocol):
    key: SourceKey
    requires: frozenset[str]          # {"html"} / {"js_text"} / {"source_map"} / {"http"} …
    online: bool                      # True = 需要发包，受 egress 约束

    def applicable(self, ctx: "ScanContext") -> bool: ...
    def discover(self, ctx: "ScanContext") -> DiscoveryResult: ...
```

**注册表**：`SOURCES: list[EndpointSource]` 显式登记，禁止自动扫描导入（可审计）。

**编排器**（新增 `TOOLS/pipeline/endpoint_collect.py`）：

```
1. 建 ScanContext（entry_url / out_dir / egress / 预算 / 已抓产物缓存）
2. 按 requires 拓扑排序 SOURCES
3. 逐个 discover()，每个的产物写入 context 供后续来源复用
4. 每条 source 的结果写 endpoint_source_runs（无论成功失败）
5. 候选合并 → 归一化 → 落库
6. 输出覆盖率报告
```

**失败隔离**：任一 source 抛异常 → 记 `errors_json` 继续跑下一个。**绝不因一个来源失败而整体返回 0**（这正是当前截断坑的形态）。

### 4.3 与现有代码的关系

| 现有模块 | 终态 |
|---|---|
| `js_chunk_manifest.py` | 保持纯解析；被 S1/S2 包装，不再被 `chunk_discover` 直接调用 |
| `chunk_discover.py` | 降级为**抓取执行器**（提供 `fetch(url)->text` + 预算），来源探测交给 Sources |
| `js_extractors.py` | 保持；被 S2 的 `api-path` 子来源使用 |
| `js_recon.py` | 不变（它管还原与落库，不抢来源职责） |
| `auth_surface.py` 的 chunk 展开 | 改为复用 S1/S2 + 认证命名白名单过滤，删掉自己那套正则（消除重复实现） |

---

## 5. Source 清单

> 优先级 = 收益率/成本。`online` 标注是否发包。

### S1 HTML 已声明资源（online，已实现）

| 项 | 内容 |
|---|---|
| 读什么 | `rel=prefetch` / `rel=preload` / `rel=modulepreload` 的 `.js` |
| 泛化风险 | 属性引号写法（已覆盖三种）；`rel` 大小写 |
| 实测收益 | 一个请求拿到 965 条 |
| 状态 | ✅ 已有 `extract_declared_chunks()` |

### S2 打包器清单（online，已实现，需扩展）

| 子来源 | 形态 | 状态 |
|---|---|---|
| `s2.webpack.manifest` | `__webpack_require__.u=` 模板 | ✅ |
| `s2.webpack.signature` | 无符号名，按 `{...}[x]+".js"` 签名 | ✅ |
| `s2.vite.mapdeps` | `__vite__mapDeps` f 数组 | ✅ |
| `s2.esm.import` | 明文 `import()` / `__vitePreload` | ⚠️ 散在 `js_extractors` |
| `s2.rollup.chunks` | Rollup 输出 | ❌ 待调研 |
| `s2.angular.esbuild` | Angular 17+ | ❌ 待调研 |
| `s2.systemjs` | SystemJS 模块映射 | ❌ 待调研 |

### S3 Source Map（online 或离线，**高价值，未利用**）

| 项 | 内容 |
|---|---|
| 读什么 | `*.js.map` 的 `sourcesContent`（未压缩原始源码）与 `sources`（原始文件路径） |
| 为什么高价值 | 压缩后的 bundle 参数名会被混淆，`sourcesContent` 里是**可读的原名**；且路径结构完整（`src/api/user.ts`） |
| 泛化风险 | map 可能不公开（404）；可能无 `sourcesContent`（只有 sources 列表） |
| 已有基础 | `source_map_utils.detect_source_map_url()` / `parse_source_map_text()` |
| 落点 | 把 `sourcesContent` 逐份喂给 S2 的路径/参数提取器，`via="s3.sourcemap"`，置信度 high |

### S4 路由表（离线，**未利用**）

| 项 | 内容 |
|---|---|
| 读什么 | `vue-router` 的 `routes:[{path:...}]`、`react-router` 的 `<Route path=...>`、Angular `Routes` |
| 价值 | 拿到**全部前端路由**（含从未访问页面的）；配合 mock 进壳即可触发其接口 |
| 泛化风险 | 压缩后 `path:` 键名可能被保留（字符串字面量不会混淆）；动态拼接路由须标注 low |
| 落点 | 产出 `frontend_routes` 候选（`route_kind='frontend'`），**不直接当 API** |

### S5 OpenAPI / Swagger / GraphQL SDL（online，**最高价值缺口**）

| 项 | 内容 |
|---|---|
| 读什么 | `/v2/api-docs`、`/v3/api-docs`、`/swagger-resources`、`/swagger-ui.html`、`/doc.html`、`/openapi.json`、`/graphql`（introspection） |
| 为什么最高价值 | 这是**站点自己发布的接口契约**：路径、方法、参数、schema 全有。读到一份等于整站接口清单 |
| 泛化风险 | 常需认证/被禁；Knife4j / springdoc / drf-spectacular 等方言差异 |
| 边界 | 只读标准约定文件，不做路径爆破；URL 候选来自 S1/S2/S6 里出现过的字符串 |
| 置信度 | high（有完整 schema）→ 直接写 `parameter_names_json` |

> 注：`AGENTS.md` 硬约束 10 已把 Swagger/Actuator 列为探测信号，但**当前代码没有任何 Swagger 发现实现**——这是硬约束与实现脱节的地方。

### S6 前端配置常量（离线，**高性价比**）

| 项 | 内容 |
|---|---|
| 读什么 | `config.js` / `env.js` / `window._CONFIG` / `VUE_APP_*` / `API_BASE_URL` / `baseURL:` / `service:` |
| 实测价值 | 一站 `config.js` 直接给出真实 API 基址（`/zya-api`，非默认 `/jeecg-boot`）与 SSO 配置 |
| 泛化风险 | 变量名不统一 → 用**语义模式**而非固定键名 |
| 产出 | `api_base` 候选（影响后续所有相对路径解析）+ 第三方服务清单 |

### S7 被动流量（离线读库，**来源之一**）

| 项 | 内容 |
|---|---|
| 读什么 | Yakit/Burp 已捕获的 URL、`network_observations`、历史 `endpoint_observations` |
| 价值 | 零额外请求；能补回"人手工点过的页面" |
| 泛化风险 | 依赖运维习惯（有没有开代理）；不保证覆盖 |
| 产出 | `via="s7.passive"`，置信度 high（真实流量） |

### S8 运行时录制（online，**未实现，缺口最大**）

| 项 | 内容 |
|---|---|
| 读什么 | 浏览器 XHR/fetch/**WebSocket 帧**/**SSE**/GraphQL POST body |
| 为什么必须 | 前端**实际发出的请求**是终极答案；静态永远可能漏动态拼接 URL |
| 技术要点 | WS 必须走 CDP（`Network.webSocketCreated/FrameSent/FrameReceived`）——fetch/XHR 拦截**看不到 WS**（ARTEX 注释明确） |
| 泛化风险 | 需真实浏览器；需处理登录态；请求量大 |
| 前置 | 归属 `intensity` 需操作员确认（建议：纯录制不发新请求 = `safe_active`） |

### S9 标准约定文件（online，低成本）

| 项 | 内容 |
|---|---|
| 读什么 | `robots.txt`、`sitemap.xml`、`manifest.json`、`/.well-known/security.txt` |
| 边界 | 这些是**标准声明**，不是猜路径（§3.3） |
| 价值 | 中低；主要补 MPA 与传统站点 |

### 5.1 来源 × 优先级矩阵

| Source | 类型 | 泛化难度 | 预期收益 | 优先级 |
|---|---|---|---|---|
| S1 HTML prefetch | 静态 | 低（已覆盖） | 高 | ✅ 已完成 |
| S2 打包器清单 | 静态 | 中（多方言） | 高 | ✅ 已完成，待扩方言 |
| S3 Source Map | 静态 | **低** | **高** | **P1-1** |
| S4 路由表 | 静态 | 低 | 中高 | P1-2 |
| S5 OpenAPI | 静态 | 中 | **最高** | **P1-3** |
| S6 配置常量 | 静态 | 低 | 中高 | P1-4 |
| S7 被动流量 | 库内 | 低 | 中 | P2-1 |
| S9 标准文件 | 动态 | 低 | 低 | P2-2 |
| S8 运行时录制 | 动态 | **高** | **高** | P2-3 |
| Mock 进壳 | 动态 | 极高 | 高 | P4（可选，需授权形态确认） |

---

## 6. 归一化：端点身份

### 6.1 为什么必须做

不做归一化时，`/api/user/1` … `/api/user/999` 是 999 条记录，接口数虚高，且无法回答"这个端点有几个参数、谁能访问"。**"收集全"不等于"条数多"**。

### 6.2 与 CyberStrike 的有意分歧

CyberStrike 的 `key_hash` 把 `body_hash`/`query_key_hash`/`op_key_hash` 都算进身份（`normalize/index.ts:120-133`），好处是精确区分"同一路径不同操作"，代价是**同一接口的不同参数组合会分裂成多条**。

我们的目标是"接口清单"，因此采用：

```
template_path = 路径数字/UUID/长 hex → {id}/{uuid}/{hash}
endpoint_key_hash = sha256(method ∥ origin ∥ template_path)[:16]
参数名单独存 parameter_names_json（并集累积）
```

**好处**：一个接口一条记录，参数随观测累积合并。
**代价**：丢失"不同 body 形状是不同操作"的信息 → 用 `parameter_names_json` 的并集 + `variant_count` 补偿。

### 6.3 模板化规则（可测试、无歧义）

| 片段 | 归一为 | 例 |
|---|---|---|
| 纯数字 | `{id}` | `/user/123` → `/user/{id}` |
| UUID | `{uuid}` | `/doc/550e8400-e29b-41d4-a716-446655440000` → `/doc/{uuid}` |
| 长度 ≥8 的 hex | `{hash}` | `/static/8f14e45fceea167a` → `/static/{hash}` |
| 剩余 query 键排序后 | `?a=1&b=2` → `{a,b}` | 只取键名 |
| 末段无扩展名且非固定词 | **不归一**（避免把 `/list` `/add` 变成 `{id}`） | 保守 |

> 保守原则：**宁可少归一，不可错归一**。错误归一会把两个真实接口合成一条，比虚高更难发现。

---

## 7. 数据模型改动

### 7.1 新增表 `endpoint_source_runs`

**这是泛化的度量基础**——没有它就无法回答"哪个来源漏了、为什么漏"。

```sql
CREATE TABLE IF NOT EXISTS endpoint_source_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_name TEXT NOT NULL,
    run_id TEXT NOT NULL,              -- 一次采集跑的标识
    source_key TEXT NOT NULL,          -- "s2.webpack.manifest"
    applicable INTEGER NOT NULL,       -- 0/1
    candidates_raw INTEGER DEFAULT 0,
    candidates_new INTEGER DEFAULT 0,  -- 去掉跨来源重复后
    skipped_reason TEXT,
    warnings_json TEXT DEFAULT '[]',
    errors_json TEXT DEFAULT '[]',
    duration_ms INTEGER,
    created_at TEXT DEFAULT (datetime('now','localtime')),
    UNIQUE(target_name, run_id, source_key)
);
CREATE INDEX IF NOT EXISTS idx_esr_target_run ON endpoint_source_runs(target_name, run_id);
```

### 7.2 `endpoint_observations` 增量列

```sql
ALTER TABLE endpoint_observations ADD COLUMN endpoint_key_hash TEXT;
ALTER TABLE endpoint_observations ADD COLUMN template_path TEXT;
ALTER TABLE endpoint_observations ADD COLUMN discovered_via_json TEXT DEFAULT '[]';  -- 多来源列表
ALTER TABLE endpoint_observations ADD COLUMN source_count INTEGER DEFAULT 1;
ALTER TABLE endpoint_observations ADD COLUMN param_sources_json TEXT DEFAULT '{}';   -- {param: [static|ui|openapi|runtime|diff|error]}
CREATE INDEX IF NOT EXISTS idx_eo_key_hash ON endpoint_observations(target_name, endpoint_key_hash);
```

**多来源合并语义**：同一 `canonical_url` 被 N 个来源命中 → `source_count=N`、`discovered_via_json` 累积、`confidence` 取最高、`parameter_names_json` 取并集。**多来源印证本身就是置信度信号**。

---

## 8. 泛化验证：fixture 矩阵（本方案的核心）

### 8.1 原则

**不允许用真实目标作为唯一验证手段。** 每个来源都必须能用合成样本在 CI 里验证。

### 8.2 矩阵

落点 `TOOLS/tests/fixtures/endpoint_collection/<case>/`，每个 case 含 `input.*` + `expected.json`。

| case | 覆盖 | 主验证来源 |
|---|---|---|
| `wp4-hash16` | webpack 4 经典形态 | S2 |
| `wp5-contenthash20` | webpack 5 默认 20 位 contenthash + 内联前缀 | S2 |
| `wp5-named` | 具名 chunk（名字表 + 哈希表） | S2 |
| `vuecli-jsonp` | Vue CLI 压缩形态（无 `u=` 字面量、字符串 chunk id） | S2 |
| `wp-huge-map` | 哈希表 600+ 条（窗口边界） | S2 |
| `vite-mapdeps` | Vite `__vite__mapDeps` | S2 |
| `html-prefetch` | Vue CLI 生成的 prefetch 列表 | S1 |
| `html-unquoted` | 无引号属性 | S1 |
| `sourcemap-v3` | 带 `sourcesContent` 的 map | S3 |
| `sourcemap-no-content` | 只有 `sources` 列表 | S3（降级） |
| `vue-router` | `routes:[{path:...}]` | S4 |
| `react-router` | `<Route path>` | S4 |
| `openapi3-json` | OpenAPI 3 JSON | S5 |
| `swagger2-json` | Swagger 2.0 | S5 |
| `knife4j` | Knife4j 方言 | S5 |
| `graphql-sdl` | introspection 结果 | S5 |
| `config-vue` | `window._CONFIG` + `VUE_APP_*` | S6 |
| `config-webpack` | `API_BASE_URL` / `baseURL:` | S6 |
| `mpa-forms` | 传统 MPA 表单 | S6/S9 |
| `broken-json` | 畸形输入 | 全部（必须返回 warning 不崩） |
| `empty-shell` | 空壳页（无任何清单） | 全部（必须报"未识别"而非静默 0） |

### 8.3 判据

| 判据 | 阈值 | 说明 |
|---|---|---|
| 单 case recall | **1.00** | 金标准里的每个端点都必须找到（fixture 是确定的，没有"大概"） |
| 单 case precision | **1.00** | 不许凭空造 URL（`only_B` 必须为空） |
| 跨来源一致度 | ≥ 0.95 | 同一 case 多来源比对（如 S1 vs S2 在 `vuecli-jsonp` 上） |
| 降级行为 | 全通过 | 任一来源异常时其余仍产出 |
| 空输入行为 | 全通过 | 必须 `warnings` 非空，不许静默 |

### 8.4 已有的先例（照此扩展）

`TOOLS/tests/test_js_chunk_manifest.py` 已有 5 个真实形状样本 + 变异测试；
`tmp/artex-verify/mutation_check.py` 的变异思路应固化为常规手段：
**把已知缺陷注入实现，确认测试会失败** —— 否则测试可能只是恰好通过。

### 8.5 真机验证（补充，非替代）

真机只用于**发现新方言**，不用于判定"完成"。每发现一个新方言 → 立刻抽象成新 fixture → 再改代码。

---

## 9. 分阶段实施

### P0 骨架与泛化地基（约 3 人日）—— 必须先做

| # | 任务 | 产出 |
|---|---|---|
| 0.1 | `TOOLS/lib/endpoint_source.py`：`Candidate` / `DiscoveryResult` / `EndpointSource` 协议 + 注册表 | 协议层 |
| 0.2 | 把 `js_chunk_manifest.py` 包装成 S1/S2 两个 Source（行为不变，只改调用方式） | S1/S2 入协议 |
| 0.3 | `TOOLS/pipeline/endpoint_collect.py`：编排器 + 失败隔离 + 来源审计 | 编排层 |
| 0.4 | `endpoint_source_runs` 表 + 迁移 | 度量基础 |
| 0.5 | **fixture 矩阵**（§8.2 前 9 个 case）+ 金标准 + recall/precision 测试 | 泛化验证 |
| 0.6 | `--report-coverage` 命令：输出"命中/跳过/失败 + 原因" | 可解释性 |

**P0 验收**：9 个 fixture 全过；真实目标跑完能打印来源审计表。

### P1 静态来源补齐（约 3 人日）

| # | 任务 | 说明 |
|---|---|---|
| 1.1 | **S3 Source Map 提端点** | 复用 `source_map_utils`；`sourcesContent` 喂现有提取器 |
| 1.2 | **S5 OpenAPI/Swagger** | 最高价值；方言差异用 fixture 覆盖 |
| 1.3 | S4 路由表 | 产出 `route_kind='frontend'`，不当 API |
| 1.4 | S6 配置常量 | 提取 `api_base`，修正后续相对路径解析 |
| 1.5 | 新增 8 个 fixture（sourcemap×2、router×2、openapi×3、config×2） | 每个来源独立验证 |

**P1 验收**：新增来源全部有 fixture；`endpoint_observations` 条数在至少 3 个不同目标上可解释增长。

### P2 动态来源（约 4 人日）

| # | 任务 | 说明 |
|---|---|---|
| 2.1 | S7 被动流量导入 | 读 Yakit/Burp/`network_observations`，零额外请求 |
| 2.2 | S9 标准约定文件 | robots/sitemap/manifest |
| 2.3 | **S8 运行时录制** | 浏览器 XHR/fetch + **CDP WebSocket 帧** + SSE |
| 2.4 | 归一化层（§6） | `template_path` + `endpoint_key_hash` |
| 2.5 | `mpa-forms` / `empty-shell` / `broken-json` fixture | 边界与降级 |

**P2 验收**：同一目标"仅静态"与"静态+运行时"的接口数差异可量化；归一化后接口数与模板数分离可见。

### P3 富化（约 3 人日，可选）

| # | 任务 | 来源 |
|---|---|---|
| 3.1 | `hiddenParams`（请求参数 − UI 字段） | 借 CyberStrike `capture.ts:328-375` |
| 3.2 | 多样本 diff（同接口不同操作各录一次） | 借 ARTEX 参数触发矩阵 |
| 3.3 | 错误反推（发不完整请求读 400 拿必填字段） | 借 ARTEX |
| 3.4 | 多角色可见性差异 | 借 CyberStrike `element_roles` |

> 3.3 会发非 GET 请求，**必须**走操作员门控（硬约束 5）。

### P4 Mock 进壳（约 3 人日，需先定授权形态）

用 L1/L2/L3 stub 撑开登录后壳层。**前置**：明确 `forward:false` 纯离线是否算 `passive`，需操作员拍板后再动。

---

## 10. 验收标准（可量化）

| # | 标准 | 判据 |
|---|---|---|
| 1 | fixture 矩阵 recall/precision | 每个 case 均为 1.00 |
| 2 | 每个来源有独立用例 | 无来源处于"只靠真机验证"状态 |
| 3 | 失败隔离 | 注入任一来源异常，其余来源产出不变 |
| 4 | 空输入可解释 | 空壳页必须输出非空 `warnings`，不许静默 0 |
| 5 | 来源审计可用 | 任一目标跑完，能列出每个 source 的 applicable/hits/new/原因 |
| 6 | 泛化抽检 | 在 ≥3 个**不同技术栈**的真实目标上跑，无一方言需要改代码才能工作 |
| 7 | 边界未被突破 | 全程无字典/后缀/目录探测；`egress` 串行；scope 门生效 |

**第 6 条是本文档的核心验收项**：如果换 3 个目标还需要改代码，就是没做到泛化。

---

## 11. 边界与风险

### 11.1 必须遵守的现有约束

| 约束 | 出处 | 对本方案的影响 |
|---|---|---|
| 不猜路径 | `AGENTS.md` 硬约束 | 只读声明；§3.3 判据 |
| 受管出口 + 串行低频 | 硬约束 9 | S8/S9 的请求量与节拍 |
| 一致性：事实优先落库 | 硬约束 2 | 候选必须落 `endpoint_observations`，不许只留文件 |
| 操作员门控 | 硬约束 5 | P3.3 错误反推、P4 mock 进壳需逐次确认 |
| 不写目标专用代码 | 本文 §3.2 | 词表进 `TOOLS/dicts/<client>/` |

### 11.2 风险

| 风险 | 表现 | 缓解 |
|---|---|---|
| **来源爆炸导致请求量失控** | 965 chunk × 0.5 rps ≈ 32 分钟 | 预算门 + 优先级（先 S3/S5 这类"一请求一清单"的） |
| 归一化错归 | 两个真接口被合成一条 | 保守规则（§6.3），可疑不归一 |
| fixture 与真实脱节 | 合成样本太干净 | 用**真机抓到的畸形样本**（脱敏后）作为 fixture 来源 |
| 多来源互相污染 | 一个来源的低置信结果被另一个"印证"成高置信 | 只有 high×high 才升级；low 永不升级 |
| 运行时录制引入登录态依赖 | 没账号就录不到 | S8 明确标注"需认证"，与无凭据来源分开统计 |

### 11.3 未决问题（需操作员拍板）

1. **S8 运行时录制的 `intensity` 归属**：只录制不发新请求，算 `passive` 还是 `safe_active`？
2. **P4 Mock 进壳**：`forward:false` 纯离线 stub 是否可默认执行？
3. **S5 OpenAPI 探测范围**：标准路径（`/v2/api-docs` 等）属于"读声明"还是"猜路径"？本文倾向前者（业界标准约定），但需确认。

---

## 12. 与现有文档的关系

| 文档 | 关系 |
|---|---|
| `docs/modules/js-analysis-toolchain.md` | **现行真源**（JS 采集/还原/落库）。本文落地后，在它里面加一节指向本文，避免两处描述来源 |
| `docs/modules/egress-traffic-shaping.md` | 所有 online 来源的出口约束真源 |
| `docs/absorption/04-artex-吸收评估报告.md` | 本方案的 S8/mock 进壳思想来源 |
| `docs/absorption/05-*.md`（待写） | 三家接口处理机制对比（归一化 / 证据 / 枚举三种取向） |
| `AGENTS.md` | 硬约束真源，本文只引用编号不复制正文 |

---

## 13. 一页速查

```
目标：接口收集全 + 换目标不用改代码

骨架：五层（来源 → 解析 → 归一到 → 富化 → 落库）
协议：EndpointSource { key, requires, online, applicable(), discover() }
关键：解析层纯函数无 I/O；一来源失败不影响其它；每条 source 都写审计表

泛化三判据：输入泛化 / 失败可解释 / 可独立验证
泛化地基：fixture 矩阵 21 个 case，recall=precision=1.00
禁止：用真实目标当唯一验证；数值阈值硬编码；目标词表进通用代码

最高杠杆（按序）：
  S5 OpenAPI   —— 站点自己发布的接口契约
  S3 SourceMap —— 未压缩原始源码，路径与参数最完整
  S1/S2 清单   —— 已实现
  S8 运行时    —— 终极答案，但成本最高

边界：读声明 ≠ 猜路径；全程受 egress 串行 + scope 门
```

---

**下一步**：从 P0-0.1 开始（协议层），因为后面所有来源都挂在它上面；P0-0.5（fixture 矩阵）与 P0-0.1 并行做，它是泛化的验收尺子，缺了它后面每一步都无法证明"可泛化"。
