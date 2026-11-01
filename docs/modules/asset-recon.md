# L0/L1 资产录入与公开情报

> **何时读这份**：做 L0/L1 广度侦察（资产录入、公开情报、被动切片、归属门控、系统聚类与候选产出）时。**L3 深测走 [`src-pipeline.md`](src-pipeline.md)。**
> 术语（黑板 / 覆盖账本 / 候选 / 三件套）见 [`docs/GLOSSARY.md`](../GLOSSARY.md)；授权门控真源是 [`engagement-authorization.md`](engagement-authorization.md)。
> 命令口径：本机无全局 `uv`，统一 `.venv/Scripts/python.exe`（硬约束 4；文档里写 `uv run python` 处等价位就是它）。执行位置统一为**仓库根目录**。

## 1. 边界

L0/L1 只记录**已授权根资产**、被动事实、指纹与仅供复核的候选。它：

- **不**创建 `work_items`、worker 队列、`focus` 状态、`pages` 或 `scan_state`；**不**运行 `sprint_tick`；**不**派发 lane worker。
- 同根域的新发现一律停留在 `needs_review` / `intel_only`，直到操作员另行做出归属与范围裁定。
- 产出对象是：资产、HTTP 指纹、系统类型、后台/登录入口候选。

## 2. 显式新建库路径

```bash
# 执行位置：仓库根目录。DB=dbs/<ascii-slug>.db
.venv/Scripts/python.exe TOOLS/db/db_admin.py init \
    --target "<TARGET>" --slug <ascii-slug> --domain <root.example.com>
.venv/Scripts/python.exe TOOLS/recon/recon_doctor.py --target "<TARGET>" --db <DB>
.venv/Scripts/python.exe TOOLS/pipeline/init_scan.py --target "<TARGET>" --db <DB> --baseline
.venv/Scripts/python.exe TOOLS/db/v3_chain.py --target "<TARGET>" --db <DB>
.venv/Scripts/python.exe TOOLS/db/human_brief.py --target "<TARGET>" --db <DB> --json
```

- `init` 零网络请求；仅当库为新建且传了 `--domain` 时，才把该根域写成 `target_assets` 一行（`asset_type=domain`、`scope_status=in_scope`、`scope_class=owned`、`authorization_state=explicit_init`）——这是本次委托唯一可审计的授权种子。
- 每个后续命令都会校验所给库里确实存在该目标；路径缺失或不匹配时 fail-closed。目标必须显式传入（`--target` / `--file`），禁止环境变量推断（硬约束 1）。
- **不得**用临时脚本直接编排 `httpx` / `subfinder` / FOFA 替代 `init_scan --baseline`。全端口扫描不属于 v4.6 入口；非 HTTP 端口、源站验证与 CIDR 需要三件套（硬约束 8）。
- 端口事实必须写入 `network_observations`，并同时保留 source、时间、预算与停止原因。

## 3. 被动情报切片

```bash
# 每次调用只执行一个来源（代码是 if/elif 链，先命中者生效，其余静默忽略）
.venv/Scripts/python.exe TOOLS/recon/recon_intel.py --target "<TARGET>" --db <DB> \
    --subfinder-domain <root.example.com>

# 只读提议下一个被动切片（零写入，不选系统）
.venv/Scripts/python.exe TOOLS/recon/recon_plan.py --target "<TARGET>" --db <DB> --json

# opt-in 执行：一次一个已授权根域切片；--execute 取值只有 ct / subfinder
.venv/Scripts/python.exe TOOLS/recon/recon_plan.py --target "<TARGET>" --db <DB> \
    --execute ct --domain <root.example.com>

# CT 也可单独跑，只把同根域名称写成复核候选
.venv/Scripts/python.exe TOOLS/recon/ct_search.py --target "<TARGET>" --db <DB> --domain <root.example.com>
```

可用来源开关（`TOOLS/recon/recon_intel.py`）：`--github-query`、`--subfinder-domain`、`--amass-domain`、`--uncover-query`、`--gau-domain`、`--passive-dns-domain`、`--asnmap-org` / `--asnmap-asn`、`--tianyan-company`、`--import-json`。**一次只传一个。**

每次调用写一行 compact 运行台账到 `recon_runs`（adapter、来源输入指纹、attempt、budget、cursor、状态、重试时间）；来源事实写 `recon_sources` 及相关事实表。`TOOLS/recon/cdn_detect.py --target <T> --db <DB> --input <json>` 只消费**已收集**的 DNS/TLS 观测（不自己发请求），其源站候选始终是复核项，**不自动验证、不扫描、不晋级**。归属门控走 `TOOLS/recon/ownership_gate.py`，未通过的资产只能作被动事实。

FOFA 只经 `recon_intel.py --uncover-engine fofa` 的 capability resolver，当前策略是 **relay-only**（只认 `FOFA_RELAY_KEY`，不做 uncover provider 回退）；不得直接调用 `uncover -e fofa`、不得直连 FOFA、不得复制凭据。

## 4. 事实、定性与范围

- 系统按**认证边界、产品证据、部署边界**聚合；同 SLD 或同 IP 只是候选关系，不构成同一个系统。
- 产品判定为 `corroborated` 需要**两类独立 evidence ref**；证据互斥时保持 `conflicted`，不要择一。
- 域名 → IP → port → service/product → system 的每一跳都必须带 `source` / 时间 / `confidence`。共享 IP 与 vhost **不继承** scope、授权状态、产品或漏洞。
- 公开路径、外部文档与被动邻居只作 `needs_review` 情报；原文、完整 HTTP、Cookie 与密钥留在证据层。
- 覆盖（coverage）**不等于**已发请求：`covered` 指该切片已有证据锚点或已确认空结果，不代表主动测试做过。

被动来源状态语义（写进 `recon_runs` / `recon_sources`）：

| 状态 | 含义 |
| --- | --- |
| `unknown` | 未运行，或缺少判断锚点 |
| `covered` | 有 evidence ref 的空结果或命中 |
| `blocked` | 登录墙、CAPTCHA、配额耗尽、提取码等外部阻塞 |
| `uncovered` | 本机没有对应 provider / 工具 |

## 5. 有界递归与假设生成

入口递归只消费**已观察**的 HTML / JS / HAR / Burp / archive / 已复核文档入口。硬性预算（`TOOLS/db/entry_recursion.py`）：最大深度 `MAX_DEPTH = 2`、每入口 `MAX_PER_ENTRY = 20`、每系统每 tick `MAX_PER_SYSTEM_TICK = 50`。

以下情况**不自动递归**：路径字典、DNS/IP 推导、猜测的 chunk 名、soft-404、跨域资源。命中阻塞型响应类别（`soft_404` / `auth_blocked` / `captcha` / `download` / `state_change`）即停。预算耗尽记为 `partial` / `blocked`，不伪装成完成。

参数语义分析最多生成一条 `generic_probe:input_error_diff` 假设（`TOOLS/db/param_semantics.py` 的 `PROBE_SUBTYPE`），**不得**直接产出 SQLi finding 或高危 payload。重复结论只按「同系统/资产 + 规范路径 + 漏洞类 + 根因」精确抑制（`TOOLS/db/duplicate_finding_scope.py`），不整块跳过资产。

## 6. 输出边界与升级

- `human_brief --target <T> --db <DB> --json` 是候选系统与来源健康的 compact 只读读模型；原始 provider 响应、凭据、HTTP 正文与 Cookie 不进 brief，也不进 `worker_result`（硬约束 3）。
- 端口、指纹、系统类型、可疑点与证据引用必须落事实表，不能只留在对话里（硬约束 2）。候选进 `suspicious_points` 时必须带 `reasoning` 与 `evidence`，否则 `StoreKit.check_integrity()` 会报缺（见 [`probe-and-store-toolkit.md`](probe-and-store-toolkit.md)）。
- 跑完后候选由 `human_brief` 呈现；**框架不会自动选焦点**。操作员显式选定后才进入 L3，见 [`src-pipeline.md`](src-pipeline.md)。
