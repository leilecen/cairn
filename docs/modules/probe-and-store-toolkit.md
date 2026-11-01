# 落库助手（store_kit）与探测方法学

> **何时读这份**：写落库脚本前，或要判定一次探测结果算不算漏洞时。
> 本文是 `TOOLS/lib/store_kit.py` 用法与落库自检的**真源**；DDL 与列名的真源是 `TOOLS/db/schema.sql` + `migrations/`（人类可读说明见 [`db-schema-reference.md`](db-schema-reference.md)，冲突以 DDL 为准）。
> 命令口径：本机无全局 `uv`，统一 `.venv/Scripts/python.exe`（硬约束 4）。文档里写 `uv run python` 的地方等价位就是它。
> 术语（受管出口 / 证据引用 / 覆盖账本）见 [`docs/GLOSSARY.md`](../GLOSSARY.md)。

## 1. 落库：一律用 `StoreKit`，不手写裸 sqlite3

硬约束 2 要求所有落库脚本走 `TOOLS/lib/store_kit.py`。理由是手写裸 SQL 会踩这 5 类坑，而 `StoreKit` 逐条挡住：

| 坑 | 裸 sqlite3 的后果 | StoreKit 的行为 |
| --- | --- | --- |
| 写错列名 | 字段被静默丢弃，只留骨架行 | 抛 `SchemaError`，并列出该表可用列 |
| 显式传 `created_at=None` | `KeyError` / NOT NULL 报错 | 自动剔除有 DEFAULT 的列 |
| 枚举值写错 | `CHECK constraint failed`，整批回滚 | 抛 `EnumViolation`，并列出全部合法值 |
| 撞复合唯一约束 | `IntegrityError`，整批失败 | `upsert(key=[...])` 自动改判 insert/update |
| 落库后发现空关键字段 | 靠人肉核对，容易漏 | `check_integrity()` 输出「表→行→列」 |

```python
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "TOOLS"))
from lib.store_kit import StoreKit

with StoreKit("{target}") as db:            # 按 target_name 解析 dbs/<slug>.db
    db.upsert("suspicious_points", {...}, key=["id"])
    db.report_counts(["suspicious_points", "coverage_ledger"])
    db.check_integrity()
```

可复制模板：`TOOLS/lib/templates/store_example.py`。

**自检判据**（`lib/store_kit.py` 的 `INTEGRITY_RULES` + `_JSON_EMPTY_COLS`）：`suspicious_points.reasoning`/`evidence`、`js_signals.evidence_snippet`、`endpoint_observations.business_hint`、`evidence_refs.title`/`summary`、`coverage_ledger`，以及**所有**含 `evidence_refs_json` 列的表（值为空 `[]` 也算缺失）。

单独自检一个已有库（只读）：

```bash
# 执行位置：仓库根目录。产物：stdout 报告；退出码 0 = 无问题，1 = 有空关键字段
.venv/Scripts/python.exe TOOLS/lib/store_kit.py "<target|db 路径>" [--counts]
```

回归测试是**脚本式**的（`check()` / `expect_raises()` 断言，不走 pytest 收集），自包含于临时库：

```bash
.venv/Scripts/python.exe TOOLS/tests/test_store_kit.py
```

## 2. 写探测客户端的四条硬要求

这几条是从"客户端 bug 被当成服务端行为"的实际假阴性里换来的。任何自建 HTTP 探测脚本都必须满足：

1. **URL 强制编码**。手拼 `f"{k}={v}"` 时载荷含空格/控制字符会抛 `http.client.InvalidURL`；异常被吞掉后表现为"无回显"，直接造成 **SQLi 假阴性**。用 `urlencode(..., quote_via=quote)` 并做控制字符兜底。
2. **传输失败显式建模**。状态码/长度之外必须能区分"服务端返回"与"客户端故障"（超时、连接重置、TLS 失败）。批次里出现任何传输失败时，该批次结论不可采信。
3. **首连重试**。首次连接被重置（`ConnectionAbortedError` / WinError 10053）是常见现象，之后稳定成功；不重试会把它误记为"服务端无响应"。
4. **凭据集中读取**。从 `tmp/<target>/.probe_env.json` 或环境变量读，缺凭据时明确报错，而不是静默用空 token。不要把 token 硬编码进脚本。

传输层与出口纪律的现成实现：

| 需求 | 用哪个 |
| --- | --- |
| 目标侧请求的唯一出口（串行低频、身份固定、熔断、台账） | `TOOLS/utils/egress.py`（硬约束 9，真源 [`egress-traffic-shaping.md`](egress-traffic-shaping.md)） |
| 需要自己建传输层时的参考实现 | `TOOLS/utils/http_fetcher.py`（目标侧默认经受管出口，情报 API 显式 `audience="intel"`） |
| 大响应降噪后再进对话 | `TOOLS/utils/etl_analyzer.py`（见 [`analysis-rules.md`](analysis-rules.md)） |

> 目标侧发包**禁止**脚本内 for 循环连发、禁止并发批量、禁止在未获操作员口头指定时启用环境代理（Clash）。`TOOLS/utils/waf_rotate.py` 的 IP 轮换属出口变更，只在操作员明确允许时使用。

## 3. 差异判定：用 `TOOLS/utils/compare.py`

同一份响应的差异判读不要靠肉眼。仓库里有现成的三层重放比对器，输出 `confirmed` / `low_confidence` / `false_positive` 判决与理由：

```bash
# 执行位置：仓库根目录。产物：stdout JSON {"verdict": ..., "evidence": ...}
.venv/Scripts/python.exe TOOLS/utils/compare.py --test-type idor \
    --a-status 200 --a-body "<我方对象响应>" \
    --b-status 200 --b-body "<他人对象响应>"

.venv/Scripts/python.exe TOOLS/utils/compare.py --test-type unauth \
    --a-status 200 --a-body "<已认证响应>" \
    --unauth-status 200 --unauth-body "<未认证响应>" --url "<被测 URL>" --auth-mode "<鉴权载体>"
```

`--test-type` 取值见 `TOOLS/utils/compare.py` 的 `_HANDLERS`（`idor`、`unauth`、`info_leak`、`param_logic`、`user_enum`、`captcha_reuse`、`password_reset_takeover`、`boundary_value`、`vertical_priv_esc`、`batch_idor` 等）。

## 4. 假阴性：把客户端问题当服务端行为

| 现象 | 真因 | 防线 |
| --- | --- | --- |
| 载荷"无回显" | URL 里的空格被 `http.client` 拒绝，**载荷根本没发出** | 强制编码（§2.1） |
| 多个端点"超时" | 客户端超时太短，服务端实际不到 2 秒 | 加大超时后复测；任何超时结论都要复测 |
| 并发扫端口报 80/443 关闭 | 高延迟链路上的假阴性 | 并发发现 → 串行复测 → 确认才落库 |
| 首连失败被记为"服务端无响应" | TLS 握手后被重置 | 内置重试（§2.3） |
| 405 被判为"安全差异" | 方法不匹配，不是鉴权差异 | 先落库观测到的合法方法，再发请求 |

## 5. 假阳性：脚本 bug 导致的误报

| 现象 | 真因 |
| --- | --- |
| 字段"被接受" | `None != None` 被判为值变化 |
| 字段"被改动" | 多个读回共用同一结果键，只有最后一次存活 |

**铁律：写入类测试必须用「唯一标记 payload + 3 次连续读回」确认。**

## 6. 报漏洞前自检

- **CSRF** → 先确认鉴权载体；header-only（Bearer）下"GET 改状态"不可利用。
- **SQLi** → 确认 `(状态码, 长度)` 收敛、延时/布尔差异确实存在，且**载荷确实发出了**。
- **IDOR** → 做非固有 ID 对照；能区分"不存在"与"非本人"才算存在性泄露。
- **金额篡改** → 先抓前端调用签名；**服务端重算价格是正确设计，不是漏洞**。
- **Mass Assignment** → 必须多次读回对照，不能凭一次响应。
- **HTTP 500** → 检查有无堆栈 / SQL / 环境变量外泄；无外带时归类为"错误处理"，**不要包装成越权**。
- **定级** → 若同模块其他端点对相同输入能优雅返回 400，说明是局部实现问题而非框架级缺陷，只能定 low。

## 7. 边界

- 原始 HTTP、Cookie、完整响应体只写证据层或 `tmp/`；事实表存指针与结论（硬约束 3）。
- `suspicious_points` 只承接**未经验证**的可疑点，`findings` 只承接已确认结论；两者严格分层。
- 写入类（state_changing）与敏感读取（sensitive_read）测试受硬约束 5 门控；confirmed finding 与正式交付必须交操作员确认。
