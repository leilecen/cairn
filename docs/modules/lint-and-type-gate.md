# 代码门禁：ruff / ruff-format / mypy

> **给谁看**：提交被 pre-commit 拦下的人、要新增或调整 lint 规则的人、怀疑"某处 noqa 是不是糊上去的"的人。
> **真源**：规则在 `pyproject.toml`（`[tool.ruff]`、`[tool.mypy]`），钩子在 `.pre-commit-config.yaml`。
> **最后更新**：2026-10-17（三项全部归零并由 pre-commit 强制）。

---

## 1. 现状（怎么自查）

```powershell
cd <repo>
.venv\Scripts\python.exe -m ruff check TOOLS            # 期望 All checks passed!
.venv\Scripts\python.exe -m ruff format --check TOOLS   # 期望 "300 files already formatted"
.venv\Scripts\python.exe -m mypy TOOLS                  # 期望 Success: no issues found in 300 source files
.venv\Scripts\python.exe -m pre_commit run --all-files  # 五个 hook 全 Passed
```

`pre-commit` 已 `install`：**提交时自动跑**，不需要也不应该再用 `--no-verify`。

---

## 2. 工具链在哪（别踩这个坑）

| 项 | 事实 |
|---|---|
| venv 里有什么 | `pytest`、`ruff`、`mypy`、`pre-commit`（`uv pip install --python .venv\Scripts\python.exe ...`） |
| venv 里**没有**什么 | 生产依赖（httpx/playwright/impacket…）。venv 是**测试与门禁**环境 |
| `uv.lock` 的作用 | 只锁生产依赖 + pytest；lint 工具不进 lock（避免锁文件被工具版本绑架） |
| mypy 版本 | **2.4.0**（`pyproject` 的 `python_version = "3.11"`） |

⚠️ **`python -m mypy` 与 `mypy.exe` 不是一回事**：本机全局安装的 `mypy.exe`（`%LOCALAPPDATA%\Python\...\Scripts\`）是 2.1.0，venv 里是 2.4.0，两者对同一棵树报的 error 集合不同。**门禁口径以 `.venv` 为准**，pre-commit 的 `mirrors-mypy` 已钉到同版本 `v2.4.0`。

---

## 3. 规则取舍（为什么不是"全开"或"全关"）

### 3.1 `line-length = 140`（不是 120）

曾按 120 卡，产生 173 处 E501，其中**几乎全是**内嵌 SQL/DDL 字面量与中文注释。按 120 硬折行会把一条 SQL 切成碎片，无法和 `TOOLS/db/schema.sql` 对读。提到 140 后仍超的 105 行，**逐文件核查确认 100% 是单行 SQL/DDL 字面量**，因此在 `[tool.ruff.lint.per-file-ignores]` 里按文件放行，并在 pyproject 写明依据。

**新增超长行怎么办**：优先折行或把它放进常量；确实是一条 SQL 的，加进对应文件的 per-file-ignore 并说明"这是 SQL 字面量"，不要往 `select` 里减规则。

### 3.2 S608（SQL 注入）是**逐点审计**后加 noqa，不是关规则

44 处 `S608` 每一处都读过源码，分两类：

- **A 类（绝大多数）**：f-string 只插入 `",".join("?" for _ in xs)` 这类占位符生成器或模块常量，值全部走 `?` 参数绑定 → Bandit 误报。
- **B 类**：插入的是表名/列名，逐一确认来源为 `PRAGMA table_info` 交集、schema introspection、或模块内静态白名单（`LANE_DISPATCH`、`RECON_KEYS`、固定表名元组）。

注释格式统一为 `# noqa: S608 -- <这一处为什么安全>`。

**新增 `S608` 的正确做法**：先问"这段标识符从哪来"。来自用户输入 → **改代码**，不要加 noqa。来自 schema 白名单 → 加 noqa 并写清白名单名字。

> noqa 的**位置**有讲究：ruff 只认它报告的 `noqa_row`。多行 SQL 里把注释写在字符串内部等于没写（tokenizer 视为零宽），写在开引号那行也会被忽略。用 `ruff check --output-format json` 看 `noqa_row` 字段再落注释。

### 3.3 S603（subprocess）

8 处均为"argv 列表 + `shell=False` + 命令由本仓库构造"，逐点加 noqa。真正的 `shell=True`（`full_port_scan.run_cmd`）**已改代码**：`shell=True` + 字符串在输出目录带空格时会把 nmap/httpx 的参数截断，换成 `shlex.split` + argv 列表。

### 3.4 mypy 没有用全局宽限

`mypy TOOLS` = 0 error 是**修出来的**，不是 `ignore_errors` 盖出来的。唯一被移出检查范围的是 `TOOLS/codeql/`——那是第三方 CodeQL CLI 的解包（`.gitignore` 已排除、不进版本控制），它的 `imp.py` / six stubs 报错与本项目无关。

修掉的真缺陷举例（都在测试覆盖内复验过）：

| 文件 | 问题 | 后果 |
|---|---|---|
| `TOOLS/lib/store_kit.py` | `__exit__`/`cur` 用 `assert self.conn is not None` 守卫 | `python -O` 下 assert 被剥掉 → `commit()` 抛 `AttributeError` 且跳过 `finally` → **连接泄漏** |
| `TOOLS/pipeline/full_port_scan.py` | `shell=True` + 字符串命令 | 路径含空格时 nmap/httpx 参数被截断 |
| `TOOLS/db/{blackboard_seed,dispatcher,claude_monitor,human_brief}.py` | dict 里 int/dict/list 混存但没有注解 | mypy 退化成 `object`，下游 `+=` / `.items()` 全部失检 |
| `TOOLS/db/rebuild_target_db.py` | 声明返回 `dict[str, int | str]`，实际混入 dict/list | 返回值不是"可序列化计数"，调用方按计数用会踩到 dict |
| 15 处 | `int(cur.lastrowid)` | typeshed 里是 `int | None`；补 `or 0` |
| `TOOLS/auth/auth_state.py` | 注解写 `list[dict]`，实际是 playwright Cookie 对象 | 读代码的人会以为能直接入库 |

**仍然允许的松散**：`disallow_untyped_defs` 没开。全量补注解属于另一件事（会改动大量函数签名），当前只保证"已有注解是对的 + 关键路径不漏检"。

---

## 4. pre-commit 钩子清单

| hook | 作用 | 失败含义 |
|---|---|---|
| `ruff`（`--fix`） | 自动修可修的（导入排序、未用导入等） | 剩下的是需要人工判断的 |
| `ruff-format` | 格式（会就地改文件；改完要 `git add` 重提） | 有文件未格式化 |
| `mypy` | 类型检查，**整树跑一次**（`pass_filenames: false` + `args: [..., TOOLS]`） | 逐文件跑会得到与 `python -m mypy TOOLS` 不同的结果，必须整树 |
| `sync_skills.py --check` | 技能真源 `.agents/skills/` 与镜像是否漂移 | 改了真源没跑生成器 |
| `sync_agents.py --check` | agent 真源 `.agents/agents/` 与三方镜像是否漂移 | 同上（`KNOWN-GAP postexp` 是已知项，不影响退出码） |

跳过钩子 `--no-verify` 只在"钩子本身坏了"时用，且必须在提交信息里写原因。

---

## 5. 改规则时的检查表

1. 改 `pyproject.toml` 的规则/忽略 → 跑 §1 四条命令，**必须有输出证据**。
2. 增删 `noqa` → 说明写进注释，能被人复核；"不安全所以关掉"不是理由。
3. 升 mypy/ruff 版本 → **同时**改 `.venv` 安装版本与 `.pre-commit-config.yaml` 的 `rev`，否则本地绿、提交红（v1.15.0 → v2.4.0 就是这么踩出来的）。
4. 改完 `docs/` 里的门禁描述 → 同步本文件，别让文档和规则各说一套。
