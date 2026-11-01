# 贡献指南

## 环境

- Python 3.11+，建议用虚拟环境：`python -m venv .venv`；
- 依赖写在 `pyproject.toml`，用 `pip install -e .` 安装；
- 测试：`pytest`（`testpaths = TOOLS/tests`）；
- 代码风格：`ruff check` + `ruff format`，类型检查 `mypy`，配置都在 `pyproject.toml`。

## 提交规范

- 一个提交只做一件事，主题行用「动词(范围): 说明」，例如 `fix(egress): 修正 header 非 ASCII 时的编码回退`；
- 不要提交任何目标侧数据：`dbs/`、`reports/`、`outs/`、`output/`、`logs/`、`tmp/` 都已在 `.gitignore` 里，提交前再看一眼 `git status`；
- 不要在代码、测试、文档里写死真实域名、内网地址、凭据或委托方名称，测试统一用 `example.com` / RFC 5737 地址段。

## 加一个工具（TOOLS 脚本）

1. 放到对应子目录：`recon/`（情报探测）、`pipeline/`（编排管线）、`db/`（黑板与事实）、`lib/`（共享库）、`utils/`（出口与通用能力）、`auth/`（认证态）；
2. 任何目标侧发包必须经 `TOOLS/utils/egress.py`，不要在脚本里自己写 `requests` 循环或并发批量发包；
3. 任何落库必须经 `TOOLS/lib/store_kit.py`，模板见 `TOOLS/lib/templates/store_example.py`；
4. 在 `TOOLS/tests/` 补测试，尽量用真实实现而不是把 mock 拼成形状；
5. 如果新增了闭环里的一环，在 `docs/modules/` 对应文档里写清楚它和现有表的关系。

## 改 schema

`migrations/` 按编号顺序演进，不允许回头改已经发布的迁移。新增迁移要：

- 只加不改：新表、新列、新索引；需要改语义时用 `ALTER TABLE` + 回填；
- 在 `TOOLS/db/migrate.py` 的注册处登记；
- 补一个迁移测试，覆盖「空库升级」和「已有数据升级」两条路径。

## 改文档

- 结论性内容保持单一真源，派生文档在开头写清楚它派生自哪里；
- 术语先查 [`docs/GLOSSARY.md`](docs/GLOSSARY.md)，新术语先在术语表里定义；
- 文档里出现真实委托方名称、内网地址、真实凭据形态的一律不接受。

## 报告安全问题

见 [`SECURITY.md`](SECURITY.md)。
