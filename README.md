# Cairn

一个给**授权安全评估**用的 agent 工作台。

叫 Cairn 是因为它的核心不是"更聪明的扫描器"，而是一堆路标：每走一步就留一个标记，后来的人（或者另一个 agent 会话）能沿着标记走回来，知道到过哪里、看过什么、哪条路已经断了。

具体一点：一次评估里最容易丢的东西是"做过什么"和"为什么这么判断"。Cairn 把资产、端点、指纹、可疑点、证据、覆盖情况全部落进每个目标一个的 SQLite 库；AI agent 在这个库上领任务、干活、把结果写回去；人只负责定焦点、批高危动作、看结论。程序负责记住，人负责判断。

> 仅用于你拥有书面授权的目标。授权怎么声明、什么情况会拒绝执行，见 [docs/modules/engagement-authorization.md](docs/modules/engagement-authorization.md) 和 [SECURITY.md](SECURITY.md)。

---

## 为什么写它

大模型做渗透测试，会稳定地在三个地方翻车，跟模型多强关系不大：

**一是忘。** 上下文一长，半小时前扫过哪个子域、哪个接口返回过 500，全丢了。于是同一个页面被反复打开，同一个参数被反复猜。换成更大的上下文窗口也只是把翻车时间往后推。

**二是把猜测当结论。** "这里可能存在越权"和"这里确认越权"在对话里长得几乎一样，但交付物里差一个数量级。更麻烦的是"已经测完了"这句话——没有账本就没法反驳，也没法复核。

**三是发包不像人。** 让 agent 自己写脚本、并发、批量打，轻则把测试环境打挂，重则直接越过授权边界。真出了事，你连它发了什么包都说不清。

Cairn 的做法很土：把这些东西都变成数据库里的表。资产是表，可疑点是表，证据是指针，覆盖情况是账本，任务队列有租约和心跳。agent 每次只能看到自己那一小块，结论必须写回库里才能进入下一步。听起来慢，但它是可复核的。

## 几个刻意为之的设计

### 目标事实库是唯一真源

每个目标一个 `dbs/<target>.db`，schema 由 `migrations/` 管。资产、端点、系统类型、认证态、可疑点、确认发现、证据引用、覆盖账本都在里面，全部带 `observed_at / source / confidence`。对话里的结论一律视为派生视图，和库冲突时以库为准。

这么做还有一个附带好处：换会话、换人、换 agent 都能接手，因为交接面就是一张表，不是一段聊天记录。

### 猜测和结论严格分层

`suspicious_points` 是候选，`findings` 是已确认，两者不共用一张表，也不能靠改字段"升级"。一条候选要变成发现，必须有可复现的请求和证据引用；`report_repro_gate` 会卡住"结构齐全但复现不了"的报告。

"这个目标的这一面已经测完了"同样需要证据：`coverage_ledger` 按 `item_key × category` 记 `covered / unknown / uncovered / blocked`，说穷尽就得把 unknown 和 uncovered 解释清楚。

### 目标侧只有一个出口

所有发往目标的请求都走 `TOOLS/utils/egress.py`：串行、低频、身份固定、节奏受控、异常熔断，每次请求记 `egress_log`（只记 host 和 path，不记 query/body/cookie）。脚本里直接裸 `requests` 打目标是被明确禁止的，测试里也有守卫。

这不只是为了留痕。真实评估里，流量特征本身就是要交付的一部分——客户问"你们昨晚是不是在扫我们"时，你能拿出时间线和请求量。

### 人和 agent 的边界写在代码里

- 焦点必须由操作员显式选定，`soft_target_scorer` 只排序，不自动选；
- 高危动作（认证边界、批量操作、内网、确认漏洞的深度验证）要过操作员门控；
- 每轮最多派两个单一 work item，并发被结构性限制住，而不是靠提示词自觉。

## 一轮推进长什么样

主会话跑一次 `sprint-tick`，做的事是固定的：

1. 从库里读当前状态（资产、覆盖、候选、操作员收件箱）；
2. 回收超时的 work item，必要时重新排队；
3. 按候选门控规则决定这一轮要不要派活、派给哪个 lane；
4. 派出 1–2 个 work item；
5. lane worker 以 `claim → heartbeat → partial → complete / block` 的生命周期执行，中间结果和结论都写库；
6. 下一轮主会话只读 compact 摘要，不读原始流量。

lane 是执行通道，比如 `asset_ingest`、`quick_scout`、`js_reverse`、`logic_probe`、`vuln_review`、`evidence_pack`。每个 lane 绑一类 worker，worker 拿到的是一段明确的 objective 和数据库里的上下文，不是整个对话历史。

## 目录

```
TOOLS/
  recon/        资产与情报：FOFA/CT/CDN 识别、归属门控、认证面、指纹、入口候选
  pipeline/     编排管线：基线验活、JS 还原与依赖链、端口/竞态等探测器的统一入口
  db/           黑板与队列：schema、work_queue、dispatcher、sprint_tick、覆盖账本、报告汇总
  lib/          共享库：落库工具、证据渲染、发现定级、可复现性门
  utils/        受管出口 egress、HTTP/比较/ETL 等通用能力、JS 静态分析
  auth/         认证态采集与复用（浏览器、会话等状态维护）
  tests/        回归测试（pytest）
migrations/     目标库 schema，按编号顺序演进
warroom/        只读看板：把库里的状态渲染成给人看的视图
docs/           模块文档与术语表
config/ rules/  指纹、路径、规则等可配置数据
```

## 快速开始

需要 Python 3.11+。`uv` 不是必须的，用 venv + pip 也行。

```bash
python -m venv .venv
.venv\Scripts\activate            # Linux/macOS: source .venv/bin/activate
pip install -e .
cp .env.example .env              # 可选：情报 API、LLM 端点等；不填也能跑
```

建一个目标库，跑一遍基础验活：

```bash
python TOOLS/db/db_admin.py init --target "demo" --slug demo --domain example.com
python TOOLS/pipeline/init_scan.py --target "demo" --baseline
python TOOLS/db/v3_chain.py --target "demo"
```

`init_scan --baseline` 是无队列副作用的 L0 广度验活：只做 DNS/HTTP 基线、入口 HTML 和静态资源，不做主动探测。跑完再看候选和覆盖：

```bash
python TOOLS/src_cli.py soft-targets --target demo --top 10
python TOOLS/src_cli.py sprint-tick --target demo --json
```

看板：

```powershell
powershell -ExecutionPolicy Bypass -File warroom/start.ps1
```

会起一个本地只读服务（默认 8787），把库渲染成资产、队列、时间线、覆盖和发现视图。前端是 React + TS，源码在 `warroom/web/`。

## 测试

```bash
pip install pytest
pytest
```

测试以 `TOOLS/tests/` 为主，覆盖队列租约、派发门控、覆盖账本、证据渲染、报告可复现性门、JS 分析、认证态等。测试全部用临时 SQLite 和示例域名，不依赖外网。

## 关于这个公开版本

这个仓库是**框架本体**，不是完整的作战目录。有几块内容刻意没有放进来：

- **知识库 / playbook**：方法论文档、payload 参考库、字典和真实案例库，属于私有工作资产，单独维护；
- **客户与目标数据**：逐目标事实库、报告、抓包、日志、截图全部在 `.gitignore` 里，仓库里没有任何真实委托数据；
- **本地环境与账号配置**：`.env`、MCP 配置、AI harness 配置、个人字典。

所以直接克隆下来可以读代码、跑测试、看架构，但要完整跑一次评估，需要自己准备知识库和外部工具（Burp/Yakit/Playwright 等都可选）。这也意味着部分文档里会引用仓库中不存在的路径，属于预期内。

## 使用边界

这个项目只服务于**有书面授权的安全评估**。授权六要素（委托方、授权依据、目标清单、排除项、时间窗、强度）写在 `docs/modules/engagement-authorization.md`，代码里对应 `TOOLS/recon/ownership_gate.py` 和 `TOOLS/recon/scope.py` 的判定。

没有授权就用它测别人的系统，在大多数司法辖区是违法行为，和这个仓库无关。如果你在范围内发现了漏洞，按 `SECURITY.md` 的流程处理。

## 许可

[MIT](LICENSE)
