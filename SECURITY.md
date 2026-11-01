# 安全策略

## 这个项目是什么，不是什么

本项目是**授权渗透测试的执行框架**：操作员下达授权委托（engagement），框架负责资产梳理、漏洞验证、证据留存与报告。

**它不是**一个可以直接对着任意目标运行的扫描器。它内置的每一条主动测试路径都要求显式传入目标并绑定委托声明；仓库里**不包含**任何真实委托数据、目标清单、凭据或漏洞成果。

## 授权使用（硬性要求）

使用本框架前，你必须对目标拥有**书面授权**：

- 目标必须由操作员显式提供（`--target` / 委托声明），本框架不会自行发现或猜目标；
- 授权范围、排除项、时间窗、强度等级必须写明；强度为 `passive` / `safe_active` 时不得执行 `active` 及以上动作；
- 破坏性/不可逆操作、批量爆破、真实数据批量外带、生产钓鱼/社工**不在**本框架的默认能力范围内，也不应通过改配置绕过。

完整授权模型见 [`docs/modules/engagement-authorization.md`](docs/modules/engagement-authorization.md)。未经授权的测试在多数司法辖区属于违法行为，责任由使用者自负。

## 报告漏洞（指本框架自身的漏洞）

如果你在本框架**代码或默认配置**中发现安全问题，请通过私下渠道报告，不要开公开 issue：

1. 优先使用 GitHub 的 [Private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)（仓库 Security 选项卡 → Report a vulnerability）；
2. 若无该入口，发邮件给仓库维护者（见 `git log` 中的提交邮箱）。

请包含：影响范围、复现步骤、最小 PoC、你判断的严重性。**不要**在报告里附带任何真实目标的数据。

我们会在 7 天内确认收到，并在修复后与你协商致谢方式。

## 明确不在范围内

- 需要先拿到他人系统权限才能触发的「漏洞」；
- 框架**按设计**执行的行为：向授权目标发包、执行本地 PoC 脚本、读写本地目标数据库；
- 使用者自行修改配置造成的后果（例如把 `EGRESS_MODE` 改成绕过出口治理、关闭操作员门控）。

## 数据卫生

本仓库的 `.gitignore` 已把委托数据、交付物、凭据、运行痕迹全部排除在版本控制之外。**提交前请确认 `git status` 中不存在真实目标数据**——`.gitignore` 顶部的分类注释就是边界清单。
