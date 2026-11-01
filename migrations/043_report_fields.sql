-- 043: 报告编写所需的字段（吸收自 CyberStrike triage 规则 + Strix 反脆弱字段）。
--
-- 背景：此前 findings 只有 type/url/param/payload/evidence/risk/cvss/remediation，
-- 报告生成只能填模板占位符。要写出"可复核"的报告，至少还缺：
--   1. 标题（必须具体到端点/参数，而不是 [高危] XSS - F-001）
--   2. 前置条件 / 反证 / 置信度理由 / 什么情况下该改等级  <- Strix 抗过度评级的核心
--   3. 定级依据（声明等级 vs 该类别上限）              <- CyberStrike triage 规则
-- 全部可空：旧数据不迁移也能继续出报告，只是这些小节显示占位符。

ALTER TABLE findings ADD COLUMN title TEXT;
ALTER TABLE findings ADD COLUMN preconditions TEXT;
ALTER TABLE findings ADD COLUMN counterevidence TEXT;
ALTER TABLE findings ADD COLUMN confidence_rationale TEXT;
ALTER TABLE findings ADD COLUMN severity_change_conditions TEXT;
ALTER TABLE findings ADD COLUMN impact TEXT;
ALTER TABLE findings ADD COLUMN poc_description TEXT;
ALTER TABLE findings ADD COLUMN fix_verification TEXT;

CREATE INDEX IF NOT EXISTS idx_findings_risk ON findings(risk);
