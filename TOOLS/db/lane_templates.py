"""Strict compact prompt contracts for existing blackboard lanes."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any

_TOOLS_DIR = Path(__file__).resolve().parent.parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

from db.db_utils import force_utf8_stdout  # noqa: E402
from db.worker_result import compact_public_text  # noqa: E402

SUPPORTED_LANES = {
    "asset_ingest",
    "quick_scout",
    "cognitive_experiment",
    "entry_explore",
    "source_intel",
    "network_profile",
    "origin_verify",
    "entry_probe",
    "preauth_probe",
    "replay",
    "evidence_pack",
    "js_reverse",
    "logic_probe",
    "vuln_review",
    "postexp",
    "report_audit",
    "hypothesis",
    "semantic_profile",
    "asset_triage",
    "operator_task",
}
VALID_RISKS = {"safe_passive", "safe_replay", "sensitive_read", "state_changing", "high_risk"}
REQUIRED = (
    "target_name",
    "work_item_id",
    "lane",
    "subject_table",
    "subject_id",
    "objective",
    "expected_output",
    "timebox_minutes",
    "heartbeat_minutes",
    "risk_class",
    "scope_boundary",
)
MAPPING_LANES = {"asset_ingest", "source_intel"}

# lane -> .agents/agents/<agent>.md 定义文件（唯一真源；三份 harness 镜像由
# scripts/sync_agents.py 生成，本模块只读真源正文，不读镜像）。
# 主 session/操作员决策类（asset_triage/operator_task）无独立 agent 定义。
LANE_TO_AGENT = {
    "asset_ingest": "asset-recon",
    "source_intel": "asset-recon",
    "quick_scout": "surface-scout",
    "entry_explore": "surface-scout",
    "replay": "surface-scout",
    # dispatcher.py 的 LANE_DISPATCH 也把 cognitive_experiment 派给 surface-scout；
    # 此前本表缺这一行，agent 定义里的 cognitive_experiment lane 无人承认。
    "cognitive_experiment": "surface-scout",
    "entry_probe": "entry-probe",
    "preauth_probe": "preauth-probe",
    "network_profile": "stealth-scanner",
    "origin_verify": "stealth-scanner",
    "evidence_pack": "src-reporter",
    "js_reverse": "js-reversing-helper",
    "logic_probe": "param-fuzzer",
    "vuln_review": "vuln-reviewer",
    "postexp": "postexp-worker",
    "report_audit": "vuln-auditor",
    "hypothesis": "hypothesis-drafter",
    "semantic_profile": "attack-surface-profiler",
}

# lane -> src-hunter 知识库 playbook（相对 .agents/skills/src-hunter/）。
# 知识库→agent 回路：lane subagent prompt 注入对应 playbook 路径，agent 必须 Read
# 该文件再动手，禁止凭记忆生成 payload（src-hunter 反幻觉硬约束）。
# 值为相对 .agents/skills/src-hunter/ 的路径列表（可多 playbook，全部注入）。
# 原则：每个 lane 只注入与其职责直接相关的 playbook（避免 prompt 爆炸），
# 覆盖"知识库有、工具不做"的高价值向量类型。
LANE_TO_PLAYBOOK = {
    "logic_probe": [
        "references/playbooks/sqli.md",
        "references/playbooks/race-conditions.md",
        "references/playbooks/graphql.md",
        "references/playbooks/api-rest/00-index.md",
        "references/playbooks/logic-flaws/00-index.md",
    ],
    "vuln_review": [
        "references/playbooks/sqli.md",
        "references/playbooks/arbitrary-x-authz.md",
        "references/playbooks/ssrf-cache-host/00-index.md",
        "references/playbooks/path-traversal/00-index.md",
        "references/playbooks/rce/00-index.md",
        "references/playbooks/xss/00-index.md",
        "references/playbooks/oauth-saml-jwt/00-index.md",
    ],
    "postexp": [
        "references/playbooks/intranet-postexp/00-index.md",
        "references/compliance.md",
    ],
    "entry_probe": [
        "references/playbooks/unauth-access.md",
        "references/playbooks/info-disclosure.md",
        "references/playbooks/oauth-saml-jwt/00-index.md",
    ],
    "preauth_probe": [
        "references/playbooks/unauth-access.md",
        "references/playbooks/info-disclosure.md",
        "references/playbooks/oauth-saml-jwt/00-index.md",
    ],
    "js_reverse": ["references/playbooks/api-rest/00-index.md"],
}
# lane -> 额外知识库（绝对路径，src-hunter 之外）。与 LANE_TO_PLAYBOOK 同样注入 prompt，
# 要求 agent 先 Read 再动手。移动端 API 面规则（一次 HCM 0day 教训）：入口探测、
# JS API 提取的 lane 必须知道 /Mobile /TableName /GetData 这条高价值链。
LANE_TO_EXTRA_KNOWLEDGE = {
    "entry_probe": ["skills/mobile-api-attack-surface/SKILL.md"],
    "preauth_probe": ["skills/mobile-api-attack-surface/SKILL.md"],
    "js_reverse": ["skills/mobile-api-attack-surface/SKILL.md"],
}

# lane -> 必须使用的离线工具（缺口 7：把 ui_context 从"人工记得调"变成"lane 契约的一部分"）。
# 这些 lane 都会拿到页面 HTML，但不会自己解析表单字段；不注入的话表单端点与参数名永远进不了
# endpoint_observations，下游 auth_logic_probe / sqli_scan 就少了参数名来源。
LANE_TO_OFFLINE_TOOL = {
    "quick_scout": ["ui_context"],
    "entry_explore": ["ui_context"],
    "entry_probe": ["ui_context"],
    "preauth_probe": ["ui_context"],
    "logic_probe": ["ui_context"],
    "semantic_profile": ["ui_context"],
}
UI_CONTEXT_CMD = (
    '.venv/Scripts/python.exe TOOLS/pipeline/ui_context.py --html <已落盘的页面 HTML> --page-url <该页 URL> --target "<目标名>" --store'
)
SRC_HUNTER_DIR = Path(__file__).resolve().parent.parent.parent / ".agents" / "skills" / "src-hunter"
AGENTS_SKILLS_DIR = Path(__file__).resolve().parent.parent.parent / ".agents"
_FRONTMATTER_RE = re.compile(r"(?s)^---\r?\n.*?\r?\n---\r?\n")


def validate_template_input(contract: dict[str, Any]) -> list[str]:
    errors = [key for key in REQUIRED if contract.get(key) in (None, "", [])]
    if contract.get("lane") not in SUPPORTED_LANES:
        errors.append("lane")
    timebox = contract.get("timebox_minutes")
    heartbeat = contract.get("heartbeat_minutes")
    if not isinstance(timebox, int) or not 1 <= timebox <= 120:
        errors.append("timebox_minutes")
    if not isinstance(heartbeat, int) or not isinstance(timebox, int) or not 1 <= heartbeat <= timebox:
        errors.append("heartbeat_minutes")
    if contract.get("risk_class") not in VALID_RISKS:
        errors.append("risk_class")
    if not isinstance(contract.get("expected_output"), list):
        errors.append("expected_output")
    if not isinstance(contract.get("evidence_refs"), list):
        errors.append("evidence_refs")
    if contract.get("lane") not in MAPPING_LANES:
        if not contract.get("url"):
            errors.append("url")
        if not contract.get("evidence_refs"):
            errors.append("evidence_refs")
    return sorted(set(errors))


def render_lane_prompt(contract: dict[str, Any]) -> str:
    lane = contract.get("lane")
    if lane not in SUPPORTED_LANES:
        raise ValueError(f"unsupported lane: {lane}")
    errors = validate_template_input(contract)
    if errors:
        raise ValueError(f"missing or invalid template fields: {', '.join(errors)}")
    clean = lambda value, limit=500: compact_public_text(value, max_chars=limit)  # noqa: E731
    return (
        f"目标: {clean(contract['target_name'], 120)}\n"
        f"work_item: {contract['work_item_id']} | lane: {lane} | "
        f"subtype: {clean(contract.get('subtype') or 'none', 120)}\n"
        f"对象: {clean(contract['subject_table'], 80)}:{clean(contract['subject_id'], 120)} | "
        f"URL: {clean(contract.get('url') or 'none')}\n"
        f"任务: {clean(contract['objective'])}（单点信号，禁止扩展 scope）\n"
        f"产出: {','.join(clean(x, 80) for x in contract['expected_output'][:20])}\n"
        f"时间盒: {contract['timebox_minutes']}min | 心跳: {contract['heartbeat_minutes']}min\n"
        f"门控: {contract['risk_class']} | 授权边界: {clean(contract['scope_boundary'])}\n"
        f"证据引用: {','.join(clean(x, 120) for x in contract['evidence_refs'][:20]) or 'none'}\n"
        "原始 HTTP/HTML/JS、Cookie、Authorization 只留证据层，不得写入 prompt 或 worker_result。"
    )


def build_dsh_subagent_prompt(lane: str, contract: dict[str, Any], agents_dir: str | Path = ".agents/agents") -> str:
    """DSH subagent 完整 prompt = lane 定义（.agents/agents/<agent>.md 正文）+ 本次任务上下文。

    DSH 没有 Claude Code 的 ``Agent(subagent_type=...)`` 自动注入，主模型派发时把
    本函数输出直接传给 ``subagent(prompt=...)``，体验等价于 Claude Code 的 lane
    subagent：agent 定义（职责、work_queue 生命周期、worker_result 契约、blocker
    升级）随 prompt 一起进入子代理。
    """
    agent_name = LANE_TO_AGENT.get(lane)
    if not agent_name:
        raise ValueError(f"lane {lane} has no lane-agent definition (main/operator decision lane)")
    md_path = Path(agents_dir) / f"{agent_name}.md"
    if not md_path.exists():
        raise FileNotFoundError(f"lane agent definition not found: {md_path}")
    body = _FRONTMATTER_RE.sub("", md_path.read_text(encoding="utf-8")).strip()
    context = render_lane_prompt(contract)

    # 知识库注入：本 lane 对应的 src-hunter playbook + 额外知识库（如 mobile-api-attack-surface）
    # 存在时，把绝对路径塞进 prompt，要求 agent 先 Read 再执行（payload 不凭记忆）。不存在则静默跳过。
    knowledge_hint = ""
    playbook_rels = LANE_TO_PLAYBOOK.get(lane) or []
    extra_rels = LANE_TO_EXTRA_KNOWLEDGE.get(lane) or []
    existing_paths = [SRC_HUNTER_DIR / rel for rel in playbook_rels if (SRC_HUNTER_DIR / rel).exists()]
    existing_paths += [AGENTS_SKILLS_DIR / rel for rel in extra_rels if (AGENTS_SKILLS_DIR / rel).exists()]
    if existing_paths:
        waf_bypass = SRC_HUNTER_DIR / "references" / "payloader" / "waf-bypass.md"
        waf_hint = f"\nWAF 被拦时另读：`{waf_bypass.resolve()}`（263 绕过变体）" if waf_bypass.exists() else ""
        path_lines = "\n".join(f"- `{p.resolve()}`" for p in existing_paths)
        knowledge_hint = (
            "\n\n# 知识库（必读，payload 不凭记忆）\n\n"
            f"动手前先 Read 本 lane 对应的攻击知识库：\n{path_lines}{waf_hint}\n"
            "按其中向量分布/探测手法/WAF 绕过矩阵执行；header/cookie/query 等注入向量"
            "都要覆盖（如 SQLi 知识库 §2.2：HTTP Header 26%、Cookie 12%，勿只测 GET 参数）；"
            "被 WAF 拦截先按 bypass 矩阵换 payload/编码，再考虑换源 IP，不直接放弃。"
        )

    tool_hint = ""
    if "ui_context" in (LANE_TO_OFFLINE_TOOL.get(lane) or []):
        tool_hint = (
            "\n\n# 离线表单上下文（必做一步，不发包）\n\n"
            "本 lane 会拿到页面 HTML 时，**先**把已落盘的 HTML 过一遍 `ui_context.py`，"
            "再把表单端点和参数名当作攻击面输入（它只做静态解析，绝不记录字段值、不发任何请求）：\n"
            f"```\n{UI_CONTEXT_CMD}\n```\n"
            "产出落在 `endpoint_observations.parameter_names_json`，下游 `auth_logic_probe` / `sqli_scan` "
            "直接吃这份参数名。**不要**手工猜参数名，也不要跳过这一步——跳过等于丢掉整页表单面。"
        )

    return (
        f"# Lane 定义（{agent_name}，DSH subagent 职责契约）\n\n{body}"
        f"{knowledge_hint}{tool_hint}\n\n"
        "# 本次任务（单 work_item，禁止扩展 scope）\n\n" + context
    )


def main(argv: list[str] | None = None) -> int:
    force_utf8_stdout()
    parser = argparse.ArgumentParser(prog="lane_templates.py", description="Lane prompt 契约：dsh-prompt 生成 DSH subagent 完整 prompt")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("dsh-prompt", help="生成 DSH subagent prompt（lane 定义 + 任务上下文）")
    p.add_argument("--lane", required=True)
    p.add_argument("--target", required=True)
    p.add_argument("--work-item-id", required=True)
    p.add_argument("--subtype", default="")
    p.add_argument("--subject-table", default="")
    p.add_argument("--subject-id", default="")
    p.add_argument("--url", default="")
    p.add_argument("--objective", required=True)
    p.add_argument(
        "--expected-output",
        nargs="*",
        default=["status", "summary", "evidence_refs", "confidence", "next_action"],
    )
    p.add_argument("--timebox-minutes", type=int, default=30)
    p.add_argument("--heartbeat-minutes", type=int, default=10)
    p.add_argument("--risk-class", default="safe_passive", choices=sorted(VALID_RISKS))
    p.add_argument("--scope-boundary", default="single authorized subject; do not expand scope")
    p.add_argument("--evidence-refs", nargs="*", default=[])
    p.add_argument("--agents-dir", default=".agents/agents")
    args = parser.parse_args(argv)

    if args.cmd == "dsh-prompt":
        contract = {
            "target_name": args.target,
            "work_item_id": args.work_item_id,
            "lane": args.lane,
            "subtype": args.subtype,
            "subject_table": args.subject_table,
            "subject_id": args.subject_id,
            "url": args.url,
            "objective": args.objective,
            "expected_output": args.expected_output,
            "timebox_minutes": args.timebox_minutes,
            "heartbeat_minutes": args.heartbeat_minutes,
            "risk_class": args.risk_class,
            "scope_boundary": args.scope_boundary,
            "evidence_refs": args.evidence_refs,
        }
        try:
            print(build_dsh_subagent_prompt(args.lane, contract, agents_dir=args.agents_dir))
        except (ValueError, FileNotFoundError) as exc:
            print(f"[lane_templates] error: {exc}", file=sys.stderr)
            return 1
        return 0
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
