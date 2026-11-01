"""可复现性门：拦住"结构齐全但读者照着做不出来"的报告。

为什么需要这个模块
------------------
`finding_grader.validate_finding_quality()` 检查的是字段**存在性**（有没有 url /
evidence / 前置条件 / 证伪记录），它回答的是"该说的说了吗"。

但真实交付暴露了另一类缺陷：**该有的都有，却复现不了**。实测一份报告同时具备
前置条件、复现步骤、证据、证伪说明、置信度理由、改级条件、修复建议——却没有
一个 `curl`、没有一条原始 HTTP、没有一个代码块；内网 IP 被统一脱敏成
`10.x.x.41`，而复现步骤又让人「全文检索 10.x.x.41」——**脱敏把复现指令变成了假指令**。

这类问题靠"字段存在性"永远查不出来，所以单独建一层：**对成品 Markdown 做静态检查**，
不依赖数据来源（DB 行也好、人工写的也好，都适用）。

设计原则
--------
- **只读文本，不读库**：成品报告的质量就该按"读者能否照做"来判，与数据怎么生成无关。
- **可定位**：每条问题给出章节/条目位置，不只给一句话结论。
- **分 block / warn**：block 级不许称为"可交付报告"；warn 级允许人工豁免但要说明理由。
- **不猜意图**：不做"看起来像"的语义判断，只查可机械判定的结构。

用法
----
    from lib.report_repro_gate import check_report_text, format_findings

    issues = check_report_text(markdown_text)
    print(format_findings(issues))
    blocked = [i for i in issues if i.severity == "block"]
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ReproIssue:
    """一条可复现性问题。"""

    code: str  # 稳定标识，便于测试与豁免
    severity: str  # "block" | "warn"
    where: str  # 章节 / 条目定位
    detail: str  # 出了什么问题
    fix: str  # 怎么改


# ---------------------------------------------------------------- 正则与常量

# 一节标题：`## 一、...` / `### YJ-01｜...`
_SECTION_RE = re.compile(r"^(#{2,3})\s+(.+)$", re.MULTILINE)

# 代码块
_FENCE_RE = re.compile(r"```([^\n]*)\n(.*?)```", re.DOTALL)

# 可执行的请求痕迹
_CURL_RE = re.compile(r"\bcurl\b", re.IGNORECASE)
_RAW_HTTP_RE = re.compile(r"^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+\S+\s+HTTP/\d\.\d", re.MULTILINE)
_HTTP_VER_RE = re.compile(r"HTTP/\d\.\d")

# 响应样例痕迹
_JSON_BODY_RE = re.compile(r'\{[\s\S]{10,400}?"[\w-]+"\s*:')

# 脱敏形态：10.x.x.41 / 10.*.*.41 / *** / <masked> / <工号>
_MASKED_IP_RE = re.compile(r"\b\d{1,3}\.(?:x{1,3}|\*)\.[\dx*]{1,3}\.\d{1,3}\b", re.IGNORECASE)
_PLACEHOLDER_RE = re.compile(r"<[^>\n]{1,24}>|\*{3,}|x{2,}")

# 「让人去检索某个值」这类指令
_SEARCH_VERB_RE = re.compile(r"检索|搜索|grep|查找|全文搜索|搜一下", re.IGNORECASE)

# 掩码映射说明
_MAPPING_RE = re.compile(r"真实值|原值|映射表|未脱敏|内部版|internal|随包交付|见附件")

# 只指向临时目录的证据路径
_TMP_PATH_RE = re.compile(r"(?<![\w/])tmp/[\w./\-*|]*", re.IGNORECASE)

# 高风险等级词（这些条目一律要求可执行请求）
_HIGH_RISK_RE = re.compile(r"\b(critical|high|严重|高危)\b", re.IGNORECASE)


# ---------------------------------------------------------------- 主入口


def check_report_text(markdown: str) -> list[ReproIssue]:
    """对成品 Markdown 做可复现性检查。返回问题列表（空 = 通过）。"""
    issues: list[ReproIssue] = []
    if not markdown.strip():
        return [
            ReproIssue(
                code="empty_report",
                severity="block",
                where="(全文)",
                detail="报告为空",
                fix="先有内容再谈可复现性",
            )
        ]

    sections = _split_sections(markdown)

    issues.extend(_check_global_request(markdown, sections))
    issues.extend(_check_prose_steps(sections))
    issues.extend(_check_masked_self_reference(markdown))
    issues.extend(_check_mask_mapping(markdown))
    issues.extend(_check_evidence_paths(markdown))
    issues.extend(_check_response_sample(markdown, sections))
    return issues


def check_report_file(path: Path | str) -> list[ReproIssue]:
    return check_report_text(Path(path).read_text(encoding="utf-8"))


def format_findings(issues: list[ReproIssue]) -> str:
    """人读输出。"""
    if not issues:
        return "[OK] 可复现性检查通过"
    blocks = [i for i in issues if i.severity == "block"]
    warns = [i for i in issues if i.severity == "warn"]
    lines = [f"[FAIL] 可复现性：{len(blocks)} 个阻断项、{len(warns)} 个提醒项", ""]
    for group, label in ((blocks, "阻断"), (warns, "提醒")):
        if not group:
            continue
        lines.append(f"—— {label} ——")
        for issue in group:
            lines.append(f"  [{issue.code}] {issue.where}")
            lines.append(f"      问题: {issue.detail}")
            lines.append(f"      修法: {issue.fix}")
        lines.append("")
    return "\n".join(lines).rstrip()


# ---------------------------------------------------------------- 分节


def _split_sections(markdown: str) -> list[tuple[str, str]]:
    """按 `##`/`###` 切分，返回 [(标题, 正文)]；首段标题记为 "(开头)"。"""
    matches = list(_SECTION_RE.finditer(markdown))
    if not matches:
        return [("(开头)", markdown)]

    out: list[tuple[str, str]] = []
    head = markdown[: matches[0].start()]
    if head.strip():
        out.append(("(开头)", head))
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(markdown)
        out.append((match.group(2).strip(), markdown[match.end() : end]))
    return out


# ---------------------------------------------------------------- 各项检查


def _check_global_request(markdown: str, sections: list[tuple[str, str]]) -> list[ReproIssue]:
    """C1：全文必须至少有一处可直接执行的请求。"""
    fences = _FENCE_RE.findall(markdown)
    has_curl = any(_CURL_RE.search(body) for _, body in fences)
    has_raw = any(_RAW_HTTP_RE.search(body) for _, body in fences)
    if has_curl or has_raw:
        return []
    return [
        ReproIssue(
            code="no_executable_request",
            severity="block",
            where="(全文)",
            detail="报告里没有任何可直接复制执行的请求：无 curl、无原始 HTTP 请求行、无请求代码块。"
            "读者只能读到「请求某接口」这类散文，无法照做。",
            fix="每个 finding 至少给一个代码块，内含 `curl '<完整URL>' -H '...'` 或原始 HTTP 报文。",
        )
    ]


def _check_prose_steps(sections: list[tuple[str, str]]) -> list[ReproIssue]:
    """C2：带「复现步骤」的条目里必须有代码块，不能全是散文。

    判据必须是**「复现步骤」这个具体标签**，不能是「复现」二字——否则
    「附录 A：证据与可复现性」这类标题会被误判成复现章节（实测误报）。
    """
    issues: list[ReproIssue] = []
    for title, body in sections:
        if "复现步骤" not in title and "复现步骤" not in body:
            continue
        # 该节内的代码块
        has_block = any(_CURL_RE.search(text) or _RAW_HTTP_RE.search(text) or "HTTP/" in text for _, text in _FENCE_RE.findall(body))
        if has_block:
            continue
        issues.append(
            ReproIssue(
                code="prose_only_repro",
                severity="block",
                where=title,
                detail="有「复现步骤」但整节没有可执行代码块，步骤是叙述性文字（如「取得会话令牌」「请求 xxx」），读者无法逐步照做。",
                fix="把步骤换成编号 + 每步一个代码块；至少第一步给出获取凭据的具体命令/请求。",
            )
        )
    return issues


def _check_masked_self_reference(markdown: str) -> list[ReproIssue]:
    """C3：脱敏自指矛盾 —— 让人去「检索」一个已被掩码的值。

    实测形态：IP 被写成 `10.x.x.41`，而复现步骤要求「全文检索 10.x.x.41」。
    在真实 bundle 里搜这个字符串什么也搜不到，复现指令本身是假的。
    """
    issues: list[ReproIssue] = []
    for lineno, line in enumerate(markdown.splitlines(), 1):
        if not _SEARCH_VERB_RE.search(line):
            continue
        masked = _MASKED_IP_RE.findall(line) or [m for m in _PLACEHOLDER_RE.findall(line) if len(m) > 3]
        if not masked:
            continue
        issues.append(
            ReproIssue(
                code="masked_self_reference",
                severity="block",
                where=f"第 {lineno} 行",
                detail=f"要求去检索 `{masked[0]}`，但该值是**脱敏后的掩码**，在真实产物里搜不到。这条指令无法执行，属于脱敏与可复现冲突。",
                fix="复现指令必须用真实值；对外交付时改为「检索内部版给出的原值」并保留映射。",
            )
        )
    return issues


def _check_mask_mapping(markdown: str) -> list[ReproIssue]:
    """C4：出现掩码但全文没有映射/说明。"""
    masked = _MASKED_IP_RE.findall(markdown)
    if not masked:
        return []
    if _MAPPING_RE.search(markdown):
        return []
    uniq = sorted(set(masked))
    return [
        ReproIssue(
            code="mask_without_mapping",
            severity="block",
            where="(全文)",
            detail=f"出现 {len(uniq)} 个脱敏掩码（如 `{uniq[0]}`）但全文没有任何映射或说明，读者既拿不到真值也定位不到资产。",
            fix="给出掩码↔真值映射（或指向内部未脱敏版的锚点），或只掩掉不影响定位的部分。",
        )
    ]


def _check_evidence_paths(markdown: str) -> list[ReproIssue]:
    """C5：证据只指向 tmp/ 这类不可交付目录。"""
    tmp_paths = _TMP_PATH_RE.findall(markdown)
    if not tmp_paths:
        return []
    if _MAPPING_RE.search(markdown):
        return []
    return [
        ReproIssue(
            code="evidence_tmp_only",
            severity="warn",
            where="(证据/附录)",
            detail=f"证据路径只指向临时目录（如 `{tmp_paths[0]}`），交付后该目录不存在，第三方无法据此复核。",
            fix="把关键报文复制进 `reports/<target>/evidence/` 随包交付，或明确写「证据随包另附」。",
        )
    ]


def _check_response_sample(markdown: str, sections: list[tuple[str, str]]) -> list[ReproIssue]:
    """C6：无任何响应样例（状态行或响应体片段）。"""
    fences = _FENCE_RE.findall(markdown)
    has_response = any(_HTTP_VER_RE.search(body) or _JSON_BODY_RE.search(body) for _, body in fences)
    if has_response:
        return []
    return [
        ReproIssue(
            code="no_response_sample",
            severity="block",
            where="(全文)",
            detail="没有任何响应样例：既无 HTTP 状态行，也无可辨的响应体片段。读者无法判断「怎样才算复现成功」。",
            fix="每个 finding 的代码块里附响应关键片段（状态行 + 必要字段），并标注脱敏处。",
        )
    ]


# ---------------------------------------------------------------- 汇总


def summarize(issues: list[ReproIssue]) -> dict[str, int]:
    """给 CLI / 报告用：按级别计数。"""
    blocks = sum(1 for i in issues if i.severity == "block")
    warns = sum(1 for i in issues if i.severity == "warn")
    return {"block": blocks, "warn": warns, "total": len(issues)}


def is_deliverable(issues: list[ReproIssue]) -> bool:
    """有任一 block 项即不可交付。"""
    return not any(i.severity == "block" for i in issues)
