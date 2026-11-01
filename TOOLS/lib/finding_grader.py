"""漏洞定级规则与证据质量门（triage 视角）。

为什么要有这个文件
------------------
本项目此前的等级来自人工填 `findings.risk`，没有口径、没有反例，结果就是
"扫描器式高估"：CORS 报高危、缺安全头报中危、自 XSS 报高危。两份开源评估里
CyberStrike 的 `tool/report_vulnerability.txt` 是全套规则里质量最高的部分——
它的核心不是"漏洞类型 → 等级"的查表，而是**四个追问 + 常见高估反例 + 降级矩阵**。

本模块把那套规则落成可执行的两件事：

1. `grade_finding()`：按漏洞类别给出**建议区间**，并检出"典型高估"情形；
2. `validate_finding_quality()`：落库/交付前的证据质量门（缺证据、缺前置条件、
   标题不具体、把否定结论当发现等）。

设计边界
--------
- **只给建议，不自动改库**。定级是有争议的判断，工具负责把"该说明什么"摆出来，
  由人/主 session 决定；`risk` 仍由调用方写。
- 规则是**可反驳的检查清单**，不是评分模型：每条命中都要能指向具体证据。
- 不引入 CVSS 计算（那是另一件事）。这里回答的是"这个类别在哪一档、什么情况下该降"。

用法
----
    from lib.finding_grader import grade_finding, validate_finding_quality

    grade = grade_finding({"type": "cors", "evidence": "", "param": ""})
    grade["suggested_ceiling"]   # "low"
    grade["overclaims"]          # ["CORS 没有跨域读到会话数据，按规则不高于 low"]
    problems = validate_finding_quality(finding_dict)
"""

from __future__ import annotations

import re
from typing import Any

# 等级顺序（用于比较与降级；unknown 不参与降级链）
LEVELS = ("info", "low", "medium", "high", "critical")

# 每个类别的"默认上限"：不给额外证据时，这一档就是天花板。
# 依据 CyberStrike 的四个追问（无交互可得 / 是否触达他人数据 / 能否到 RCE/接管 /
# 是否是实际配置可利用）+ 其"常见高估"反例。
CLASS_CEILING: dict[str, str] = {
    # 缺安全头/配置类：几乎永远不该超过 low
    "missing_header": "low",
    "x-frame-options": "low",
    "csp": "info",
    "hsts": "low",
    "security_header": "low",
    "server_version_disclosure": "info",
    "banner": "info",
    # CORS 是全网最常被高估的类别
    "cors": "low",
    # 自 XSS / 只影响本人
    "self_xss": "low",
    "self_csrf": "low",
    # 信息泄露：不触达凭据/个人数据时上限中等
    "info_disclosure": "medium",
    "directory_listing": "low",
    "debug_page": "medium",
    "stacktrace": "low",
    # 开放重定向单独无链时 low
    "open_redirect": "low",
    # 上传：存下来但不执行 → 至多 medium
    "file_upload": "medium",
    # CSRF 视动作敏感度，默认 medium（敏感动作可到 high，由人工上调）
    "csrf": "medium",
    # 限流缺失：可爆破认证才算 medium
    "rate_limit": "medium",
    "no_rate_limit": "medium",
    # 目录穿越读非敏感文件
    "path_traversal": "medium",
    "lfi": "high",
    # SSRF：盲打不能取数 → medium；能读云元数据 → critical（由证据上调）
    "ssrf": "medium",
    # SQLi / XSS / IDOR / 认证类：默认 high，是否 critical 由证据与前提决定
    "sqli": "critical",
    "sql_injection": "critical",
    "xss": "high",
    "stored_xss": "high",
    "idor": "high",
    "auth_bypass": "critical",
    "broken_auth": "critical",
    "rce": "critical",
    "deserialization": "critical",
    "ssti": "high",
    "xxe": "high",
    "jwt": "high",
    "privilege_escalation": "high",
    "account_takeover": "critical",
}

# 典型高估：命中就要求作者补充证据或下调。
OVERCLAIM_RULES: list[dict[str, Any]] = [
    {
        "id": "cors_without_sensitive_data",
        "applies": ("cors",),
        "max": "low",
        "reason": "CORS 没有证明能跨域读到「会话绑定的敏感数据」，按规则不高于 low；"
        "要上 medium 必须同时满足：回显 Origin + Allow-Credentials:true + 实际读到他人数据。",
    },
    {
        "id": "header_as_vulnerability",
        "applies": ("missing_header", "csp", "hsts", "x-frame-options", "security_header"),
        "max": "low",
        "reason": "缺失安全头是「缺少纵深防御」，不是可利用漏洞；只有能证明具体利用（如点击劫持点了敏感动作）才高于 low。",
    },
    {
        "id": "self_only_impact",
        "applies": ("self_xss", "self_csrf"),
        "max": "low",
        "reason": "只影响攻击者本人的会话，不构成对他人/系统的危害。",
    },
    {
        "id": "blind_ssrf_no_extraction",
        "applies": ("ssrf",),
        "max": "medium",
        "reason": "盲 SSRF 只能探内网、不能取回数据时按 medium 处理；触达云元数据凭据另算。",
    },
    {
        "id": "upload_not_executed",
        "applies": ("file_upload",),
        "max": "medium",
        "reason": "文件上传但无法证明被执行/可被解析为脚本时，至多 medium。",
    },
    {
        "id": "admin_required",
        "applies": None,  # 全类别
        "max": None,  # 不设上限，只要求说明
        "requires_note": "需要管理员权限才能利用的漏洞，其危害等级应低于「未授权即可利用」的同类问题；"
        "如果攻击者已经是管理员，危害面主要是「可持久化/可越权到更高层」，请在证据里说明。",
    },
    {
        "id": "theoretical_no_poc",
        "applies": None,
        "max": None,
        "requires_note": "没有可执行 PoC / 没有实测差异的，只能是「待验证」而非「已确认」。",
    },
]

# 证据质量门：落库或交付前必须能回答。
QUALITY_FIELDS = {
    "title": "标题必须具体到端点/参数（写「XSS」不算，「userName 参数存储型 XSS 在后台审核页执行」才算）",
    "url": "缺少受影响 URL，无法复核",
    "evidence": "缺少证据（响应差异 / 关键字段 / 截图引用），无法复核",
}

# 否定结论不是发现：这些措辞出现在标题/结论里说明测完没找到东西。
NEGATIVE_PATTERNS = [
    re.compile(r"未发现|没有发现|不存在(该)?漏洞|无漏洞|测试通过|未测出|no\s+vulnerab", re.IGNORECASE),
    re.compile(r"未授权验证|待验证|疑似|可能(存在)?|理论上", re.IGNORECASE),
]

# 前置条件关键词：报告里必须显式写清楚，否则客户侧无法复现。
PRECONDITION_HINTS = ("登录", "认证", "admin", "管理员", "角色", "内网", "前置", "需要", "依赖", "已登录", "会话")


def _norm_type(vuln_type: str) -> str:
    text = (vuln_type or "").strip().lower()
    text = text.replace(" ", "_").replace("-", "_")
    return text


# 中文类型名 → 规范类别。本项目 findings.type 大量是中文（历史数据 + 人工录入），
# 只登记英文键会让中文记录完全漏判（实测「缺失安全头」曾直接返回 None）。
CN_ALIASES: dict[str, str] = {
    "缺失安全头": "security_header",
    "缺安全头": "security_header",
    "安全响应头缺失": "security_header",
    "安全头缺失": "security_header",
    "点击劫持": "x-frame-options",
    "跨域配置错误": "cors",
    "跨域资源共享配置错误": "cors",
    "跨域": "cors",
    "信息泄露": "info_disclosure",
    "敏感信息泄露": "info_disclosure",
    "信息泄漏": "info_disclosure",
    "目录遍历": "path_traversal",
    "路径穿越": "path_traversal",
    "任意文件读取": "path_traversal",
    "文件读取": "lfi",
    "任意文件包含": "lfi",
    "文件包含": "lfi",
    "文件上传": "file_upload",
    "上传漏洞": "file_upload",
    "sql注入": "sqli",
    "sql 注入": "sqli",
    "注入": "sqli",
    "跨站脚本": "xss",
    "存储型跨站脚本": "stored_xss",
    "反射型跨站脚本": "xss",
    "越权": "idor",
    "越权访问": "idor",
    "水平越权": "idor",
    "垂直越权": "privilege_escalation",
    "逻辑缺陷": "logic_flaw",
    "业务逻辑": "logic_flaw",
    "登陆绕过": "broken_auth",
    "登录绕过": "auth_bypass",
    "未授权访问": "auth_bypass",
    "认证绕过": "auth_bypass",
    "开放重定向": "open_redirect",
    "命令执行": "rce",
    "远程命令执行": "rce",
    "代码执行": "rce",
    "反序列化": "deserialization",
    "模板注入": "ssti",
    "服务端请求伪造": "ssrf",
    "请求伪造": "ssrf",
    "xxe": "xxe",
    "xml外部实体": "xxe",
    "csrf": "csrf",
    "跨站请求伪造": "csrf",
    "限流缺失": "rate_limit",
    "无限流": "rate_limit",
    "弱口令": "weak_password",
    "版本泄露": "server_version_disclosure",
    "服务器版本泄露": "server_version_disclosure",
    "调试信息": "debug_page",
    "堆栈信息": "stacktrace",
}


def ceiling_for(vuln_type: str) -> str | None:
    """返回该类别在「无额外证据」时的建议上限。"""
    text = _norm_type(vuln_type)
    if not text:
        return None
    if text in CLASS_CEILING:
        return CLASS_CEILING[text]
    # 中文别名优先（先精确，再包含）
    for alias, target in CN_ALIASES.items():
        if text == alias:
            return CLASS_CEILING.get(target)
    for alias, target in CN_ALIASES.items():
        if alias in text:
            return CLASS_CEILING.get(target)
    # 英文模糊匹配：类型字段常写成 "存储型 XSS" 或 "CORS 配置错误"
    for key, ceiling in CLASS_CEILING.items():
        if key in text:
            return ceiling
    return None


def grade_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """给出定级建议与高估风险。

    返回：
      ceiling          该类别默认上限（None 表示未知类别，需要人工定级）
      overclaims       命中的高估规则说明（空 = 没有明显高估）
      required_notes   必须补充的说明（做不到就只能降级/降为待验证）
    """
    vuln_type = str(finding.get("type") or "")
    declared = str(finding.get("risk") or "").strip().lower()
    evidence = str(finding.get("evidence") or "")
    param = str(finding.get("param") or "")

    ceiling = ceiling_for(vuln_type)
    overclaims: list[str] = []
    required_notes: list[str] = []

    text = _norm_type(vuln_type)
    for rule in OVERCLAIM_RULES:
        applies = rule["applies"]
        if applies is not None and not any(key in text for key in applies):
            continue
        max_level = rule["max"]
        if max_level and ceiling:
            # 该类别的上限不高于规则上限时，规则本身不额外收紧
            ceiling = min(ceiling, max_level, key=LEVELS.index)
        if rule.get("requires_note"):
            required_notes.append(str(rule["requires_note"]))
        # 只有当类别上限 ≤ 规则上限时才判定"高估"：天花板本身更高的类别
        # （例如 IDOR 默认 high）不能因为某条通用规则而被判成高估。
        if (
            max_level
            and ceiling
            and LEVELS.index(ceiling) <= LEVELS.index(max_level)
            and declared
            and declared in LEVELS
            and LEVELS.index(declared) > LEVELS.index(max_level)
        ):
            overclaims.append(f"[{rule['id']}] 声明等级 {declared} 高于该类别的合理上限 {max_level}：{rule['reason']}")

    # 通用高估检查：没有证据却给了 high/critical
    if declared in ("high", "critical") and not evidence.strip():
        overclaims.append("没有证据却声明 high/critical：先补响应差异或关键字段，否则只能算待验证。")
    # 没有参数却声称参数级漏洞
    param_level_types = ("sqli", "xss", "idor", "sql_injection")
    if any(key in text for key in param_level_types) and not param.strip():
        required_notes.append("参数级漏洞请在 param 写明具体参数名；只写端点无法定位修复点。")

    return {
        "declared": declared or None,
        "ceiling": ceiling,
        "overclaims": overclaims,
        "required_notes": required_notes,
    }


def _looks_negative(text: str) -> bool:
    return any(pattern.search(text or "") for pattern in NEGATIVE_PATTERNS)


def has_precondition(finding: dict[str, Any]) -> bool:
    """证据/说明里是否交代了前置条件。"""
    haystack = " ".join(str(finding.get(key) or "") for key in ("evidence", "review_notes", "notes", "payload"))
    lowered = haystack.lower()
    return any(hint in lowered for hint in PRECONDITION_HINTS)


def validate_finding_quality(finding: dict[str, Any]) -> list[str]:
    """交付前的证据质量门。返回问题列表（空 = 可以交付）。

    与 `store_kit` 的字段校验互补：那边管"列名/枚举"，这边管"能不能拿去交付"。
    """
    problems: list[str] = []

    for field, message in QUALITY_FIELDS.items():
        if not str(finding.get(field) or "").strip():
            problems.append(message)

    title = str(finding.get("title") or "")
    # 标题过于笼统：只有漏洞类别名，没有端点/参数
    if title and len(title.strip()) <= 12 and not any(ch in title for ch in ("/", "?", "参数")):
        problems.append("标题过于笼统：必须包含受影响端点或参数，否则客户无法定位。")

    # 否定结论不是发现
    combined = f"{title} {finding.get('conclusion') or ''} {finding.get('review_notes') or ''}"
    if _looks_negative(combined):
        problems.append(
            "标题/结论是「未发现/疑似/待验证」这类否定或不确定表述：这类结果不应作为已确认漏洞交付，应放进「无法确认」或「已证伪」附录。"
        )

    # 反证：没有排除误报就交付等于不可复核
    counter = str(finding.get("counterevidence") or finding.get("review_notes") or "").strip()
    if not counter:
        problems.append("缺少证伪记录：写清「试过什么、为什么不是误报/不是正常业务」，否则无法复核。")

    grade = grade_finding(finding)
    problems.extend(grade["overclaims"])

    if not has_precondition(finding):
        problems.append("缺少前置条件：是否需要登录、需要什么角色、是否需内网，都必须写明。")

    return problems


def render_grade_notes(finding: dict[str, Any]) -> list[str]:
    """把定级建议渲染成报告里的「定级依据」小节行。"""
    grade = grade_finding(finding)
    lines: list[str] = []
    if grade["ceiling"]:
        lines.append(f"- 该类别在无额外证据时的建议上限：**{grade['ceiling']}**")
    if grade["declared"]:
        lines.append(f"- 当前声明等级：**{grade['declared']}**")
    if grade["overclaims"]:
        lines.append("- ⚠️ 高估风险：")
        lines.extend(f"  - {item}" for item in grade["overclaims"])
    if grade["required_notes"]:
        lines.append("- 定级必须交代：")
        lines.extend(f"  - {item}" for item in grade["required_notes"])
    return lines
