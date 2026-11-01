"""Soft-target asset scorer — 软柿子寻找评分引擎.

Scores each asset in a target DB using a softness-oriented model:
  遗忘风险(20) + 技术老旧(15) + 功能攻击面(10) + 权限复杂度(15)
  + 暴露程度(10) + 指纹风险(10) + 异常迹象(10) + 页面线索(10)

Production/root sites and high-complexity authenticated applications receive
negative penalties. Attack surface remains evidence, but is not treated as
softness by itself.

Tiers:
  80-100: 立即测试 (tier1)
  60-79:  高优先级 (tier2)
  40-59:  正常测试 (tier3)
  20-39:  低优先级 (tier4)
  0-19:   通常跳过 (tier5)

Usage:
  uv run python TOOLS/db/soft_target_scorer.py --target "example-client"
  uv run python TOOLS/db/soft_target_scorer.py --target "example-client" --json
  uv run python TOOLS/db/soft_target_scorer.py --target "example-client" --top 20
  uv run python TOOLS/db/soft_target_scorer.py --target "example-client" --focus-id 12
  uv run python TOOLS/db/soft_target_scorer.py --target "example-client" --fail-id 12 --reason "无有效入口"
"""

from __future__ import annotations

import argparse
import io
import json
import re
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

_TOOLS_DIR = Path(__file__).resolve().parent.parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

from db.db_utils import connect, find_db  # noqa: E402
from db.work_queue import create_work_item  # noqa: E402

# ---------------------------------------------------------------------------
# Signal lists — compiled from the user's tier breakdown
# ---------------------------------------------------------------------------

# Tier 1: 遗忘型资产
ABANDONED_PATTERNS = [
    re.compile(pat, re.IGNORECASE)
    for pat in [
        r"\btest[.-]",
        r"\bdev[.-]",
        r"\buat[.-]",
        r"\bstaging[.-]",
        r"\bold[.-]",
        r"\bbackup[.-]",
        r"\bdemo[.-]",
        r"\btmp[.-]",
        r"\btemp[.-]",
        r"\bpre[.-]",
        r"\bpreview[.-]",
        r"\bbeta[.-]",
        r"\bsandbox[.-]",
        r"\bdebug[.-]",
        r"\blocalhost",
    ]
]

# Tier 2: 暴露的管理与基础设施系统
INFRA_KEYWORDS = [
    re.compile(pat, re.IGNORECASE)
    for pat in [
        r"\bvpn\b",
        r"\bsslvpn\b",
        r"\bbastion\b",
        r"\bjenkins\b",
        r"\bgitlab\b",
        r"\bharbor\b",
        r"\bsonarqube\b",
        r"\bgrafana\b",
        r"\bprometheus\b",
        r"\bkibana\b",
        r"\bphpmyadmin\b",
        r"\badminer\b",
        r"\bgitea\b",
        r"\bgogs\b",
        r"\bconfluence\b",
        r"\bjira\b",
        r"\bredmine\b",
        r"\bzabbix\b",
        r"\bnagios\b",
        r"\brouter\b",
        r"\bfirewall\b",
        r"\bnas\b",
        r"\bsynology\b",
        r"\bqnap\b",
        r"\bvmware\b",
        r"\besxi\b",
        r"\bproxmox\b",
        r"\bopenstack\b",
        r"\bdocker\b",
        r"\bportainer\b",
        r"\brancher\b",
        r"\bk8s\b",
        r"\bkubernetes\b",
        r"\bswagger\b",
        r"\bopenapi\b",
        r"\bgraphql\b",
        r"\bapi.?gateway\b",
        r"\bapi.?docs\b",
        r"\bconfig\b.*center",
        r"\bregistry\b",
        r"\bminio\b",
        r"\bceph\b",
        r"\bobject.?storage\b",
        r"\bfile.?manager\b",
        r"\belasticsearch\b",
        r"\bkafka\b",
        r"\brabbitmq\b",
        r"\bredis\b.*admin",
        r"\bmongo\b.*admin",
        r"\badminer\b",
        r"\bwaf\b",
        r"\bcacti\b",
        r"\bnetdata\b",
    ]
]

# Tier 3: 功能复杂的自研业务系统
BUSINESS_KEYWORDS = [
    re.compile(pat, re.IGNORECASE)
    for pat in [
        r"\boa\b",
        r"\berp\b",
        r"\bcrm\b",
        r"\border\b",
        r"\bpay(ment)?\b",
        r"\brefund\b",
        r"\bsupplier\b",
        r"\bmerchant\b",
        r"\bvendor\b",
        r"\bpartner\b",
        r"\bcustomer.?service\b",
        r"\bsupport\b",
        r"\buser.?center\b",
        r"\bupload\b",
        r"\bdocument.*review\b",
        r"\baudit\b",
        r"\bsaas\b",
        r"\btenant\b",
        r"\bworkflow\b",
        r"\bapproval\b",
        r"\bdispatch\b",
        r"\blogistic\b",
        r"\bwarehouse\b",
        r"\binventory\b",
        r"\breport\b",
        r"\bdashboard\b",
        r"\bstats?\b",
        r"\banalytics?\b",
        r"\bmonitor\b",
        r"\bmanage\b",
        r"\badmin\b",
        r"\bsetting\b",
        r"\bconsole\b",
    ]
]

# Tier 4: API / 移动端 / 小程序后端
API_PATTERNS = [
    re.compile(pat, re.IGNORECASE)
    for pat in [
        r"/api/",
        r"/v[12]/",
        r"/graphql",
        r"/swagger",
        r"/openapi",
        r"/rest/",
        r"/rpc/",
        r"/gateway/",
        r"/ws/",
        r"/websocket",
        r"\bswagger\b",
        r"\bopenapi\b",
        r"\bgraphql\b",
    ]
]

API_SENSITIVE_PARAMS = [
    re.compile(pat, re.IGNORECASE)
    for pat in [
        r"\buserid\b",
        r"\buser_id\b",
        r"\buid\b",
        r"\btenantid\b",
        r"\btenant_id\b",
        r"\broleid\b",
        r"\brole_id\b",
        r"\borderid\b",
        r"\border_id\b",
        r"\borgid\b",
        r"\borg_id\b",
        r"\bdeptid\b",
        r"\baccountid\b",
    ]
]

# Tier 5: 旧 CMS 和通用建站程序
CMS_PATTERNS = [
    re.compile(pat, re.IGNORECASE)
    for pat in [
        r"\bwordpress\b",
        r"\bwp-content\b",
        r"\bwp-admin\b",
        r"\bwp-json\b",
        r"\bdrupal\b",
        r"\bjoomla\b",
        r"\bdiscuz\b",
        r"\bdedecms\b",
        r"\bphpcms\b",
        r"\bthinkphp\b",
        r"\byiiframework\b",
        r"\byii\b",
        r"\blaravel\b",
        r"\bstruts2?\b",
        r"\bspring\b",
        r"\bhibernate\b",
        r"\bjsf\b",
        r"\bstruts\b",
        r"\bdwr\b",
        r"\bfckeditor\b",
        r"\bckeditor\b",
        r"\bueditor\b",
        r"\bkindeditor\b",
        r"\bwebpack\b",
        r"\bjquery\b",
        r"\bbootstrap\b",
    ]
]

# Strong positive signals — one is enough to bump priority significantly
STRONG_PLUS = [
    re.compile(pat, re.IGNORECASE)
    for pat in [
        r"\bdev[.-]",
        r"\btest[.-]",
        r"\buat[.-]",
        r"\bstaging[.-]",
        r"\bold[.-]",
        r"/upload",
        r"/import",
        r"/export",
        r"/download",
        r"/preview",
        r"/convert",
        r"\bswagger\b",
        r"\bopenapi\b",
        r"/api/docs",
        r"/doc\.html",
        r"\bregister\b",
        r"\bsignup\b",
        r"\bforgot.*password",
        r"\breset.*password",
        r"\bsms\b.*code",
        r"\binvite\b",
        r"\bverify\b",
        r"\baudit\b.*flow",
        r"\bapproval\b.*flow",
    ]
]

# Signals that reduce priority
NEGATIVE_SIGNALS = [
    re.compile(pat, re.IGNORECASE)
    for pat in [
        r"\.(jpg|jpeg|png|gif|svg|ico|css|woff2?|ttf|eot)(\?|$)",
        r"\.(js|map)(\?|$)",
        r"cdn[.-]",
        r"static[.-]",
        r"assets[.-]",
        r"img[.-]",
        r"image[.-]",
        r"font[.-]",
    ]
]

# Technology keywords indicating old tech
OLD_TECH = [
    re.compile(pat, re.IGNORECASE)
    for pat in [
        r"\bstruts1?\b",
        r"\bspring\s*2\b",
        r"\bhibernate\s*[123]\b",
        r"\bjquery\s*[12]",
        r"\bangularjs?\b",
        r"\bie[6789]?\b",
        r"\bphp\s*[345]\b",
        r"\bjava\s*[567]\b",
        r"\b\.net\s*[123]\b",
        r"\bpython\s*2\b",
        r"\bjdk\s*[567]\b",
        r"\btomcat\s*[567]\b",
        r"\bapache\s*2\.[012]\b",
        r"\bnginx\s*1\.[01]\b",
        r"\biis\s*[567]\b",
        r"\bweblogic\s*1[012]\b",
    ]
]

# Page titles that boost score (debug/error/infra pages)
HIGH_VALUE_TITLES = [
    re.compile(pat, re.IGNORECASE)
    for pat in [
        r"\bdebug\b",
        r"\btest\b",
        r"\berror\b",
        r"\bexception\b",
        r"\bstack\s*trace\b",
        r"\bphpinfo\b",
        r"\bphp\s*info\b",
        r"\bswagger\b",
        r"\bapi\s*doc",
        r"\b登录\b",
        r"\b后台\b",
        r"\b管理\b",
        r"\b上传\b",
        r"\bsign\s*in\b",
        r"\bsign\s*up\b",
        r"\blogin\b",
        r"\bregister\b",
        r"\bdashboard\b",
        r"\bconsole\b",
        r"\badmin\b",
        r"\bdirectory\s*listing\b",
        r"\bindex\s*of\b",
        r"\b403\b.*forbidden",
        r"\b500\b.*internal",
        r"\bwelcome\s*to\b",
        r"\bapache\s*tomcat\b",
        r"\bnginx\b",
        r"\biis\d",
        r"\bjenkins\b",
        r"\bgitlab\b",
        r"\bgrafana\b",
        r"\bzabbix\b",
    ]
]

JS_HIGH_SIGNAL_PATTERNS = [
    re.compile(pat, re.IGNORECASE)
    for pat in [
        r"\badmin\b",
        r"\bteacher\b",
        r"\bmanage\b",
        r"\bsystem\b",
        r"\bstaff\b",
        r"\bupload\b",
        r"\bdownload\b",
        r"\bexport\b",
        r"\bimport\b",
        r"\buserid\b",
        r"\buid\b",
        r"\borderid\b",
        r"\bstudentid\b",
        r"\borgid\b",
        r"\btenantid\b",
        r"\bopenid\b",
        r"\bunionid\b",
        r"\b/token\b",
        r"\b/sign\b",
        r"\b/encrypt\b",
    ]
]


# ---------------------------------------------------------------------------
# Helper: safe field access
# ---------------------------------------------------------------------------


def _s(val: Any) -> str:
    """Coerce to lowercase string; empty string for None."""
    if val is None:
        return ""
    return str(val).lower()


def _matches_any(text: str, patterns: list[re.Pattern[str]]) -> int:
    """Return count of unique patterns matching `text`."""
    seen: set[int] = set()
    for idx, pat in enumerate(patterns):
        if pat.search(text):
            seen.add(idx)
    return len(seen)


def _contains_any(text: str, patterns: list[re.Pattern[str]]) -> bool:
    """Return True if any pattern matches `text`."""
    for pat in patterns:
        if pat.search(text):
            return True
    return False


# ---------------------------------------------------------------------------
# Score dimensions
# ---------------------------------------------------------------------------


def score_abandonment(asset: Mapping[str, Any]) -> tuple[int, list[str]]:
    """遗忘和维护风险: 0-20."""
    clues: list[str] = []
    score = 0

    value = _s(asset.get("asset_value", ""))
    notes = _s(asset.get("notes", ""))
    title = _s(asset.get("title", ""))
    text = f"{value} {notes} {title}"

    # Abandoned subdomain patterns
    hits = _matches_any(text, ABANDONED_PATTERNS)
    if hits >= 3:
        score += 15
        clues.append(f"遗忘型子域名(重度,{hits}匹配): {value}")
    elif hits >= 2:
        score += 12
        clues.append(f"遗忘型子域名({hits}匹配): {value}")
    elif hits >= 1:
        score += 8
        clues.append(f"遗忘型子域名({hits}匹配): {value}")

    # IP-access without domain (abandoned or shadow IT)
    if asset.get("asset_type") == "ip" and not notes:
        score += 5
        clues.append(f"裸IP资产: {value}")

    # Certificate anomalies
    cert_anomaly = _s(asset.get("cert_anomaly", ""))
    if cert_anomaly and cert_anomaly not in ("none", "ok", "valid"):
        score += 5
        clues.append(f"证书异常: {cert_anomaly}")

    if score > 20:
        score = 20
    return score, clues


def score_tech_age(asset: Mapping[str, Any]) -> tuple[int, list[str]]:
    """技术老旧程度: 0-15."""
    clues: list[str] = []
    score = 0

    tech_stack = _s(asset.get("tech_stack", ""))
    notes = _s(asset.get("notes", ""))
    title = _s(asset.get("title", ""))
    page_type = _s(asset.get("page_type", ""))
    text = f"{tech_stack} {notes} {title} {page_type}"

    old_hits = _matches_any(text, OLD_TECH)
    cms_hits = _matches_any(text, CMS_PATTERNS)

    if old_hits >= 2:
        score += 12
        clues.append(f"老技术栈(重度,{old_hits}匹配)")
    elif old_hits >= 1:
        score += 8
        clues.append(f"老技术栈({old_hits}匹配)")

    if cms_hits >= 2 and old_hits == 0:
        score += 5
        clues.append(f"CMS/通用程序({cms_hits}匹配)")

    # Explicit PHP / Java version from page title
    if re.search(r"php\s*[345]\b", text, re.IGNORECASE):
        score += 5
        clues.append("PHP旧版本")
    if re.search(r"java\s*[567]\b", text, re.IGNORECASE):
        score += 5
        clues.append("Java旧版本")

    if score > 15:
        score = 15
    return score, clues


def score_attack_surface(asset: Mapping[str, Any]) -> tuple[int, list[str]]:
    """功能攻击面: 0-10; surface is evidence, not softness by itself."""
    clues: list[str] = []
    score = 0

    value = _s(asset.get("asset_value", ""))
    notes = _s(asset.get("notes", ""))
    title = _s(asset.get("title", ""))
    page_type = _s(asset.get("page_type", ""))
    text = f"{value} {notes} {title} {page_type}"

    # Infra systems
    infra_hits = _matches_any(text, INFRA_KEYWORDS)
    if infra_hits:
        score += min(infra_hits * 5, 12)
        clues.append(f"基础设施({infra_hits}匹配)")

    # Business systems
    biz_hits = _matches_any(text, BUSINESS_KEYWORDS)
    if biz_hits:
        score += min(biz_hits * 4, 12)
        clues.append(f"业务系统({biz_hits}匹配)")

    has_login = (
        _s(asset.get("has_login", "")) in ("1", "true", "yes")
        or _s(asset.get("auth_entry_found"))
        in (
            "1",
            "true",
            "yes",
        )
        or _s(asset.get("login_urls")) not in ("", "[]", "null")
    )
    has_register = _s(asset.get("has_register", "")) in ("1", "true", "yes") or _s(asset.get("register_urls")) not in (
        "",
        "[]",
        "null",
    )

    # Has login/register
    if has_login:
        score += 5
        clues.append("有登录功能")
    if has_register:
        score += 3
        clues.append("发现注册入口线索")

    # Has upload/download/export functions
    for kw in ["upload", "import", "export", "download", "preview", "convert"]:
        if f"/{kw}" in text or re.search(rf"\b{kw}\b", text, re.IGNORECASE):
            score += 3
            clues.append(f"有{kw}功能")
            break

    # Has search
    if _s(asset.get("has_search", "")) in ("1", "true", "yes"):
        score += 3
        clues.append("有搜索功能")

    # API docs exposure
    if _contains_any(text, API_PATTERNS):
        score += 4
        clues.append("API端点暴露")

    if score > 10:
        score = 10
    return score, clues


def score_permission_complexity(asset: Mapping[str, Any]) -> tuple[int, list[str]]:
    """权限复杂度: 0-15."""
    clues: list[str] = []
    score = 0

    value = _s(asset.get("asset_value", ""))
    notes = _s(asset.get("notes", ""))
    title = _s(asset.get("title", ""))
    text = f"{value} {notes} {title}"

    # Multi-role indicators
    role_keywords = [
        r"\badmin\b",
        r"\bteacher\b",
        r"\bstudent\b",
        r"\bstaff\b",
        r"\bmerchant\b",
        r"\bagent\b",
        r"\bpartner\b",
        r"\bsupplier\b",
        r"\bauditor\b",
        r"\boperator\b",
        r"\bmanager\b",
    ]
    role_hits = _matches_any(text, [re.compile(p, re.IGNORECASE) for p in role_keywords])
    if role_hits >= 3:
        score += 12
        clues.append(f"多角色系统({role_hits}角色类型)")
    elif role_hits >= 2:
        score += 9
        clues.append(f"多角色系统({role_hits}角色)")
    elif role_hits >= 1:
        score += 5
        clues.append("存在角色分化")

    # Has admin/staff + user distinction
    if _contains_any(text, [re.compile(r"\badmin\b", re.IGNORECASE)]) and _contains_any(
        text, [re.compile(r"\b(user|member|customer|client)\b", re.IGNORECASE)]
    ):
        score += 4
        clues.append("前后台+用户双系统")

    # Multi-tenant
    if _contains_any(text, [re.compile(r"\btenant\b|\bsaas\b|\borg\b", re.IGNORECASE)]):
        score += 5
        clues.append("多租户系统")

    # Has register — more permission surface. This is only an entry clue,
    # never proof that registration succeeds.
    if _s(asset.get("has_register", "")) in ("1", "true", "yes") or _s(asset.get("register_urls")) not in (
        "",
        "[]",
        "null",
    ):
        score += 3
        clues.append("注册入口线索→需操作员确认")

    if score > 15:
        score = 15
    return score, clues


def score_exposure(asset: Mapping[str, Any]) -> tuple[int, list[str]]:
    """暴露程度: 0-10."""
    clues: list[str] = []
    score = 0

    value = _s(asset.get("asset_value", ""))
    asset_type = _s(asset.get("asset_type", ""))
    port_str = str(asset.get("port") or "")
    notes = _s(asset.get("notes", ""))
    title = _s(asset.get("title", ""))

    # Direct IP
    if asset_type in ("ip",):
        score += 5
        clues.append("IP直连")

    # Non-standard port
    if port_str.isdigit():
        port = int(port_str)
        if port not in (80, 443, 8080, 8443, 0):
            score += 3
            clues.append(f"非标准端口:{port}")

    # Management/admin exposure
    if _contains_any(f"{value} {notes} {title}", INFRA_KEYWORDS):
        score += 3
        clues.append("管理类系统暴露")

    # Self/expired cert
    cert = _s(asset.get("cert_info", ""))
    if any(kw in cert for kw in ("self-signed", "自签名", "expired", "过期")):
        score += 3
        clues.append("自签名/过期证书")

    if score > 10:
        score = 10
    return score, clues


def score_fingerprint_risk(asset: Mapping[str, Any]) -> tuple[int, list[str]]:
    """指纹与已知风险: 0-10."""
    clues: list[str] = []
    score = 0

    tech_stack = _s(asset.get("tech_stack", ""))
    notes = _s(asset.get("notes", ""))
    title = _s(asset.get("title", ""))
    page_type = _s(asset.get("page_type", ""))
    text = f"{tech_stack} {notes} {title} {page_type}"

    # Clear product + version
    version_pattern = re.compile(r"(version|ver|v)\s*[:=]?\s*([0-9]+\.[0-9.]+)", re.IGNORECASE)
    if version_pattern.search(text):
        score += 5
        clues.append("明确产品版本")

    # CMS fingerprint
    if _matches_any(text, CMS_PATTERNS) >= 2:
        score += 4
        clues.append("CMS/程序指纹明确")

    # Infra product with historical vulns
    infra_hits = _matches_any(text, INFRA_KEYWORDS)
    if infra_hits >= 2:
        score += 4
        clues.append("知名基础设施产品")

    if score > 10:
        score = 10
    return score, clues


def score_anomaly_signals(asset: Mapping[str, Any]) -> tuple[int, list[str]]:
    """异常迹象: 0-10."""
    clues: list[str] = []
    score = 0

    title = _s(asset.get("title", ""))
    notes = _s(asset.get("notes", ""))
    page_type = _s(asset.get("page_type", ""))
    value_str = _s(asset.get("asset_value", ""))
    text = f"{title} {notes} {page_type} {value_str}"

    # Debug / error pages
    if _contains_any(
        text,
        [
            re.compile(r"\bdebug\b", re.IGNORECASE),
            re.compile(r"\bstack\s*trace\b", re.IGNORECASE),
            re.compile(r"\bexception\b", re.IGNORECASE),
            re.compile(r"\berror\b", re.IGNORECASE),
            re.compile(r"\bwarning\b", re.IGNORECASE),
            re.compile(r"\bfatal\b", re.IGNORECASE),
        ],
    ):
        score += 4
        clues.append("调试/错误信息泄露")

    # Directory listing
    if _contains_any(
        text,
        [
            re.compile(r"index of /", re.IGNORECASE),
            re.compile(r"directory listing", re.IGNORECASE),
            re.compile(r"parent directory", re.IGNORECASE),
        ],
    ):
        score += 4
        clues.append("目录列表暴露")

    # API docs without auth
    if _contains_any(text, API_PATTERNS) and _s(asset.get("requires_auth", "")) in ("0", "", "false"):
        score += 3
        clues.append("API文档无需认证")

    # Config / backup exposure
    if _contains_any(
        text,
        [
            re.compile(r"\.bak", re.IGNORECASE),
            re.compile(r"\.backup", re.IGNORECASE),
            re.compile(r"\.conf\b", re.IGNORECASE),
            re.compile(r"\.config\b", re.IGNORECASE),
            re.compile(r"\.env\b", re.IGNORECASE),
            re.compile(r"\.git/", re.IGNORECASE),
            re.compile(r"\.svn/", re.IGNORECASE),
            re.compile(r"\.yml\b", re.IGNORECASE),
            re.compile(r"phpinfo", re.IGNORECASE),
        ],
    ):
        score += 3
        clues.append("配置文件泄露风险")

    # SQL error / Java stack trace
    if _contains_any(
        text,
        [
            re.compile(r"sql.*error", re.IGNORECASE),
            re.compile(r"sql.*syntax", re.IGNORECASE),
            re.compile(r"\bsqlexception\b", re.IGNORECASE),
            re.compile(r"java\.lang\.", re.IGNORECASE),
            re.compile(r"\bat\s+\w+\.\w+\(.*\.java:", re.IGNORECASE),
            re.compile(r"\.py\", line \d", re.IGNORECASE),
        ],
    ):
        score += 4
        clues.append("SQL/堆栈错误泄露")

    # Cloud keys / internal IP leak from notes or title
    if _contains_any(
        text,
        [
            re.compile(r"access.?key.?id", re.IGNORECASE),
            re.compile(r"secret.?access.?key", re.IGNORECASE),
            re.compile(r"AKIA[0-9A-Z]{16}", re.IGNORECASE),
            re.compile(r"192\.168\.", re.IGNORECASE),
            re.compile(r"10\.\d+\.\d+\.\d+", re.IGNORECASE),
            re.compile(r"172\.(1[6-9]|2\d|3[01])\.", re.IGNORECASE),
            re.compile(r"oss-", re.IGNORECASE),
            re.compile(r"\.s3\.", re.IGNORECASE),
        ],
    ):
        score += 4
        clues.append("云密钥/内部IP泄露")

    if score > 10:
        score = 10
    return score, clues


def score_pages_bonus(pages: list[dict[str, Any]]) -> tuple[int, list[str]]:
    """Bonus signals derived from associated pages data."""
    clues: list[str] = []
    score = 0

    titles = " ".join(_s(p.get("title", "")) for p in pages)
    # High-value page titles
    if _matches_any(titles, HIGH_VALUE_TITLES) >= 3:
        score += 5
        clues.append("高价值页面标题")
    elif _matches_any(titles, HIGH_VALUE_TITLES) >= 1:
        score += 2

    # JS count
    for p in pages:
        js_raw = p.get("js_files_json") or "[]"
        try:
            js_list = json.loads(js_raw) if isinstance(js_raw, str) else js_raw
            js_count = len(js_list) if isinstance(js_list, list) else 0
        except (json.JSONDecodeError, TypeError):
            js_count = 0
        if js_count >= 5:
            score += 3
            clues.append(f"JS丰富({js_count}文件) → 接口攻击面大")
            break

    # Forms
    for p in pages:
        forms_raw = p.get("forms_json") or "[]"
        try:
            forms_list = json.loads(forms_raw) if isinstance(forms_raw, str) else forms_raw
            form_count = len(forms_list) if isinstance(forms_list, list) else 0
        except (json.JSONDecodeError, TypeError):
            form_count = 0
        if form_count >= 2:
            score += 3
            clues.append(f"表单丰富({form_count}表单) → 交互攻击面大")
            break

    # API calls found
    for p in pages:
        api_raw = p.get("api_calls_json") or "[]"
        try:
            api_list = json.loads(api_raw) if isinstance(api_raw, str) else api_raw
            api_count = len(api_list) if isinstance(api_list, list) else 0
        except (json.JSONDecodeError, TypeError):
            api_count = 0
        if api_count >= 5:
            score += 5
            clues.append(f"API调用丰富({api_count}端点)")
            break
        elif api_count >= 1:
            score += 2

    return min(score, 10), clues


def score_negative(asset: Mapping[str, Any], pages: list[dict[str, Any]]) -> int:
    """Negative signals that reduce softness priority."""
    penalty = 0
    live_status = _s(asset.get("live_status"))
    if live_status == "dead":
        penalty += 80
    elif live_status == "internal_only":
        # Only reachable from an internal network: cannot be tested without
        # operator-provided access, so it is not a low-resistance target.
        penalty += 70
    elif live_status == "unreachable":
        # Verified to answer on no path (direct and proxy); verification cost is
        # currently unbounded even though the asset itself is in scope.
        penalty += 60
    elif live_status == "unknown":
        penalty += 10
    value = _s(asset.get("asset_value", ""))
    notes = _s(asset.get("notes", ""))
    pages_text = " ".join(_s(p.get("title", "")) + " " + _s(p.get("url", "")) for p in pages)
    text = f"{value} {notes} {pages_text}"

    if _matches_any(text, NEGATIVE_SIGNALS) >= 3:
        penalty += 15
    elif _matches_any(text, NEGATIVE_SIGNALS) >= 1:
        penalty += 5

    host = _domain_key(value)
    root = _domain_key(_s(asset.get("target_root_domain", "")))
    if root and host == root:
        penalty += 25
    elif root and host == f"www.{root}":
        penalty += 20
    elif host.startswith("www."):
        penalty += 15

    # A large authenticated application is valuable, but it is not a soft target.
    attack_score, _ = score_attack_surface(asset)
    auth_required = _s(asset.get("auth_required", asset.get("requires_auth", ""))) in (
        "1",
        "true",
        "yes",
    )
    if attack_score >= 8:
        penalty += 6
    if auth_required:
        penalty += 8

    return penalty


def determine_tier(score: int) -> str:
    if score >= 80:
        return "tier1_立即测试"
    elif score >= 60:
        return "tier2_高优先级"
    elif score >= 40:
        return "tier3_正常测试"
    elif score >= 20:
        return "tier4_低优先级"
    else:
        return "tier5_通常跳过"


def tier_emoji(tier: str) -> str:
    return {
        "tier1_立即测试": "[!]",
        "tier2_高优先级": "[+]",
        "tier3_正常测试": "[~]",
        "tier4_低优先级": "[-]",
        "tier5_通常跳过": "[ ]",
    }.get(tier, "[?]")


# ---------------------------------------------------------------------------
# Main scoring pipeline
# ---------------------------------------------------------------------------


def _domain_key(asset_value: str) -> str:
    """Strip wildcard/port prefix for matching: '*.foo.com' → 'foo.com'."""
    from urllib.parse import urlparse

    v = asset_value.strip().lower()
    if "://" in v:
        parsed = urlparse(v)
        v = parsed.netloc or parsed.path
    v = v.partition("/")[0].partition(":")[0]
    if v.startswith("*."):
        v = v[2:]
    return v


def _pages_match_asset(page_url: str, asset_value: str) -> bool:
    """Check if a page URL belongs to an asset, handling wildcards."""
    from urllib.parse import urlparse

    page_host = urlparse(page_url).netloc.lower().partition(":")[0] if "://" in page_url else page_url.lower().partition(":")[0]
    asset_key = _domain_key(asset_value)
    asset_value_l = asset_value.strip().lower()

    # Exact match
    if page_host == asset_key:
        return True
    # Wildcard/domain asset can own child subdomains; concrete subdomain assets should not
    # absorb siblings or parent-domain pages.
    if (asset_value_l.startswith("*.") or asset_key.count(".") <= 1) and page_host.endswith("." + asset_key):
        return True
    # Asset is a full URL
    if "://" in asset_value_l and page_url.lower().startswith(asset_value_l.rstrip("/") + "/"):
        return True
    return False


def _table_columns(conn: Any, table: str) -> set[str]:
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}


def ensure_soft_target_schema(conn: Any) -> None:
    """Create the soft-target store used by scorer and lifecycle operations."""
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS soft_targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_name TEXT NOT NULL,
            asset_id INTEGER,
            asset_type TEXT DEFAULT 'domain',
            asset_value TEXT NOT NULL,
            port INTEGER,
            protocol TEXT DEFAULT 'https',
            total_score INTEGER NOT NULL DEFAULT 0,
            raw_score INTEGER NOT NULL DEFAULT 0,
            penalty INTEGER NOT NULL DEFAULT 0,
            tier TEXT NOT NULL,
            rank INTEGER,
            status TEXT NOT NULL DEFAULT 'ranked'
                CHECK(status IN ('ranked','available','focused','failed','parked','completed','excluded')),
            dimension_scores_json TEXT NOT NULL DEFAULT '{}',
            evidence_json TEXT NOT NULL DEFAULT '[]',
            failure_reason TEXT,
            failure_evidence_json TEXT,
            focused_at TEXT,
            completed_at TEXT,
            created_at TEXT DEFAULT (datetime('now','localtime')),
            updated_at TEXT DEFAULT (datetime('now','localtime')),
            UNIQUE(target_name, asset_id)
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_soft_targets_identity
            ON soft_targets(target_name, asset_value, COALESCE(port, 443));
        CREATE INDEX IF NOT EXISTS idx_soft_targets_rank
            ON soft_targets(target_name, status, total_score DESC, rank ASC);

        CREATE TABLE IF NOT EXISTS soft_target_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            soft_target_id INTEGER REFERENCES soft_targets(id),
            target_name TEXT NOT NULL,
            asset_value TEXT NOT NULL,
            from_status TEXT,
            to_status TEXT NOT NULL
                CHECK(to_status IN ('ranked','available','focused','failed','parked','completed','excluded')),
            reason TEXT,
            evidence_json TEXT,
            actor TEXT DEFAULT 'soft_target_scorer',
            created_at TEXT DEFAULT (datetime('now','localtime'))
        );
        CREATE INDEX IF NOT EXISTS idx_soft_target_events_target
            ON soft_target_events(target_name, created_at);
        """
    )


def _asset_row_is_better(a: Mapping[str, Any], b: Mapping[str, Any]) -> bool:
    """Pick the richer row when multiple port-variant rows share one host.

    live > reachable-but-refused > unknown; then verified beats unverified;
    then lower id.
    """
    order = {"live": 4, "unreachable": 3, "internal_only": 3, "dead": 2, "unknown": 0}
    a_rank = order.get(str(a.get("live_status") or "unknown"), 0)
    b_rank = order.get(str(b.get("live_status") or "unknown"), 0)
    if a_rank != b_rank:
        return a_rank > b_rank
    a_v = a.get("last_verified_at")
    b_v = b.get("last_verified_at")
    if bool(a_v) != bool(b_v):
        return bool(a_v)
    return int(a.get("id") or 0) < int(b.get("id") or 0)


def fetch_assets(conn: Any, target_name: str) -> list[dict[str, Any]]:
    """Fetch all target_assets and enrich with matched page data."""
    # Check if target_assets table exists
    has_table = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='target_assets'").fetchone()
    if not has_table:
        return []

    asset_rows = conn.execute(
        """
        SELECT *
        FROM target_assets
        WHERE target_name = ?
          AND COALESCE(status, 'new') NOT IN ('excluded')
        ORDER BY priority DESC, id ASC
        """,
        (target_name,),
    ).fetchall()

    targets_table = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='targets'").fetchone()
    if targets_table:
        target_row = conn.execute(
            "SELECT domain FROM targets WHERE target_name = ? ORDER BY id LIMIT 1",
            (target_name,),
        ).fetchone()
        target_root_domain = str(target_row["domain"] or "") if target_row else ""
    else:
        target_root_domain = ""

    page_cols = _table_columns(conn, "pages")
    page_select = "url, title, status, js_files_json, forms_json, api_calls_json"
    page_where = "url IS NOT NULL"
    params: list[Any] = []
    if "target_name" in page_cols:
        page_where += " AND target_name = ?"
        params.append(target_name)
    elif "target_id" in page_cols:
        target_ids = [
            row[0]
            for row in conn.execute(
                "SELECT id FROM targets WHERE target_name = ?",
                (target_name,),
            ).fetchall()
        ]
        if target_ids:
            placeholders = ",".join("?" for _ in target_ids)
            page_where += f" AND target_id IN ({placeholders})"
            params.extend(target_ids)

    page_sql = f"""
        SELECT {page_select}
        FROM pages
        WHERE {page_where}
        ORDER BY depth ASC, id ASC
        """  # noqa: S608 - SELECT/WHERE fragments are built from fixed column/schema branches.
    page_rows = conn.execute(page_sql, params).fetchall()

    assets: list[dict[str, Any]] = []
    seen: set[str] = set()

    # FOFA 端口变体会为同一 host 生成多行 (host:8080, host:8443, ...)；
    # 软柿子打分按 host 合并，只保留验证信息最全的一行。
    # 优先 live > dead > unknown，其次有 last_verified_at，最后 id 靠前。
    by_host: dict[str, dict[str, Any]] = {}
    for row in asset_rows:
        d = dict(row)
        host = str(d["asset_value"] or "").strip().lower()
        if not host:
            continue
        d["target_root_domain"] = target_root_domain
        prev = by_host.get(host)
        if prev is None or _asset_row_is_better(d, prev):
            by_host[host] = d

    for d in by_host.values():
        key = f"{d['asset_value']}:{d.get('port') or 443}"
        if key in seen:
            continue
        seen.add(key)

        # 验活数据回填：旧列为空时用 last_title/last_tech_stack 补齐，
        # 让 title/指纹驱动的评分维度能触发。
        if not d.get("tech_stack") and d.get("last_tech_stack"):
            d["tech_stack"] = d["last_tech_stack"]
        if not d.get("title") and d.get("last_title"):
            d["title"] = d["last_title"]
        if not d.get("page_title") and d.get("last_title"):
            d["page_title"] = d["last_title"]

        # Find matching pages
        matched: dict[str, str] = {}
        matched_pages: list[dict[str, Any]] = []
        best_page: dict[str, Any] | None = None
        for pr in page_rows:
            if _pages_match_asset(str(pr["url"]), str(d["asset_value"])):
                matched_pages.append(dict(pr))
                if best_page is None:
                    best_page = dict(pr)
                # Pick best title
                if pr["title"] and (not matched.get("title")):
                    matched["title"] = pr["title"]

        if best_page:
            d["page_title"] = matched.get("title", "") or (best_page.get("title") or "")
            d["page_status"] = best_page.get("status", "")
            d["page_js_files_json"] = best_page.get("js_files_json", "[]")
            d["page_forms_json"] = best_page.get("forms_json", "[]")
            d["page_api_calls_json"] = best_page.get("api_calls_json", "[]")
        else:
            d.setdefault("page_title", "")
            d.setdefault("page_status", "")
            d.setdefault("page_js_files_json", "[]")
            d.setdefault("page_forms_json", "[]")
            d.setdefault("page_api_calls_json", "[]")
        d["matched_pages"] = matched_pages

        assets.append(d)
    return assets


def score_asset(asset: dict[str, Any], pages: list[dict[str, Any]]) -> dict[str, Any]:
    """Score a single asset across all dimensions."""
    dims: dict[str, tuple[int, list[str]]] = {}
    dims["abandonment"] = score_abandonment(asset)
    dims["tech_age"] = score_tech_age(asset)
    dims["attack_surface"] = score_attack_surface(asset)
    dims["permission"] = score_permission_complexity(asset)
    dims["exposure"] = score_exposure(asset)
    dims["fingerprint"] = score_fingerprint_risk(asset)
    dims["anomaly"] = score_anomaly_signals(asset)

    pages_bonus, pages_clues = score_pages_bonus(pages)
    dims["pages_bonus"] = (pages_bonus, pages_clues)

    raw = sum(s for s, _ in dims.values())
    penalty = score_negative(asset, pages)
    final = min(100, max(0, raw - penalty))
    tier = determine_tier(final)

    dimension_detail = {name: {"score": s, "clues": c} for name, (s, c) in dims.items()}

    return {
        "id": asset["id"],
        "asset_id": asset["id"],
        "asset_type": asset.get("asset_type", "domain"),
        "asset_value": asset.get("asset_value", ""),
        "port": asset.get("port"),
        "protocol": asset.get("protocol", "https"),
        "tech_stack": asset.get("tech_stack", ""),
        "page_title": asset.get("page_title", ""),
        "live_status": asset.get("live_status", "unknown"),
        "auth_required": asset.get("auth_required", asset.get("requires_auth", 0)),
        "auth_entry_found": asset.get("auth_entry_found", 0),
        "login_urls": asset.get("login_urls", "[]"),
        "register_urls": asset.get("register_urls", "[]"),
        "auth_blocker": asset.get("auth_blocker", "unknown"),
        "total_score": final,
        "raw_score": raw,
        "penalty": penalty,
        "tier": tier,
        "dimensions": dimension_detail,
        "evidence": [{"dimension": name, "reason": clue} for name, (_, clues) in dims.items() for clue in clues]
        + [
            {
                "dimension": "asset_verification",
                "live_status": asset.get("live_status", "unknown"),
                "auth_required": asset.get("auth_required", asset.get("requires_auth", 0)),
                "auth_entry_found": asset.get("auth_entry_found", 0),
                "login_urls": _load_json_obj(asset.get("login_urls"), []),
                "register_urls": _load_json_obj(asset.get("register_urls"), []),
                "auth_blocker": asset.get("auth_blocker", "unknown"),
            }
        ],
    }


def _rank_results(scored: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Stable deterministic ranking: score desc, less penalty, asset identity."""
    scored.sort(
        key=lambda x: (
            -int(x["total_score"]),
            int(x.get("penalty", 0)),
            str(x.get("tier", "")),
            str(x.get("asset_value", "")),
            int(x.get("port") or 0),
            int(x.get("asset_id") or x.get("id") or 0),
        )
    )
    for idx, item in enumerate(scored, start=1):
        item["rank"] = idx
    return scored


def _top_reasons(dimensions: Mapping[str, Any], *, limit: int = 3) -> list[str]:
    reasons: list[str] = []
    for key in (
        "abandonment",
        "tech_age",
        "attack_surface",
        "permission",
        "exposure",
        "fingerprint",
        "anomaly",
        "pages_bonus",
    ):
        dim = dimensions.get(key) if isinstance(dimensions, Mapping) else None
        if not isinstance(dim, Mapping) or int(dim.get("score") or 0) <= 0:
            continue
        for clue in dim.get("clues") or []:
            if clue:
                reasons.append(str(clue))
            if len(reasons) >= limit:
                return reasons
    return reasons


def _unknown_items(dimensions: Mapping[str, Any]) -> list[str]:
    labels = {
        "tech_age": "技术栈版本未知",
        "attack_surface": "功能攻击面未知",
        "permission": "角色/权限模型未知",
        "fingerprint": "产品指纹未知",
    }
    unknown: list[str] = []
    for key, label in labels.items():
        dim = dimensions.get(key) if isinstance(dimensions, Mapping) else None
        if not isinstance(dim, Mapping) or int(dim.get("score") or 0) == 0:
            unknown.append(label)
    return unknown


def _estimated_test_cost(row: Mapping[str, Any], dimensions: Mapping[str, Any]) -> str:
    score = int(row.get("total_score") or 0)
    status = str(row.get("status") or "")
    unknown_count = len(_unknown_items(dimensions))
    if status in {"failed", "parked", "excluded"}:
        return "skip_until_reopened"
    if score >= 70 and unknown_count <= 1:
        return "low"
    if score >= 40 and unknown_count <= 3:
        return "medium"
    return "high"


def _load_json_obj(raw: Any, default: Any) -> Any:
    try:
        value = json.loads(raw or "")
    except (TypeError, json.JSONDecodeError):
        return default
    return value if isinstance(value, type(default)) else default


def compact_soft_target_row(row: Mapping[str, Any]) -> dict[str, Any]:
    """Compact main-model soft-target view: ranked facts only, no raw asset data."""
    dimensions = _load_json_obj(row.get("dimension_scores_json"), {})
    evidence = _load_json_obj(row.get("evidence_json"), [])
    verification = next(
        (item for item in evidence if isinstance(item, Mapping) and item.get("dimension") == "asset_verification"),
        {},
    )
    return {
        "id": row.get("id"),
        "rank": row.get("rank"),
        "asset_id": row.get("asset_id"),
        "asset": row.get("asset_value"),
        "port": row.get("port"),
        "protocol": row.get("protocol") or "https",
        "status": row.get("status"),
        "score": row.get("total_score"),
        "tier": row.get("tier"),
        "reason_summary": _top_reasons(dimensions),
        "unknown_items": _unknown_items(dimensions),
        "estimated_test_cost": _estimated_test_cost(row, dimensions),
        "evidence_count": len(evidence) if isinstance(evidence, list) else 0,
        "live_status": verification.get("live_status", "unknown"),
        "auth_required": bool(verification.get("auth_required")),
        "auth_entry_found": bool(verification.get("auth_entry_found")),
        "login_urls": verification.get("login_urls") or [],
        "register_urls": verification.get("register_urls") or [],
        "auth_blocker": verification.get("auth_blocker", "unknown"),
        "failure_reason": row.get("failure_reason"),
        "updated_at": row.get("updated_at"),
    }


def save_soft_targets(conn: Any, target_name: str, results: list[dict[str, Any]]) -> None:
    """Persist ranked soft-targets without choosing a focused target for the user."""
    ensure_soft_target_schema(conn)
    # 清理旧的自动排序行（ranked/available），保留操作员决策状态，
    # 避免 FOFA 端口变体行在重复跑分后残留。
    conn.execute(
        """
        DELETE FROM soft_targets
        WHERE target_name = ?
          AND status IN ('ranked', 'available')
        """,
        (target_name,),
    )
    for r in results:
        existing = conn.execute(
            """
            SELECT id, status FROM soft_targets
            WHERE target_name = ?
              AND (asset_id = ? OR (asset_value = ? AND COALESCE(port, 443) = COALESCE(?, 443)))
            ORDER BY id ASC
            LIMIT 1
            """,
            (target_name, r["asset_id"], r["asset_value"], r.get("port")),
        ).fetchone()
        old_status = existing["status"] if existing else None
        status = old_status if old_status in {"focused", "failed", "parked", "completed", "excluded"} else "ranked"
        dims_json = json.dumps(r["dimensions"], ensure_ascii=False, sort_keys=True)
        evidence_json = json.dumps(r["evidence"], ensure_ascii=False, sort_keys=True)
        if existing:
            conn.execute(
                """
                UPDATE soft_targets
                SET asset_id = ?, asset_type = ?, asset_value = ?, port = ?, protocol = ?,
                    total_score = ?, raw_score = ?, penalty = ?, tier = ?, rank = ?,
                    status = ?, dimension_scores_json = ?, evidence_json = ?,
                    updated_at = datetime('now','localtime')
                WHERE id = ?
                """,
                (
                    r["asset_id"],
                    r["asset_type"],
                    r["asset_value"],
                    r.get("port"),
                    r.get("protocol"),
                    r["total_score"],
                    r["raw_score"],
                    r["penalty"],
                    r["tier"],
                    r["rank"],
                    status,
                    dims_json,
                    evidence_json,
                    existing["id"],
                ),
            )
            soft_target_id = existing["id"]
        else:
            cur = conn.execute(
                """
                INSERT INTO soft_targets (
                    target_name, asset_id, asset_type, asset_value, port, protocol,
                    total_score, raw_score, penalty, tier, rank, status,
                    dimension_scores_json, evidence_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    target_name,
                    r["asset_id"],
                    r["asset_type"],
                    r["asset_value"],
                    r.get("port"),
                    r.get("protocol"),
                    r["total_score"],
                    r["raw_score"],
                    r["penalty"],
                    r["tier"],
                    r["rank"],
                    status,
                    dims_json,
                    evidence_json,
                ),
            )
            soft_target_id = cur.lastrowid
        if old_status != status:
            conn.execute(
                """
                INSERT INTO soft_target_events (
                    soft_target_id, target_name, asset_value, from_status, to_status, reason, evidence_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (soft_target_id, target_name, r["asset_value"], old_status, status, "scored_ranked", evidence_json),
            )
    conn.commit()


def update_soft_target_status(
    conn: Any,
    soft_target_id: int,
    status: str,
    *,
    reason: str | None = None,
    evidence: Any = None,
    actor: str = "operator",
) -> None:
    """Move a soft target through its lifecycle, preserving failure reason/evidence."""
    ensure_soft_target_schema(conn)
    if status not in {"ranked", "available", "focused", "failed", "parked", "completed", "excluded"}:
        raise ValueError(f"invalid soft target status: {status}")
    row = conn.execute("SELECT * FROM soft_targets WHERE id = ?", (soft_target_id,)).fetchone()
    if row is None:
        raise ValueError(f"soft target not found: {soft_target_id}")
    evidence_json = json.dumps(evidence if evidence is not None else [], ensure_ascii=False, sort_keys=True)
    updates = ["status = ?", "updated_at = datetime('now','localtime')"]
    params: list[Any] = [status]
    if status == "focused":
        updates.append("focused_at = datetime('now','localtime')")
    if status == "completed":
        updates.append("completed_at = datetime('now','localtime')")
    if status == "failed":
        updates.extend(["failure_reason = ?", "failure_evidence_json = ?"])
        params.extend([reason or "", evidence_json])
    params.append(soft_target_id)
    conn.execute(  # noqa: S608 - update column fragments are selected from fixed literals above.
        f"UPDATE soft_targets SET {', '.join(updates)} WHERE id = ?",  # noqa: S608
        params,
    )
    conn.execute(
        """
        INSERT INTO soft_target_events (
            soft_target_id, target_name, asset_value, from_status, to_status, reason, evidence_json, actor
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (soft_target_id, row["target_name"], row["asset_value"], row["status"], status, reason, evidence_json, actor),
    )
    conn.commit()


def run_scorer(
    conn: Any,
    *,
    target_name: str,
    top: int | None = None,
) -> dict[str, Any]:
    """Main entry: fetch, score, rank, return."""
    assets = fetch_assets(conn, target_name)

    scored: list[dict[str, Any]] = []
    for asset in assets:
        # Page data was already embedded in fetch_assets
        page_dicts: list[dict[str, Any]] = asset.get("matched_pages") or [
            {
                "title": asset.get("page_title", ""),
                "url": str(asset.get("asset_value", "")),
                "js_files_json": str(asset.get("page_js_files_json", "[]")),
                "forms_json": str(asset.get("page_forms_json", "[]")),
                "api_calls_json": str(asset.get("page_api_calls_json", "[]")),
            }
        ]
        result = score_asset(asset, page_dicts)
        scored.append(result)

    _rank_results(scored)
    save_soft_targets(conn, target_name, scored)

    if top and top > 0:
        scored = scored[:top]

    tier_counts: dict[str, int] = {}
    for r in scored:
        tier_counts[r["tier"]] = tier_counts.get(r["tier"], 0) + 1

    return {
        "target": target_name,
        "total_assets": len(assets),
        "scored": len(scored),
        "tier_counts": tier_counts,
        "results": scored,
    }


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------


def format_text(payload: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("=" * 70)
    lines.append(f"  软柿子资产评分 — {payload['target']}")
    lines.append("=" * 70)
    lines.append(
        f"  资产总数: {payload['total_assets']} | "
        + " | ".join(f"{tier_emoji(t)} {t.replace('tier', '').replace('_', ' ')}: {c}" for t, c in sorted(payload["tier_counts"].items()))
    )
    lines.append("-" * 70)

    for idx, r in enumerate(payload["results"], start=1):
        emoji = tier_emoji(r["tier"])
        protocol = r.get("protocol", "https")
        value = r["asset_value"]
        port = f":{r['port']}" if r.get("port") and r["port"] not in (80, 443, 0) else ""
        url = f"{protocol}://{value}{port}"

        lines.append(f"\n{emoji} #{idx} [{r['total_score']}分] {url}")
        lines.append(f"   类型: {r['asset_type']} | 梯队: {r['tier']}")
        if r.get("tech_stack"):
            lines.append(f"   技术栈: {r['tech_stack']}")
        if r.get("page_title"):
            lines.append(f"   标题: {r['page_title'][:80]}")

        # Dimension breakdown
        dims = r["dimensions"]
        dim_names = [
            ("abandonment", "遗忘风险"),
            ("tech_age", "技术老旧"),
            ("attack_surface", "攻击面"),
            ("permission", "权限复杂度"),
            ("exposure", "暴露程度"),
            ("fingerprint", "指纹风险"),
            ("anomaly", "异常迹象"),
            ("pages_bonus", "页面加成"),
        ]
        clues_shown: list[str] = []
        for key, label in dim_names:
            d = dims.get(key, {})
            s = d.get("score", 0)
            if s > 0:
                clues_shown.append(f"{label}(+{s})")

        if clues_shown:
            lines.append(f"   加分: {' | '.join(clues_shown)}")
        if r.get("penalty", 0) > 0:
            lines.append(f"   扣分: -{r['penalty']}")

        # Show top 3 clues
        all_clues: list[str] = []
        for key in (
            "abandonment",
            "tech_age",
            "attack_surface",
            "permission",
            "exposure",
            "fingerprint",
            "anomaly",
            "pages_bonus",
        ):
            for c in dims.get(key, {}).get("clues", []):
                all_clues.append(c)
        for clue in all_clues[:3]:
            lines.append(f"   -> {clue}")

    lines.append("\n" + "=" * 70)
    lines.append("  测试建议:")
    tier1 = [r for r in payload["results"] if r["tier"] == "tier1_立即测试"]
    tier2 = [r for r in payload["results"] if r["tier"] == "tier2_高优先级"]
    if tier1:
        lines.append(f"  [!] 立即测试 ({len(tier1)}个): 投入40%时间")
        for r in tier1:
            lines.append(f"     - {r['asset_value']} ({r['total_score']}分)")
    if tier2:
        lines.append(f"  [+] 高优先级 ({len(tier2)}个): 投入35%时间")
        for r in tier2:
            lines.append(f"     - {r['asset_value']} ({r['total_score']}分)")
    tier3_count = sum(1 for r in payload["results"] if r["tier"] == "tier3_正常测试")
    if tier3_count:
        lines.append(f"  [~] 正常测试 ({tier3_count}个): 投入25%时间做基础覆盖")
    lines.append("=" * 70)
    return "\n".join(lines)


def list_soft_targets(conn: Any, *, target_name: str, top: int | None = None) -> dict[str, Any]:
    """Return persisted soft-target rankings without changing focus state."""
    ensure_soft_target_schema(conn)
    sql = """
        SELECT id, asset_id, asset_value, port, protocol, total_score, tier, rank, status,
               dimension_scores_json, evidence_json, failure_reason, updated_at
        FROM soft_targets
        WHERE target_name = ?
          AND status NOT IN ('failed','parked','completed','excluded')
        ORDER BY rank ASC, total_score DESC, id ASC
    """
    params: list[Any] = [target_name]
    if top and top > 0:
        sql += " LIMIT ?"
        params.append(top)
    rows = [compact_soft_target_row(dict(row)) for row in conn.execute(sql, params).fetchall()]
    focused = any(row.get("status") == "focused" for row in rows)
    return {
        "target": target_name,
        "count": len(rows),
        "results": rows,
        "empty": len(rows) == 0,
        "selection_required": bool(rows) and not focused,
        "message": "" if rows else "no available soft targets; run scoring or reopen parked/failed candidates",
    }


def format_focus_list(payload: dict[str, Any]) -> str:
    """Pretty-print persisted soft-target lifecycle state."""
    lines = [
        "=" * 70,
        f"  软柿子候选排序 — {payload['target']}",
        "=" * 70,
    ]
    if not payload["results"]:
        lines.append("  暂无 soft_targets 记录；先运行评分：")
        lines.append(f'  uv run python TOOLS/db/soft_target_scorer.py --target "{payload["target"]}" --top 30')
        return "\n".join(lines)
    for row in payload["results"]:
        port = f":{row['port']}" if row.get("port") and row["port"] not in (80, 443, 0) else ""
        url = f"{row.get('protocol') or 'https'}://{row['asset']}{port}"
        suffix = f" | failed={row['failure_reason']}" if row.get("failure_reason") else ""
        lines.append(
            f"#{row['rank']} id={row['id']} [{row['score']}分] {row['status']} "
            f"{url} {row['tier']} cost={row['estimated_test_cost']} "
            f"unknown={','.join(row['unknown_items']) or 'none'}{suffix}"
        )
    lines.append("-" * 70)
    lines.append("只展示排序，不自动选择主攻目标；必须由操作员明确指定 id 后再 --focus-id。")
    return "\n".join(lines)


def focus_soft_target(conn: Any, *, target_name: str, soft_target_id: int, actor: str = "operator") -> dict[str, Any]:
    """Mark one operator-selected candidate focused; never infer from rank."""
    ensure_soft_target_schema(conn)
    row = conn.execute(
        "SELECT * FROM soft_targets WHERE id = ? AND target_name = ?",
        (soft_target_id, target_name),
    ).fetchone()
    if row is None:
        raise ValueError(f"soft target not found for target={target_name}: {soft_target_id}")
    update_soft_target_status(
        conn,
        soft_target_id,
        "focused",
        reason="operator_selected_focus",
        evidence={"rank": row["rank"], "score": row["total_score"], "asset": row["asset_value"]},
        actor=actor,
    )
    work_item_id = _ensure_focus_work_item(conn, target_name=target_name, row=dict(row))
    return {
        "target": target_name,
        "id": soft_target_id,
        "asset_value": row["asset_value"],
        "status": "focused",
        "queued_work_item_id": work_item_id,
        "next_action": "dispatch entry_explore worker for the focused asset",
    }


def transition_soft_target(
    conn: Any,
    *,
    target_name: str,
    soft_target_id: int,
    status: str,
    reason: str,
    actor: str = "operator",
) -> dict[str, Any]:
    """Move one named-target candidate through lifecycle with target scoping."""
    ensure_soft_target_schema(conn)
    row = conn.execute(
        "SELECT * FROM soft_targets WHERE id = ? AND target_name = ?",
        (soft_target_id, target_name),
    ).fetchone()
    if row is None:
        raise ValueError(f"soft target not found for target={target_name}: {soft_target_id}")
    update_soft_target_status(
        conn,
        soft_target_id,
        status,
        reason=reason,
        evidence={"reason": reason, "asset": row["asset_value"], "rank": row["rank"], "score": row["total_score"]},
        actor=actor,
    )
    payload = {
        "target": target_name,
        "id": soft_target_id,
        "asset_value": row["asset_value"],
        "status": status,
        "reason": reason,
    }
    if status in {"failed", "parked"}:
        payload["next_candidates"] = list_soft_targets(conn, target_name=target_name, top=5)["results"]
        payload["selection_required"] = bool(payload["next_candidates"])
    return payload


def _ensure_focus_work_item(conn: Any, *, target_name: str, row: Mapping[str, Any]) -> int | None:
    """Create or reuse the first worker task for an explicitly focused soft target."""
    has_work_items = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='work_items'").fetchone()
    if not has_work_items:
        return None
    subject_id = str(row.get("asset_id") or row.get("id"))
    subject_table = "target_assets" if row.get("asset_id") else "soft_targets"
    active_statuses = ("queued", "claimed", "partial")
    existing = conn.execute(
        """
        SELECT id
        FROM work_items
        WHERE target_name = ?
          AND lane = 'entry_probe'
          AND subject_table = ?
          AND subject_id = ?
          AND status IN (?, ?, ?)
        ORDER BY id ASC
        LIMIT 1
        """,
        (target_name, subject_table, subject_id, *active_statuses),
    ).fetchone()
    if existing:
        return int(existing["id"])
    return create_work_item(
        conn,
        target_name=target_name,
        lane="entry_probe",
        subtype="focused_soft_target",
        subject_table=subject_table,
        subject_id=subject_id,
        title=f"Explore focused soft target {row.get('asset_value')}",
        objective="Collect compact facts for the operator-selected focused soft target; do not expand scope.",
        priority=max(80, int(row.get("total_score") or 0)),
        model_tier="haiku",
        reasoning_tier="low",
        auth_requirement="unknown",
        risk_class="safe_passive",
        timebox_minutes=20,
        heartbeat_minutes=5,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _resolve_db_path(args: argparse.Namespace) -> Path:
    if args.db:
        return Path(args.db)
    return find_db(args.target)


def _list_targets() -> list[dict[str, Any]]:
    """List all targets with their DBs."""
    targets: list[dict[str, Any]] = []
    dbs_dir = Path(__file__).resolve().parent.parent.parent / "dbs"
    for db_path in sorted(dbs_dir.glob("*.db"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            conn = connect(str(db_path))
            rows = conn.execute("SELECT target_name, domain FROM targets LIMIT 1").fetchall()
            if rows:
                row = rows[0]
                # Check for target_assets
                has_assets = (
                    conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='target_assets'").fetchone()[0] > 0
                )
                has_pages = conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='pages'").fetchone()[0] > 0
                asset_count = 0
                page_count = 0
                if has_assets:
                    asset_count = conn.execute("SELECT COUNT(*) FROM target_assets WHERE status != 'excluded'").fetchone()[0]
                if has_pages:
                    page_count = conn.execute("SELECT COUNT(*) FROM pages WHERE status != 'error'").fetchone()[0]
                targets.append(
                    {
                        "db_path": str(db_path),
                        "db_name": db_path.name,
                        "target_name": row["target_name"],
                        "domain": row["domain"] or "",
                        "asset_count": asset_count,
                        "page_count": page_count,
                    }
                )
            conn.close()
        except Exception:  # noqa: S112 - best-effort target list skips unreadable DBs.
            continue
    return targets


def _format_target_list(targets: list[dict[str, Any]]) -> str:
    """Pretty-print the target list."""
    if not targets:
        return "No targets found with target_assets table. Use asset-recon first."

    lines = [
        "=" * 60,
        "  Available Targets (with target_assets)",
        "=" * 60,
    ]
    for t in targets:
        lines.append(f"  {t['target_name']:20s}  assets={t['asset_count']:4d}  pages={t['page_count']:4d}  {t['db_name']}")
    lines.append("=" * 60)
    lines.append(f"  Total: {len(targets)} targets")
    return "\n".join(lines)


def main() -> None:
    # Force UTF-8 encoding for Windows GBK terminals
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(description="软柿子寻找 — 资产评分排序引擎")
    parser.add_argument("--target", required=True, help="target_name in the DB, or '_list_' to list all targets")
    parser.add_argument("--db", help="explicit DB path")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--top", type=int, default=0, help="limit to top N assets")
    parser.add_argument(
        "--list-ranked",
        action="store_true",
        help="list persisted soft-target ranking/status without rescoring",
    )
    parser.add_argument("--focus-id", type=int, help="operator-selected soft_targets.id to mark focused")
    parser.add_argument("--fail-id", type=int, help="soft_targets.id to mark failed before pivoting away")
    parser.add_argument("--park-id", type=int, help="soft_targets.id to park without deleting evidence")
    parser.add_argument("--reason", default="", help="status transition reason for --fail-id/--park-id")
    parser.add_argument("--actor", default="operator", help="actor recorded in soft_target_events")
    args = parser.parse_args()

    if args.target == "_list_":
        targets = _list_targets()
        if args.json:
            print(json.dumps(targets, ensure_ascii=True, default=str))
        else:
            print(_format_target_list(targets))
        return

    conn = connect(_resolve_db_path(args))
    try:
        if args.focus_id:
            payload = focus_soft_target(
                conn,
                target_name=args.target,
                soft_target_id=args.focus_id,
                actor=args.actor,
            )
        elif args.fail_id:
            payload = transition_soft_target(
                conn,
                target_name=args.target,
                soft_target_id=args.fail_id,
                status="failed",
                reason=args.reason or "focus_failed",
                actor=args.actor,
            )
        elif args.park_id:
            payload = transition_soft_target(
                conn,
                target_name=args.target,
                soft_target_id=args.park_id,
                status="parked",
                reason=args.reason or "operator_parked",
                actor=args.actor,
            )
        elif args.list_ranked:
            payload = list_soft_targets(conn, target_name=args.target, top=args.top or None)
        else:
            payload = run_scorer(conn, target_name=args.target, top=args.top or None)
    finally:
        conn.close()

    if args.json:
        print(json.dumps(payload, ensure_ascii=True, default=str))
    elif args.list_ranked:
        print(format_focus_list(payload))
    else:
        if args.focus_id or args.fail_id or args.park_id:
            print(json.dumps(payload, ensure_ascii=False, default=str))
        else:
            print(format_text(payload))


if __name__ == "__main__":
    main()
