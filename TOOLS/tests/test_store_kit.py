"""store_kit 回归测试 — 每个用例对应 2026-09-23 踩过的一个真实坑。

运行：.venv/Scripts/python.exe TOOLS/tests/test_store_kit.py
"""

from __future__ import annotations

import sqlite3
import sys
import tempfile
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_TOOLS))

from lib.store_kit import EnumViolation, SchemaError, StoreKit  # noqa: E402

# 复刻踩坑表的**真实 DDL 片段**（含 CHECK 枚举与复合唯一约束）
SCHEMA = """
CREATE TABLE targets (
    id INTEGER PRIMARY KEY, target_name TEXT, domain TEXT
);
CREATE TABLE suspicious_points (
    id TEXT PRIMARY KEY,
    url TEXT, param TEXT, method TEXT DEFAULT 'GET',
    test_type TEXT, evidence TEXT, reasoning TEXT,
    risk TEXT DEFAULT 'Medium', test_status TEXT DEFAULT 'untested',
    risk_score INTEGER DEFAULT 0,
    notes TEXT, response_summary TEXT,
    created_at TEXT DEFAULT (datetime('now','localtime'))
);
CREATE TABLE coverage_ledger (
    id INTEGER PRIMARY KEY,
    target_name TEXT NOT NULL,
    item_key TEXT NOT NULL, category TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'unknown',
    evidence_refs_json TEXT NOT NULL DEFAULT '[]',
    summary TEXT, created_at TEXT DEFAULT (datetime('now','localtime'))
);
CREATE TABLE evidence_refs (
    id INTEGER PRIMARY KEY,
    target_name TEXT NOT NULL, source_table TEXT, source_id INTEGER NOT NULL,
    evidence_type TEXT, title TEXT, summary TEXT, ref_json TEXT,
    created_at TEXT DEFAULT (datetime('now','localtime')),
    CHECK (evidence_type IN (
        'request','response','diff','screenshot','js_signal',
        'hypothesis','semantic_profile','coverage_ledger','repeater_tab','operator_note'
    ))
);
CREATE TABLE operator_inbox (
    id INTEGER PRIMARY KEY, target_name TEXT,
    kind TEXT, title TEXT, detail TEXT, blocking INTEGER, status TEXT,
    CHECK (kind IN (
        'choose_asset','login_required','secondary_account_required','role_account_required',
        'screenshot_needed','confirm_scope','confirm_high_risk','manual_review','report_decision',
        'evidence_capture','focus_switch','registration_required','burp_action_required',
        'scope_cluster_confirm','blocked_decision'
    ))
);
CREATE TABLE js_signals (
    id TEXT PRIMARY KEY, target_id INTEGER, js_file_id INTEGER,
    source_kind TEXT NOT NULL, signal_type TEXT NOT NULL,
    method TEXT, url TEXT, path TEXT, host TEXT,
    evidence_snippet TEXT, evidence_location TEXT,
    confidence INTEGER DEFAULT 50, status TEXT DEFAULT 'new',
    created_at TEXT DEFAULT (datetime('now','localtime')),
    UNIQUE (js_file_id, signal_type, method, path, evidence_location)
);
"""


def _mkdb() -> Path:
    p = Path(tempfile.mkdtemp()) / "test.db"
    c = sqlite3.connect(str(p))
    c.executescript(SCHEMA)
    c.execute("INSERT INTO targets (id, target_name, domain) VALUES (1,'example-target','example-target.com')")
    c.commit()
    c.close()
    return p


PASS = 0
FAIL = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ✓ {name}")
    else:
        FAIL += 1
        print(f"  ✗ {name}  {detail}")


def expect_raises(name: str, exc, fn, *, contains: str = "") -> None:
    global PASS, FAIL
    try:
        fn()
    except exc as e:
        if contains and contains not in str(e):
            FAIL += 1
            print(f"  ✗ {name}  —— 异常消息未包含 {contains!r}：{e}")
        else:
            PASS += 1
            print(f"  ✓ {name}")
    except Exception as e:  # noqa: BLE001
        FAIL += 1
        print(f"  ✗ {name}  —— 抛出了 {type(e).__name__} 而非 {exc.__name__}: {e}")
    else:
        FAIL += 1
        print(f"  ✗ {name}  —— 未抛异常")


def main() -> int:
    db = _mkdb()
    print(f"测试库：{db}\n")

    # ---------------------------------------------------------- 坑 1：未知列静默丢失
    print("坑 1：写错列名曾导致 reasoning 被静默吞掉")
    with StoreKit(db_path=db, verbose=False) as kit:
        expect_raises(
            "未知列抛 SchemaError 并列出可用列",
            SchemaError,
            lambda: kit.insert(
                "suspicious_points",
                {
                    "id": "sp-1",
                    "reasoning": "r",
                    "test_result": "应报错",
                },
            ),
            contains="test_result",
        )
        # 确认消息里有可用列提示
        try:
            kit.insert("suspicious_points", {"id": "x", "bogus_col": 1})
        except SchemaError as e:
            check("报错消息包含可用列清单", "test_type" in str(e), str(e)[:120])

    # ---------------------------------------------------------- 坑 2：显式传默认值列
    print("\n坑 2：created_at 有默认值，显式传 None 曾触发 KeyError")
    with StoreKit(db_path=db, verbose=False) as kit:
        rowid = kit.insert(
            "suspicious_points",
            {
                "id": "sp-2",
                "reasoning": "有理由",
                "evidence": "tmp/x.json",
                "test_status": "confirmed_low",
                "created_at": None,
            },
        )
        check("created_at=None 被自动剔除", rowid > 0)
        r = kit.cur.execute("SELECT created_at, reasoning, evidence FROM suspicious_points WHERE id=?", ("sp-2",)).fetchone()
        check("created_at 由 DB 默认值填充", bool(r[0]), f"got {r[0]!r}")
        check("reasoning / evidence 完整落库", r[1] == "有理由" and r[2] == "tmp/x.json")

    # ---------------------------------------------------------- 坑 3：CHECK 枚举
    print('\n坑 3：evidence_type="recon" 曾被 CHECK 约束拒绝')
    with StoreKit(db_path=db, verbose=False) as kit:
        expect_raises(
            "evidence_type 非法值抛 EnumViolation",
            EnumViolation,
            lambda: kit.insert(
                "evidence_refs",
                {
                    "target_name": "example-target",
                    "source_id": 0,
                    "evidence_type": "recon",
                    "title": "t",
                    "summary": "s",
                },
            ),
            contains="coverage_ledger",
        )
        try:
            kit.insert(
                "evidence_refs",
                {"target_name": "t", "source_id": 0, "evidence_type": "network", "title": "a", "summary": "b"},
            )
        except EnumViolation as e:
            check(
                "枚举报错列出全部合法值",
                all(v in str(e) for v in ("request", "js_signal", "operator_note")),
                str(e)[:160],
            )

        expect_raises(
            'operator_inbox.kind="provide_credential" 被拒',
            EnumViolation,
            lambda: kit.insert(
                "operator_inbox",
                {
                    "target_name": "t",
                    "kind": "provide_credential",
                    "title": "x",
                },
            ),
            contains="login_required",
        )

        # 合法值应通过
        kit.insert(
            "evidence_refs",
            {
                "target_name": "example-target",
                "source_id": 0,
                "evidence_type": "coverage_ledger",
                "title": "ok",
                "summary": "s",
            },
        )
        check("合法枚举值正常写入", True)

    # ---------------------------------------------------------- 坑 4：复合唯一约束
    print("\n坑 4：js_signals 复合唯一约束曾导致整批 IntegrityError")
    with StoreKit(db_path=db, verbose=False) as kit:
        rec = {
            "id": "sig-a",
            "target_id": 1,
            "js_file_id": 3,
            "source_kind": "bundle_ast",
            "signal_type": "api_endpoint",
            "method": "GET",
            "path": "/user/ticket/fetch",
            "evidence_location": "main.js",
            "evidence_snippet": "G_=e=>ke.get(...)",
        }
        r1 = kit.upsert("js_signals", rec, key=["js_file_id", "signal_type", "method", "path", "evidence_location"])
        check("首次 upsert → insert", r1 == "insert", r1)

        rec2 = dict(rec, id="sig-b", evidence_snippet="Y_=e=>ke.get(...)")
        r2 = kit.upsert("js_signals", rec2, key=["js_file_id", "signal_type", "method", "path", "evidence_location"])
        check("同指纹二次 upsert → update（不炸唯一约束）", r2 == "update", r2)
        n = kit.scalar("SELECT COUNT(*) FROM js_signals WHERE path='/user/ticket/fetch'")
        check("同指纹只保留 1 行", n == 1, f"got {n}")
        snippet = kit.scalar("SELECT evidence_snippet FROM js_signals WHERE path='/user/ticket/fetch'")
        check("upsert 更新了内容", snippet == "Y_=e=>ke.get(...)", snippet)

        # 不同 method 应视为不同信号
        r3 = kit.upsert(
            "js_signals",
            dict(rec, id="sig-c", method="POST"),
            key=["js_file_id", "signal_type", "method", "path", "evidence_location"],
        )
        check("不同 method → 新插入", r3 == "insert", r3)

    # ---------------------------------------------------------- 坑 5：完整性自检
    print("\n坑 5：落库后需自检空关键字段（reasoning/evidence 曾被吞）")
    # 先造一批"坏数据"，再检查能否被检出
    with StoreKit(db_path=db, verbose=False) as kit:
        kit.cur.execute("INSERT INTO suspicious_points (id, reasoning, evidence) VALUES ('bad-1', NULL, '')")
        kit.cur.execute("INSERT INTO coverage_ledger (target_name,item_key,category,status) VALUES ('t','bad-key','vuln','covered')")
        kit.cur.execute(
            "INSERT INTO js_signals (id,target_id,js_file_id,source_kind,signal_type,method,path,evidence_snippet,evidence_location) "
            "VALUES ('bad-sig',1,3,'bundle_ast','api_endpoint','GET','/x','','loc')"
        )
        problems = kit.check_integrity()
        check("检出 suspicious_points 的空字段", "suspicious_points" in problems, str(problems))
        sp_bad = {c for _, c in problems.get("suspicious_points", [])}
        check("    检出 reasoning 为空", "reasoning" in sp_bad, str(sp_bad))
        check("    检出 evidence 为空", "evidence" in sp_bad, str(sp_bad))
        cl = problems.get("coverage_ledger", [])
        check("检出 coverage_ledger 空证据引用", any(c == "evidence_refs_json" for _, c in cl), str(cl))
        js = problems.get("js_signals", [])
        check("检出 js_signals 空 evidence_snippet", any(c == "evidence_snippet" for _, c in js), str(js))

        # 补齐后应通过
        kit.cur.execute("UPDATE suspicious_points SET reasoning='r', evidence='e'")
        kit.cur.execute("UPDATE coverage_ledger SET evidence_refs_json='[1]'")
        kit.cur.execute("UPDATE js_signals SET evidence_snippet='x'")
        problems2 = kit.check_integrity()
        check("补齐后自检通过", not problems2, str(problems2))

        # raise_on_fail 行为
        kit.cur.execute("UPDATE suspicious_points SET reasoning='' WHERE id='bad-1'")
        expect_raises(
            "raise_on_fail=True 时抛 SchemaError",
            SchemaError,
            lambda: kit.check_integrity(raise_on_fail=True),
            contains="完整性自检失败",
        )

    # ---------------------------------------------------------- 其他：NOT NULL / 备份 / 计数
    print("\n附加：NOT NULL 校验、备份、计数")
    with StoreKit(db_path=db, verbose=False) as kit:
        expect_raises(
            "缺 NOT NULL 且无默认值的列 → SchemaError",
            SchemaError,
            lambda: kit.insert("coverage_ledger", {"summary": "only summary"}),
            contains="item_key",
        )

    with StoreKit(db_path=db, verbose=False) as kit:
        b = kit.backup()
        check("备份文件生成", b is not None and b.is_file(), str(b))
        b2 = kit.backup()
        check("备份幂等（不覆盖）", b2 == b)

    with StoreKit(db_path=db, verbose=False) as kit:
        c = kit.counts(["suspicious_points", "coverage_ledger"])
        check("计数正常", c["suspicious_points"] >= 2 and c["coverage_ledger"] >= 1, str(c))
        tid = kit.target_id()
        check("target_id 解析", tid == 1, str(tid))

    # ---------------------------------------------------------- 事务原子性
    print("\n附加：异常整批回滚")
    before = None
    try:
        with StoreKit(db_path=db, verbose=False) as kit:
            kit.insert("coverage_ledger", {"target_name": "t", "item_key": "k1", "category": "vuln", "status": "covered"})
            before = kit.scalar("SELECT COUNT(*) FROM coverage_ledger WHERE item_key='k1'")
            raise RuntimeError("模拟中途失败")
    except RuntimeError:
        pass
    with StoreKit(db_path=db, verbose=False) as kit:
        after = kit.scalar("SELECT COUNT(*) FROM coverage_ledger WHERE item_key='k1'")
    check("异常时整批回滚（k1 未落库）", before == 1 and after == 0, f"before={before} after={after}")

    # ---------------------------------------------------------- 枚举解析正确性
    print("\n附加：枚举解析（coverage_ledger.status 在真实库里无 CHECK，靠规则约束）")
    # 在测试 schema 里给一个带枚举的表，验证解析逻辑本身
    with StoreKit(db_path=db, verbose=False) as kit:
        enums = kit.enums("evidence_refs")
        check(
            "解析出 evidence_refs.evidence_type 枚举",
            "evidence_type" in enums and "repeater_tab" in enums["evidence_type"],
            str(enums),
        )
        oi = kit.enums("operator_inbox")
        check("解析出 operator_inbox.kind 枚举", "kind" in oi and "blocked_decision" in oi["kind"], str(oi))
        cl = kit.enums("coverage_ledger")
        check("coverage_ledger 无 CHECK 时返回空（不误报）", cl == {}, str(cl))

        # 真实库里 status 枚举靠约定，store_kit 应能用 allow 参数拦住（可选增强）
        expect_raises(
            "evidence_refs 非法 evidence_type 被拦（二次确认）",
            EnumViolation,
            lambda: kit.insert(
                "evidence_refs",
                {"target_name": "t", "source_id": 0, "evidence_type": "recon", "title": "a", "summary": "b"},
            ),
            contains="request",
        )

    print(f"\n{'=' * 52}\n通过 {PASS} / 失败 {FAIL}\n{'=' * 52}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
