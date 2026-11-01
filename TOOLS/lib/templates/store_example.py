# -*- coding: utf-8 -*-
"""落库脚本模板 —— 复制这个文件开始写新目标的事实入库。

为什么必须用 `StoreKit` 而不是裸 `sqlite3`（实战踩到的 5 个坑）：
  1. 写错列名 → 立刻 SchemaError 并列出可用列（不会静默丢字段）
  2. 显式传 created_at=None → 自动剔除（不会 KeyError）
  3. evidence_type 写错 → 立刻 EnumViolation 并列出合法值
  4. js_signals 同指纹重复 → upsert 自动改判 update（不会整批炸）
  5. 落库后 check_integrity() 自动扫描空关键字段

用法：把本文件复制到 `tmp/<slug>/write_facts.py` 后改造。
运行：`.venv/Scripts/python.exe tmp/<slug>/write_facts.py`
"""

import sys
from pathlib import Path

# 向上找到仓库根（含 TOOLS/lib/store_kit.py 的那一层）
ROOT = next(p for p in Path(__file__).resolve().parents if (p / "TOOLS" / "lib" / "store_kit.py").exists())
sys.path.insert(0, str(ROOT / "TOOLS"))

from lib.store_kit import StoreKit  # noqa: E402

TARGET = "example-target"


def main() -> int:
    # 自动解析 dbs/*.db（含日期后缀与中文名兼容），无需硬编码路径
    with StoreKit(TARGET) as db:
        db.report_counts(
            [
                "target_assets",
                "endpoint_observations",
                "js_signals",
                "coverage_ledger",
                "evidence_refs",
                "suspicious_points",
            ]
        )

        # ---------- 写 suspicious_points（主键 id，按 id upsert）
        db.upsert(
            "suspicious_points",
            {
                "id": "demo-001",
                "url": "https://api.example.com/v1/users/demo",
                "method": "POST",
                "test_type": "authz_object",
                "evidence": "tmp/example-target/demo_results.json",  # 指向原始产物
                "reasoning": "写清楚：测了什么、看到什么、为什么得这个结论",
                "risk": "low",
                "test_status": "refuted",
                "risk_score": 0,
                "created_at": None,  # 显式 None 也行 —— 会被自动剔除，交给 DB 默认值
            },
            key=["id"],
        )

        # ---------- 写 evidence_refs（evidence_type 必须在枚举内，写错会立刻报错）
        db.upsert(
            "evidence_refs",
            {
                "target_name": TARGET,
                "source_table": "suspicious_points",
                "source_id": 0,  # 无来源时填 0（NOT NULL）
                "evidence_type": "hypothesis",  # 合法值见 store_kit 报错提示
                "title": "示例证据：某端点越权假设证伪",
                "summary": "一句话结论 + 关键数据（请求数、响应长度、对照结果）",
                "ref_json": '{"verdict": "refuted"}',
            },
            key=["title", "target_name"],
        )

        # ---------- 写 coverage_ledger
        db.upsert(
            "coverage_ledger",
            {
                "target_name": TARGET,
                "item_key": "demo_surface",
                "category": "vuln",
                "status": "covered",  # covered / unknown / uncovered / blocked（无 partial）
                "confidence": "high",
                "evidence_refs_json": "[1]",
                "summary": "该面已闭合",
                "created_at": None,
                "updated_at": None,
            },
            key=["item_key", "target_name"],
        )

        # ---------- 落库后自检（有问题会明确列出 表→行→列）
        problems = db.check_integrity()
        if problems:
            print("\n⚠ 自检发现问题，请补齐后再收尾：")
            for table, bad in problems.items():
                print(f"  {table}: {len(bad)} 处")

    return 0


if __name__ == "__main__":
    sys.exit(main())
