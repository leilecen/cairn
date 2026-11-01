"""通用落库/工具库（TOOLS 内共享）。

主要模块：
- store_kit: schema 感知的落库助手（列校验、枚举校验、唯一约束去重、完整性自检）
"""

from .store_kit import (  # noqa: F401
    INTEGRITY_RULES,
    EnumViolation,
    SchemaError,
    StoreKit,
    check_integrity,
)

__all__ = ["StoreKit", "SchemaError", "EnumViolation", "check_integrity", "INTEGRITY_RULES"]
