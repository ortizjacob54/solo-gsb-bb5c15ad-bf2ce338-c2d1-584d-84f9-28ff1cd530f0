"""RFC3339 时间戳解析与数据库时间格式互转。

数据库中的 created_at / revoked_at 由 SQLite
``strftime('%Y-%m-%dT%H:%M:%fZ', 'now')`` 生成 (UTC, 毫秒, Z 后缀),
历史时点校验 (``?at=``) 的解析与比较都围绕这一格式进行。
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

# 严格 RFC3339: 日期 + T/t + 时间 (+可选小数秒) + 显式时区偏移 (Z/z 或 ±HH:MM)。
_RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})$"
)


def parse_rfc3339_utc(raw: str) -> datetime:
    """解析 RFC3339 时间戳并归一化为 UTC。

    必须带显式时区偏移; 非法输入抛出 ValueError。
    """
    text = raw.strip()
    if not _RFC3339_RE.match(text):
        raise ValueError(f"at 不是合法的 RFC3339 时间戳: {raw!r}")
    normalized = text[:-1] + "+00:00" if text[-1] in ("Z", "z") else text
    try:
        dt = datetime.fromisoformat(normalized)
    except ValueError:
        raise ValueError(f"at 不是合法的 RFC3339 时间戳: {raw!r}") from None
    return dt.astimezone(timezone.utc)


def format_utc_ms(dt: datetime) -> str:
    """格式化为与 SQLite 默认值一致的 UTC 毫秒串 (字典序可比较)。

    截断到毫秒与库存储精度对齐, 保证 ``created_at <= at`` 的字符串比较
    在边界上与数值比较一致。
    """
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"
