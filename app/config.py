"""运行配置, 全部来自环境变量。"""
from __future__ import annotations

import os
from dataclasses import dataclass

from .crypto import KeyDecodeError, decode_public_key


@dataclass(frozen=True)
class Settings:
    database_path: str
    # 受信任的根签发者公钥集合 (Base64)。为空时退化为“任意自签名根均可信任”。
    trusted_root_issuers: frozenset[str]
    # 单次校验允许遍历的最大链长度, 防御异常数据导致的资源消耗。
    max_chain_depth: int


def _parse_trusted_roots(raw: str) -> frozenset[str]:
    issuers: set[str] = set()
    for item in raw.split(","):
        issuer = item.strip()
        if not issuer:
            continue
        try:
            decode_public_key(issuer)
        except KeyDecodeError:
            raise RuntimeError(
                "环境变量 TRUSTED_ROOT_ISSUERS 中存在非法的 Ed25519 公钥: "
                f"{issuer[:16]}..."
            ) from None
        issuers.add(issuer)
    return frozenset(issuers)


def get_settings() -> Settings:
    return Settings(
        database_path=os.environ.get("DATABASE_PATH", "data/proofs.db"),
        trusted_root_issuers=_parse_trusted_roots(
            os.environ.get("TRUSTED_ROOT_ISSUERS", "")
        ),
        max_chain_depth=int(os.environ.get("MAX_CHAIN_DEPTH", "256")),
    )


settings = get_settings()
