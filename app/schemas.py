"""请求/响应模型。"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator


class ProofIn(BaseModel):
    artifact_digest: str = Field(
        ..., min_length=1, description="被证明制品的摘要 (如 sha256:<hex>)"
    )
    issuer: str = Field(
        ...,
        min_length=1,
        description="签发者公钥, Base64 编码的 Ed25519 公钥 (32 字节)",
    )
    parent_digest: str | None = Field(
        None, description="父制品摘要; 为空表示这是根证明"
    )
    signature: str = Field(
        ..., min_length=1, description="对规范化载荷的 Ed25519 签名 (Base64)"
    )

    @field_validator("artifact_digest", "issuer", "signature", "parent_digest")
    @classmethod
    def _strip(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip()
        return v or None


class RevokeIn(BaseModel):
    artifact_digest: str = Field(..., min_length=1)
    reason: str = Field(..., min_length=1, max_length=1024)

    @field_validator("artifact_digest", "reason")
    @classmethod
    def _strip(cls, v: str) -> str:
        return v.strip()


class WriteProofResponse(BaseModel):
    status: str
    proof_id: int
    deduplicated: bool = False
    forks_existing: bool = False
    record_count_for_artifact: int


class RevokeResponse(BaseModel):
    status: str
    artifact_digest: str
    reason: str
    revoked_at: str | None = None
    already_revoked: bool = False


class GenericMessage(BaseModel):
    status: str
    detail: str
    proof: dict[str, Any] | None = None
    proofs: list[dict[str, Any]] | None = None
    revocations: list[dict[str, Any]] | None = None


# ---------- 信任根版本 ----------


class TrustRootIn(BaseModel):
    name: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description=(
            "版本唯一名称, 字母/数字/._- 组成, 用于 URL 与固定引用"
            " (?root_version=)"
        ),
    )
    public_keys: list[str] = Field(
        ...,
        min_length=1,
        description="该版本信任的 Ed25519 公钥集合 (Base64), 至少一个",
    )
    description: str = Field("", max_length=2048, description="版本说明")

    @field_validator("name")
    @classmethod
    def _strip_name(cls, v: str) -> str:
        return v.strip()

    @field_validator("description")
    @classmethod
    def _strip_description(cls, v: str) -> str:
        return v.strip()

    @field_validator("public_keys")
    @classmethod
    def _normalize_keys(cls, values: list[str]) -> list[str]:
        cleaned = [v.strip() for v in values if v is not None and v.strip()]
        if not cleaned:
            raise ValueError("public_keys 至少需要一个公钥")
        # 去重但保留首次出现顺序。
        seen: set[str] = set()
        unique: list[str] = []
        for key in cleaned:
            if key not in seen:
                seen.add(key)
                unique.append(key)
        return unique


class TrustRootResponse(BaseModel):
    name: str
    description: str
    public_keys: list[str]
    created_at: str
    is_active: bool = False
    activated_at: str | None = None


class TrustRootListResponse(BaseModel):
    status: str
    active_version: str | None = None
    effective_source: str
    trust_roots: list[TrustRootResponse]
