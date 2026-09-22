"""Ed25519 签名与签名载荷规范化。

信任模型:
- issuer 字段直接携带 Base64 编码的 Ed25519 公钥 (32 字节),
  即“密钥即身份”, 服务端不维护额外的签发者注册表。
- 签名内容为规范化后的字节串 canonical_message(...)。
"""
from __future__ import annotations

import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

__all__ = [
    "KeyDecodeError",
    "canonical_message",
    "decode_public_key",
    "encode_public_key",
    "sign",
    "verify",
]


class KeyDecodeError(ValueError):
    """issuer 公钥无法解码为 Ed25519 公钥。"""


def _b64_encode(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64_decode(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:  # pragma: no cover - cryptography raises binascii.Error
        raise ValueError(f"非法的 Base64 数据: {value!r}") from exc


def canonical_message(
    artifact_digest: str,
    parent_digest: str | None,
) -> bytes:
    """构造被签名的规范化字节串。

    格式 (NUL 字节分隔, 长度前缀杜绝字段拼接歧义)::

        SCIPROOF/v1\\n
        len(artifact_digest):<digest>\\n
        PARENT<len>:<parent 或空串>
    """
    artifact = artifact_digest.encode("utf-8")
    parent = (parent_digest or "").encode("utf-8")
    return b"".join(
        [
            b"SCIPROOF/v1\n",
            f"ARTIFACT:{len(artifact)}:".encode("ascii"),
            artifact,
            b"\n",
            f"PARENT:{len(parent)}:".encode("ascii"),
            parent,
        ]
    )


def decode_public_key(issuer: str) -> Ed25519PublicKey:
    """把 Base64 公钥字符串解码为 Ed25519PublicKey。"""
    raw = _b64_decode(issuer)
    try:
        key = Ed25519PublicKey.from_public_bytes(raw)
    except Exception as exc:
        raise KeyDecodeError("issuer 不是合法的 Ed25519 公钥") from exc
    return key


def encode_public_key(key: Ed25519PublicKey) -> str:
    return _b64_encode(key.public_bytes_raw())


def sign(
    private_key: Ed25519PrivateKey,
    artifact_digest: str,
    parent_digest: str | None,
) -> str:
    """用私钥对证明记录签名, 返回 Base64 签名。"""
    return _b64_encode(
        private_key.sign(canonical_message(artifact_digest, parent_digest))
    )


def verify(
    issuer: str,
    artifact_digest: str,
    parent_digest: str | None,
    signature_b64: str,
) -> bool:
    """验证签名, 任何环节失败均返回 False。"""
    try:
        key = decode_public_key(issuer)
        signature = _b64_decode(signature_b64)
        key.verify(signature, canonical_message(artifact_digest, parent_digest))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
