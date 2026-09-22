"""FastAPI 入口: 记录写入 / 制品校验 / 撤销 / 查询 / 信任根版本接口。"""
from __future__ import annotations

import dataclasses
import re
import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, Response

from . import crypto
from .config import settings
from .database import (
    TrustRootConflict,
    TrustRootNotFound,
    activate_trust_root,
    create_trust_root,
    fetch_active_root,
    fetch_named_root_keys,
    fetch_proofs,
    fetch_revocation,
    get_connection,
    init_db,
    list_trust_roots,
    row_to_dict,
)
from .schemas import (
    GenericMessage,
    ProofIn,
    RevokeIn,
    RevokeResponse,
    TrustRootIn,
    TrustRootListResponse,
    TrustRootResponse,
    WriteProofResponse,
)
from .timeutil import parse_rfc3339_utc
from .verifier import verify_artifact

# 版本名用于 URL 路径与查询参数, 仅允许 URL 安全字符。
_TRUST_ROOT_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")

# GET /trust-roots 的 effective_source 取值。
_SOURCE_ACTIVE_VERSION = "active_trust_root_version"
_SOURCE_ENV = "TRUSTED_ROOT_ISSUERS"
_SOURCE_DEV = "dev_mode_any_self_signed_root"


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="Supply Chain Proof Chain API",
    description=(
        "接收有向证明记录 (Ed25519 签名), 从根递归校验父证明链; "
        "分叉或撤销祖先时返回可定位的失败路径, 成功时返回有序信任链。"
    ),
    version="1.0.0",
    lifespan=lifespan,
)


def db() -> sqlite3.Connection:
    conn = get_connection()
    try:
        yield conn
    finally:
        conn.close()


@app.get("/health", tags=["meta"])
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post(
    "/proofs",
    response_model=WriteProofResponse,
    tags=["proofs"],
    summary="写入一条证明记录",
)
def write_proof(
    payload: ProofIn,
    response: Response,
    conn: sqlite3.Connection = Depends(db),
) -> dict[str, Any]:
    # 提前校验公钥/签名格式, 不合法的记录拒绝入库。
    try:
        crypto.decode_public_key(payload.issuer)
    except (crypto.KeyDecodeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f"issuer 公钥非法: {exc}") from exc
    crypto.canonical_message(payload.artifact_digest, payload.parent_digest)

    existing = fetch_proofs(conn, payload.artifact_digest)
    is_duplicate = any(
        r["issuer"] == payload.issuer
        and (r["parent_digest"] or None) == payload.parent_digest
        and r["signature"] == payload.signature
        for r in existing
    )

    if is_duplicate:
        response.status_code = 200
        proof_id = next(
            r["id"]
            for r in existing
            if r["issuer"] == payload.issuer
            and (r["parent_digest"] or None) == payload.parent_digest
            and r["signature"] == payload.signature
        )
        return {
            "status": "ACCEPTED",
            "proof_id": proof_id,
            "deduplicated": True,
            "forks_existing": len({(r["issuer"], r["signature"]) for r in existing}) > 1,
            "record_count_for_artifact": len(existing),
        }

    cur = conn.execute(
        "INSERT INTO proofs (artifact_digest, issuer, parent_digest, signature)"
        " VALUES (?, ?, ?, ?)",
        (
            payload.artifact_digest,
            payload.issuer,
            payload.parent_digest,
            payload.signature,
        ),
    )
    conn.commit()
    response.status_code = 201

    total = len(existing) + 1
    return {
        "status": "ACCEPTED",
        "proof_id": cur.lastrowid,
        "deduplicated": False,
        "forks_existing": total > 1,
        "record_count_for_artifact": total,
    }


@app.get(
    "/proofs/artifact/{artifact_digest}",
    tags=["proofs"],
    summary="列出某制品的全部证明记录",
)
def list_proofs(
    artifact_digest: str, conn: sqlite3.Connection = Depends(db)
) -> dict[str, Any]:
    rows = fetch_proofs(conn, artifact_digest)
    if not rows:
        raise HTTPException(status_code=404, detail="未找到该制品的证明记录")
    return {"status": "OK", "artifact_digest": artifact_digest, "proofs": rows}


@app.get(
    "/verify/{artifact_digest}",
    tags=["verify"],
    summary="从根递归校验制品的完整证明链",
)
def verify(
    artifact_digest: str,
    at: str | None = Query(
        default=None,
        description=(
            "历史时点 (RFC3339 UTC, 如 2026-09-22T08:00:00Z)。"
            "传入时只基于 created_at/revoked_at <= at 的数据求值, "
            "响应附带 evaluated_at。"
        ),
    ),
    root_version: str | None = Query(
        default=None,
        description=(
            "固定使用指定名称的信任根版本进行根校验; 未指定时使用当前激活版本,"
            "未配置任何版本时退回 TRUSTED_ROOT_ISSUERS 行为。未知版本返回 400。"
        ),
    ),
    conn: sqlite3.Connection = Depends(db),
) -> dict[str, Any]:
    at_dt: datetime | None = None
    if at is not None:
        try:
            at_dt = parse_rfc3339_utc(at)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if at_dt > datetime.now(timezone.utc):
            raise HTTPException(
                status_code=400, detail="at 晚于当前时间, 无法对未来时点求值"
            )

    if root_version is not None:
        root_version = root_version.strip() or None

    # 解析本次校验使用的信任根集合:
    # - 指定 root_version: 固定该版本 (未知版本 400), 与激活状态无关;
    # - 未指定: 优先当前激活版本; 无激活版本时保持 TRUSTED_ROOT_ISSUERS 行为
    #   (为空则开发模式, 任意自签名根均可)。
    # 公钥集合在一次单条查询中读出, 整个校验期间固定, 不随并发激活变化。
    effective_version: str | None = None
    trusted_issuers: frozenset[str] | None
    if root_version is not None:
        trusted_issuers = fetch_named_root_keys(conn, root_version)
        if trusted_issuers is None:
            raise HTTPException(
                status_code=400,
                detail=f"未知的信任根版本: {root_version}",
            )
        effective_version = root_version
    else:
        active = fetch_active_root(conn)
        if active is not None:
            effective_version, trusted_issuers = active
        else:
            trusted_issuers = settings.trusted_root_issuers

    cfg = dataclasses.replace(settings, trusted_root_issuers=trusted_issuers)
    result = verify_artifact(conn, artifact_digest, cfg, at=at_dt)
    if result["status"] == "NOT_FOUND":
        raise HTTPException(status_code=404, detail=result["failure"]["detail"])
    if effective_version is not None:
        result["root_version"] = effective_version
    return result


@app.post(
    "/revocations",
    response_model=RevokeResponse,
    tags=["revocations"],
    summary="撤销一个制品 (其所有下游校验将失败)",
)
def revoke_artifact(
    payload: RevokeIn,
    response: Response,
    conn: sqlite3.Connection = Depends(db),
) -> dict[str, Any]:
    existing = fetch_revocation(conn, payload.artifact_digest)
    if existing:
        response.status_code = 200
        return {
            "status": "REVOKED",
            "artifact_digest": payload.artifact_digest,
            "reason": existing["reason"],
            "revoked_at": existing["revoked_at"],
            "already_revoked": True,
        }

    conn.execute(
        "INSERT INTO revocations (artifact_digest, reason) VALUES (?, ?)",
        (payload.artifact_digest, payload.reason),
    )
    conn.commit()
    response.status_code = 201
    row = fetch_revocation(conn, payload.artifact_digest)
    return {
        "status": "REVOKED",
        "artifact_digest": payload.artifact_digest,
        "reason": row["reason"],
        "revoked_at": row["revoked_at"],
        "already_revoked": False,
    }


@app.get("/revocations", tags=["revocations"], summary="列出全部撤销记录")
def list_revocations(conn: sqlite3.Connection = Depends(db)) -> dict[str, Any]:
    rows = [
        row_to_dict(r)
        for r in conn.execute("SELECT * FROM revocations ORDER BY id").fetchall()
    ]
    return {"status": "OK", "revocations": rows}


@app.get(
    "/revocations/{artifact_digest}",
    tags=["revocations"],
    summary="查询单个制品的撤销状态",
)
def get_revocation(
    artifact_digest: str, conn: sqlite3.Connection = Depends(db)
) -> GenericMessage:
    row = fetch_revocation(conn, artifact_digest)
    if not row:
        raise HTTPException(status_code=404, detail="该制品未被撤销")
    return GenericMessage(status="REVOKED", detail=row["reason"], proof=row)


# ---------- 信任根版本 ----------


@app.post(
    "/trust-roots",
    response_model=TrustRootResponse,
    tags=["trust-roots"],
    summary="创建不可变的信任根版本 (唯一名称 + Ed25519 公钥集合 + 说明)",
    status_code=201,
)
def create_trust_root_version(
    payload: TrustRootIn,
    response: Response,
    conn: sqlite3.Connection = Depends(db),
) -> dict[str, Any]:
    if not _TRUST_ROOT_NAME_RE.match(payload.name):
        raise HTTPException(
            status_code=400,
            detail=(
                "name 仅允许 1-128 个字母、数字、点、下划线或连字符"
                " (A-Za-z0-9._-)"
            ),
        )
    # 公钥必须全部可解码为 Ed25519 公钥, 任一非法则拒绝创建。
    for key in payload.public_keys:
        try:
            crypto.decode_public_key(key)
        except (crypto.KeyDecodeError, ValueError) as exc:
            raise HTTPException(
                status_code=400, detail=f"存在非法的 Ed25519 公钥: {exc}"
            ) from exc

    try:
        version = create_trust_root(
            conn,
            payload.name,
            payload.public_keys,
            payload.description,
        )
    except TrustRootConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    response.status_code = 201
    return version


@app.put(
    "/trust-roots/{name}/activate",
    response_model=TrustRootResponse,
    tags=["trust-roots"],
    summary="原子切换当前激活的信任根版本",
)
def activate_trust_root_version(
    name: str, conn: sqlite3.Connection = Depends(db)
) -> dict[str, Any]:
    name = name.strip()
    try:
        return activate_trust_root(conn, name)
    except TrustRootNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get(
    "/trust-roots",
    response_model=TrustRootListResponse,
    tags=["trust-roots"],
    summary="列出全部信任根版本及激活状态",
)
def list_trust_root_versions(
    conn: sqlite3.Connection = Depends(db),
) -> dict[str, Any]:
    # 版本列表与激活标记来自同一单条 SELECT 的同一快照,
    # active_version 直接由该结果推导, 与并发切换不会错配。
    versions = list_trust_roots(conn)
    active = next((v["name"] for v in versions if v["is_active"]), None)
    if active is not None:
        effective_source = _SOURCE_ACTIVE_VERSION
    elif settings.trusted_root_issuers:
        effective_source = _SOURCE_ENV
    else:
        effective_source = _SOURCE_DEV
    return {
        "status": "OK",
        "active_version": active,
        "effective_source": effective_source,
        "trust_roots": versions,
    }
