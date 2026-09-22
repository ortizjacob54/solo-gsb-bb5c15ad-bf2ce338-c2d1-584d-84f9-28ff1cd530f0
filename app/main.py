"""FastAPI 入口: 记录写入 / 制品校验 / 撤销 / 查询接口。"""
from __future__ import annotations

import dataclasses
import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, Response

from . import crypto
from .config import settings
from .database import (
    activate_trust_root_version,
    create_trust_root_version,
    fetch_active_trust_root,
    fetch_proofs,
    fetch_revocation,
    fetch_trust_root_version_by_name,
    get_connection,
    init_db,
    list_trust_root_versions,
    row_to_dict,
)
from .schemas import (
    GenericMessage,
    ProofIn,
    RevokeIn,
    RevokeResponse,
    TrustRootActivateResponse,
    TrustRootCreateResponse,
    TrustRootIn,
    TrustRootListResponse,
    WriteProofResponse,
)
from .timeutil import parse_rfc3339_utc
from .verifier import verify_artifact


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
            "固定使用指定名称的信任根版本校验; 未知版本返回 400。"
            "不传时使用当前激活版本; 尚未配置任何版本时回退到 "
            "TRUSTED_ROOT_ISSUERS 环境变量行为。"
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

    # 解析本次校验使用的信任根集合:
    # 指定 root_version -> 固定该版本 (未知 -> 400);
    # 未指定 -> 当前激活版本; 无激活版本 -> 环境变量 TRUSTED_ROOT_ISSUERS。
    cfg = settings
    trust_meta: dict[str, Any] | None = None
    if root_version is not None:
        version = fetch_trust_root_version_by_name(conn, root_version.strip())
        if version is None:
            raise HTTPException(
                status_code=400,
                detail=f"未知的信任根版本: {root_version!r}",
            )
        cfg = dataclasses.replace(
            settings, trusted_root_issuers=frozenset(version["public_keys"])
        )
        trust_meta = {
            "version": version["name"],
            "pinned": True,
            "active": version["active"],
        }
    else:
        active_name, active_keys = fetch_active_trust_root(conn)
        if active_name is not None:
            cfg = dataclasses.replace(settings, trusted_root_issuers=active_keys)
            trust_meta = {"version": active_name, "pinned": False, "active": True}

    result = verify_artifact(conn, artifact_digest, cfg, at=at_dt)
    if result["status"] == "NOT_FOUND":
        raise HTTPException(status_code=404, detail=result["failure"]["detail"])
    if trust_meta is not None:
        result["trust_root"] = trust_meta
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
    response_model=TrustRootCreateResponse,
    status_code=201,
    tags=["trust-roots"],
    summary="创建不可变的信任根版本 (唯一名称 + Ed25519 公钥集合)",
)
def create_trust_root(
    payload: TrustRootIn, conn: sqlite3.Connection = Depends(db)
) -> dict[str, Any]:
    if not payload.public_keys:
        raise HTTPException(
            status_code=400, detail="public_keys 至少包含一个非空的 Ed25519 公钥"
        )
    # 提前校验公钥格式, 不合法的版本拒绝入库。
    for key in payload.public_keys:
        try:
            crypto.decode_public_key(key)
        except (crypto.KeyDecodeError, ValueError) as exc:
            raise HTTPException(
                status_code=400, detail=f"公钥非法 ({key[:16]}...): {exc}"
            ) from exc

    try:
        version = create_trust_root_version(
            conn,
            name=payload.name,
            public_keys=payload.public_keys,
            description=payload.description,
        )
    except sqlite3.IntegrityError as exc:
        raise HTTPException(
            status_code=409, detail=f"信任根版本 {payload.name!r} 已存在"
        ) from exc
    return {"status": "CREATED", "version": version}


@app.get(
    "/trust-roots",
    response_model=TrustRootListResponse,
    tags=["trust-roots"],
    summary="列出全部信任根版本及其激活状态",
)
def list_trust_roots(conn: sqlite3.Connection = Depends(db)) -> dict[str, Any]:
    versions = list_trust_root_versions(conn)
    active = next((v["name"] for v in versions if v["active"]), None)
    return {"status": "OK", "active_version": active, "versions": versions}


@app.put(
    "/trust-roots/{name}/activate",
    response_model=TrustRootActivateResponse,
    tags=["trust-roots"],
    summary="原子切换当前激活的信任根版本",
)
def activate_trust_root(
    name: str, conn: sqlite3.Connection = Depends(db)
) -> dict[str, Any]:
    if not activate_trust_root_version(conn, name.strip()):
        raise HTTPException(
            status_code=404, detail=f"信任根版本 {name!r} 不存在"
        )
    version = fetch_trust_root_version_by_name(conn, name.strip())
    return {"status": "ACTIVATED", "active_version": version}
