"""SQLite 持久层。"""
from __future__ import annotations

import os
import sqlite3
from typing import Any, Iterable

from .config import settings

_SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS proofs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    artifact_digest TEXT NOT NULL,
    issuer          TEXT NOT NULL,
    parent_digest    TEXT,
    signature       TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- 同一条证明 (内容完全一致) 幂等去重。
CREATE UNIQUE INDEX IF NOT EXISTS ux_proofs_record
    ON proofs (artifact_digest, issuer, COALESCE(parent_digest, ''), signature);

CREATE INDEX IF NOT EXISTS ix_proofs_artifact
    ON proofs (artifact_digest);

CREATE INDEX IF NOT EXISTS ix_proofs_parent
    ON proofs (parent_digest);

CREATE TABLE IF NOT EXISTS revocations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    artifact_digest TEXT NOT NULL UNIQUE,
    reason          TEXT NOT NULL,
    revoked_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
"""


def _apply_pragmas(conn: sqlite3.Connection) -> None:
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")


def get_connection(db_path: str | None = None) -> sqlite3.Connection:
    path = db_path or settings.database_path
    if path != ":memory:":
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    _apply_pragmas(conn)
    return conn


def init_db(conn: sqlite3.Connection | None = None) -> None:
    """创建表结构与索引。测试时可传入内存连接。"""
    own_conn = conn is None
    conn = conn or get_connection()
    try:
        conn.executescript(_SCHEMA)
        conn.commit()
    finally:
        if own_conn:
            conn.close()


def row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {k: row[k] for k in row.keys()}


def fetch_proofs(
    conn: sqlite3.Connection,
    artifact_digest: str,
    at: str | None = None,
) -> list[dict[str, Any]]:
    """读取某制品的证明记录; 传入 at 时只返回 created_at <= at 的记录。"""
    if at is None:
        rows: Iterable[sqlite3.Row] = conn.execute(
            "SELECT * FROM proofs WHERE artifact_digest = ? ORDER BY id",
            (artifact_digest,),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM proofs WHERE artifact_digest = ? AND created_at <= ?"
            " ORDER BY id",
            (artifact_digest, at),
        ).fetchall()
    return [row_to_dict(r) for r in rows]


def fetch_revocation(
    conn: sqlite3.Connection,
    artifact_digest: str,
    at: str | None = None,
) -> dict[str, Any] | None:
    """读取撤销记录; 传入 at 时仅 revoked_at <= at 的撤销视为生效。"""
    if at is None:
        row = conn.execute(
            "SELECT * FROM revocations WHERE artifact_digest = ?",
            (artifact_digest,),
        ).fetchone()
    else:
        row = conn.execute(
            "SELECT * FROM revocations WHERE artifact_digest = ? AND revoked_at <= ?",
            (artifact_digest, at),
        ).fetchone()
    return row_to_dict(row) if row else None
