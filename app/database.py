"""SQLite 持久层。"""
from __future__ import annotations

import os
import sqlite3
from typing import Any, Iterable

from .config import settings


class TrustRootConflict(Exception):
    """信任根版本名称已存在 (唯一名称冲突)。"""


class TrustRootNotFound(Exception):
    """指定的信任根版本不存在。"""

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

-- 信任根版本: 不可变。创建后不更新/不删除, 公钥集合固定。
CREATE TABLE IF NOT EXISTS trust_root_versions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- 每个版本的 Ed25519 公钥集合; 仅随版本创建插入, 之后只读。
CREATE TABLE IF NOT EXISTS trust_root_keys (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    version_id INTEGER NOT NULL REFERENCES trust_root_versions(id),
    position   INTEGER NOT NULL,
    public_key TEXT NOT NULL,
    UNIQUE (version_id, public_key)
);

-- 最多一行: 当前激活版本。激活为单行 UPSERT, 对外部观察者是原子切换。
CREATE TABLE IF NOT EXISTS trust_root_state (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    version_id INTEGER NOT NULL REFERENCES trust_root_versions(id),
    activated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
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


# ---------- 信任根版本 ----------


def create_trust_root(
    conn: sqlite3.Connection,
    name: str,
    public_keys: list[str],
    description: str = "",
) -> dict[str, Any]:
    """创建不可变的信任根版本, 版本与其公钥集合在同一事务中提交。

    名称重复抛出 TrustRootConflict。
    """
    try:
        with conn:
            cur = conn.execute(
                "INSERT INTO trust_root_versions (name, description)"
                " VALUES (?, ?)",
                (name, description),
            )
            version_id = cur.lastrowid
            conn.executemany(
                "INSERT INTO trust_root_keys (version_id, position, public_key)"
                " VALUES (?, ?, ?)",
                [
                    (version_id, position, key)
                    for position, key in enumerate(public_keys)
                ],
            )
    except sqlite3.IntegrityError as exc:
        raise TrustRootConflict(f"信任根版本 {name!r} 已存在") from exc
    out = get_trust_root(conn, name)
    assert out is not None
    return out


def activate_trust_root(conn: sqlite3.Connection, name: str) -> dict[str, Any]:
    """把当前激活版本原子切换为 name; 版本不存在抛出 TrustRootNotFound。

    单行 UPSERT 与 busy_timeout 共同保证: 并发激活串行化, 校验方要么读到
    旧版本的完整公钥集合, 要么读到新版本的完整公钥集合, 不会读到半套。
    """
    row = conn.execute(
        "SELECT id FROM trust_root_versions WHERE name = ?",
        (name,),
    ).fetchone()
    if row is None:
        raise TrustRootNotFound(f"信任根版本 {name!r} 不存在")
    with conn:
        conn.execute(
            "INSERT INTO trust_root_state (id, version_id) VALUES (1, ?)"
            " ON CONFLICT(id) DO UPDATE SET"
            " version_id = excluded.version_id,"
            " activated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')",
            (row["id"],),
        )
    out = get_trust_root(conn, name)
    assert out is not None
    return out


def get_trust_root(conn: sqlite3.Connection, name: str) -> dict[str, Any] | None:
    """按名称读取单个版本 (含公钥集合与激活状态)。"""
    row = conn.execute(
        "SELECT v.id, v.name, v.description, v.created_at,"
        " CASE WHEN s.version_id IS NULL THEN 0 ELSE 1 END AS is_active,"
        " s.activated_at"
        " FROM trust_root_versions v"
        " LEFT JOIN trust_root_state s ON s.version_id = v.id"
        " WHERE v.name = ?",
        (name,),
    ).fetchone()
    if row is None:
        return None
    keys = [
        r["public_key"]
        for r in conn.execute(
            "SELECT public_key FROM trust_root_keys WHERE version_id = ?"
            " ORDER BY position",
            (row["id"],),
        ).fetchall()
    ]
    return {
        "name": row["name"],
        "description": row["description"],
        "public_keys": keys,
        "created_at": row["created_at"],
        "is_active": bool(row["is_active"]),
        "activated_at": row["activated_at"],
    }


def list_trust_roots(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """列出全部信任根版本 (含公钥集合与激活状态), 按创建顺序。

    版本与公钥在同一单条 SELECT 中读取, 取同一事务快照,
    与并发激活并发时也不会出现版本与公钥集合错配。
    """
    # Ed25519 公钥为标准 Base64, 不含逗号, 可用 ',' 作为 GROUP_CONCAT 分隔符。
    rows = conn.execute(
        "SELECT v.id, v.name, v.description, v.created_at,"
        " CASE WHEN s.version_id IS NULL THEN 0 ELSE 1 END AS is_active,"
        " s.activated_at,"
        " (SELECT GROUP_CONCAT(public_key, ',') FROM ("
        "     SELECT public_key FROM trust_root_keys"
        "     WHERE version_id = v.id ORDER BY position"
        " )) AS joined_keys"
        " FROM trust_root_versions v"
        " LEFT JOIN trust_root_state s ON s.version_id = v.id"
        " ORDER BY v.id"
    ).fetchall()
    result: list[dict[str, Any]] = []
    for row in rows:
        keys = row["joined_keys"].split(",") if row["joined_keys"] else []
        result.append(
            {
                "name": row["name"],
                "description": row["description"],
                "public_keys": keys,
                "created_at": row["created_at"],
                "is_active": bool(row["is_active"]),
                "activated_at": row["activated_at"],
            }
        )
    return result


def fetch_active_root(
    conn: sqlite3.Connection,
) -> tuple[str, frozenset[str]] | None:
    """读取当前激活版本的 (名称, 公钥集合)。

    名称与公钥集合在同一条 SELECT 中取同一事务快照, 与并发激活并发时
    二者不会错配; 激活是单行 UPSERT, 故公钥集合要么是旧版整套、
    要么是新版整套, 不会读到半套。未配置激活版本时返回 None,
    调用方退回 TRUSTED_ROOT_ISSUERS 行为。
    """
    # Ed25519 公钥为标准 Base64, 不含逗号。
    row = conn.execute(
        "SELECT v.name AS name,"
        " (SELECT GROUP_CONCAT(public_key, ',') FROM ("
        "     SELECT public_key FROM trust_root_keys"
        "     WHERE version_id = v.id ORDER BY position"
        " )) AS joined_keys"
        " FROM trust_root_state s"
        " JOIN trust_root_versions v ON v.id = s.version_id"
    ).fetchone()
    if row is None:
        return None
    keys = frozenset(row["joined_keys"].split(",")) if row["joined_keys"] else frozenset()
    return row["name"], keys


def fetch_named_root_keys(
    conn: sqlite3.Connection, name: str
) -> frozenset[str] | None:
    """固定读取某已创建版本的公钥集合; 版本不存在返回 None。

    版本公钥不可变且在单条 SELECT 中读取, 并发激活/校验时无需加锁
    也不会读到半套公钥。
    """
    row = conn.execute(
        "SELECT id FROM trust_root_versions WHERE name = ?",
        (name,),
    ).fetchone()
    if row is None:
        return None
    rows = conn.execute(
        "SELECT public_key FROM trust_root_keys WHERE version_id = ?"
        " ORDER BY position",
        (row["id"],),
    ).fetchall()
    return frozenset(r["public_key"] for r in rows)
