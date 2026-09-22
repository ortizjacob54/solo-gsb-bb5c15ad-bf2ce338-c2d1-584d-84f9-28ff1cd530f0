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

-- 信任根版本: 名称唯一, 一经创建不可变 (不提供更新/删除接口)。
CREATE TABLE IF NOT EXISTS trust_root_versions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- 版本携带的 Ed25519 公钥集合; position 保留提交顺序。
-- 整组公钥与其版本在同一事务中提交, 提交前其他连接不可见,
-- 因此任何读取方都不会看到“半套公钥”。
CREATE TABLE IF NOT EXISTS trust_root_keys (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    version_id INTEGER NOT NULL REFERENCES trust_root_versions(id),
    position   INTEGER NOT NULL,
    public_key TEXT NOT NULL,
    UNIQUE (version_id, position),
    UNIQUE (version_id, public_key)
);

CREATE INDEX IF NOT EXISTS ix_trust_root_keys_version
    ON trust_root_keys (version_id);

-- 当前激活版本: 单行 (id 恒为 1), 通过 UPSERT 原子切换。
CREATE TABLE IF NOT EXISTS trust_root_state (
    id                INTEGER PRIMARY KEY CHECK (id = 1),
    active_version_id INTEGER NOT NULL REFERENCES trust_root_versions(id)
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


def _trust_root_version(
    conn: sqlite3.Connection,
    version_row: sqlite3.Row | None,
    active_name: str | None,
) -> dict[str, Any] | None:
    """把版本行组装为对外的版本字典 (含公钥集合与激活状态)。"""
    if version_row is None:
        return None
    key_rows = conn.execute(
        "SELECT public_key FROM trust_root_keys WHERE version_id = ? ORDER BY position",
        (version_row["id"],),
    ).fetchall()
    return {
        "name": version_row["name"],
        "description": version_row["description"],
        "public_keys": [r["public_key"] for r in key_rows],
        "created_at": version_row["created_at"],
        "active": version_row["name"] == active_name,
    }


def _fetch_active_version_name(conn: sqlite3.Connection) -> str | None:
    row = conn.execute(
        "SELECT v.name AS name FROM trust_root_state s"
        " JOIN trust_root_versions v ON v.id = s.active_version_id"
        " WHERE s.id = 1"
    ).fetchone()
    return row["name"] if row else None


def create_trust_root_version(
    conn: sqlite3.Connection, name: str, public_keys: list[str], description: str
) -> dict[str, Any]:
    """在单个事务内创建不可变版本并写入全部公钥, 成功后整体可见。

    名称重复时抛出 sqlite3.IntegrityError (唯一索引), 由路由层映射为 409。
    """
    try:
        cur = conn.execute(
            "INSERT INTO trust_root_versions (name, description) VALUES (?, ?)",
            (name, description),
        )
        version_id = cur.lastrowid
        conn.executemany(
            "INSERT INTO trust_root_keys (version_id, position, public_key)"
            " VALUES (?, ?, ?)",
            [(version_id, i, key) for i, key in enumerate(public_keys)],
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    row = conn.execute(
        "SELECT * FROM trust_root_versions WHERE id = ?", (version_id,)
    ).fetchone()
    out = _trust_root_version(conn, row, None)
    assert out is not None
    out["active"] = False
    return out


def list_trust_root_versions(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """返回全部版本 (按创建顺序), 各自标注是否为当前激活版本。"""
    active_name = _fetch_active_version_name(conn)
    rows = conn.execute(
        "SELECT * FROM trust_root_versions ORDER BY id"
    ).fetchall()
    return [_trust_root_version(conn, r, active_name) for r in rows]


def fetch_trust_root_version_by_name(
    conn: sqlite3.Connection, name: str
) -> dict[str, Any] | None:
    """按名称读取版本 (含公钥集合与激活状态); 不存在返回 None。"""
    active_name = _fetch_active_version_name(conn)
    row = conn.execute(
        "SELECT * FROM trust_root_versions WHERE name = ?", (name,)
    ).fetchone()
    return _trust_root_version(conn, row, active_name)


def fetch_active_trust_root(
    conn: sqlite3.Connection,
) -> tuple[str | None, frozenset[str]]:
    """读取当前激活版本 (名称, 公钥集合)。

    名称与公钥在同一查询的同一快照中取得, 与激活用的单行 UPSERT 配合,
    保证并发切换/校验时不会读到半套公钥。未配置激活版本时返回 (None, frozenset())。
    """
    rows = conn.execute(
        "SELECT v.name AS name, k.public_key AS public_key"
        " FROM trust_root_state s"
        " JOIN trust_root_versions v ON v.id = s.active_version_id"
        " JOIN trust_root_keys k ON k.version_id = v.id"
        " WHERE s.id = 1"
        " ORDER BY k.position"
    ).fetchall()
    if not rows:
        return None, frozenset()
    return rows[0]["name"], frozenset(r["public_key"] for r in rows)


def activate_trust_root_version(conn: sqlite3.Connection, name: str) -> bool:
    """原子地把当前激活版本切换为 name。

    单条 UPSERT 语句完成切换。目标版本不存在时返回 False (由路由层映射为 404)。
    """
    version = conn.execute(
        "SELECT id FROM trust_root_versions WHERE name = ?", (name,)
    ).fetchone()
    if version is None:
        return False
    conn.execute(
        "INSERT INTO trust_root_state (id, active_version_id) VALUES (1, ?)"
        " ON CONFLICT(id) DO UPDATE SET active_version_id = excluded.active_version_id",
        (version["id"],),
    )
    conn.commit()
    return True
