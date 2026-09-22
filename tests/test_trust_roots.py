"""信任根版本管理与 ?root_version 校验的端到端测试。"""
from __future__ import annotations

import sqlite3
import sys
import threading
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import crypto  # noqa: E402
from app.config import Settings  # noqa: E402
from app.database import (  # noqa: E402
    activate_trust_root_version,
    create_trust_root_version,
    fetch_active_trust_root,
    fetch_trust_root_version_by_name,
    get_connection,
    init_db,
)
from app.main import app, db  # noqa: E402


def _keypair():
    priv = Ed25519PrivateKey.generate()
    return priv, crypto.encode_public_key(priv.public_key())


def _post_root(client, priv, pub, artifact):
    sig = crypto.sign(priv, artifact, None)
    return client.post(
        "/proofs",
        json={
            "artifact_digest": artifact,
            "issuer": pub,
            "parent_digest": None,
            "signature": sig,
        },
    )


@pytest.fixture()
def client():
    """内存库 + 开发模式 (无环境信任根, 也尚无信任根版本)。"""
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    init_db(conn)

    def _db():
        yield conn

    app.dependency_overrides[db] = _db
    import app.main as main_mod

    main_mod.settings = Settings(
        database_path=":memory:",
        trusted_root_issuers=frozenset(),
        max_chain_depth=256,
    )
    try:
        with TestClient(app) as c:
            yield c, conn
    finally:
        app.dependency_overrides.clear()


def _create_version(client, name, keys, description=""):
    return client.post(
        "/trust-roots",
        json={
            "name": name,
            "public_keys": keys,
            "description": description,
        },
    )


# ---------- 创建版本 ----------


def test_create_trust_root_version(client):
    c, _ = client
    _, pub = _keypair()
    r = _create_version(c, "v1", [pub], "首个版本")
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["status"] == "CREATED"
    v = body["version"]
    assert v["name"] == "v1"
    assert v["public_keys"] == [pub]
    assert v["description"] == "首个版本"
    assert v["active"] is False
    assert "created_at" in v


def test_create_version_duplicate_name_409(client):
    c, _ = client
    _, pub = _keypair()
    assert _create_version(c, "v1", [pub]).status_code == 201
    r = _create_version(c, "v1", [pub], "不同说明也不行")
    assert r.status_code == 409


def test_create_version_invalid_key_400(client):
    c, _ = client
    r = _create_version(c, "v1", ["not-base64!!!"])
    assert r.status_code == 400


def test_create_version_empty_keys_400(client):
    c, _ = client
    r = c.post(
        "/trust-roots",
        json={"name": "v1", "public_keys": ["  "], "description": ""},
    )
    assert r.status_code == 400


def test_create_version_bad_name_422(client):
    c, _ = client
    _, pub = _keypair()
    for bad in ["", "has space", "-leading-dash", "中文", "a/b"]:
        r = _create_version(c, bad, [pub])
        assert r.status_code == 422, bad


def test_create_version_deduplicates_keys(client):
    c, _ = client
    _, pub = _keypair()
    r = _create_version(c, "v1", [pub, pub])
    assert r.status_code == 201
    assert r.json()["version"]["public_keys"] == [pub]


def test_version_immutable_no_update_endpoint(client):
    c, _ = client
    _, pub = _keypair()
    _create_version(c, "v1", [pub])
    # 不存在任何修改/删除接口: PUT/POST/DELETE 同名集合均不被接受
    assert c.put("/trust-roots", json={}).status_code in (404, 405)
    assert c.delete("/trust-roots/v1").status_code in (404, 405)


# ---------- 列表与激活 ----------


def test_list_versions_and_active_flag(client):
    c, _ = client
    _, p1 = _keypair()
    _, p2 = _keypair()
    _create_version(c, "v1", [p1])
    _create_version(c, "v2", [p2])

    body = c.get("/trust-roots").json()
    assert body["status"] == "OK"
    assert body["active_version"] is None
    assert [v["name"] for v in body["versions"]] == ["v1", "v2"]
    assert all(v["active"] is False for v in body["versions"])

    r = c.put("/trust-roots/v2/activate")
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "ACTIVATED"
    assert r.json()["active_version"]["name"] == "v2"
    assert r.json()["active_version"]["active"] is True

    body = c.get("/trust-roots").json()
    assert body["active_version"] == "v2"
    flags = {v["name"]: v["active"] for v in body["versions"]}
    assert flags == {"v1": False, "v2": True}


def test_activate_switch_is_atomic(client):
    c, _ = client
    _, p1 = _keypair()
    _, p2 = _keypair()
    _create_version(c, "v1", [p1])
    _create_version(c, "v2", [p2])

    assert c.put("/trust-roots/v1/activate").status_code == 200
    assert c.get("/trust-roots").json()["active_version"] == "v1"

    assert c.put("/trust-roots/v2/activate").status_code == 200
    assert c.get("/trust-roots").json()["active_version"] == "v2"
    # 重复激活同一版本仍然成功 (幂等)
    assert c.put("/trust-roots/v2/activate").status_code == 200


def test_activate_unknown_version_404(client):
    c, _ = client
    assert c.put("/trust-roots/ghost/activate").status_code == 404


# ---------- 校验: 环境变量回退 ----------


def test_verify_falls_back_to_env_dev_mode_when_no_versions(client):
    c, _ = client
    priv, pub = _keypair()
    _post_root(c, priv, pub, "sha256:root")
    body = c.get("/verify/sha256:root").json()
    assert body["status"] == "OK"
    # 回退到环境变量行为时不带 trust_root 元信息
    assert "trust_root" not in body


def test_verify_falls_back_to_configured_env_roots():
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    init_db(conn)
    app.dependency_overrides[db] = lambda: (yield conn)

    trusted_priv, trusted_pub = _keypair()
    rogue_priv, rogue_pub = _keypair()

    import app.main as main_mod

    main_mod.settings = Settings(
        ":memory:", frozenset({trusted_pub}), 256
    )
    try:
        with TestClient(app) as c:
            _post_root(c, rogue_priv, rogue_pub, "sha256:rogue")
            assert c.get("/verify/sha256:rogue").json()["status"] == "UNTRUSTED_ROOT"

            _post_root(c, trusted_priv, trusted_pub, "sha256:good")
            body = c.get("/verify/sha256:good").json()
            assert body["status"] == "OK"
            assert "trust_root" not in body

            # 创建但未激活的版本不影响环境变量回退
            _create_version(c, "future", [rogue_pub])
            assert c.get("/verify/sha256:good").json()["status"] == "OK"
    finally:
        app.dependency_overrides.clear()


# ---------- 校验: 激活版本与固定版本 ----------


def test_verify_uses_active_version(client):
    c, _ = client
    k1, p1 = _keypair()
    k2, p2 = _keypair()
    _create_version(c, "v1", [p1])
    _create_version(c, "v2", [p2])
    _post_root(c, k1, p1, "sha256:r1")
    _post_root(c, k2, p2, "sha256:r2")

    c.put("/trust-roots/v1/activate")
    body = c.get("/verify/sha256:r1").json()
    assert body["status"] == "OK"
    assert body["trust_root"] == {"version": "v1", "pinned": False, "active": True}
    assert c.get("/verify/sha256:r2").json()["status"] == "UNTRUSTED_ROOT"

    # 切换激活版本: 根信任判定立即整体改变
    c.put("/trust-roots/v2/activate")
    assert c.get("/verify/sha256:r2").json()["status"] == "OK"
    assert c.get("/trust-roots").json()["active_version"] == "v2"
    assert c.get("/verify/sha256:r1").json()["status"] == "UNTRUSTED_ROOT"


def test_verify_pinned_root_version_ignores_active_switch(client):
    c, _ = client
    k1, p1 = _keypair()
    k2, p2 = _keypair()
    _create_version(c, "v1", [p1])
    _create_version(c, "v2", [p2])
    _post_root(c, k1, p1, "sha256:r1")
    _post_root(c, k2, p2, "sha256:r2")
    c.put("/trust-roots/v2/activate")

    # 固定到非当前激活版本 v1: 仍按 v1 的公钥集合判定
    body = c.get("/verify/sha256:r1", params={"root_version": "v1"}).json()
    assert body["status"] == "OK"
    assert body["trust_root"] == {"version": "v1", "pinned": True, "active": False}
    body = c.get("/verify/sha256:r2", params={"root_version": "v1"}).json()
    assert body["status"] == "UNTRUSTED_ROOT"


def test_verify_pinned_multi_key_version(client):
    c, _ = client
    k1, p1 = _keypair()
    k2, p2 = _keypair()
    k3, p3 = _keypair()
    # 版本携带多个根公钥, 任一签发的根均被接受
    _create_version(c, "multi", [p1, p2, p3])
    c.put("/trust-roots/multi/activate")
    _post_root(c, k1, p1, "sha256:r-a")
    _post_root(c, k2, p2, "sha256:r-b")
    _post_root(c, k3, p3, "sha256:r-c")
    for d in ("sha256:r-a", "sha256:r-b", "sha256:r-c"):
        assert c.get(f"/verify/{d}").json()["status"] == "OK", d


def test_verify_unknown_root_version_400(client):
    c, _ = client
    priv, pub = _keypair()
    _post_root(c, priv, pub, "sha256:r")
    res = c.get("/verify/sha256:r", params={"root_version": "nope"})
    assert res.status_code == 400


def test_verify_root_version_with_history_at(client):
    c, conn = client
    k1, p1 = _keypair()
    _create_version(c, "v1", [p1])
    c.put("/trust-roots/v1/activate")
    _post_root(c, k1, p1, "sha256:r")
    conn.execute(
        "UPDATE proofs SET created_at = '2024-01-01T00:00:00.000Z'"
        " WHERE artifact_digest = 'sha256:r'"
    )
    conn.commit()
    # root_version 与历史时点 ?at= 可组合
    body = c.get(
        "/verify/sha256:r",
        params={"root_version": "v1", "at": "2999-01-01T00:00:00Z"},
    )
    assert body.status_code == 400  # 未来 at 仍然 400, 与是否固定版本无关
    body = c.get(
        "/verify/sha256:r",
        params={"root_version": "v1", "at": "2024-06-01T00:00:00Z"},
    ).json()
    assert body["status"] == "OK"
    assert body["evaluated_at"] == "2024-06-01T00:00:00.000Z"
    assert body["trust_root"]["version"] == "v1"


# ---------- 并发: 切换/校验不得读到半套公钥 ----------


def test_concurrent_activate_and_read_never_sees_half_key_set(tmp_path):
    db_path = tmp_path / "trust.db"
    import app.main as main_mod

    main_mod.settings = Settings(
        database_path=str(db_path),
        trusted_root_issuers=frozenset(),
        max_chain_depth=256,
    )
    init_db(get_connection(str(db_path)))

    setup = get_connection(str(db_path))
    a_keys = [crypto.encode_public_key(Ed25519PrivateKey.generate().public_key())
              for _ in range(3)]
    b_keys = [crypto.encode_public_key(Ed25519PrivateKey.generate().public_key())
              for _ in range(5)]
    create_trust_root_version(setup, "a", a_keys, "")
    create_trust_root_version(setup, "b", b_keys, "")
    activate_trust_root_version(setup, "a")
    setup.close()

    stop = threading.Event()
    errors: list[str] = []

    def activator():
        conn = get_connection(str(db_path))
        toggle = "a"
        try:
            for _ in range(200):
                toggle = "b" if toggle == "a" else "a"
                activate_trust_root_version(conn, toggle)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"activator: {exc!r}")
        finally:
            conn.close()
            stop.set()

    def active_reader():
        conn = get_connection(str(db_path))
        expect = {"a": frozenset(a_keys), "b": frozenset(b_keys)}
        try:
            for _ in range(300):
                name, keys = fetch_active_trust_root(conn)
                # 必须读到某一版本的完整公钥集合, 绝不允许空/半套/混合
                if name not in expect or keys != expect[name]:
                    errors.append(f"active reader saw partial set: {name} {len(keys)}")
                    return
        except Exception as exc:  # noqa: BLE001
            errors.append(f"active reader: {exc!r}")
        finally:
            conn.close()

    def pinned_reader():
        conn = get_connection(str(db_path))
        try:
            for _ in range(300):
                v = fetch_trust_root_version_by_name(conn, "a")
                assert v is not None
                # 版本不可变: 无论怎样切换, 固定版本始终是完整原始公钥集合
                if v["public_keys"] != a_keys:
                    errors.append("pinned version content changed")
                    return
        except Exception as exc:  # noqa: BLE001
            errors.append(f"pinned reader: {exc!r}")
        finally:
            conn.close()

    threads = [threading.Thread(target=activator)]
    threads += [threading.Thread(target=active_reader) for _ in range(3)]
    threads += [threading.Thread(target=pinned_reader) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors


def test_concurrent_verify_requests_consistent_key_set(tmp_path):
    """HTTP 层并发: 激活版本反复切换时, 校验结果只可能是 OK 或 UNTRUSTED_ROOT,
    绝不出现 5xx 或其它异常状态。每个请求使用独立文件连接, 贴近生产。"""
    db_path = str(tmp_path / "trust_http.db")
    init_db(get_connection(db_path))

    def _file_db():
        conn = get_connection(db_path)
        try:
            yield conn
        finally:
            conn.close()

    app.dependency_overrides[db] = _file_db
    try:
        ka, pa = _keypair()
        kb, pb = _keypair()
        with TestClient(app) as c:
            _create_version(c, "a", [pa])
            _create_version(c, "b", [pb])
            c.put("/trust-roots/a/activate")
            _post_root(c, ka, pa, "sha256:ra")
            _post_root(c, kb, pb, "sha256:rb")

            stop = threading.Event()
            errors: list[str] = []

            def activator():
                toggle = "a"
                for _ in range(100):
                    toggle = "b" if toggle == "a" else "a"
                    r = c.put(f"/trust-roots/{toggle}/activate")
                    if r.status_code != 200:
                        errors.append(f"activate {r.status_code}")
                        return
                stop.set()

            def verifier():
                # 两个制品的证明均已落库后才启动, 启动后状态只可能是
                # OK (当前激活版本包含其根公钥) 或 UNTRUSTED_ROOT。
                while not stop.is_set():
                    for digest in ("sha256:ra", "sha256:rb"):
                        r = c.get(f"/verify/{digest}")
                        if r.status_code != 200:
                            errors.append(f"verify {r.status_code}")
                            return
                        if r.json()["status"] not in ("OK", "UNTRUSTED_ROOT"):
                            errors.append(f"unexpected status {r.json()['status']}")
                            return

            def pinned_verifier():
                while not stop.is_set():
                    r = c.get("/verify/sha256:ra", params={"root_version": "a"})
                    if r.status_code != 200 or r.json()["status"] != "OK":
                        errors.append("pinned verify drifted")
                        return

            threads = [
                threading.Thread(target=activator),
                threading.Thread(target=verifier),
                threading.Thread(target=pinned_verifier),
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            assert not errors, errors
    finally:
        app.dependency_overrides.clear()
