"""信任根版本管理接口与 ?root_version 固定版本校验的端到端测试。"""
from __future__ import annotations

import dataclasses
import sys
import threading
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import crypto  # noqa: E402
from app.config import Settings  # noqa: E402
from app.database import init_db  # noqa: E402
from app.main import app, db  # noqa: E402


def _keypair():
    priv = Ed25519PrivateKey.generate()
    return priv, crypto.encode_public_key(priv.public_key())


def _sign(priv, artifact, parent=None):
    return crypto.sign(priv, artifact, parent)


def _post_proof(client, priv, pub, artifact, parent=None, signature=None):
    sig = signature if signature is not None else _sign(priv, artifact, parent)
    return client.post(
        "/proofs",
        json={
            "artifact_digest": artifact,
            "issuer": pub,
            "parent_digest": parent,
            "signature": sig,
        },
    )


def _build_chain(client, priv, pub, n=3, prefix="r"):
    digests = [f"sha256:{prefix}-root"]
    r = _post_proof(client, priv, pub, digests[0])
    assert r.status_code == 201, r.text
    for i in range(1, n):
        d = f"sha256:{prefix}-a{i}"
        r = _post_proof(client, priv, pub, d, parent=digests[-1])
        assert r.status_code == 201, r.text
        digests.append(d)
    return digests


@pytest.fixture()
def client():
    import sqlite3

    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    init_db(conn)

    def _db():
        yield conn

    app.dependency_overrides[db] = _db
    import app.main as main_mod

    saved = main_mod.settings
    cfg = Settings(
        database_path=":memory:",
        trusted_root_issuers=frozenset(),
        max_chain_depth=256,
    )
    main_mod.settings = cfg
    try:
        with TestClient(app) as c:
            yield c, conn
    finally:
        main_mod.settings = saved
        app.dependency_overrides.clear()


def _create_version(c, name, keys, description=""):
    return c.post(
        "/trust-roots",
        json={
            "name": name,
            "public_keys": keys,
            "description": description,
        },
    )


# ---------- 创建 / 列表 / 激活 ----------


def test_create_trust_root_version(client):
    c, _ = client
    priv, pub = _keypair()
    r = _create_version(c, "v1", [pub], "initial root set")
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["name"] == "v1"
    assert body["public_keys"] == [pub]
    assert body["description"] == "initial root set"
    assert body["is_active"] is False
    assert body["activated_at"] is None
    assert body["created_at"]


def test_create_duplicate_name_conflict(client):
    c, _ = client
    _, pub1 = _keypair()
    _, pub2 = _keypair()
    assert _create_version(c, "same", [pub1]).status_code == 201
    r = _create_version(c, "same", [pub2])
    assert r.status_code == 409


def test_create_invalid_public_key_400(client):
    c, _ = client
    r = _create_version(c, "v1", ["not-a-key!!!"])
    assert r.status_code == 400


def test_create_empty_public_keys_422(client):
    c, _ = client
    r = c.post("/trust-roots", json={"name": "v1", "public_keys": []})
    assert r.status_code == 422


def test_create_invalid_name_400(client):
    c, _ = client
    _, pub = _keypair()
    for bad in ("bad/name", "bad name", "bad?name", ""):
        r = _create_version(c, bad, [pub])
        assert r.status_code in (400, 422), bad


def test_public_keys_deduplicated(client):
    c, _ = client
    _, pub = _keypair()
    r = _create_version(c, "v1", [pub, pub, f"  {pub}  "])
    assert r.status_code == 201, r.text
    assert r.json()["public_keys"] == [pub]


def test_list_versions_with_active_status(client):
    c, _ = client
    _, pub1 = _keypair()
    _, pub2 = _keypair()
    _create_version(c, "v1", [pub1])
    _create_version(c, "v2", [pub2])
    r = c.put("/trust-roots/v2/activate")
    assert r.status_code == 200
    assert r.json()["is_active"] is True

    body = c.get("/trust-roots").json()
    assert body["status"] == "OK"
    assert body["active_version"] == "v2"
    by_name = {v["name"]: v for v in body["trust_roots"]}
    assert by_name["v1"]["is_active"] is False
    assert by_name["v2"]["is_active"] is True
    assert by_name["v1"]["activated_at"] is None
    assert by_name["v2"]["activated_at"]


def test_activate_unknown_name_404(client):
    c, _ = client
    assert c.put("/trust-roots/ghost/activate").status_code == 404


def test_reactivate_same_version_idempotent(client):
    c, _ = client
    _, pub = _keypair()
    _create_version(c, "v1", [pub])
    r1 = c.put("/trust-roots/v1/activate")
    first = r1.json()["activated_at"]
    r2 = c.put("/trust-roots/v1/activate")
    assert r2.status_code == 200
    assert r2.json()["is_active"] is True


def test_activation_atomic_switch(client):
    c, _ = client
    a_priv, a_pub = _keypair()
    b_priv, b_pub = _keypair()
    digests_a = _build_chain(c, a_priv, a_pub, n=2, prefix="a")
    digests_b = _build_chain(c, b_priv, b_pub, n=2, prefix="b")
    _create_version(c, "va", [a_pub])
    _create_version(c, "vb", [b_pub])

    c.put("/trust-roots/va/activate")
    body = c.get(f"/verify/{digests_a[-1]}").json()
    assert body["status"] == "OK"
    assert body["root_version"] == "va"
    assert c.get(f"/verify/{digests_b[-1]}").json()["status"] == "UNTRUSTED_ROOT"

    c.put("/trust-roots/vb/activate")
    body = c.get(f"/trust-roots").json()
    assert body["active_version"] == "vb"
    assert c.get(f"/verify/{digests_b[-1]}").json()["status"] == "OK"
    assert c.get(f"/verify/{digests_a[-1]}").json()["status"] == "UNTRUSTED_ROOT"


# ---------- ?root_version 固定版本 ----------


def test_pin_version_independent_of_active(client):
    c, _ = client
    a_priv, a_pub = _keypair()
    b_priv, b_pub = _keypair()
    digests_a = _build_chain(c, a_priv, a_pub, n=1, prefix="pa")
    digests_b = _build_chain(c, b_priv, b_pub, n=1, prefix="pb")
    _create_version(c, "va", [a_pub])
    _create_version(c, "vb", [b_pub])
    c.put("/trust-roots/vb/activate")

    # 激活的是 vb, 但固定用 va 校验 A 仍成功
    body = c.get(f"/verify/{digests_a[-1]}?root_version=va").json()
    assert body["status"] == "OK"
    assert body["root_version"] == "va"
    # 固定用 va 校验 B -> 不信任
    body = c.get(f"/verify/{digests_b[-1]}?root_version=va").json()
    assert body["status"] == "UNTRUSTED_ROOT"
    # 未指定时仍走激活版本 vb
    body = c.get(f"/verify/{digests_b[-1]}").json()
    assert body["status"] == "OK"
    assert body["root_version"] == "vb"


def test_pin_inactive_version_ok(client):
    c, _ = client
    priv, pub = _keypair()
    digests = _build_chain(c, priv, pub, n=1, prefix="x")
    _create_version(c, "v1", [pub])
    # 从未激活, 固定引用仍可使用
    body = c.get(f"/verify/{digests[-1]}?root_version=v1").json()
    assert body["status"] == "OK"
    assert body["root_version"] == "v1"


def test_unknown_root_version_400(client):
    c, _ = client
    priv, pub = _keypair()
    _post_proof(c, priv, pub, "sha256:y")
    r = c.get("/verify/sha256:y?root_version=nope")
    assert r.status_code == 400


def test_root_version_checked_before_artifact_lookup(client):
    c, _ = client
    # 未知版本优先返回 400, 即使制品本身不存在
    r = c.get("/verify/sha256:missing?root_version=nope")
    assert r.status_code == 400


def test_root_version_whitespace_treated_as_unset(client):
    c, _ = client
    priv, pub = _keypair()
    _post_proof(c, priv, pub, "sha256:z")
    # 空白字符串与未传等价 -> 开发模式接受自签名根, 且不附带 root_version
    body = c.get("/verify/sha256:z", params={"root_version": "   "}).json()
    assert body["status"] == "OK"
    assert "root_version" not in body


def test_pinned_version_accepts_any_key_in_set(client):
    c, _ = client
    _, pub1 = _keypair()
    k2_priv, pub2 = _keypair()
    digests = _build_chain(c, k2_priv, pub2, n=1, prefix="multi")
    _create_version(c, "multi", [pub1, pub2])
    c.put("/trust-roots/multi/activate")
    body = c.get(f"/verify/{digests[-1]}").json()
    assert body["status"] == "OK"
    assert body["root_issuer"] == pub2


# ---------- 无激活版本时回退 TRUSTED_ROOT_ISSUERS ----------


def test_fallback_to_env_trusted_issuers():
    import sqlite3

    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    init_db(conn)
    app.dependency_overrides[db] = lambda: (yield conn)

    env_priv = Ed25519PrivateKey.generate()
    env_pub = crypto.encode_public_key(env_priv.public_key())
    rogue_priv, rogue_pub = _keypair()

    import app.main as main_mod

    saved = main_mod.settings
    main_mod.settings = Settings(":memory:", frozenset({env_pub}), 256)
    try:
        with TestClient(app) as c:
            listing = c.get("/trust-roots").json()
            assert listing["active_version"] is None
            assert listing["effective_source"] == "TRUSTED_ROOT_ISSUERS"

            _post_proof(c, env_priv, env_pub, "sha256:env-root")
            assert c.get("/verify/sha256:env-root").json()["status"] == "OK"
            _post_proof(c, rogue_priv, rogue_pub, "sha256:rogue-root")
            assert (
                c.get("/verify/sha256:rogue-root").json()["status"]
                == "UNTRUSTED_ROOT"
            )

            # 一旦创建并激活版本, 环境变量集合不再参与
            _, new_pub = _keypair()
            r = _create_version(c, "managed", [new_pub])
            assert r.status_code == 201
            c.put("/trust-roots/managed/activate")
            body = c.get("/verify/sha256:env-root").json()
            assert body["status"] == "UNTRUSTED_ROOT"
            assert body["root_version"] == "managed"
    finally:
        main_mod.settings = saved
        app.dependency_overrides.clear()


def test_fallback_dev_mode_when_nothing_configured(client):
    c, _ = client
    body = c.get("/trust-roots").json()
    assert body["active_version"] is None
    assert body["effective_source"] == "dev_mode_any_self_signed_root"
    priv, pub = _keypair()
    _post_proof(c, priv, pub, "sha256:dev")
    body = c.get("/verify/sha256:dev").json()
    assert body["status"] == "OK"
    assert "root_version" not in body


def test_version_immutable_no_keys_added(client):
    c, conn = client
    _, pub1 = _keypair()
    _, pub2 = _keypair()
    _create_version(c, "v1", [pub1])
    c.put("/trust-roots/v1/activate")
    # 持久层无追加公钥的写接口; 同名再创建冲突, 公钥集合保持原样
    assert _create_version(c, "v1", [pub2]).status_code == 409
    body = c.get("/trust-roots").json()
    v1 = next(v for v in body["trust_roots"] if v["name"] == "v1")
    assert v1["public_keys"] == [pub1]


# ---------- 并发: 激活切换与校验不得读到半套公钥 ----------


def test_concurrent_activate_and_verify_no_torn_keys(tmp_path):
    """多线程交替激活 va/vb 并校验, 任何一次校验的结论都必须与
    其使用的版本公钥集合自洽 (OK/UNTRUSTED_ROOT), 且不得出现 5xx。"""
    import app.database as db_mod
    import app.main as main_mod

    db_path = str(tmp_path / "concurrent.db")
    init_db(db_mod.get_connection(db_path))

    saved_path = db_mod.settings.database_path
    saved_settings = main_mod.settings
    db_mod.settings = dataclasses.replace(saved_settings, database_path=db_path)
    main_mod.settings = db_mod.settings
    try:
        a_priv, a_pub = _keypair()
        b_priv, b_pub = _keypair()
        with TestClient(app) as setup:
            da = _build_chain(setup, a_priv, a_pub, n=2, prefix="ca")
            db_ = _build_chain(setup, b_priv, b_pub, n=2, prefix="cb")
            assert _create_version(setup, "va", [a_pub]).status_code == 201
            assert _create_version(setup, "vb", [b_pub]).status_code == 201
            setup.put("/trust-roots/va/activate")

        errors: list[AssertionError] = []
        errors_lock = threading.Lock()

        def worker(wid: int, iterations: int):
            try:
                with TestClient(app) as c:
                    for i in range(iterations):
                        if (wid + i) % 3 == 0:
                            name = "va" if i % 2 == 0 else "vb"
                            r = c.put(f"/trust-roots/{name}/activate")
                            assert r.status_code == 200, r.text
                        else:
                            target = da[-1] if i % 2 == 0 else db_[-1]
                            expect_pub = a_pub if i % 2 == 0 else b_pub
                            r = c.get(f"/verify/{target}")
                            assert r.status_code == 200, r.text
                            body = r.json()
                            assert "root_version" in body
                            if body["status"] == "OK":
                                assert body["root_version"] in ("va", "vb")
                                if body["root_version"] == "va":
                                    assert body["root_issuer"] == expect_pub
                            else:
                                assert body["status"] == "UNTRUSTED_ROOT"
            except AssertionError as exc:  # noqa: BLE001
                with errors_lock:
                    errors.append(exc)

        threads = [
            threading.Thread(target=worker, args=(wid, 25))
            for wid in range(6)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors, errors
    finally:
        db_mod.settings = dataclasses.replace(
            saved_settings, database_path=saved_path
        )
        main_mod.settings = saved_settings
