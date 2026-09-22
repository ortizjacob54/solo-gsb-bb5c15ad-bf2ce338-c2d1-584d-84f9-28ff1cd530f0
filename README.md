# 供应链证明链校验 API

基于 **FastAPI + SQLite + Ed25519** 的有向证明记录（attestation）与信任链校验服务。

- 接收制品证明记录：`artifact_digest`、`issuer`（Ed25519 公钥）、`parent_digest`、`signature`
- 写入时校验公钥格式；**校验时验证 Ed25519 签名**，并从被校验制品出发**沿父链递归直到信任根**
- 同一制品出现**分叉**（多条不同证明）或链上存在**被撤销祖先**时，返回带有序节点的 **可定位失败路径**
- 校验成功时返回**有序信任链**（target → … → root）
- 支持 `?at=<RFC3339 UTC>` **历史时点校验**：只基于该时点已可见的证明与已生效的撤销求值，晚到分叉/后续撤销不改变更早时点的结论
- 提供记录写入、制品校验、撤销、记录查询接口
- Dockerfile + Docker Compose 一键启动，SQLite 数据持久化到命名卷

## 1. 快速启动

### 方式一：Docker Compose（推荐）

```bash
docker compose up --build -d
```

服务地址与端口：

| 用途 | 地址 |
| --- | --- |
| API 基础地址 | <http://localhost:8080> |
| 健康检查 | <http://localhost:8080/health> |
| Swagger 交互文档 | <http://localhost:8080/docs> |
| ReDoc 文档 | <http://localhost:8080/redoc> |
| OpenAPI Schema | <http://localhost:8080/openapi.json> |

停止与清理：

```bash
docker compose down          # 停止
docker compose down -v       # 停止并删除数据库卷
```

### 方式二：本地直接运行

```bash
python3 -m pip install -r requirements.txt
DATABASE_PATH=data/proofs.db python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8080
```

### 一键演示（成功链 / 撤销祖先 / 祖先分叉）

```bash
# 服务启动后, 另开终端:
python3 demo/demo.py
# 或指定地址:
BASE_URL=http://localhost:8080 python3 demo/demo.py
```

## 2. 信任模型

- **密钥即身份**：`issuer` 字段直接携带 Base64 编码的 Ed25519 公钥（32 字节），服务端不维护额外的签发者注册表。
- **签名载荷**（canonical message）为长度前缀的 NUL/换行分隔字节串，定义见 `app/crypto.py`：

  ```
  SCIPROOF/v1
  ARTIFACT:<len>:<artifact_digest>
  PARENT:<len>:<parent_digest 或空串>
  ```

- **信任根**：根证明的 `parent_digest` 为空。根的 `issuer` 必须在 `TRUSTED_ROOT_ISSUERS` 环境变量中（多个公钥用逗号分隔）。**该变量留空时为开发模式：任意自签名根均被接受，生产环境务必配置。**

生成信任根密钥对（Python）：

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from app.crypto import encode_public_key
priv = Ed25519PrivateKey.generate()
print(encode_public_key(priv.public_key()))   # 填入 docker-compose.yml 的 TRUSTED_ROOT_ISSUERS
```

## 3. API 一览

所有接口前缀：`http://localhost:8080`

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `POST` | `/proofs` | 写入一条证明记录（内容完全相同的重复提交幂等去重，返回 `200`） |
| `GET` | `/proofs/artifact/{artifact_digest}` | 列出某制品的全部证明记录 |
| `GET` | `/verify/{artifact_digest}` | 递归校验完整证明链；可选 `?at=<RFC3339 UTC>` 做历史时点校验 |
| `POST` | `/revocations` | 撤销一个制品（幂等，已撤销返回 `200`） |
| `GET` | `/revocations` | 列出全部撤销记录 |
| `GET` | `/revocations/{artifact_digest}` | 查询单个制品撤销状态 |
| `GET` | `/health` | 健康检查 |

### 3.1 写入证明 `POST /proofs`

```json
{
  "artifact_digest": "sha256:abc123",
  "issuer": "<Base64 Ed25519 公钥>",
  "parent_digest": "sha256:def456",
  "signature": "<Base64 Ed25519 签名>"
}
```

根证明把 `parent_digest` 设为 `null` 或空串。返回 `201`（新建）或 `200`（幂等重复）。
响应中的 `forks_existing` 会提示该制品是否已存在多条不同证明。

### 3.2 校验制品 `GET /verify/{artifact_digest}`

**成功**（HTTP 200）——`chain` 为从目标制品到信任根的有序信任链：

```json
{
  "artifact_digest": "sha256:image",
  "status": "OK",
  "length": 3,
  "root_issuer": "<根公钥>",
  "chain": [
    { "artifact_digest": "sha256:image", "issuer": "...", "parent_digest": "sha256:app", "relation": "target", "revocation": null },
    { "artifact_digest": "sha256:app",   "issuer": "...", "parent_digest": "sha256:os",  "relation": "ancestor", "revocation": null },
    { "artifact_digest": "sha256:os",    "issuer": "...", "parent_digest": null,          "relation": "root", "revocation": null }
  ]
}
```

**失败**（除 `NOT_FOUND` 为 HTTP 404 外，其余为 HTTP 200 且 `status != OK`）：

- `FORK`：目标或祖先存在多条不同证明。`failure.at` 定位分叉点，`failure.branches` 列出全部候选分支（含各自的签名/撤销状态）；`failure_path` 给出从目标到分叉点的有序路径。
- `REVOKED`：目标或祖先被撤销。路径末节点 `relation` 为 `revoked`（目标自身）或 `revoked_ancestor`（祖先），并携带 `revocation` 详情（原因、时间）。
- `INVALID_SIGNATURE`：Ed25519 签名验证失败。
- `MISSING_PARENT`：父制品没有任何证明记录，`failure.missing_artifact` 指明缺失节点。
- `UNTRUSTED_ROOT`：根签发者不在 `TRUSTED_ROOT_ISSUERS` 中。
- `CYCLE`：父链成环，`relation=cycle_point` 定位环上节点。
- `MAX_DEPTH_EXCEEDED`：链长超过 `MAX_CHAIN_DEPTH`（默认 256）。

失败路径示例（撤销祖先）：

```json
{
  "status": "REVOKED",
  "failure": {
    "code": "REVOKED",
    "detail": "制品 sha256:os 已被撤销: 密钥轮换",
    "at": { "artifact_digest": "sha256:os", "relation": "revoked_ancestor", "revocation": { "reason": "密钥轮换", "revoked_at": "2026-09-22T..." } }
  },
  "failure_path": [
    { "artifact_digest": "sha256:image", "relation": "target" },
    { "artifact_digest": "sha256:app",   "relation": "ancestor" },
    { "artifact_digest": "sha256:os",    "relation": "revoked_ancestor" }
  ]
}
```

#### 历史时点校验 `?at=<RFC3339 UTC>`

```bash
curl "http://localhost:8080/verify/sha256:image?at=2026-09-22T08:00:00Z"
```

- **数据可见性**：只读取 `created_at <= at` 的证明记录，且仅 `revoked_at <= at` 的撤销视为生效（边界均为闭区间）。因此**晚到的分叉/父证明、以及时点之后的撤销，都不会改变更早时点的结论**。
- **`evaluated_at`**：传入 `at` 时响应附带该字段，为归一化后的 UTC 毫秒串（如 `2026-09-22T08:00:00.000Z`）；带偏移的输入（如 `+08:00`，需 URL 编码为 `%2B`）会归一化为 UTC。未传 `at` 时响应结构与之前完全一致，不含该字段。
- **错误语义**：`at` 非法（非 RFC3339、缺时区偏移等）或**晚于当前时间**返回 `400`；该时点尚无目标制品的任何证明记录仍返回 `404`；其余状态码与失败路径语义与实时校验相同。

### 3.3 撤销制品 `POST /revocations`

```json
{ "artifact_digest": "sha256:os", "reason": "CVE-2026-xxxx / 密钥泄露" }
```

撤销后，该制品及其**全部下游**校验都会失败（附完整失败路径）。撤销本身幂等、不可通过该接口删除。

### 3.4 生成签名（客户端示例）

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from app.crypto import sign, encode_public_key

priv = Ed25519PrivateKey.generate()
issuer = encode_public_key(priv.public_key())
signature = sign(priv, "sha256:abc123", "sha256:def456")  # parent 为 None 表示根
```

## 4. 校验规则汇总

1. 制品无任何记录 → `NOT_FOUND`（404）。
2. 目标制品已撤销 → `REVOKED`。
3. 同一 `artifact_digest` 存在多条不同证明（issuer/parent/signature 任一不同）→ `FORK`。
4. 用记录内 `issuer` 公钥对 canonical message 验签，失败 → `INVALID_SIGNATURE`。
5. 沿 `parent_digest` 向上重复 2–4；父节点缺失 / 分叉 / 撤销 / 签名非法 / 成环均带有序失败路径返回。
6. 到达根（`parent_digest` 为空）时，根 `issuer` 必须在信任根集合中，否则 `UNTRUSTED_ROOT`。

传入 `?at=` 时，上述规则中的“存在记录”与“已撤销”均按该时点判定（`created_at <= at`、`revoked_at <= at`），规则本身与返回结构不变。

## 5. 环境变量

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `DATABASE_PATH` | `data/proofs.db`（容器内 `/data/proofs.db`） | SQLite 文件路径，容器内挂载命名卷 |
| `TRUSTED_ROOT_ISSUERS` | 空（开发模式） | 受信任根公钥，Base64，逗号分隔 |
| `MAX_CHAIN_DEPTH` | `256` | 单次校验最大遍历深度 |

## 6. 运行测试

```bash
python3 -m pip install pytest httpx
python3 -m pytest -q
```

覆盖：合法链/根、签名往返、幂等写入与撤销、目标/祖先分叉、目标/祖先撤销定位、非法签名、缺失父节点、成环、非信任根，以及历史时点校验（非法/未来 `at` → 400、时点前 404、时间边界闭区间、`evaluated_at` 归一化、晚到分叉、晚到父证明、撤销前后）等 26 个用例。

## 7. 目录结构

```
.
├── app/
│   ├── main.py        # FastAPI 路由
│   ├── verifier.py    # 递归校验 / 分叉 / 撤销 / 失败路径 / 历史时点求值
│   ├── crypto.py      # Ed25519 与规范化签名载荷
│   ├── database.py    # SQLite 表结构与查询 (含时点过滤)
│   ├── timeutil.py    # RFC3339 解析与 UTC 毫秒格式化
│   ├── config.py      # 环境变量配置
│   └── schemas.py     # Pydantic 模型
├── demo/demo.py       # 端到端演示
├── tests/             # pytest 测试
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```
