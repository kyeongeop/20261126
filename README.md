# Incident Evidence

事故时间线与签名证据包服务。技术栈为 Python 3.12、FastAPI、SQLite、
Ed25519 和 pytest，面向事故结论的外部团队复核。

一次 `POST` 即可生成 ZIP 证据包，包内包含：

- 事故时间线（`timeline.json`、`timeline.csv`）
- 原始文件清单及原文件副本（`raw-files.json`、`raw/`）
- 每个文件的 SHA-256、大小和全量校验文件（`checksums.sha256`）
- 事故来源配置（`source_config.json`）
- 导出人姓名、邮箱和组织（`exporter.json`）
- 被签名覆盖的完整元数据（`manifest.json`）
- Ed25519 签名和公钥（`signature.json`、`public_key.pem`）
- 可直接执行的验证命令（API 响应、manifest 和 `VERIFY.md`）

校验器会验证签名、文件覆盖集合和每个文件的 SHA-256。任何原始文件、时间线、
配置、清单、公钥或校验文件被替换，或者出现新增、缺失、重名、目录穿越、加密
成员时，验证都会失败。

## 快速开始

```sh
python3.12 -m venv .venv
.venv/bin/pip install -e '.[test]'
.venv/bin/uvicorn incident_evidence.main:app --host 127.0.0.1 --port 8000
```

打开 `http://127.0.0.1:8000/docs` 查看 OpenAPI 文档。默认数据位于 `./data/`：

```text
data/
├── incidents.sqlite3
├── keys/
│   ├── evidence-signing-key.pem       # Ed25519 私钥，0600，不进入证据包
│   └── evidence-signing-key.pub.pem   # 独立交付给复核方的公钥
├── uploads/<incident_id>/             # 入库时保存的原始文件
└── packages/                          # 生成后的签名 ZIP
```

支持的环境变量：

| 变量 | 默认值 | 用途 |
| --- | --- | --- |
| `INCIDENT_DATA_DIR` | `./data` | SQLite、上传文件和证据包根目录 |
| `EVIDENCE_SIGNING_KEY` | `<data>/keys/evidence-signing-key.pem` | 本地签名私钥路径 |
| `MAX_UPLOAD_BYTES` | `104857600` | 单个原始文件上传上限 |

首次启动会生成本地 Ed25519 密钥。私钥只在服务主机保存；复核方应通过独立渠道
获取 `evidence-signing-key.pub.pem`，不要把证据包内的公钥当唯一信任来源。

## API 流程

所有时间戳必须包含时区，服务统一规范化为 UTC。

### 1. 创建事故和来源配置

```sh
curl -sS -X POST http://127.0.0.1:8000/api/incidents \
  -H 'content-type: application/json' \
  -d '{
    "title": "Checkout latency incident",
    "description": "Checkout p99 exceeded the error budget.",
    "source_config": {
      "environment": "production",
      "clock": "UTC",
      "log_sources": [{"name": "checkout-api", "type": "application_log"}]
    }
  }'
```

### 2. 上传原始文件和追加时间线事件

```sh
INCIDENT_ID=inc_xxx
curl -sS -X POST \
  "http://127.0.0.1:8000/api/incidents/$INCIDENT_ID/raw-files" \
  -F 'file=@fixtures/raw/checkout-api.log;type=text/plain' \
  -F 'source=application-log' \
  -F 'captured_at=2026-11-25T08:25:00Z'

curl -sS -X POST \
  "http://127.0.0.1:8000/api/incidents/$INCIDENT_ID/events" \
  -H 'content-type: application/json' \
  -d '{
    "occurred_at": "2026-11-25T08:02:00Z",
    "title": "Latency alert fired",
    "description": "p99 checkout latency crossed 2.5 seconds.",
    "source": "monitoring",
    "actor": "alertmanager",
    "artifact_ids": ["raw_xxx"]
  }'
```

`GET /api/incidents/{incident_id}/timeline` 按 `occurred_at`、入库时间、ID
稳定排序返回时间线。

### 3. 一键生成签名证据包

```sh
curl -sS -X POST \
  "http://127.0.0.1:8000/api/incidents/$INCIDENT_ID/evidence-packages" \
  -H 'content-type: application/json' \
  -d '{
    "exporter": {
      "name": "Alice Chen",
      "email": "alice.chen@example.com",
      "organization": "Platform Reliability"
    }
  }'
```

响应包含 ZIP 路径、包 SHA-256、下载地址、签名公钥指纹和可直接执行的
`verification.command`。例如：

```json
{
  "id": "pkg_...",
  "filename": "evidence-inc_...zip",
  "sha256": "...",
  "download_url": "/api/evidence-packages/pkg_.../download",
  "verification": {
    "command": "python3 -m incident_evidence.cli verify '/abs/evidence.zip' --public-key '/abs/evidence-signing-key.pub.pem'",
    "public_key_path": "/abs/evidence-signing-key.pub.pem",
    "public_key_sha256": "...",
    "key_id": "..."
  }
}
```

如果原始上传文件在入库后被修改，导出会返回 `409`，不会生成带错误内容的证据包。

## 外部复核

将证据 ZIP 和通过独立渠道获得的公钥交给复核方，然后运行导出响应中的命令：

```sh
python3 -m incident_evidence.cli verify \
  ./evidence-inc_xxx.zip \
  --public-key ./evidence-signing-key.pub.pem
```

退出码 `0` 表示有效，`1` 表示验证失败，`2` 表示命令参数错误。需要机器可读结果
时增加 `--json`。在线复核接口也可用：

```sh
curl -sS -X POST http://127.0.0.1:8000/api/evidence-packages/verify \
  -F 'package=@evidence-inc_xxx.zip;type=application/zip' \
  -F 'public_key=@evidence-signing-key.pub.pem;type=application/x-pem-file'
```

验证器执行的关键检查：

1. ZIP 结构完整，成员路径安全，名称不重复且没有加密或符号链接成员。
2. `manifest.json` 的原始字节与 `signature.json` 中的 Ed25519 签名匹配。
3. `signature.json` 使用固定规范化序列化，格式变化也会被视为篡改。
4. manifest、签名和公钥的 key id / SHA-256 指纹一致；提供外部公钥时必须匹配。
5. 包内每个文件都恰好出现在已签名 `checksums` 中，不存在未签名附加文件。
6. 逐个重算文件大小和 SHA-256，并确认独立元数据文件与签名 manifest 内容一致。
7. `raw/` 中的副本必须与 `raw-files.json` 和 `checksums.sha256` 的摘要一致。

包内也提供 `checksums.sha256`，解压后可人工执行：

```sh
unzip evidence-inc_xxx.zip -d evidence
cd evidence
sha256sum -c checksums.sha256
```

该命令只做人工摘要核对。外部复核仍应运行完整 CLI 验证，因为只有它会验证签名、
manifest 覆盖关系以及包内每个文件是否都已被签名。

## 数据与测试

测试数据位于 `fixtures/`，所有测试统一使用 pytest：

```sh
.venv/bin/python -m pytest
```

测试覆盖时间线排序、跨事故引用拒绝、证据包内容、CLI/API 验证、同尺寸原始文件
替换、manifest/时间线/配置/公钥/校验文件替换、签名尾随空白、未签名新增文件、
缺失文件以及外部错误公钥。

数据库已存在时，也可以不启动 HTTP 服务直接导出：

```sh
.venv/bin/python -m incident_evidence.cli export inc_xxx \
  --exporter-name 'Alice Chen' \
  --exporter-email 'alice.chen@example.com' \
  --exporter-organization 'Platform Reliability'
```

查看当前签名公钥：

```sh
.venv/bin/python -m incident_evidence.cli key-info
```

## 安全边界

- 私钥默认生成为 `0600`，不会写入 ZIP。生产环境应限制数据目录访问并做好备份。
- 有效签名只能证明内容由对应私钥签署；复核方必须独立获得公钥，否则攻击者可
  同时替换包内公钥、manifest 和签名。
- 证据包是生成时数据库快照与原始文件副本的集合。生成之后对服务端源文件的修改
  不会改变已签名 ZIP，重新导出则会反映并重新签名当前状态。
- ZIP 外层下载文件自身也可用导出响应中的包 SHA-256 进行人工比对，但核心防篡改
  保证来自包内签名和逐文件校验。
