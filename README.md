# fileshare — 版本化加密的团队文件共享

纯 Go 标准库实现（Go 1.24，仅用 `net/http`、`os`、`encoding/json`、`crypto/*`），
所有数据落在仓库内本地目录，不依赖任何云服务或外部数据库。

## 解决的问题

旧实现中每个新版本直接覆盖同一个加密文件，历史内容无法回读。本实现改为：

- **每个版本独立的文件密钥（DEK）**：每次上传生成全新 AES-256 DEK，用当前
  激活的 KEK 版本做信封封装后写进版本清单，密文存为独立 blob（`v1.enc`、`v2.enc`…）。
- **版本清单（manifest）**：每个逻辑文件一个 append-only 的 `manifest.json`，
  保留每版的密钥版本（`key_version`）、明文/密文 SHA-256 校验值、大小、创建者和时间。
- **下载任意历史版本**：`GET /files/{id}/versions/{number}`，按该版本记录的
  KEK 版本解包 DEK，再解密对应 blob，并双向校验校验值。
- **密钥轮换不重写历史**：轮换只生成新 KEK 版本并切换激活版本；旧 KEK 永久保留，
  旧 blob 与已封装 DEK 永不修改。回读旧版本只做解密，不存在任何重写/重新封装路径。

## 加密设计

- 算法：AES-256-GCM（认证加密），每次加密随机 12 字节 nonce，nonce 前置在 blob 中。
- 两层密钥：
  - KEK（密钥加密密钥）按版本存于 `keyring/keys/kN.key`，清单 `keyring/keyring.json`
    记录版本号、KEK 的 SHA-256、创建者、创建时间。
  - DEK（每版本一个）封装后内联在文件版本清单的 `wrapped_dek` 字段，从不出现在 HTTP 响应中。
- 校验：密文 blob 与解密后明文均做 SHA-256 比对；GCM tag 同时提供完整性认证，
  篡改 blob 会在校验或解密阶段失败（见 `TestReadVersionDetectsTampering`）。

## 数据目录布局

```
data/
  keyring/
    keyring.json            # KEK 版本清单（含激活版本、校验值、创建者）
    keys/k1.key, k2.key ... # 各版本 KEK 原始材料（0600）
  files/
    <id>/
      manifest.json         # 版本清单（append-only，含 wrapped_dek）
      v1.enc, v2.enc ...    # 每版本独立密文 blob
```

所有 JSON 通过临时文件 + rename 原子写入；密钥与清单文件权限为 `0600`，目录 `0700`。

## HTTP API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/files/{id}/versions` | 上传新版本（请求体为文件内容，头 `X-Creator` 必填，可选 `X-Filename`、`X-Note`） |
| GET | `/files/{id}/versions/{number}` | 下载任意历史版本（解密后明文，响应头带密钥版本与校验值） |
| GET | `/files/{id}/manifest` | 查看版本清单（不含 wrapped DEK 与存储路径） |
| GET | `/files` | 列出所有文件及其版本元数据 |
| POST | `/keys/rotate` | 轮换 KEK：`{"created_by":"carol"}`，生成新版本并激活 |
| GET | `/keys` | 列出全部 KEK 版本（版本号、校验值、创建者、时间） |

## 运行与测试

```bash
go test ./...                       # 含轮换后回读、密文不重写、篡改检测、重启持久化
go run ./cmd/fileshare -addr :8080 -data ./data

# 演示：上传两版 → 轮换密钥 → 再传一版 → 回读全部历史版本
curl -X POST localhost:8080/files/contract/versions -H 'X-Creator: alice' --data 'v1'
curl -X POST localhost:8080/files/contract/versions -H 'X-Creator: bob'   --data 'v2'
curl -X POST localhost:8080/keys/rotate -H 'Content-Type: application/json' \
  --data '{"created_by":"carol"}'
curl -X POST localhost:8080/files/contract/versions -H 'X-Creator: carol' --data 'v3'
curl localhost:8080/files/contract/versions/1   # 轮换后仍可回读 v1，旧密文未改动
```

## 代码结构

- `internal/envelope`：AES-256-GCM 信封加解密、随机密钥与 SHA-256。
- `internal/keyring`：KEK 版本管理、轮换、按版本加载历史密钥、持久化。
- `internal/store`：版本清单、每版本独立 DEK 加密、任意版本回读与校验。
- `internal/server`：`net/http` 路由与请求/响应模型。
- `cmd/fileshare`：进程入口。
