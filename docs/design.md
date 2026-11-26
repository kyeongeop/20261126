# 离线镜像同步验证设计

`mirrorsync` 把“只校验文件名”的离线镜像同步升级为完整的内容与签名验证。
全部功能只依赖 Go 1.24 标准库（`net/http`、`archive/tar`、`crypto/sha256`、
`crypto/ed25519` 等），测试统一通过 `go test ./...` 运行，不连接外部数据库。

## 1. 清单（manifest）

清单是 JSON 文件，逐个列出镜像中的软件包：

```json
{
  "version": 1,
  "imageId": "repo-2026-11",
  "createdAt": "2026-11-26T00:00:00Z",
  "packages": [
    {"path": "pool/a.deb", "size": 1234, "sha256": "..."},
    {"path": "pool/b.rpm", "size": 5678, "sha256": "..."}
  ],
  "rootHash": "..."
}
```

解析阶段会拒绝：不支持的版本、空 `imageId`、绝对路径或包含 `..` 的路径、
非规范路径、非法摘要、清单内重复的包路径，以及与记录值不一致的 `rootHash`。

### 完整性哈希链

每个条目都与上一个条目链接（见 `internal/manifest/types.go` 的 `EntryHash`）：

```
entryHash = SHA256(prevHash || "\n" || path || "\n" || size || "\n" || sha256 || "\n")
```

链从空串开始，最终结果写入 `rootHash`。任意包被替换、删除、插入或调整顺序，
都会改变 `rootHash`，从而无法通过 `Validate`。

## 2. 签名链

签名体系是自包含的轻量证书链（不依赖 X.500/PKI 基础设施）：

```
root-ca（自签名 Ed25519 证书）
  └─ intermediate-ca（可选，由 root 签发，isCA=true）
       └─ mirror-signer（叶子证书，isCA=false）
```

- 证书对其规范化 JSON 载荷做 Ed25519 签名；
- 叶子密钥对“清单文件的原始字节”签名，签名封装（envelope）同时记录
  清单 SHA-256、叶子证书以及到根的整条证书链；
- 核验（`trust.VerifyEnvelope`）依次检查：清单摘要、叶子签名、每一级证书
  签名与签发关系、CA 标志、证书有效期，以及链末端是否等于受信任根证书。

受信任根证书通过带外渠道（不是镜像包本身）分发到隔离网内。

## 3. 同步与断点续传

同步源实现统一的 `source.Source` 接口，支持三种后端：

- `HTTPSource`：基于 `net/http`，用 `Range: bytes=N-` 续传，内置文件服务器
  （`serve` 子命令）由 `http.FileServer` 原生支持 Range；
- `TarSource`：基于 `archive/tar` 顺序扫描，定位到条目后跳过已传字节；
- `DirSource`：本地目录/U 盘，打开文件后 `Seek` 到断点。

目标目录保存 `.mirrorsync-state.json` 检查点，逐包记录已传字节数与完成状态，
采用临时文件 + 原子重命名写入。中断后重跑：

1. 读取检查点，已完成的包仍会重新哈希，绝不只凭状态文件信任；
2. 未完成的包从断点继续；忽略 Range 的后端会被识别并从 0 重写；
3. 瞬时错误按 `--max-retries` 重试，`not found` 与内容不匹配不重试，
   分别归类为“缺失”和“被替换”，并继续处理其余包。

每个下载完成的包都重新计算 SHA-256 与大小，和清单逐项比对。

## 4. 异常分类

报告把问题分成相互独立的列表，便于单独处置：

- `missing`：清单声明但镜像中没有（源也无法提供）；
- `replaced`：文件存在但摘要或大小与清单不符（含磁盘上未声明的额外文件，
  单独放在 `extra` 中）；
- `duplicated`：传输源（tar 包/目录）中同一路径出现多次，或大小写归一化后冲突。

## 5. 跨机器复核摘要

同步结束后在目标目录生成两份自描述产物：

- `sync-summary.json`：镜像 ID、清单 `rootHash`、完整报告与全部包条目；
- `SHA256SUMS.txt`：可移植的 `<sha256>  <相对路径>` 文本清单。

另一台机器只需要 `review` 子命令即可重算所有摘要；若同时携带清单、签名
封装和受信任根证书，还会重新核验整条签名链与 `rootHash`。

## 6. 典型流程

```bash
# 发布侧
mirrorsync keygen --subject root-ca --key root.key
mirrorsync root-cert --key root.key --cert root.cert
mirrorsync keygen --subject signer --key leaf.key
mirrorsync issue-cert --ca-key root.key --ca-cert root.cert \
  --subject signer --key leaf.key --cert leaf.cert
mirrorsync build --image ./image --image-id repo-2026-11 --manifest manifest.json
mirrorsync sign --key leaf.key --cert leaf.cert --chain root.cert \
  --manifest manifest.json --signature signature.json

# 隔离网内同步（HTTP / tar / 目录三选一）
mirrorsync sync --source http://publisher.example/ --dest ./replica \
  --manifest manifest.json --signature signature.json --root-cert root.cert

# 另一台机器复核
mirrorsync review --image ./replica --summary ./replica/sync-summary.json \
  --manifest manifest.json --signature signature.json --root-cert root.cert
```
