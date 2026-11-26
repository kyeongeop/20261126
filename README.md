# 20261126

离线镜像同步验证工具 `mirrorsync`。用清单解析、逐包 SHA-256 校验、
Ed25519 签名链核验和断点续传，取代“只校验文件名”的同步方式；对镜像中
缺失、重复、被替换的包分别列出，并在同步完成后生成可供另一台机器复核的
摘要文件。

仅使用 Go 1.24 标准库（`net/http`、`archive/tar`、`crypto/sha256` 等），
不依赖外部数据库。

## 运行测试

```bash
go test ./...
```

## 代码结构

- `internal/manifest`：清单解析、路径安全校验、完整性哈希链、镜像构建
- `internal/trust`：Ed25519 密钥/证书、root→CA→叶子签名链与核验
- `internal/source`：HTTP（Range 续传）、tar 包、本地目录三种同步源与文件服务器
- `internal/sync`：断点续传引擎、逐包摘要校验、异常分类、跨机器复核摘要
- `cmd/mirrorsync`：`keygen/root-cert/issue-cert/build/sign/verify/sync/review/serve`

详细设计与命令示例见 `docs/design.md`。
