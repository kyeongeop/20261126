# 20261126 — 离线吊销状态处理 TLS 网关

隔离环境（无法访问公网 OCSP/CRL 分发点）下的本地 TLS 网关：通过**固定（pinned）CRL
或 OCSP 响应**校验客户端证书吊销状态，记录签发时间（thisUpdate）、下次更新时间
（nextUpdate）与未知状态；响应过期时按配置选择放行、拒绝或降级，并把选择原因写入
审计日志。

技术栈：Go 1.24、`crypto/tls`、`crypto/x509`、`net`（仅标准库，OCSP 响应由
`encoding/asn1` 最小化解析并验签，无需任何第三方依赖）。

## 结构

- `internal/revoke` — 吊销源加载（CRL / OCSP）、状态判定、过期策略、审计日志
- `internal/gateway` — mTLS 网关，握手后执行吊销检查，拒绝则中断握手
- `cmd/gateway` — 命令行入口
- `internal/testutil` — 测试用内存 PKI（CA、证书、CRL、签名 OCSP 响应）

## 运行

```sh
go run ./cmd/gateway \
  -addr 127.0.0.1:8443 \
  -cert server.pem -key server-key.pem -ca client-ca.pem \
  -crl pinned-ca.crl -ocsp pinned-response.der \
  -stale-policy degrade \
  -audit audit.log
```

- `-crl` / `-ocsp`：逗号分隔的固定吊销文件，加载时逐一对 CA 验签
- `-stale-policy`：`deny`（默认，过期即拒绝）| `allow`（放行）| `degrade`（放行但标记降级）
- 审计日志为 JSON Lines，含 `this_update`、`next_update`、`stale`、`stale_policy`、
  `decision`（allow/deny/degrade）与 `reason`（选择原因）

## 判定规则

1. 固定 OCSP 响应优先于 CRL；两者都没有 → 状态 `unknown`，拒绝
2. `revoked` → 拒绝；`unknown` → 拒绝
3. `good` 且 `now > nextUpdate`（过期）→ 按 `-stale-policy` 放行 / 拒绝 / 降级
4. 每次判定都写一条审计记录，`reason` 字段说明选择原因

## 构建与测试（干净目录一次跑通）

```sh
go build ./... && go test ./...
```
