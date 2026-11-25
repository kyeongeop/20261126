# CertGateway — 一次性邀请的客户端证书自助注册

新增内部服务不再需要人工为每个客户端签发证书。管理员创建绑定 **服务名 + 有效期 +
用途** 的一次性邀请；客户端凭邀请提交 CSR、完成私钥持有挑战后，CA 才签发证书；
证书通过自定义绑定扩展与 URI SAN 被严格限制为只能访问约定服务，网关在 TLS 握手
阶段强制该校验。邀请一旦使用或过期，就不能再次签发。

纯 Go 标准库实现（Go 1.24，仅用 `crypto/tls`、`crypto/x509`、`net`、`net/http`
等），**不接外部数据库**，邀请与挑战保存在带互斥锁的内存存储中。

## 需求到实现的映射

| 需求 | 实现位置 |
| --- | --- |
| 邀请绑定服务名、有效期、用途 | `invitation/store.go` 的 `CreateInput`：`Service` / `Purpose` / `InviteTTL` / `CertValidity` |
| 一次性令牌，明文只展示一次 | `invitation.Store.Create` 生成 256-bit token，仅存 SHA-256 哈希 |
| 客户端完成挑战后才签发 | `enroll/service.go` 的 `Begin` / `Complete`：nonce 与 CSR 绑定，验证私钥签名（支持 ECDSA/RSA/Ed25519） |
| 邀请只能使用一次 | `invitation.Store.Consume` 在同一把锁内做 `pending → consumed` CAS；并发测试保证 64 个竞争只有一个赢家 |
| 过期邀请不能签发 | `ExpiresAt` + 可注入时钟；`AuthenticateToken` 与 `Consume` 都强制校验，过期惰性置为 `expired` |
| 证书只能用于约定服务 | `identity/binding.go`：证书内含 `Binding{Service,Purpose,InvitationID}` 扩展和等价的 `certgw://` URI SAN |
| 网关强制服务绑定 | `gateway/gateway.go` 的 `tls.Config.VerifyConnection` + `RequireAndVerifyClientCert` |
| 用途（api/metrics/admin）授权 | `gateway/handler.go` 按路由校验 `Purpose`，同时证书 EKU 仅含 `ClientAuth` |
| 本地 TLS 网关，基于 `net`/`crypto/tls` | `gateway.Start`：`net.Listen("tcp", …)` + `tls.NewListener` + `http.Server` |
| 测试统一 `go test` | 全部为标准 `testing` 测试，含真实 localhost TCP/TLS 端到端用例，无外部依赖 |

## 目录结构

```
clock/        可注入的并发安全时钟（确定性地测试过期）
identity/     服务/用途绑定：x509 扩展 OID、certgw:// URI SAN、校验逻辑
invitation/   一次性邀请聚合根 + 内存存储 + 状态机（pending/consumed/revoked/expired）
pki/          本地根 CA、客户端证书与服务端证书签发（crypto/x509）
enroll/       Begin/Complete 挑战服务、JSON HTTP API、Go 注册客户端
gateway/      net + crypto/tls mTLS 网关、VerifyConnection、用途路由
cmd/
  certgateway/  serve（启动 API+网关）、invite（建邀请）、demo（进程内演示）
  enroll/       客户端 CLI：建密钥/CSR、解挑战、落盘 client.key/client.pem
flow_test.go  根包端到端测试（真实 TCP 全链路）
```

## 一键验证

```bash
go test ./...          # 全部单元/并发/HTTP/mTLS/端到端测试
go test -race ./...    # 并发与数据竞争检查（可选）
go run ./cmd/certgateway demo
```

根目录直接运行 `go test` 也会执行端到端流程。所有测试离线可跑，不需要数据库、
容器或任何第三方 Go 模块。

## 手动跑一遍真实流程

```bash
# 终端 1：启动注册 API（:8080）与 mTLS 网关（:8443），生成 ca-cert.pem
go run ./cmd/certgateway serve \
  --service billing.internal \
  --admin-token dev-admin \
  --state-dir ./certgateway-state

# 终端 2：管理员创建一次性邀请（token 只输出这一次）
go run ./cmd/certgateway invite \
  --admin-token dev-admin \
  --service billing.internal --purpose metrics \
  --invite-ttl 15m --cert-ttl 24h

# 客户端：用 token 自助注册，默认写入 ./client-creds/client.{key,pem}
go run ./cmd/enroll --token '<上一步的 token>'

# 用签发的证书访问网关
curl --cacert certgateway-state/ca-cert.pem \
     --cert client-creds/client.pem --key client-creds/client.key \
     https://127.0.0.1:8443/whoami

curl ... https://127.0.0.1:8443/metrics   # metrics 用途 -> 200
curl ... https://127.0.0.1:8443/api/x     # metrics 用途 -> 403
# 同一 token 再次 enroll -> 409 invitation: already used
```

### 单端口统一 TLS 模式（自助注册也走 TLS 网关）

客户端注册前还没有证书，因此统一网关在同一 HTTPS 端口上对 `/api/v1/*`
使用 `VerifyClientCertIfGiven`（凭邀请 token 即可注册），其余业务路由由
`RequireBoundClientCert` 中间件强制 mTLS 与服务绑定：

```bash
go run ./cmd/certgateway serve --unified \
  --gateway-addr 127.0.0.1:8443 --service billing.internal \
  --admin-token dev-admin --state-dir ./certgateway-state

go run ./cmd/certgateway invite --api https://127.0.0.1:8443 \
  --cacert certgateway-state/ca-cert.pem --admin-token dev-admin \
  --service billing.internal --purpose api
go run ./cmd/enroll --server https://127.0.0.1:8443 \
  --cacert certgateway-state/ca-cert.pem --token '<token>'
```

无证书访问注册接口成功、访问 `/whoami` 得 401；他服务的有效证书完成 TLS
握手后在路由层得 403。见 `gateway/unified_test.go`。

## 注册协议

1. `POST /api/v1/invitations`（管理员 Bearer token）创建邀请，返回一次性 token。
2. 客户端生成 P-256 密钥与 PKCS#10 CSR，调用 `POST /api/v1/enroll/begin`
   提交 `{token, csr_pem}`；服务校验邀请有效后返回 `challenge_id` 与随机 nonce。
3. 客户端对
   `SHA256("certgateway-enroll-challenge-v1" || nonce || csr_raw)`
   完成签名（ECDSA/RSA/Ed25519 各自按算法哈希），调用
   `POST /api/v1/enroll/complete`。
4. 服务验证挑战一次性、未过期且签名与 CSR 公钥匹配；随后生成证书序列号，
   在 `Store.Consume` 中原子占用邀请并记录该序列号，再由 CA 签发绑定证书。
5. 邀请状态成为 `consumed`，重放挑战或再次使用 token 分别得到
   `challenge already completed` / `invitation already used`。

## 安全设计要点

- **原子一次性保证**：`Consume` 是唯一的签发闸门，互斥锁内检查状态与过期时间
  并翻转状态；只有赢家会进入 CA 签发，邀请记录的证书序列号与证书实际序列号一致。
- **私钥持有证明**：挑战 transcript 同时绑定服务端 nonce 与 CSR DER，无法把挑战
  签名挪用到另一把公钥；挑战本身也只能完成一次。
- **服务绑定**：签发证书的 Subject、EKU（仅 `ClientAuth`）、自定义绑定扩展和
  `certgw://<service>/<purpose>/<invitation-id>` URI SAN 均由 CA 签名。
  网关在标准链校验通过后，于 `VerifyConnection` 中强制
  `binding.Service == 本网关服务名`，其他服务的证书在 TLS 层即被拒绝
  （Go 客户端观察到 `remote error: tls: bad certificate`）。
- **为什么自定义扩展不是 critical**：Go 的 `crypto/x509` 会因无法处理的 critical
  扩展令整条链校验失败，因此绑定扩展设为非关键；网关显式要求并校验其存在与内容，
  安全性不依赖客户端自觉，同时用标准 URI SAN 做交叉印证。
- **纵深授权**：TLS 层校验服务归属，HTTP 中间件按用途（api/metrics/admin）放行
  路由；无证书、过期证书、错误 CA、错误服务、越权用途均有对应测试。
- **无外部数据库**：`invitation.Store` 为内存实现，进程重启即清空，适合本地网关
  与测试；持久化只需提供同语义的存储实现替换该接口即可。

## 测试覆盖

- `invitation`：创建/鉴别、参数校验、单次消费、过期、吊销、64 并发唯一赢家、防御性拷贝。
- `identity`：绑定 DER/URI 往返、校验、服务/用途不匹配拒绝。
- `pki`：CA 签发、链验证、EKU、过期验证、绑定解析。
- `enroll`：快乐路径、错误签名、挑战重放、邀请不可二次签发、邀请/挑战过期、
  16 个并发完成仅一张证书、真实 HTTP API 与 Go 客户端、管理员鉴权。
- `gateway`：匹配服务放行、跨服务证书拒绝、无证书拒绝、过期证书拒绝、用途路由 200/403。
- 根包端到端：建邀请 → HTTP 自助注册 → mTLS 访问 `/whoami`，以及跨服务/过期邀请失败。
