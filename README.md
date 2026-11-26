# 本地 TLS SNI 证书网关

一个纯本地、无云服务依赖的 TLS 网关。它在 TCP 连接建立后读取 SNI，为同一监听端口上的多个域名选择证书，并把每次选择写入 debug 日志。

技术栈限定为 Go 1.24、`crypto/tls`、`crypto/x509` 和 `net`；配置、证书与私钥都保存在本仓库内。

## 路由优先级

选择顺序固定为：

1. 显式域名：`shop.example.com`
2. 通配域名：`*.example.com`
3. 未知 SNI 策略
   - `unknown_sni: "default"`：返回 `default_certificate`
   - `unknown_sni: "reject"`：拒绝 TLS 握手

通配规则与证书通配语义一致：`*.example.com` 只匹配一个标签，即 `api.example.com`，不匹配 `example.com` 或 `a.b.example.com`。多个通配规则同时匹配时，后缀更长（更具体）的规则优先。SNI 比较会忽略大小写和末尾的点。

没有 SNI、SNI 为空或没有匹配规则时，同样进入未知 SNI 策略。

## 配置更新语义

`Store` 使用原子快照发布整张路由表：

- TCP 连接被 `Accept` 时捕获当时的路由快照和配置代次。
- 该连接后续的整个 TLS 握手只使用这份快照；即使握手期间配置更新，也不会混用新旧路由。
- 更新之后接受的新连接使用新快照。
- debug 日志中的 `config_generation` 可区分连接使用的配置代次。

进程会轮询配置文件（默认每 2 秒），也支持 `SIGHUP` 立即重载。重载失败时保留旧快照并继续服务。`listen_address` 变更需要重启进程，其他路由和证书变更可热更新。

## 运行

仓库已包含开发用证书。需要重新生成时：

```bash
go run ./cmd/devcerts -out certs
```

默认证书模式：

```bash
go run ./cmd/sni-gateway -config config/gateway.json
```

未知域名拒绝握手模式：

```bash
go run ./cmd/sni-gateway -config config/gateway-reject.json
```

仅校验配置：

```bash
go run ./cmd/sni-gateway -config config/gateway.json -check
```

探测选择结果：

```bash
# 显式域名 -> exact-shop 证书
openssl s_client -connect 127.0.0.1:8443 -servername shop.example.com \
  -CAfile certs/ca.pem </dev/null

# 通配域名 -> wildcard-example 证书
openssl s_client -connect 127.0.0.1:8443 -servername api.example.com \
  -CAfile certs/ca.pem </dev/null

# 未知域名：default 配置返回默认证书，reject 配置握手失败
openssl s_client -connect 127.0.0.1:8443 -servername unknown.example.org \
  -CAfile certs/ca.pem </dev/null
```

TLS 握手成功后会返回一个简短的 HTTP 文本响应，便于确认本次使用的路由结果。

## 配置格式

```json
{
  "listen_address": "127.0.0.1:8443",
  "log_level": "debug",
  "unknown_sni": "default",
  "handshake_timeout": "10s",
  "certificates": [
    {
      "name": "exact-shop",
      "cert_file": "../certs/exact-shop.pem",
      "key_file": "../certs/exact-shop-key.pem"
    },
    {
      "name": "default",
      "cert_file": "../certs/default.pem",
      "key_file": "../certs/default-key.pem"
    }
  ],
  "routes": [
    {"host": "shop.example.com", "certificate": "exact-shop"},
    {"host": "*.example.com", "certificate": "exact-shop"}
  ],
  "default_certificate": "default"
}
```

证书路径相对于配置文件所在目录解析。`unknown_sni` 缺省为 `reject`；支持 `reject`（也接受 `reject_handshake`、`disabled`、`disable`、`drop`）和 `default`（也接受 `default_certificate`、`default_cert`）。`unknown_sni: "default"` 必须配置 `default_certificate`。

## 调试日志

选择发生在握手回调内，日志级别为 `debug`，消息为 `sni certificate routing decision`，包括：

- `sni`：规范化后的 SNI
- `result`：`exact`、`wildcard`、`default` 或 `rejected`
- `reason`：命中的具体原因
- `pattern`：命中的显式或通配规则
- `certificate`、`certificate_subject`、`certificate_sha256`
- `config_generation`：该连接捕获的配置代次
- `remote_addr`：客户端地址

## 测试

```bash
go test ./...
go test -race ./...
```

测试覆盖显式/通配/默认优先级、最具体通配规则、未知 SNI 的两种策略、真实 TLS 握手、debug 日志，以及“旧连接在配置更新后才开始握手仍使用旧快照”的并发语义。

## 仓库结构

- `cmd/sni-gateway/`：本地 TLS 网关入口
- `cmd/devcerts/`：开发证书生成器
- `gateway/`：配置、证书加载、路由快照、原子 Store 和 TLS 服务
- `config/`：示例配置
- `certs/`：仓库内开发证书与私钥

`certs/` 中的私钥仅用于本地开发与测试，不应部署到生产环境。
