# Local TLS Gateway · 证书库存与到期提醒

本地 TLS 网关的证书管理入口。页面扫描分散目录中的 PEM 证书，展示域名、签发者、到期时间、链完整性和网关当前使用状态，并支持按到期日与状态筛选。

实现仅使用 Go 1.24 标准库（`crypto/tls`、`crypto/x509`、`net` 等）和仓库内夹具，不引入第三方依赖。

## 快速启动

```bash
go run .
```

打开 <http://127.0.0.1:8080/certificates>。

可用环境变量：

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `GATEWAY_ROOT` | `.` | 相对路径解析基准 |
| `GATEWAY_CONFIG` | `fixtures/gateway/gateway.json` | 网关证书清单 |
| `GATEWAY_STATE` | `fixtures/gateway/state.json` | 网关最近一次重载的内存快照 |
| `PORT` | `8080` | 监听端口 |
| `ADDR` | `127.0.0.1:8080` | 完整监听地址，优先级高于 `PORT` |

## 功能

- 清单字段：域名 / SAN、签发者、到期时间、链完整性、当前使用状态、证书路径。
- 到期筛选：7 / 30 / 90 天内、已过期、自定义起止日期；也可按使用状态和关键字筛选。
- 链校验：使用本地根 CA 与证书文件内的中间证书执行 `x509.Verify`，区分完整链、缺少中间证书和不受信任链。
- 未重载检测：网关重载时通过 `tls.LoadX509KeyPair` 记录叶证书与证书包指纹；库存请求会重新读取磁盘并比对。文件被替换但网关未重载时显示“文件已替换 / 未重载”。
- 重载入口：页面右上角“重载网关”会重新加载配置和证书、更新内存快照，并持久化到 `GATEWAY_STATE`。

## API

```text
GET /api/certificates
GET /api/certificates?expiry=30d
GET /api/certificates?expiry=expired
GET /api/certificates?expiry=custom&expires_after=2027-01-01&expires_before=2027-12-31
GET /api/certificates?usage=stale
POST /api/gateway/reload
GET /healthz
```

`expiry` 支持 `all`、`7d`、`30d`、`90d`、`expired`、`custom`；日期格式为 `YYYY-MM-DD`，范围包含起止当天。

## 本地夹具

`fixtures/` 内含本地根 CA、中间 CA 和五个证书场景：

- `shop.example.test`：完整链，2027-01-18 到期。
- `api.example.test`：完整链，2027-09-01 到期。
- `admin.example.test`：仅叶子证书，缺少中间证书，2026-12-12 到期。
- `legacy.example.test`：已过期且未启用。
- `orders.example.test`：磁盘已是新证书，但 `state.json` 保留旧证书指纹，用来展示“文件已替换但配置未重载”。

重新生成夹具：

```bash
go run ./internal/fixturegen
```

## 验证

```bash
go test ./...
go vet ./...
```
