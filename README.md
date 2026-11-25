# 20261126

企业身份管理控制台（Enterprise Identity Console）— 租户管理员边界功能。

多个租户共用同一套控制台，但每个租户管理员只能访问本租户的应用、用户与计数；
超级管理员保留跨租户操作能力。

## 约束

- Go 1.24，零第三方依赖，`go.mod` 不含 require 项。
- 生产代码仅导入 `net/http`、`crypto/*`（`crypto/rand`、`crypto/sha256`、
  `crypto/subtle`）和 `encoding/json`。
- 测试代码使用标准库 `testing`、`net/http/httptest` 及 `io`/`strings` 辅助。
- 互斥用带缓冲 channel 实现，排序为包内泛型插入排序，避免引入白名单之外的包。

## 租户边界设计

- 每个请求都由 `Server.resolveScope` 从**服务端 session** 重新解析租户边界，
  绝不采信请求参数或页面缓存中的租户标识。
- 租户管理员被固定在其账号所属租户：即使 session 里残留其他租户的
  `ActiveTenant`，解析出的 scope 仍然回到本租户。
- 超级管理员默认跨租户（`scope.AllTenants()`）；通过切换接口选中某租户后，
  列表、计数、导出与写入都被限定到该租户，切换回空租户即恢复全局视图。
- 切换租户（`POST /api/tenant/switch`）在服务端重新校验：目标租户必须存在，
  租户管理员请求其他租户直接返回 `403`，且不修改当前上下文。
- 所有列表、计数与导出共用同一套 scope 过滤方法（`Store.Tenants`、
  `Applications`、`Users`、`UserCount`、`UserCountByApplication`），
  保证导出内容与页面看到的边界完全一致。
- 越权读取返回 `404`，越权写入/切换返回 `403`，未认证返回 `401`，
  避免通过响应差异枚举其他租户。

## HTTP API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/login` | 账号密码登录，返回不透明 session token |
| POST | `/api/logout` | 注销当前 session |
| POST | `/api/tenant/switch` | 切换活跃租户并在服务端重新校验 |
| GET  | `/api/tenants` | 租户列表及每租户用户数（scope 内） |
| GET  | `/api/applications` | 应用列表、每应用用户数与总用户数 |
| POST | `/api/applications` | 创建应用，越租户写入返回 `403` |
| GET  | `/api/users` | 用户列表与计数（scope 内） |
| GET  | `/api/stats` | 租户/应用/用户聚合计数 |
| GET  | `/api/export` | 下载 scope 过滤后的 JSON 导出快照 |

除登录外所有接口要求 `Authorization: Bearer <token>`。

## 构建与测试

```sh
go build ./...
go test -race -count=1 ./...
```

启动演示服务（监听 `:8080`，种子账号 `root/root-pass`、`acme-adm/acme-pass`、
`glob-adm/glob-pass`）：

```sh
go run ./cmd/idconsole
```
