# 命名空间所有权保护

内部包仓库的命名空间不再由“谁先创建谁拥有”决定。普通登录用户只能提交所有权申请，
管理员审批后才获得带截止时间的保留期；已有包的命名空间不能通过普通创建、
申请或发布流程取得，只能由管理员执行带审计记录的所有权转移。

实现使用 Go 1.24 标准库，HTTP 层为 `net/http`，审计导出使用 `archive/tar`，
事件链与令牌存储使用 `crypto/sha256`。示例账户、命名空间和包均来自仓库内
`fixtures/seed.json`，没有第三方依赖。

## 快速启动

```bash
go run .
```

默认监听 `127.0.0.1:8080`。首次启动会把夹具复制到 `data/state.json`，之后所有
申请、审批、转移和审计事件都会原子写入该文件。

| 环境变量 | 默认值 | 说明 |
| --- | --- | --- |
| `ADDR` | `127.0.0.1:8080` | 完整监听地址，设置后优先于 `PORT` |
| `PORT` | `8080` | 只设置端口 |
| `NAMESPACE_STATE` | `data/state.json` | 持久化状态文件 |
| `NAMESPACE_FIXTURE` | `fixtures/seed.json` | 状态文件不存在时使用的本地夹具 |

本地演示令牌（请求头 `Authorization: Bearer <token>`）：

| 用户 | 角色 | 令牌 |
| --- | --- | --- |
| `alice` | publisher | `alice-demo-token` |
| `bob` | publisher | `bob-demo-token` |
| `carol` | publisher | `carol-demo-token` |
| `admin` | admin | `admin-demo-token` |

夹具中的 `legacy-tools` 已有 `core@1.2.3`，但没有所有者；`team-alpha` 已有包并由
`alice` 持有。它们用于验证“已有包所在命名空间不可被普通流程取得”。

## 安全规则

- 普通创建接口 `POST /api/v1/namespaces` 不再直接授予所有权，只创建待审申请。
- 新命名空间申请默认保留 72 小时供管理员审核；每名普通用户最多同时持有 3 个待审申请。
- 管理员批准时可以指定保留天数，默认 90 天，上限 3650 天；所有者可续期。
- 保留期到期的空命名空间会被释放并写入 `namespace.reservation.expired` 审计事件。
- 含包的命名空间即使保留期到期也不会自动释放；其所有权只通过管理员转移变更。
- 已存在包的命名空间在申请、普通创建和发布入口均返回 `namespace_has_packages` /
  `namespace_not_owned`，即使该命名空间当前没有所有者。
- 所有权转移必须记录操作者、原所有者、新所有者、原因、请求 ID、客户端地址、时间，
  并加入 SHA-256 哈希链。
- 所有状态变更在同一把锁内复制、校验、落盘、切换；写失败不会留下半更新状态。

## 典型流程

提交申请：

```bash
curl -sS -X POST http://127.0.0.1:8080/api/v1/claims \
  -H 'Authorization: Bearer bob-demo-token' \
  -H 'Content-Type: application/json' \
  -d '{"namespace":"new-team","reason":"new service team"}'
```

管理员查看并批准（把返回的 claim id 填入命令）：

```bash
curl -sS http://127.0.0.1:8080/api/v1/admin/claims \
  -H 'Authorization: Bearer admin-demo-token'

curl -sS -X POST http://127.0.0.1:8080/api/v1/admin/claims/CLAIM_ID/approve \
  -H 'Authorization: Bearer admin-demo-token' \
  -H 'Content-Type: application/json' \
  -d '{"reservation_days":30,"note":"approved"}'
```

所有者转移给 `carol`，审计事件会出现在命名空间历史中：

```bash
curl -sS -X POST http://127.0.0.1:8080/api/v1/namespaces/new-team/transfer \
  -H 'Authorization: Bearer bob-demo-token' \
  -H 'Content-Type: application/json' \
  -d '{"to_user_id":"carol","reason":"team handoff"}'

curl -sS http://127.0.0.1:8080/api/v1/namespaces/new-team/history \
  -H 'Authorization: Bearer carol-demo-token'
```

验证并导出完整审计链：

```bash
curl -sS http://127.0.0.1:8080/api/v1/admin/audit/verify \
  -H 'Authorization: Bearer admin-demo-token'

curl -sS http://127.0.0.1:8080/api/v1/admin/audit/export \
  -H 'Authorization: Bearer admin-demo-token' \
  -o namespace-audit.tar
```

尝试抢注含包命名空间：

```bash
curl -sS -i -X POST http://127.0.0.1:8080/api/v1/namespaces/claims \
  -H 'Authorization: Bearer bob-demo-token' \
  -H 'Content-Type: application/json' \
  -d '{"namespace":"legacy-tools","reason":"squat"}'
```

## API

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| `GET` | `/healthz` | 公开 | 存活检查 |
| `GET` | `/api/v1/me` | 登录 | 当前用户 |
| `GET` | `/api/v1/policy` | 登录 | 申请与保留期策略 |
| `GET` | `/api/v1/namespaces` | 登录 | 命名空间及可用状态 |
| `GET` | `/api/v1/namespaces/{name}` | 登录 | 所有者、到期时间、包数量 |
| `POST` | `/api/v1/claims` | 登录 | 提交所有权申请 |
| `GET` | `/api/v1/claims` | 登录 | 查看自己的申请 |
| `GET` | `/api/v1/claims/{id}` | 本人/管理员 | 申请详情 |
| `POST` | `/api/v1/claims/{id}/cancel` | 申请人 | 撤回待审申请 |
| `GET` | `/api/v1/admin/claims` | 管理员 | 查看全部申请 |
| `POST` | `/api/v1/admin/claims/{id}/approve` | 管理员 | 批准并设定保留期 |
| `POST` | `/api/v1/admin/claims/{id}/reject` | 管理员 | 拒绝申请 |
| `POST` | `/api/v1/namespaces/{name}/renew` | 所有者/管理员 | 续期 |
| `POST` | `/api/v1/namespaces/{name}/transfer` | 所有者/管理员 | 转移所有权并审计 |
| `GET` | `/api/v1/namespaces/{name}/history` | 当前/历史所有者、申请人、管理员 | 该命名空间审计历史 |
| `POST` | `/api/v1/packages` | 所有者/管理员 | 在已批准命名空间发布包 |
| `GET` | `/api/v1/admin/audit` | 管理员 | 审计事件检索 |
| `GET` | `/api/v1/admin/audit/verify` | 管理员 | 校验 SHA-256 链 |
| `GET` | `/api/v1/admin/audit/export` | 管理员 | 导出 tar 审计包 |
| `POST` | `/api/v1/admin/maintenance/expire` | 管理员 | 立即处理到期申请/空命名空间 |

`POST /api/v1/namespaces` 和 `POST /api/v1/namespaces/claims` 保留为兼容入口，
行为与 `POST /api/v1/claims` 相同：返回 `202` 和待审申请，不直接授权。
错误响应统一为 `{"error":{"code":"...","message":"...","details":"..."}}`。

## 审计导出

`GET /api/v1/admin/audit/export` 返回 `application/x-tar`：

- `audit/manifest.json`：事件数、链头哈希、导出时间、格式版本。
- `audit/events/000000000001.json`：按序排列的单个事件。
- `audit/index.jsonl`：同样事件的 JSON Lines 索引。
- `audit/README.txt`：校验说明。

每条事件包含 `previous_hash` 与 `hash`。`hash` 是固定字段（含前一条哈希）的
SHA-256；事件序号必须连续，且前一条的 `hash` 必须等于后一条的 `previous_hash`。
状态文件重新加载时也会校验整条链，链被改写则拒绝启动。

## 验证

```bash
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
```

测试覆盖申请审批、保留期续期、空命名空间到期释放、含包命名空间保护、
所有者转移审计、审计哈希链篡改检测、tar 导出、HTTP 权限与错误码，以及关闭后重新打开状态文件。
