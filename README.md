# 团队文件共享 · 批量撤销分享

安全事件发生时，管理员不必再逐条打开分享链接：按 **负责人、目录、创建时间区间、链接状态**
组合筛选，先预览 **将撤销的链接数与受影响文件数（按文件去重）**，填写撤销原因后一次提交。

- 单个 Go 服务进程，仅使用标准库（`net/http`、`os`、`encoding/json`、`embed` 等）
- 零外部依赖、无需数据库；数据保存在一个 JSON 文件中，首次启动自动写入演示数据
- 批量撤销在单个事务中执行：内存快照 + 临时文件 `fsync` + `rename` 原子替换，
  任何失败都整体回滚，不会出现“撤销一半”
- 撤销不删除记录：链接状态置为 `revoked` 并保留原因 / 操作人 / 批次号；
  每批操作生成一条含完整目标清单的审计事件，随同一原子提交持久化，可随时查询

## 快速开始

要求 Go 1.24+（更低版本若支持 `go.mod` 中的 `go 1.24` 指令语法亦可，建议 1.24 及以上）。

```bash
go run .
# 团队文件共享服务已启动: http://localhost:8080
```

浏览器打开 <http://localhost:8080/> 即为中文管理界面（筛选 → 预览受影响文件数 →
填写原因 → 二次确认 → 查看审计）。

可选配置：

| 配置 | 说明 | 默认值 |
| --- | --- | --- |
| `ADDR` / `-addr` | 监听地址 | `:8080` |
| `DATA_DIR` / `-data` | JSON 数据目录（`db.json` 存分享与审计） | `data` |

```bash
ADDR=127.0.0.1:9000 DATA_DIR=/var/lib/batchshare go run .
go test -race ./...   # 单元 / HTTP / 回滚测试
```

## 筛选条件

所有查询 / 请求体字段均可选，可任意组合：

| 字段 | 含义 | 示例 |
| --- | --- | --- |
| `owner` | 负责人姓名或工号（大小写不敏感） | `张伟` / `u003` |
| `directory` | 目录；`recursive:true` 时包含所有子目录（按路径边界前缀匹配） | `/研发/API` |
| `recursive` | 是否含子目录，默认 `true` | `false` |
| `created_from` | 创建时间下界，`YYYY-MM-DD` 或 RFC3339 | `2026-11-01` |
| `created_to` | 创建时间上界；日期按当天结束处理 | `2026-11-30` |
| `status` | 链接状态：`active` / `revoked` / `expired` / `all` | `active` |

只有 `active`（有效中）链接会被真正撤销；预览同时给出条件命中的全部链接 / 文件数。

## HTTP API

### 1. 预览受影响范围（提交前）

`POST /api/shares/revoke/preview`（同样支持 `GET` 查询参数；别名
`/api/admin/revocations/preview`）

```bash
curl -s -X POST http://localhost:8080/api/shares/revoke/preview \
  -H 'Content-Type: application/json' \
  -d '{
    "owner": "王强",
    "directory": "/研发",
    "recursive": true,
    "created_from": "2026-01-01",
    "created_to": "2026-12-31",
    "status": "active"
  }'
```

响应（关键字段：`affected_files` 即**受影响文件数（按文件去重）**）：

```json
{
  "matched_links": 7,
  "matched_files": 4,
  "revocable_links": 7,
  "affected_files": 4,
  "files": [{ "file_id": "F-1007", "file_name": "openapi.yaml", "active_links": 1 }],
  "items": [ "……将撤销的链接明细……" ]
}
```

### 2. 批量撤销（必须填写原因）

`POST /api/shares/batch-revoke`（别名 `POST /api/admin/revocations`、
`POST /api/batch-revoke`；条件也可包在 `criteria` 或 `filters` 字段中）

```bash
curl -s -X POST http://localhost:8080/api/shares/batch-revoke \
  -H 'Content-Type: application/json' \
  -d '{
    "directory": "/市场活动",
    "status": "active",
    "created_from": "2026-09-01",
    "reason": "安全事件 SEC-2026-1126：市场物料外链全面收敛",
    "operator": "security-admin"
  }'
```

- 缺少 `reason` → `400 reason_required`
- 条件下没有有效链接 → `409 nothing_to_revoke`
- 落盘失败 → `500 commit_failed_rolled_back`，内存与磁盘均保持操作前状态
- 成功响应含 `batch_id`、`revoked_links`、`affected_files` 与完整 `audit`

### 3. 审计记录

```bash
curl -s http://localhost:8080/api/admin/audits          # 列表（别名 /api/audits）
curl -s http://localhost:8080/api/admin/audits/RV-xxxx   # 批次详情（别名 /api/audits/{id}）
```

每条审计包含：批次号、操作人、原因、完整筛选条件、命中 / 撤销数量、受影响文件、
全部链接 ID 与撤销时的目标快照（文件名、目录、负责人、Token、创建时间）、起止时间。

### 4. 其他

- `GET /api/health` 健康检查
- `GET /api/meta` 负责人、目录、状态下拉数据
- `GET /api/shares?owner=&directory=&recursive=&created_from=&created_to=&status=` 链接列表

## 原子性与审计保留如何实现

- `Store.update`（`store.go`）在互斥锁内先对整库做 JSON 深拷贝快照；
- 撤销变更与审计事件在同一个内存事务中完成；
- `atomicWriteJSON` 写同目录临时文件 → `Write` → `Sync` → `Close` → `Rename`
  原子替换 `db.json`，并 `fsync` 目录；
- 任一步失败：内存状态恢复快照，磁盘文件从未被部分覆盖，等价于整体回滚；
- 成功后审计事件与状态变更在同一次原子替换中生效。撤销只更新 `status`
  并追加撤销元数据，不删除任何 `shares` / `audits` 记录，重启后依旧可查。

`revoke_test.go` 中的 `TestBatchRevokeRollbackWhenCommitFails` 会注入落盘失败，
断言链接状态、审计列表与磁盘字节均保持不变，随后恢复写入可重试成功。

## 代码结构

| 文件 | 职责 |
| --- | --- |
| `main.go` | 单进程入口、优雅关闭、访问日志中间件 |
| `model.go` | `Share` / `Filter` / `AuditEvent` / `PreviewInfo` 等模型 |
| `store.go` | JSON 存储、条件匹配、预览聚合、事务 / 原子提交 / 回滚、审计查询 |
| `filter.go` | 查询参数与 JSON 条件解析、时间边界处理 |
| `handler.go` | `net/http` 路由与 JSON API |
| `seed.go` | 覆盖各负责人 / 目录 / 月份 / 状态的演示数据 |
| `web.go` + `web/index.html` | `embed` 打包的中文管理界面（无外部 CDN 依赖） |
| `*_test.go` | 存储事务、回滚、HTTP 全流程测试 |
