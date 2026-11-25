# 团队文件共享：孤儿权限清理

一个用 Go 1.24、`net/http`、`os` 和 `encoding/json` 实现的权限清理服务。
权限、用户、资源和审计记录都保存在 JSON 文件中，不依赖外部数据库。

清理严格分成两步：

1. **预览**：只读检查每个权限，返回四类结果并记录数据版本。
2. **执行**：必须引用一个已生成的预览；逐项写入变更清单后再修改权限表。

## 四类结果

| 分类 | 判定 | 执行动作 |
| --- | --- | --- |
| `file_deleted` | 稳定资源不存在，或 `os.Stat` 找不到目标 | 删除权限 |
| `directory_moved` | 资源仍存在，但权限快照路径与资源当前路径不同 | 把权限路径更新为新路径 |
| `user_disabled` | 用户不存在或 `active=false` | 删除权限 |
| `valid` | 用户有效、资源存在、路径未变化 | 保留权限 |

用户停用优先于目标文件检查。资源使用稳定 ID，因此目录迁移后即使权限里还是旧路径，
也能定位到当前资源；目录内文件的权限同样会随目录迁移一起修正。

## 启动

```bash
go run ./cmd/orphan-cleaner \
  -addr :8080 \
  -data ./data/store.json \
  -files ./files \
  -manifests ./manifests
```

`-files` 是相对资源路径的根目录。权限、资源和用户通过 `-data` 指向的 JSON 文件维护。
如果文件不存在，服务会使用空数据集。

## 数据格式

```json
{
  "version": 1,
  "revision": 42,
  "users": [
    {"id": "u-1", "name": "Alice", "active": true},
    {"id": "u-2", "name": "Bob", "active": false}
  ],
  "resources": [
    {"id": "r-1", "path": "teams/new-name", "kind": "directory"},
    {"id": "r-2", "path": "docs/deleted.pdf", "kind": "file"}
  ],
  "permissions": [
    {
      "id": "p-1",
      "user_id": "u-1",
      "resource_id": "r-1",
      "path": "teams/old-name"
    }
  ]
}
```

`revision` 在权限表真实发生变化时递增。预览会记录该版本；执行时如果版本已变化，
服务返回 `409 stale_preview`，要求重新预览，避免按过期结果误删。

## HTTP API

### 生成预览

```bash
curl -X POST http://localhost:8080/api/v1/cleanup/previews
```

返回示例（节选）：

```json
{
  "id": "e44e3a...",
  "state_revision": 42,
  "items": [
    {
      "permission_id": "p-1",
      "category": "directory_moved",
      "action": "update_permission_path",
      "permission_path": "teams/old-name",
      "current_path": "teams/new-name",
      "reason": "directory moved; grant remains valid at its new path"
    }
  ],
  "summary": {
    "total": 1,
    "by_category": {
      "directory_moved": 1,
      "file_deleted": 0,
      "user_disabled": 0,
      "valid": 0
    },
    "changes": 1
  }
}
```

### 执行预览

```bash
curl -X POST \
  http://localhost:8080/api/v1/cleanup/previews/e44e3a.../execute
```

每次执行都会生成 `manifests/<run-id>.json`。清单包含每个权限的：

- 分类、动作和状态
- 修改前后路径
- 尝试次数、失败原因、应用时间
- 当前轮次和整体运行状态

也可以直接下载最新清单：

```bash
curl -OJ http://localhost:8080/api/v1/cleanup/runs/<run-id>/manifest
```

### 从失败轮次继续

单个权限失败不会阻止同一轮处理其他权限。运行状态会变成 `partial`（部分成功）或
`failed`（全部失败），清单和状态在每项处理后都会落盘。

```bash
curl -X POST \
  http://localhost:8080/api/v1/cleanup/runs/<run-id>/resume
```

续跑会跳过已应用和无需处理的项，只重试 `pending`、`applying`（进程中断时留下）和
`failed` 项。也可以只重试指定项：

```bash
curl -X POST \
  -H 'Content-Type: application/json' \
  -d '{"item_ids":["perm:p-1"]}' \
  http://localhost:8080/api/v1/cleanup/runs/<run-id>/resume
```

服务重启后仍可从同一个 `run-id` 继续。所有变更动作都是幂等的：权限已删除或路径已更新时，
重试会记录为已应用，不会重复修改。

## 其他接口

- `GET /healthz`
- `GET /api/v1/cleanup/previews/{id}`
- `GET /api/v1/cleanup/runs/{id}`
- 兼容短路径：`/api/cleanup/preview`、`/api/cleanup/execute`

## 测试

```bash
go test ./...
go test -race ./...
```

测试使用临时目录和内存中的 JSON 数据，不需要数据库或网络服务。
