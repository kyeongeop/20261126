# 20261126

Repository initialized for 20261126.

## 团队文件共享 — 目录紧急冻结

Go 1.24 实现的团队文件共享 HTTP 服务，仅依赖标准库（`net/http`、`os`、
`encoding/json`）。发生异常外传时，管理员可立即冻结共享目录：冻结只写入
状态与日志，**不会移动、修改或删除任何共享数据**。

### 冻结语义

- 冻结对目录本身及其所有子路径生效，父目录冻结会覆盖整棵子树。
- 冻结后所有角色（`admin` / `user` / `guest` / `background` 后台任务）
  的目录列表与文件读取一律返回 `403 directory_frozen`，管理员也不例外。
- 每次被拒绝的访问都会追加记录到 `denied-access.jsonl`，含时间、路径、
  命中的冻结目录、动作、访问者 ID 与角色，供事后分析。
- 解冻必须两步完成：先提交**带原因**的解冻申请，再由管理员显式确认；
  确认前冻结持续有效。
- 所有管理动作（冻结、解冻申请、解冻确认）写入 `audit.jsonl` 审计日志。
- 状态通过临时文件 + 原子重命名持久化到 `freeze-state.json`，服务重启后
  冻结与解冻申请不丢失；状态目录位于共享目录之外，不会被当作文件对外提供。

### 运行与测试

```bash
go build ./...
go test ./...
go run ./cmd/fileshare -addr=:8080 -share-dir=./data/share -state-dir=./data/state
```

所有请求必须携带身份头：`X-Actor-Id`、`X-Actor-Role`
（取值 `admin` / `user` / `guest` / `background`），否则返回 `401`。

### API

| 方法 | 路径 | 角色 | 说明 |
| --- | --- | --- | --- |
| GET | `/api/files/{path...}` | 任意 | 列目录，冻结时 403 并记录 |
| GET | `/api/file?path=/a/b.txt` | 任意 | 读文件，冻结时 403 并记录 |
| POST | `/api/admin/freeze` | 管理员 | 紧急冻结，body 需含 `path`、`reason` |
| GET | `/api/admin/freezes` | 管理员 | 当前所有冻结 |
| POST | `/api/admin/unfreeze-requests` | 管理员 | 解冻申请，`reason` 必填 |
| POST | `/api/admin/unfreeze-requests/{id}/confirm` | 管理员 | 管理员确认，正式解冻 |
| GET | `/api/admin/unfreeze-requests` | 管理员 | 解冻申请列表 |
| GET | `/api/admin/denied-access` | 管理员 | 被拒绝访问记录 |
| GET | `/api/admin/audit` | 管理员 | 管理动作审计日志 |

### 典型流程

```bash
# 1. 紧急冻结
curl -X POST -H 'X-Actor-Id: a1' -H 'X-Actor-Role: admin' \
  -H 'Content-Type: application/json' \
  -d '{"path":"/team-a","reason":"检测到异常外传流量"}' \
  http://localhost:8080/api/admin/freeze

# 2. 任何访问（含后台任务）均被拒绝并留痕
curl -H 'X-Actor-Id: job-1' -H 'X-Actor-Role: background' \
  'http://localhost:8080/api/file?path=/team-a/docs/report.txt'

# 3. 事后分析：查看被拒绝的访问
curl -H 'X-Actor-Id: a1' -H 'X-Actor-Role: admin' \
  http://localhost:8080/api/admin/denied-access

# 4. 解冻：先填原因申请，再由管理员确认
curl -X POST -H 'X-Actor-Id: a1' -H 'X-Actor-Role: admin' \
  -H 'Content-Type: application/json' \
  -d '{"path":"/team-a","reason":"取证完成，风险主机已隔离"}' \
  http://localhost:8080/api/admin/unfreeze-requests
curl -X POST -H 'X-Actor-Id: a2' -H 'X-Actor-Role: admin' \
  http://localhost:8080/api/admin/unfreeze-requests/UR-0001/confirm
```
