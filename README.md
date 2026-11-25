# 20261126

Repository initialized for 20261126.

# TeamSync · 文件夹权限继承与覆盖

单个 Go 服务进程实现的团队文件共享权限系统，技术栈仅使用 Go 1.24 标准库
（`net/http`、`os`、`encoding/json`，前端资源用 `embed` 内嵌）。

## 权限模型

- **继承**：文件夹上的权限沿目录树向下传递，任意深度的子文件夹/文件默认继承祖先权限。
- **就近覆盖（nearest-wins）**：同一用户在多级目录都有记录时，离目标节点最近的一级生效；
  支持 `none`（显式拒绝）、`read`、`write`、`admin` 四级，高级别隐含低级别。
- **单文件/单文件夹覆盖**：只在目标节点写入直接 ACE，不改动继承链；删除直接 ACE 后自动回退到继承结果。
- **移动重算**：移动节点时直接 ACE 随节点迁移，继承权限不做任何复制，
  子树所有有效权限按新的祖先链实时推导，旧位置的“幽灵访问权”无法残留；同时重算子树路径。
- **同名用户**：用户以唯一 ID 标识，允许重名，重名用户的权限互不影响。

权限编辑页（`GET /`）对每条有效权限标注来源级别（本节点直接设置 / 继承自根目录或上级第几级）、
来源节点名称与 ID、继承链深度，并展示完整继承链。

## 运行与测试

```bash
go run . -addr :8080 -data ./data   # 启动服务，状态写入 data/teamsync.json
go test ./...                       # 验收测试（深层目录/同名用户/多级覆盖/移动重算/持久化/HTTP 鉴权）
```

## HTTP API

所有写接口发送 `Content-Type: application/json`。带 `X-Actor-Id` 请求头时按该用户做权限校验，
不带则视为引导/管理请求。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/health` | 健康检查 |
| GET/POST | `/api/users` | 列出/创建成员（允许同名） |
| GET/POST | `/api/nodes` | 列出节点 / 新建文件夹或文件 |
| GET | `/api/nodes/{id}` | 节点详情 |
| POST | `/api/nodes/{id}/move` | 移动节点，body `{"newParentId":"..."}`，移动后重算子树权限与路径 |
| GET | `/api/nodes/{id}/permissions` | 有效权限视图（继承链、来源级别、直接 ACE） |
| PUT | `/api/nodes/{id}/permissions/{userId}` | 设置单节点覆盖，body `{"level":"read|write|admin|none"}` |
| DELETE | `/api/nodes/{id}/permissions/{userId}` | 删除直接覆盖，回退到继承 |

移动操作要求对被移动节点具备 `admin`、对目标文件夹具备 `write`；
移入自身或后代返回 `422`，同级重名返回 `400`。

## 代码结构

- `internal/model`：用户、节点、ACE、有效权限行的数据结构。
- `internal/perm`：继承链解析、就近覆盖推导、来源标注与能力判断（无状态引擎）。
- `internal/store`：JSON 持久化、节点树增删移动、直接 ACE 管理与移动重算。
- `internal/server`：`net/http` 路由、权限校验与内嵌的权限编辑页（`web/`）。
