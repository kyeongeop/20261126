# GuestShare

一个只依赖 Go 标准库的团队文件共享服务。团队成员创建邀请凭据，
外部访客用该凭据换取访客会话，只能浏览和下载被授权的目录。

## 运行

仓库自带 `fixtures/team` 共享目录夹具，可直接启动：

```bash
INVITER_TOKEN='replace-with-a-long-random-value' \
go run ./cmd/guestshare
```

常用环境变量：

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `ADDR` | `:8080` | HTTP 监听地址 |
| `SHARE_ROOT` | `./fixtures/team` | 团队文件根目录 |
| `DATA_FILE` | `./data/state.json` | 邀请和会话的持久化文件 |
| `INVITER_TOKEN` | 无，必填 | 成员调用管理接口的 Bearer Token |
| `INVITER_NAME` | `team` | 记录到邀请上的邀请人名称 |
| `SECURE_COOKIES` | `false` | HTTPS 部署时设为 `true` |

启动后访问 `GET /healthz` 检查服务。管理接口需要：

```text
Authorization: Bearer <INVITER_TOKEN>
```

## 邀请流程

创建邀请。`directory` 可以是相对 `SHARE_ROOT` 的路径，也可以是位于
`SHARE_ROOT` 内的绝对路径；`passcode` 可省略：

```bash
curl -sS -X POST http://localhost:8080/api/invitations \
  -H "Authorization: Bearer $INVITER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "display_name": "外部评审",
    "passcode": "optional-passcode",
    "directory": "Design",
    "expires_at": "2026-12-31T18:00:00+08:00"
  }'
```

响应中的 `invitation_token` 只返回这一次，需通过安全渠道交给访客。访客首次
加入时将口令和邀请凭据一起提交，服务返回 `session_token` 并设置
`guest_session` HttpOnly Cookie：

```bash
curl -sS -c guest.cookies -X POST http://localhost:8080/api/guest/join \
  -H "Content-Type: application/json" \
  -d '{"token":"<invitation_token>","passcode":"optional-passcode"}'
```

之后可使用 Cookie，或 `Authorization: Bearer <session_token>` 访问文件：

```bash
curl -sS -b guest.cookies 'http://localhost:8080/api/guest/files?path='
curl -sS -b guest.cookies 'http://localhost:8080/api/guest/files/brief.txt'
```

邀请人可查看自己创建的邀请，并随时回收：

```bash
curl -sS http://localhost:8080/api/invitations \
  -H "Authorization: Bearer $INVITER_TOKEN"

curl -sS -X DELETE http://localhost:8080/api/invitations/<invitation_id> \
  -H "Authorization: Bearer $INVITER_TOKEN"
```

回收后所有已有访客会话立即失效，即使会话 Cookie 尚未过期。

## 授权与目录同步

- 创建邀请时记录授权目录的设备号和 inode，而不是只信任路径字符串。
- 每次访客请求都会重新校验邀请状态、到期时间、目录身份和文件是否存在。
- 授权目录在 `SHARE_ROOT` 内被移动或改名时，服务按 inode 找到新位置并同步
  邀请记录，访客随后看到新路径，文件内容仍来自同一目录。
- 授权目录被删除、被同名新目录替换，或被移出 `SHARE_ROOT` 时，请求返回
  `410 directory_unavailable`，不会把同名新目录误授权给旧访客。
- 访客路径始终相对于授权目录。`..`、绝对路径、越界符号链接都会被拒绝，
  因此授权目录之外的团队文件不会出现在列表或下载响应中。
- 访客接口是只读的；文件列表每次都从磁盘读取，目录内新增、删除、移动文件
  会立即反映到下一次访问。

目录移动追踪使用 Linux 的 `dev/inode` 文件身份。服务不修改共享目录，也不
依赖数据库或第三方库。

## HTTP API

| 方法 | 路径 | 鉴权 | 说明 |
| --- | --- | --- | --- |
| `POST` | `/api/invitations` | 邀请人 | 创建邀请 |
| `GET` | `/api/invitations` | 邀请人 | 列出自己的邀请状态 |
| `DELETE` | `/api/invitations/{id}` | 邀请人 | 回收邀请 |
| `POST` | `/api/guest/join` | 邀请凭据 | 加入并创建访客会话 |
| `GET` | `/api/guest/session` | 访客会话 | 当前访客与授权目录 |
| `GET` | `/api/guest/files?path=` | 访客会话 | 列出授权目录或其子目录 |
| `GET` | `/api/guest/files/{path}` | 访客会话 | 下载授权目录内的文件 |
| `POST` | `/api/guest/logout` | 无 | 清除浏览器会话 Cookie |

错误响应格式：

```json
{"error":{"code":"invitation_revoked","message":"invitation has been revoked"}}
```

常见状态码：`401` 未认证/邀请已过期/已回收，`403` 越出授权目录，`404`
不存在的文件，`410` 授权目录已被删除或替换。

## 测试

```bash
go test ./...
go vet ./...
```

测试覆盖邀请创建、可选口令、首次加入、目录列表隔离、路径穿越、符号链接
越界、目录移动跟随、目录删除/同名重建后失效、邀请回收、到期失效、状态
持久化以及完整 HTTP 流程。测试使用仓库内 `fixtures/team` 夹具的临时副本。

主要代码入口：

- `cmd/guestshare/main.go`：服务启动入口
- `internal/guest/service.go`：邀请与访客会话领域逻辑
- `internal/guest/files.go`：授权目录身份同步和文件边界
- `internal/guest/http.go`：HTTP API
