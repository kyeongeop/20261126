# 内部软件包仓库 · 删除冷静期

单个 Go 1.24 服务进程、仅使用标准库（`net/http`、`archive/tar`、`crypto/sha256`、
`encoding/json`、`html/template`）实现的内部 tar 软件包仓库。针对“维护者立即删除包，
导致正在构建的流水线突然失败”的问题，删除不再即时生效，而是进入**删除冷静期**：

1. 维护者发起申请 → 目标进入 `pending`（待删除 / 冷静期中），申请单列出
   **受影响的下载、构建（突出进行中的流水线）以及引用方**。
2. 冷静期内可由维护者/管理员**撤回**（`withdrawn`），包恢复正常。
3. 冷静期届满且无活跃引用后，进入 `cooldown_completed`（冷静期完成 / 待第二人确认）。
4. 必须由**不同于申请人的另一个有权限账号****二次确认**，才真正删除（`deleted`）。
5. 仍被其他活跃包引用的包**不能进入“冷静期完成”状态，也不能被确认删除**：
   到期推进会返回 `409 package_referenced` 并给出 `referenced_by` 列表；解除引用后才可继续。

## 状态机

```
                 申请删除                 到期 + 无引用
  active ───────────────────▶ pending ───────────────────────▶ cooldown_completed
                               │  ▲                              │
              冷静期内撤回      │  │ 撤回后可重新申请              │ 另一个有权限账号确认
                               ▼  │                              ▼
                          withdrawn                         deleted（版本/包标记删除，下载 404）

  pending 到期但仍被引用：保持 pending 且 blocked=true，不进入 cooldown_completed。
```

状态枚举：`pending`、`cooldown_completed`、`deleted`、`withdrawn`
（同时在 `state` 字段给出同义值；入参兼容 `pending_deletion`、`ready_to_confirm`、
`cancelled`、`confirmed` 等常见别名）。

## 运行

```bash
go run .
# 默认监听 http://127.0.0.1:8080 ，数据写入 ./data，冷静期 24h，首次启动写入演示数据

# 快速体验完整流程（自带 3s 冷静期、独立临时数据目录）：
bash demo.sh

# 用短冷静期启动以便手工验证：
PKG_DELETION_COOLDOWN=10s go run .
```

参数与环境变量（多种常见命名均兼容）：

| 配置 | Flag | 环境变量 | 默认 |
| --- | --- | --- | --- |
| 监听地址 | `-addr` | `PKG_ADDR` / `ADDR` / `PORT` | `127.0.0.1:8080` |
| 数据目录 | `-data` | `PKG_DATA_DIR` / `DATA_DIR` | `./data` |
| 冷静期 | `-cooldown` | `PKG_DELETION_COOLDOWN` / `DELETION_COOLDOWN` / `PKG_COOLDOWN_SECONDS` 等 | `24h` |
| 演示数据 | — | `PKG_SEED_DEMO=0` 关闭 | 开启（仅空库） |
| 账号 | — | `PKG_USERS`（`用户:密码:角色`，逗号分隔） | 见下 |
| 可信网关头 | — | `PKG_TRUST_IDENTITY_HEADERS=1` | 关闭 |

冷静期既支持 Go duration（`90s`、`10m`、`24h`），也支持纯数字秒（`86400`）。

### 内置演示账号（仅本机试用，部署请用 `PKG_USERS` 覆盖）

- `admin:admin-pass`、`admin2:admin2-pass`：两个不同的管理员，用于演示“第二人确认”。
- `maintainer:maintainer-pass` / `maintainer2:maintainer2-pass`：维护者，可申请/撤回/确认。
- `publisher:publisher-pass`：可发布包；`viewer:viewer-pass`：只读。

角色层级：`viewer < publisher < maintainer < admin`。申请/撤回需 `maintainer+`；
第二人确认需 `maintainer+` 且**账号不能等于申请人**；发布需 `publisher+`
（默认未强制发布认证，设置 `PKG_REQUIRE_PUBLISH_AUTH=1` 可开启）。

### 身份传递的三种方式

1. HTTP Basic：`curl -u admin2:admin2-pass ...`（账号来自 `PKG_USERS`）。
2. 内部网关 Actor 头（系列服务约定，默认识别）：
   `-H 'X-Actor-Id: alice' -H 'X-Actor-Role: admin'`；也兼容 `X-Actor`、`X-User-Id`、
   `X-Actor-Role`/`X-Role`。生产部署应在网关剥离外部伪造头；可用
   `PKG_DISABLE_ACTOR_HEADERS=1` 关闭该方式。
3. 已开启 `PKG_TRUST_IDENTITY_HEADERS=1` 时识别 `X-Authenticated-User` / `X-Authenticated-Role`。

JSON/form/query 中的 `actor`、`requested_by`、`confirmed_by` 等字段也可作为黑盒/CI 的
身份兜底；存在显式凭证时以凭证为准。

## Web 页面

- `/`：总览（包、进行中申请、构建/下载统计、演示账号）。
- `/deletions`：删除申请列表与发起表单。
- `/deletions/{id}`：申请详情——状态/倒计时、**受影响构建与下载**、引用方阻止信息、
  审批轨迹、撤回/推进/第二人确认表单。
- `/packages/{name}`：包详情（版本、摘要、引用方、相关构建/下载、删除入口）。
- `/builds`、`/downloads`：构建与下载记录及上报表单；`/publish`：tar 上传。

## JSON API（核心）

```bash
B=http://127.0.0.1:8080

# 发起删除（version 留空=整个包）。返回 201 与完整申请单（含 impact）
curl -u admin:admin-pass -X POST $B/api/deletion-requests \
  -H 'Content-Type: application/json' \
  -d '{"name":"core-utils","version":"","reason":"security incident"}'

curl -u maintainer:maintainer-pass -X POST $B/api/deletion-requests/$ID/withdraw
curl -u admin:admin-pass      -X POST $B/api/deletion-requests/$ID/complete   # 到期+引用检查
curl -u admin2:admin2-pass    -X POST $B/api/deletion-requests/$ID/confirm    # 另一个有权限账号

curl $B/api/deletion-requests          # 列表（items/deletion_requests/data 别名）
curl $B/api/deletion-requests/$ID      # 详情（status、impact、referenced_by、can_confirm…）
curl $B/api/deletion-requests/$ID/impact
```

兼容入口：`/api/deletions`、`/api/delete-requests`、`/api/package-deletions`、
`/api/deletion_requests`、无前缀 `/deletion-requests`；动作别名
`cancel/revoke`、`approve`、`expire/advance/mark-expired`；也支持
`PATCH /api/deletion-requests/{id}` 带 `{"action":"confirm"}` 或
`{"status":"withdrawn|cooldown_completed|deleted"}`。

REST 风格删除会转为冷静期申请（`202`，不立即删除）：

```bash
curl -u admin:admin-pass -X DELETE $B/api/packages/core-utils
curl -u admin:admin-pass -X DELETE $B/api/packages/core-utils/versions/1.4.0
```

### 包、归档、摘要

```bash
# multipart 上传（文件字段名 package/file/artifact 均可）
curl -F name=my-lib -F version=1.0.0 -F package=@my-lib-1.0.0.tar $B/publish
# 或原始 tar 流：PUT /api/packages/my-lib/versions/1.0.0
# 或 JSON {"name","version","artifact_base64"} -> POST /api/packages

curl $B/api/packages                                   # 列表
curl $B/api/packages/my-lib/versions/1.0.0             # 元数据（sha256:<hex>）
curl -OJ $B/api/packages/my-lib/versions/1.0.0/download# 下载（记录下载事件，校验摘要）
```

归档经 `archive/tar` 校验并统计条目，原始字节用 `crypto/sha256` 计算
`sha256:<hex>`，按内容寻址存入数据目录 `objects/`。归档内的
`package.json` / `manifest.json` / `dependencies.txt` 依赖会自动解析为引用关系。

### 影响数据上报

```bash
# 构建/流水线（status: running|queued|succeeded|failed|canceled …）
curl -X POST $B/api/builds -H 'Content-Type: application/json' \
  -d '{"pipeline":"checkout #4821","package":"core-utils","version":"1.5.0","status":"running"}'

# 下载事件（真实 /download 会自动记录，也可手工补录）
curl -X POST $B/api/downloads -H 'Content-Type: application/json' \
  -d '{"package":"core-utils","version":"1.5.0","user":"ci-bot"}'

# 手工登记引用关系（from 依赖 to）
curl -X POST $B/api/references -H 'Content-Type: application/json' \
  -d '{"from_package":"web-app","from_version":"3","to_package":"core-utils"}'

curl $B/api/packages/core-utils/referenced-by
```

申请单中的 `impact`（以及顶层 `affected_downloads` / `affected_builds` /
`referenced_by`）即上述数据按包名/版本聚合的结果，含
`download_count`、`build_count`、`active_build_count`、`referrer_count`。

## 持久化与测试

- 全部状态保存在数据目录的 `state.json`，写入采用“临时文件 + `fsync` + `rename`”
  原子替换；归档保存在 `objects/<sha256-hex>.tar`。单进程内互斥锁保护并发。
- `go test ./...` 包含基于可控时钟与 `httptest` 的状态机/四人眼/引用阻止/鉴权测试；
  `bash demo.sh` 为完整 HTTP 端到端演示。
