# 团队文件共享 · 一次性预览令牌（previewtoken）

预览链接不再使用可反复访问的长期令牌。本服务签发**绑定文件名、版本、用户、用途和过期时间**的一次性预览令牌：

- 令牌是 HMAC-SHA256 签名的 JSON Claims（`encoding/json`），篡改绑定字段即签名失败；
- 服务端用消费台账保证**一枚令牌只能成功使用一次**，并发请求下也恰好只有一次成功（互斥锁 + 原子落盘）；
- **过期即失效**，时间源可注入，便于测试；
- 消费台账通过 `os` 读写 JSON 文件并原子替换，**进程重启后“已使用”状态仍然生效**；
- 针对“同一页面的缩略图批量请求”，提供两种不会误判重放的机制（见下）。

仅依赖 Go 1.24 标准库（`net/http`、`os`、`encoding/json`、`crypto/hmac` 等），无第三方依赖，干净目录可离线一次构建/测试通过。

## 目录结构

```text
go.mod                 module previewtoken / go 1.24
main.go                进程入口：flag/环境变量、装配 JSON 台账与 HTTP 服务
token/claims.go        Claims、Binding、Issue/Batch 请求类型与哨兵错误
token/manager.go       签发、HMAC 校验、过期/绑定检查、原子消费、批量与页面会话
token/store.go         Store 接口 + 基于 os/encoding/json 的原子 JSON 文件台账
token/*_test.go        核心单测：重放、过期、绑定、篡改、并发唯一消费、批量、持久化
server/server.go       路由、DTO、错误分类、令牌提取
server/issue.go        签发单枚 / 批量签发 / page→batch 交换 / verify
server/preview.go      /preview 与 /preview/thumbnail 消费端点、文件读取、占位 PNG
server/demo.go+demo.html  可视化演示页（三种流程，含并发缩略图）
server/*_test.go       httptest 端到端与并发批量测试
verify.sh              干净目录一键 build + vet + test
```

## 快速开始

```bash
go run .                         # 默认 :8080，台账写入 data/tokens.json
# 或：
PREVIEW_ADDR=127.0.0.1:8090 \
PREVIEW_TOKEN_SECRET=please-use-a-long-random-secret \
PREVIEW_DATA=/var/lib/preview/tokens.json \
go run .
```

打开 <http://localhost:8080/> 即演示页，可直接点击验证：
单次令牌两次使用（200→401）、批量缩略图并发加载（全部 200）后重放（全部 401）、
page 令牌交换 batch 授权后按 item 加载（不同 item 成功、重复 item 401）。

构建与测试：

```bash
./verify.sh
# 等价于：
go build ./... && go vet ./... && go test ./... -count=1
# 并发语义建议加 -race：
go test ./... -race -count=1
```

## 令牌格式与绑定

令牌序列化为 `pt1.<base64url(json claims)>.<base64url(hmac)>`，同时兼容无版本前缀的两段式。

```json
{
  "jti": "jti_…",
  "kind": "once",
  "file": "brand/hero.png",
  "version": "v42",
  "user": "alice",
  "purpose": "thumbnail",
  "item": "w256",
  "batch_id": "batch_…",
  "iat": "2026-11-26T02:00:00Z",
  "exp": "2026-11-26T02:10:00Z"
}
```

校验顺序：签名/格式 → 过期时间 → 请求绑定（file/version/user/purpose/item）→ 台账原子消费。
绑定不匹配返回 `403 binding_mismatch`，且**不会**消费令牌；过期/重放/伪造返回 `401` 与明确的 `reason`
（`expired` / `replayed` / `invalid_token` / `unknown_token`）。

## 为什么缩略图批量请求不会被误判为重放

“重放”指的是**同一枚一次性令牌（或同一 batch 授权中的同一个 item）被第二次消费**。
同一页面的多张缩略图是不同资源，系统提供两种把它们与重放区分开的标准方式：

1. **批量签发，每图一枚独立一次性令牌（推荐，最简单）**
   `POST /api/preview/batch` 为每个尺寸/缩略图生成不同 `jti`、但共享同一 `batch_id`
   且各自带 `item` 的令牌。页面把每个 URL 放进对应 `<img src>`，浏览器并发请求时，
   每枚令牌都是第一次出现 → 全部 `200`；任何一枚被再次使用才是 `401 replayed`。

2. **页面令牌交换短时批量授权（page → batch grant）**
   先签发 `purpose:"page"` 且带 `items:[…]` 清单的一次性页面令牌；前端用它调用一次
   `POST /api/preview/session`，页面令牌当场消费，换回一枚 `kind:"batch"` 的短 TTL
   授权（含 item 白名单与 `max_uses`）。之后
   `/preview/thumbnail?batch_token=…&item=w64` 对**每个不同 item 各放行一次**；
   白名单外的 item 返回 `403 item_not_allowed`，同一 item 第二次才是 `401 replayed`。
   页面令牌本身无法二次交换。

两种模式都在 `token.Manager` 的互斥临界区内完成“检查 + 标记 + 持久化”，
因此即使几十个请求同时到达，单次令牌也恰好只有一次成功（有 `-race` 测试覆盖）。

## HTTP API

所有接口使用 `encoding/json`；时间为 RFC3339。字段同时兼容常见别名
（`file`/`filename`/`file_name`，`user`/`user_id`，`version`/`ver`）。

| 方法与路径 | 作用 |
| --- | --- |
| `GET /healthz` | 健康检查 |
| `POST /api/preview/tokens` | 签发一枚一次性令牌（可显式传 `purpose:"page"` + `items`） |
| `POST /api/preview/batch` | 为一批缩略图/资源批量签发独立一次性令牌 |
| `POST /api/preview/session` | 用一次性 page 令牌交换短时 batch 授权 |
| `POST /api/preview/verify` | 校验并消费令牌，返回 `{valid,claims}` 或错误 `reason` |
| `GET /preview?token=…[&file=&version=&user=]` | 消费并返回预览内容（有注册文件则回字节，否则回授权 JSON 回执） |
| `GET /files/<file…>/versions/<version>/preview?token=…` | 路径形式的预览（文件名可含 `/`） |
| `GET /preview/thumbnail?token=…&item=…` | 缩略图：独立令牌，或 `batch_token=…&item=<id>` |
| `GET /`（与 `/demo`） | 可视化演示页 |

令牌可通过 `?token=`、`X-Preview-Token` 头或 `Authorization: Bearer <token>` 传递；
用户绑定可用 `?user=` 或 `X-User-ID` 头断言。预览响应带
`Cache-Control: private, no-store, max-age=0`，避免中间层/浏览器缓存一次性内容。

### curl 流程

```bash
B=http://localhost:8080

# 1) 签发：绑定 welcome.txt / v1 / demo / preview / 5 分钟
ISSUE=$(curl -s -X POST $B/api/preview/tokens -H 'Content-Type: application/json' \
  -d '{"file":"welcome.txt","version":"v1","user":"demo","ttl_seconds":300}')
URL=$(echo "$ISSUE" | jq -r .preview_url)

curl -i "$B$URL&user=demo"      # 200，返回 data/content 中注册的文件内容
curl -s  "$B$URL&user=demo"     # 401 {"reason":"replayed", ...}

# 2) 缩略图批量：每图一枚令牌，并发加载全部 200，重放全部 401
curl -s -X POST $B/api/preview/batch -H 'Content-Type: application/json' \
  -d '{"file":"hero.png","version":"v42","user":"alice",
       "profiles":["w64","w128","w256","w512"]}'

# 3) page -> batch grant
PAGE=$(curl -s -X POST $B/api/preview/tokens -H 'Content-Type: application/json' \
  -d '{"file":"deck.key","version":"v2","user":"dana",
       "purpose":"page","items":["w64","w128"]}')
PT=$(echo "$PAGE" | jq -r .token)
curl -s -X POST $B/api/preview/session -H 'Content-Type: application/json' \
  -d "{\"token\":\"$PT\"}"      # 返回 thumbnail_url_template
```

## 干净目录一次跑通

本仓库无第三方依赖，复制到任意干净目录后（排除 `.git`）：

```bash
bash verify.sh
# go version …
# GOPROXY=off go build ./...   ✅
# GOPROXY=off go vet ./...     ✅
# GOPROXY=off go test ./... -count=1  ✅
```

已验证：将工作树复制到全新 `mktemp -d` 目录并以 `GOPROXY=off` 执行，
`token` 与 `server` 两个包全部通过；`go test ./... -race -count=1` 同样通过。

## 安全边界与后续建议

- HMAC 密钥来自 `-secret` / `PREVIEW_TOKEN_SECRET`；未提供时使用进程内随机密钥并打印警告
  （重启后旧令牌失效）。多实例部署请注入同一密钥并把 JSON 台账放到共享可靠存储，
  或把 `token.Store` 换成数据库实现。
- JSON 文件台账适合单实例/中小规模；`Save` 采用同目录临时文件 + `rename` 原子替换，权限 `0600`。
- 签发接口在本演示中开放；生产环境应置于现有登录/授权中间件之后，由服务端确定 `user`，
  不要信任前端传入的用户身份（预览端点因此支持 `X-User-ID` 与 Claims 做一致性校验）。
- 建议 TTL 保持分钟级；缩略图批量授权 TTL 更短（默认 2 分钟，且不超过页面令牌有效期）。
