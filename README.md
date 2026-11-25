# 团队文件共享：口令分享防猜测

带口令的分享链接默认可以被无限次尝试，本服务为其加上按“来源 +
时间窗口”计算的尝试额度、连续失败后的短暂锁定，以及防止通过响应差异
判断口令/分享是否存在的防护。所有状态落在仓库内的本地文件，不依赖
任何云服务。

技术栈：Go 1.24，仅使用标准库（`net/http`、`os`、`encoding/json`、
`crypto/*` 等）。

## 运行

```bash
go run . -addr :8080 -data-dir ./data
```

常用参数（均可用同名环境变量 `FILESHARE_*` 覆盖）：

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-addr` | `:8080` | HTTP 监听地址 |
| `-data-dir` | `data` | 状态文件目录 |
| `-max-attempts` | `5` | 每个窗口、每个来源的最大尝试次数 |
| `-window` | `10m` | 尝试计数窗口 |
| `-max-consecutive-failures` | `5` | 触发锁定的连续失败次数 |
| `-lockout` | `5m` | 锁定时长 |
| `-pbkdf2-iterations` | `600000` | 口令 PBKDF2 迭代次数 |
| `-trust-proxy` | `false` | 是否信任 `X-Forwarded-For` |

## API

创建分享（返回随机、不可猜的分享 ID）：

```bash
curl -X POST localhost:8080/api/shares \
  -d '{"filename":"q4.md","password":"hunter2","content":"aGVsbG8="}'
```

凭口令访问：

```bash
curl -X POST localhost:8080/api/shares/<id>/access \
  -d '{"password":"hunter2"}'
```

另有 `GET /healthz` 健康检查。

## 数据文件

状态目录下有两个 JSON 文件，写入均为“临时文件 + `rename`”原子替换：

- `shares.json`：分享记录，口令只保存 PBKDF2-HMAC-SHA256 加盐哈希。
- `attempts.json`：按 `分享ID + NUL + 来源IP` 分组的限流/锁定状态。

锁定状态在每次尝试后立即落盘，服务重启后从文件恢复，不会清零。

## 防猜测设计

### 尝试额度与锁定

限流键是 `(分享 ID, 来源 IP)`，两条独立规则任一触发即锁定：

1. 固定窗口额度：一个窗口内最多 `-max-attempts` 次尝试，超出后该来源
   对该分享锁定 `-lockout`。
2. 连续失败：连续 `-max-consecutive-failures` 次口令错误即锁定，即使
   窗口额度尚未用完。

锁定中的请求在做任何口令计算之前就被拒绝，返回 `429` 并带
`Retry-After` 头；锁定过期或验证成功都会清零计数。后台每分钟以及
关闭时清理过期条目，避免状态文件无限增长。

### 不泄露分享/口令是否存在

- “分享不存在”和“口令错误”返回完全相同的 `401` 状态码与响应体。
- 对不存在的分享，服务仍执行一次参数相同的 PBKDF2 派生和常量时间比较
  （dummy hash），使两类请求的耗时处于同一量级，无法用计时区分。
- 哈希比较使用 `crypto/subtle.ConstantTimeCompare`。
- 分享 ID 由 `crypto/rand` 生成 16 字节随机值，不可枚举。

### 持久化与并发

- 每次限流状态变更都原子写盘，进程崩溃不会留下半截文件，重启后锁定
  依旧有效。
- 进程内用互斥锁串行化读改写；单机部署即可保证一致性。

### 部署注意

`-trust-proxy` 只应在受信任的反向代理后开启，因为来源 IP 直接作为限流
身份；未开启时使用 TCP 连接的对端地址，客户端无法伪造。

## 代码结构

```
main.go                     入口、参数、优雅关闭、定期清理
internal/store/             通用原子 JSON 文件存储
internal/ratelimit/         窗口额度 + 连续失败锁定（纯逻辑，可注入时钟）
internal/shares/            分享记录、PBKDF2 哈希、常量时间/伪哈希验证
internal/httpapi/           net/http 路由与处理器
```

## 测试

```bash
go test ./...
```

覆盖限流状态机（窗口滚动、锁定、过期、按来源隔离）、存储原子性、
哈希与伪哈希验证路径，以及端到端的锁定、重启持久化和错误响应
不可区分性。
