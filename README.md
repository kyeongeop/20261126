# 20261126

## 团队文件共享 · 文件访问时间线

管理员追查文件外泄时，详情页过去只能看到最后一次修改。本服务在文件详情页提供
**合并的访问时间线**，把创建、授权、预览、下载、撤销、移动（以及内容更新）事件统一
存储，并支持按用户、动作、版本和时间段筛选；事件具备稳定去重键，页面可直接跳到对应版本。

技术栈严格限定 Go 1.24 标准库：`net/http`、`os`、`encoding/json`，无第三方依赖、
无外部数据库，事件持久化到本地 append-only JSONL 日志，测试统一用 `go test`。

## 目录结构

```
main.go                      服务入口（flag: -addr、-data）
internal/timeline/           时间线领域逻辑
  model.go                   事件/动作/筛选/分页模型
  dedup.go                   稳定去重键（SHA-256 规范化哈希）
  store.go                   append-only 日志、内存索引、重启重放
  ingest.go                  幂等摄取、版本派生、墓碑删除
  query.go                   合并查询、用户/动作/版本/时间筛选
internal/httpapi/            net/http 层
  server.go                  Go 1.22+ 方法路由
  api.go                     JSON API 与筛选参数解析
  page.go / templates.go     服务端渲染的文件详情页
```

## 稳定去重键

- 未带幂等令牌时，对 `file_id + action + actor_id + occurred_at(UTC) + version_id
  + 排序后的 details` 做 SHA-256，输出 `evt_<hex>`；details 顺序变化不影响结果。
- 带 `client_event_id` 时，对 `令牌 + file_id + action` 哈希，上游重试天然幂等。
- 删除事件采用**墓碑（tombstone）**记录：去重键保留在日志中，同一事件的重复上报
  会被压制（响应 `suppressed: true`）而不是重新入库；重启重放后行为一致。
- 日志只追加、不改写历史行，所有记录带全局单调 `seq`，查询按
  `(occurred_at, seq)` 稳定排序。

## 版本跳转

- `create` 事件默认落到 `v1`；未显式给版本的事件自动挂到文件当前最新版本，
  显式 `version_id`（如上传产生的 `v2`）会登记为新版本。
- 详情页顶部渲染版本芯片，每行事件也带版本链接，点击即按该版本过滤并定位时间线；
  每行去重键是锚点，可直接链接到具体事件。

## HTTP 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/healthz` | 健康检查 |
| GET | `/api/files` | 文件汇总列表 |
| GET | `/api/files/{fileID}` | 单文件汇总（版本、有效/已删除事件数、当前路径） |
| GET | `/api/files/{fileID}/timeline` | 时间线，支持 `user`、`action`、`version`、`from`、`to`(RFC3339)、`limit` |
| GET | `/api/files/{fileID}/versions` | 文件版本列表 |
| POST | `/api/files/{fileID}/events` | 上报单条事件（幂等） |
| POST | `/api/events` | 批量上报，body 含顶层 `file_id` 与 `events` 数组 |
| GET | `/api/events/{dedupKey}` | 查单条事件（已删除返回 410） |
| DELETE | `/api/events/{dedupKey}` | 墓碑删除 |
| GET | `/files/{fileID}` | 文件详情页（筛选表单 + 时间线 + 版本跳转） |

动作取值：`create`、`grant`、`preview`、`download`、`revoke`、`move`、`update`。
用户筛选同时匹配事件执行人 `actor_id` 和 details 中的相关用户
（`grantee`、`revokee`、`user`、`member` 等），因此“授权/撤销了谁”也能被筛出。

## 运行与测试

```bash
go run . -addr :8080 -data ./data
go test ./...            # 单元 + HTTP 端到端 + 重启重放测试
go test -race ./...      # 竞态检测
```

上报示例：

```bash
curl -X POST localhost:8080/api/files/fin-budget/events \
  -H 'Content-Type: application/json' \
  -d '{"action":"download","actor_id":"u2","occurred_at":"2026-11-26T11:00:00Z","version_id":"v2"}'
```
