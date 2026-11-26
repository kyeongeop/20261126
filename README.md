# 事故时间线 · Incident Timeline

事故时间线应用：时间线事件携带**稳定的来源证据链接**，可定位到原始文件的
行号、字节偏移或内容哈希前缀。每个定位在创建时同时固化内容哈希与整文件哈希，
文件更新后旧定位一律显示 `stale`（失效），绝不会跳到相似位置；文件被删除时
显示 `missing`。所有接口受 API token 与角色权限控制。

技术栈：Python 3.12+、FastAPI、SQLite（标准库 `sqlite3`）、pytest。

## 快速开始

```bash
python3 -m pip install -r requirements.txt

# 运行入口（默认 http://127.0.0.1:8000，交互式文档 /docs）
python3 -m app.run

# 或使用 uvicorn 工厂模式
python3 -m uvicorn app.main:create_app --factory --port 8000

# 测试命令
python3 -m pytest
```

可通过环境变量覆盖路径：`APP_BASE_DIR`、`APP_SOURCE_DIR`（证据源文件根目录）、
`APP_DB_PATH`（SQLite 数据库位置），默认分别为当前工作目录、
`data/sources/`、`data/timeline.db`。

## 稳定来源定位的工作方式

证据链接（`evidence_links`）支持三种锚点，全部附带 SHA-256 哈希：

| 锚点 | 创建输入 | 解析判定 |
| --- | --- | --- |
| `line` | 1-based 行号（可选结束行） | 当前行内容哈希必须与 `content_hash` 完全一致 |
| `offset` | 0-based 字节偏移 + 长度 | 该字节跨度哈希必须完全一致 |
| `hash` | 创建时的匹配文本（仅用于建链） | 当前文件中必须仍存在整行内容哈希完全相同的行 |

每条记录保存 `content_hash`（锚点内容哈希）与 `file_hash`（创建时整文件哈希），
对外暴露 12 位哈希前缀。解析结果只有三种状态：

- `valid`：锚点存在且所有哈希匹配，返回当前行号/偏移与片段。
- `stale`：文件仍在，但锚点移动或哈希不一致——**不做任何模糊重定位**。
- `missing`：源文件已不存在。

时间线接口 `GET /incidents/{id}/timeline` 对每条证据实时解析并内联状态，
前端可直接把失效链接渲染为不可跳转的失效标记。

## 权限模型

请求头 `X-API-Token: <token>`（或 `Authorization: Bearer <token>`）。
应用首次启动时向 SQLite 写入三个种子用户：

| 用户 | 角色 | token | 能力 |
| --- | --- | --- | --- |
| alice | admin | `token-admin-alice` | 全部操作，含创建事故 |
| bob | investigator | `token-investigator-bob` | 读取、创建事件与证据链接、删除证据 |
| carol | viewer | `token-viewer-carol` | 只读 |

未认证返回 `401`，已认证但角色不足返回 `403`。源文件路径禁止越出
`APP_SOURCE_DIR`（拒绝 `../` 穿越），读取接口只返回定位片段，不提供整文件下载。

## API 摘要

| 方法与路径 | 最低角色 | 说明 |
| --- | --- | --- |
| `GET /health` | 公开 | 健康检查 |
| `GET /me` | 任意认证用户 | 返回当前用户与角色 |
| `POST /incidents` | admin | 创建事故 |
| `GET /incidents` / `GET /incidents/{id}` | viewer | 事故列表/详情 |
| `POST /incidents/{id}/events` | investigator | 创建时间线事件 |
| `GET /incidents/{id}/events` | viewer | 事件列表 |
| `GET /incidents/{id}/timeline` | viewer | 事件 + 证据 + 实时解析状态 |
| `GET /events/{id}` | viewer | 事件详情（含证据链接） |
| `POST /events/{id}/evidence` | investigator | 创建证据定位（line/offset/hash） |
| `GET /evidence/{id}` | viewer | 解析单条证据，返回 valid/stale/missing |
| `DELETE /evidence/{id}` | investigator | 删除证据链接 |

创建证据链接的请求体示例：

```json
{"kind": "line", "file_path": "logs/app.log", "line": 2, "label": "磁盘告警"}
{"kind": "offset", "file_path": "logs/app.log", "offset": 10, "length": 32}
{"kind": "hash", "file_path": "logs/app.log", "search_text": "disk full"}
```

## 项目结构

```
app/
  config.py      # 环境变量配置
  database.py    # SQLite schema、连接与种子用户
  hashing.py     # SHA-256 与哈希前缀
  locators.py    # 三类定位的构建与严格解析（valid/stale/missing）
  repository.py  # 数据访问层
  schemas.py     # Pydantic 请求/响应模型
  security.py    # token 认证与角色鉴权
  routes.py      # HTTP 路由
  main.py        # 应用工厂 create_app()
  run.py         # python -m app.run 入口
tests/
  test_locators.py  # 定位语义单元测试（11 项）
  test_api.py       # API/权限/失效端到端测试（9 项）
```
