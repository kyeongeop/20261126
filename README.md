# 事故时间线 · 案件交接

一个用于事故调查时间线的 FastAPI 应用。分析员换班时可以生成交接清单，接手人核对确认后完成案件负责人切换，旧负责人自动降为只读访问。

## 技术栈

- Python 3.12
- FastAPI
- SQLite
- pytest

## 启动

项目使用 `uv` 管理 Python 3.12 虚拟环境：

```bash
uv sync --dev
uv run uvicorn app.main:app --reload
```

打开 <http://127.0.0.1:8000/> 使用页面，或访问 <http://127.0.0.1:8000/docs> 查看 OpenAPI 接口文档。

数据库默认位于 `data/incident_timeline.db`。可以通过 `INCIDENT_DB_PATH` 指定其他位置：

```bash
INCIDENT_DB_PATH=/tmp/incident.db uv run uvicorn app.main:app --reload
```

## 测试

```bash
uv run pytest
```

## 身份与权限

写入接口通过请求头 `X-Analyst-Id` 标识当前分析员。也可以在查询参数中使用 `analyst_id=...`。

- 案件创建者自动成为负责人，拥有读写权限。
- 发起交接后，接手人可以先查看并核对清单，但仍不能修改时间线。
- 接手人确认交接后，接手人成为负责人；旧负责人保留案件和清单的读取权限，所有写入请求返回 `403`。

## 交接清单

`POST /api/cases/{case_id}/handovers` 会生成以下清单：

- `unconfirmed_events`：未确认事件。
- `unfinished_hypotheses`：未完成假设。
- `evidence_to_supplement`：待补证据。
- `permission`：交接前后的权限说明。

清单项同时记录 `outgoing_note`（旧负责人手写备注）和 `successor_note`（接手人备注）。备注更新采用追加写入，刷新清单只更新自动生成的事件、假设和证据状态，不会覆盖任何已记录备注。

主要接口：

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `POST` | `/api/analysts` | 创建分析员 |
| `POST` | `/api/cases` | 创建案件 |
| `POST` | `/api/cases/{id}/events` | 添加时间线事件 |
| `POST` | `/api/cases/{id}/hypotheses` | 添加假设 |
| `POST` | `/api/cases/{id}/evidence` | 添加证据项 |
| `POST` | `/api/cases/{id}/handovers` | 发起交接并生成清单 |
| `PATCH` | `/api/cases/{id}/handovers/{hid}/items/{item_id}` | 更新核对状态或追加备注 |
| `PATCH` | `/api/cases/{id}/handovers/{hid}/checklist` | 批量更新清单 |
| `POST` | `/api/cases/{id}/handovers/{hid}/refresh` | 按最新案件状态刷新清单 |
| `POST` | `/api/cases/{id}/handovers/{hid}/confirm` | 接手人确认交接 |

请求示例：

```bash
curl -X POST http://127.0.0.1:8000/api/analysts \
  -H 'Content-Type: application/json' \
  -d '{"name":"林分析员"}'

curl -X POST http://127.0.0.1:8000/api/cases \
  -H 'Content-Type: application/json' \
  -H 'X-Analyst-Id: 1' \
  -d '{"title":"数据库连接耗尽事故"}'
```
