# Incident Timeline

事故时间线服务，使用 Python 3.12、FastAPI 和 SQLite。案件证据以不可变版本保存，
每次上传、查看、导出、替换、重命名和作废都会追加一条保管链记录。

## 保管链规则

- 主体：每个受保管操作都要求 `X-Actor` 请求头，缺失时返回 `401`。
- 时间：服务端以 UTC 写入 `occurred_at`，不接受客户端时间。
- 来源：自动记录客户端 IP、`User-Agent`、HTTP 方法和路径；`X-Source` 可标注业务来源。
- 版本摘要：内容使用 SHA-256；版本摘要覆盖证据 ID、版本号、文件名、大小、内容摘要、
  前序版本摘要、创建人和时间。
- 事件摘要：每条事件包含前序哈希，并以 `SHA-256(前序哈希 + 规范化事件 JSON)` 生成
  `record_hash`，形成可复算的链。
- 删除：`DELETE` 只把证据状态改为 `voided`，并追加 `DELETE` 事件。版本和事件均不删除。
- 数据库约束：SQLite 触发器禁止删除案件、证据、版本和保管链事件，也禁止修改版本与事件。

## 启动

```bash
uv sync --extra test
uv run uvicorn app.main:app --reload
```

也可以使用 pip：

```bash
python3.12 -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
uvicorn app.main:app --reload
```

默认数据库是 `data/incident_timeline.db`。可通过环境变量覆盖：

```bash
DATABASE_PATH=/var/lib/incident-timeline/timeline.db \
MAX_UPLOAD_BYTES=52428800 \
uv run uvicorn app.main:app
```

接口文档位于 `http://127.0.0.1:8000/docs`。

## 请求头

```text
X-Actor: analyst.alice
X-Source: incident-console
X-Forwarded-For: 203.0.113.9
User-Agent: custody-client/1.0
```

`X-Source` 可省略，此时来源使用客户端 IP。`X-Forwarded-For` 可选，部署时应仅信任
受控反向代理写入的该请求头。

## API

| 方法 | 路径 | 保管链动作 |
| --- | --- | --- |
| `POST` | `/cases` | 创建案件 |
| `GET` | `/cases/{case_id}/evidence` | 证据列表 |
| `POST` | `/cases/{case_id}/evidence` | `UPLOAD` |
| `GET` | `/cases/{case_id}/evidence/{evidence_id}` | `VIEW` |
| `GET` | `/cases/{case_id}/evidence/{evidence_id}/export` | `EXPORT` |
| `GET` | `/cases/{case_id}/evidence/{evidence_id}/versions/{n}/export` | `EXPORT` |
| `POST` | `/cases/{case_id}/evidence/{evidence_id}/versions` | `REPLACE` |
| `PATCH` | `/cases/{case_id}/evidence/{evidence_id}` | `RENAME` |
| `DELETE` | `/cases/{case_id}/evidence/{evidence_id}` | `DELETE`，只作废 |
| `GET` | `/cases/{case_id}/evidence/{evidence_id}/custody` | 查询并验证保管链 |
| `GET` | `/cases/{case_id}/evidence/{evidence_id}/verify` | 只执行完整性验证 |
| `GET` | `/cases/{case_id}/timeline` | 按时间返回案件保管链事件 |

证据列表默认只返回有效证据；传 `include_voided=true` 可查看作废证据及其全部历史版本。
作废证据不可再替换或重命名，但其历史版本仍可导出并产生新的 `EXPORT` 记录。

## 使用示例

```bash
case_id=$(curl -s -X POST http://127.0.0.1:8000/cases \
  -H 'Content-Type: application/json' \
  -H 'X-Actor: analyst.alice' \
  -d '{"title":"Checkout latency incident"}' | python -c 'import json,sys; print(json.load(sys.stdin)["id"])')

curl -X POST "http://127.0.0.1:8000/cases/$case_id/evidence" \
  -H 'X-Actor: analyst.alice' \
  -H 'X-Source: incident-console' \
  -F 'file=@tests/fixtures/logs/api-gateway-20261126.log;type=text/plain' \
  -F 'display_name=API gateway log'
```

导出响应包含以下校验头：

```text
X-Evidence-Version: 1
X-Evidence-Status: active
X-Evidence-Content-SHA256: ...
X-Evidence-Version-Digest: ...
X-Custody-Record-Hash: ...
```

`GET .../custody` 和 `GET .../verify` 会重新计算全部内容摘要、版本摘要及事件哈希链，
返回 `valid`、错误列表、检查数量和链头 `chain_head`。
若需要防御拥有数据库写权限的人整体重算哈希链，应把每次确认后的 `chain_head`
保存到独立审计存储中。

## 测试

测试统一使用 pytest，样本案件和日志位于 `tests/fixtures/`：

```bash
uv run pytest
```

覆盖内容：

- 上传、查看、导出、重命名、替换、作废的完整事件顺序与主体/时间/来源。
- 旧版本摘要链、当前版本指针和作废后历史保留。
- 损坏内容后的摘要校验失败。
- SQLite 层物理删除和版本修改拦截。
- 所有受保管操作强制要求 `X-Actor`。
