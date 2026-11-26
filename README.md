# 20261126

事故时间线应用（Python 3.12 + FastAPI + SQLite），支持“导出前脱敏”：
字段级规则、正则规则、上下文例外，导出前可预览脱敏结果与替换数量，
同一事件重复导出得到完全相同的替换结果（HMAC 确定性假名化）。

## 运行

```bash
python3.12 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/uvicorn app.main:app
```

## 测试

```bash
.venv/bin/python -m pytest
```

测试数据位于 `fixtures/`（`events.json` 事件、`rules.json` 脱敏规则）。

## API

- `POST /incidents` 创建事故；`POST /incidents/{id}/events` 追加时间线事件
- `PUT /rules/{name}` 新增/更新脱敏规则；`GET /rules` 列出规则
- `GET /events/{id}/export/preview` 脱敏预览（含每条规则的替换数量）
- `GET /events/{id}/export` 正式导出（与预览结果一致）

## 规则格式

```json
{"type": "regex", "label": "host", "pattern": "\\b[a-z0-9-]+\\.prod\\.internal\\b",
 "exceptions": [{"pattern": "^status\\.", "on": "match"}]}
{"type": "field", "label": "email", "fields": ["payload.reporter.email"]}
```

例外 `on: "match"` 表示匹配文本本身命中例外则不脱敏；`on: "context"`
表示匹配点前后 40 字符上下文命中例外则不脱敏（如文档中的示例令牌）。
