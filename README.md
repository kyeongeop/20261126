# 事故时间线 · 假设与证据关联

分析员可以维护多个假设，并把时间线事件标记为 **支持 / 反驳 / 未知**，每个判断都可填写理由。
切换假设只是切换展示视图，不会修改原始事件。

技术栈：Python 3.12 · FastAPI · SQLite (SQLAlchemy) · pytest。无 Redis、消息队列或外部账号服务。

## 运行

```bash
python3.12 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/uvicorn app.main:app --reload
```

打开 http://127.0.0.1:8000 使用假设卡片界面；API 文档见 http://127.0.0.1:8000/docs 。

## 测试

```bash
.venv/bin/python -m pytest
```

## API 概览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/events` | 新增时间线事件 |
| GET | `/api/events` | 按发生时间列出事件 |
| POST | `/api/hypotheses` | 新增假设 |
| PATCH/DELETE | `/api/hypotheses/{id}` | 修改 / 删除假设 |
| PUT | `/api/hypotheses/{hid}/events/{eid}` | 创建或更新判断（verdict + reason） |
| DELETE | `/api/hypotheses/{hid}/events/{eid}` | 移除判断 |
| GET | `/api/hypotheses/{id}/board` | 假设卡片：事件按支持/反驳/未知分组 |

判断（`hypothesis_event_links`）与事件（`events`）分表存储：
对事件下判断、切换假设视图都只读写关联表，原始事件行保持不变
（由 `tests/test_links.py` 中的 `test_judging_never_modifies_events` 保证）。
