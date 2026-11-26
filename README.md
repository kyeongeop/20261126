# 事故时间线 · 冲突事件合并

同一用户的一次登录，被两个系统（例如企业身份系统 IdP 与 VPN 网关）分别记录，
但两边给出的时间、会话 ID、IP、设备、认证方式等存在差异。本服务自动把这些
记录聚成**候选合并组**，在一个审查工作台中展示：

- **每个来源各自的时间**（UTC 规范时间 + 原始时间串 + 相互差值 / 早晚标记）；
- **逐字段差异**（每个字段在每个来源中的值，冲突项高亮）；
- **可信度**（0–100% 匹配分、高/中/低分级、可解释的评分分量，以及按来源
  可靠度加权后的可信度；同时展示每个来源自身的 `reliability`）。

分析员可以对候选组执行三种处置，并可随时重新处理：

- **保留（合并）**：生成一个规范时间线事件，可选择采用哪个来源的时间 / 字段；
- **拆分**：判定为不同事件，生成多个独立时间线事件（默认一条来源记录一个）；
- **标记未知**：无法判断时挂入“未知”队列，不写入结论性时间线事件。

> 核心保证：`source_records` 中的来源原始记录**只追加、永不修改或删除**。
> 合并 / 拆分产生的 `timeline_events` 只是派生视图，并通过
> `timeline_event_records` 反向关联到全部原始记录；任何处置后都能取回原文。

## 技术栈

- Python 3.12
- FastAPI + Pydantic v2（ASGI，`uvicorn` 运行）
- SQLite（标准库 `sqlite3`，无需外部数据库）
- pytest + FastAPI `TestClient`（httpx）
- 原生 HTML/CSS/JS 单页审查工作台（无构建步骤）

## 目录结构

```
app/
  main.py        # FastAPI 应用工厂 create_app(db_path, seed=...) 与 ASGI app
  api.py         # /api 路由（候选、处置、时间线、原始记录、重置演示）
  service.py     # 事务与合并/拆分/未知/重开工作流、查询序列化
  logic.py       # 纯函数：时间归一、字段 diff、可信度评分、规范值选择
  database.py    # SQLite 连接与 schema
  schemas.py     # 请求模型
  seed.py        # 幂等演示数据（两个系统的同一登录冲突）
static/          # 审查工作台前端（index.html / app.js / styles.css）
tests/           # pytest 套件（32 个用例）
main.py          # 根 ASGI 垫片：也支持 uvicorn main:app
requirements.txt
pytest.ini
```

## 快速开始（常规环境）

```bash
# 需要 Python 3.12
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 初始化并写入演示数据（可选；直接启动时默认也会自动播种）
python -m app.seed

# 运行入口（二选一）
python -m app.main
uvicorn app.main:app --reload
```

启动后打开：

- 审查工作台：<http://127.0.0.1:8000/>
- 交互式 API 文档：<http://127.0.0.1:8000/docs>
- 健康检查：<http://127.0.0.1:8000/api/health>

### 运行测试

```bash
pytest                 # 等价于 python -m pytest
pytest -q              # 简洁输出
```

`pytest.ini` 已配置 `testpaths = tests` 与 `pythonpath = .`，在仓库根目录直接
运行即可；测试全部使用临时 SQLite 文件，不依赖 `data/timeline.db`。

### 当前工作区已预装的离线环境

本仓库内已存在一个基于 conda-forge 的 `.venv`（含 Python 3.12 与全部依赖，
但不含 `activate` 脚本）。在本机无法访问 PyPI 时，可直接用解释器绝对路径：

```bash
./.venv/bin/python -m pytest -q
./.venv/bin/python -m app.seed
./.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

## 配置（环境变量）

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `TIMELINE_DB` | `data/timeline.db` | SQLite 路径；测试用临时文件，也支持 `:memory:` |
| `MERGE_WINDOW_HOURS` | `24` | 自动检测候选时，同用户同类型事件的最大时间窗 |
| `TIMELINE_AUTO_SEED` | `1` | 默认 app 启动时是否播种演示数据，置 `0` 关闭 |

## HTTP API 速览

| 方法 & 路径 | 说明 |
| --- | --- |
| `POST /api/sources` / `GET /api/sources` | 注册 / 列出来源系统（含 `reliability`） |
| `POST /api/records` | 录入一条来源原始记录；按 `(source_code, external_id)` 幂等，重复投递不覆盖原文 |
| `POST /api/records/batch` | 批量录入，可选择 `auto_detect` 自动建候选 |
| `GET  /api/records` / `GET /api/records/{id}` | 查询原始记录 |
| `POST /api/candidates/detect?window_hours=24` | 幂等地自动检测候选组（已分组记录不会重复分组） |
| `POST /api/candidates` | 用 `{"record_ids": [...]}` 显式建组（≥2 条，重叠分组返回 409） |
| `GET  /api/candidates?status=pending` | 候选列表（`pending/unknown/merged/split/all`） |
| `GET  /api/candidates/{id}` | **审查详情**：各来源时间、`field_diff`、`confidence`、全部原始记录、允许动作 |
| `POST /api/candidates/{id}/keep` | **保留并合并**为一个事件；可用 `time_source_record_id` / `field_sources` / `canonical_fields` 指定取值 |
| `POST /api/candidates/{id}/merge` | 同上的直观别名 |
| `POST /api/candidates/{id}/split` | **拆分**；可传 `groups: [[id,...], ...]` 自定义分组，默认每条记录一个事件 |
| `POST /api/candidates/{id}/unknown` | **标记未知**（保留记录，不生成结论事件） |
| `POST /api/candidates/{id}/reopen` | 重新处理：仅删除派生时间线事件，原始记录不动 |
| `POST /api/candidates/{id}/resolve` | 通用入口，body 带 `"decision": "keep|merge|split|unknown|reopen"` |
| `GET  /api/candidates/{id}/records` | 候选组的全部原始记录 |
| `GET  /api/candidates/{id}/actions` | 审计流水（谁在何时做了什么） |
| `GET  /api/timeline` / `GET /api/timeline/{event_id}` | 规范时间线 / 事件详情（含 `originals` 全量原文与差异） |
| `GET  /api/events/{event_id}/records` | 一个时间线事件关联的全部来源原始记录 |
| `POST /api/admin/reset-demo` | 清空并重建内置演示数据，方便反复体验 |

分析员可在请求体传 `"analyst"` / `"note"`，也可用请求头 `X-Analyst: zhangsan`。

### 端到端示例

内置演示数据可直接体验：候选 `cand-alice`（高可信，建议保留）、
`cand-bob`（低可信，建议拆分）、`cand-carol`（中可信，可标记未知），
以及已合并、已在时间线上的 `cand-dave`。

```bash
# 1. 查看待处理候选
curl -s "http://127.0.0.1:8000/api/candidates?status=pending" | python -m json.tool

# 2. 查看某个候选的时间对比 / 字段差异 / 可信度
curl -s "http://127.0.0.1:8000/api/candidates/cand-alice" | python -m json.tool

# 3a. 保留并合并，且采用 VPN 来源的时间
curl -s -X POST "http://127.0.0.1:8000/api/candidates/cand-alice/keep" \
  -H 'Content-Type: application/json' \
  -d '{"analyst":"zhangsan","note":"时钟偏差","time_source_record_id":"rec-alice-vpn"}'

# 3b. 或拆分为两个独立事件
curl -s -X POST "http://127.0.0.1:8000/api/candidates/cand-bob/split" \
  -H 'Content-Type: application/json' -d '{"analyst":"zhangsan"}'

# 3c. 或标记未知
curl -s -X POST "http://127.0.0.1:8000/api/candidates/cand-carol/unknown" \
  -H 'Content-Type: application/json' -d '{"note":"等待 EDR 日志"}'

# 4. 时间线与“合并后仍保留”的原始记录
curl -s "http://127.0.0.1:8000/api/timeline" | python -m json.tool
EVT=<event_id>
curl -s "http://127.0.0.1:8000/api/events/$EVT/records" | python -m json.tool
```

## 可信度如何计算

`app/logic.py:score_match` 给出完全可解释的 0–1 匹配分（权重之和为 1）：

- **主体与事件类型一致（0.20）**：所有来源的 `user_id` 相同得 0.12，
  `event_type` 相同得 0.08；
- **时间接近度（0.45）**：按各来源时间的最大差值分段衰减
  （≤1 分钟满分；≤5 分钟 0.92；≤15 分钟 0.75；≤1 小时 0.5；
  ≤6 小时 0.25；≤24 小时 0.1；更久 0）；
- **字段交叉印证（0.35）**：对至少两个来源都提供的字段，按
  IP / 设备 / 会话 / UA / 地理位置 / 认证方式 / 结果等权重，
  一致才得分；没有可交叉字段时取中性系数，不因缺数据而重罚。

分级阈值：`score >= 0.80` 高可信，`>= 0.55` 中可信，其余低可信。
此外 `trust_adjusted_score = score × 各来源 reliability 均值`，
把“匹配可能性”和“来源本身可信度”分开呈现。

时间统一解析为带时区的 UTC（兼容结尾 `Z` 与 `+08:00` 偏移），
因此 `17:04:57+08:00` 与 `09:04:57Z` 是同一时刻，差值计算不会被时区误导。

## “不丢失任一原始记录”的设计

- `source_records` 是**只追加表**：代码中没有任何 `UPDATE` / `DELETE`
  作用于它；重复投递相同 `(source_code, external_id)` 走 `INSERT OR IGNORE`
  并返回已存在记录，不会覆盖时间或 `payload_json`。
- 每次合并 / 拆分都在 `timeline_event_records` 中写入事件 ↔ 原始记录关联：
  - 保留合并：1 个事件关联组内**全部**记录；
  - 拆分：每个事件关联对应分组的记录（默认 1:1）；
  - 标记未知：不建事件，但候选组仍持有全部记录，可随时查看 / 再处置。
- “重新处理”只会删除**派生的** `timeline_events`（关联行通过
  `ON DELETE CASCADE` 清理），`source_records` 与 `candidate_records`
  始终保留，因此可以在保留 / 拆分 / 未知之间反复改判。
- `GET /api/timeline/{id}` 的 `originals` 与
  `GET /api/events/{id}/records` 返回完整原文；
  `tests/test_preservation.py` 对整条处置生命周期做了快照级校验。

## 测试

```bash
pytest -q
```

覆盖：

- `tests/test_logic.py`：时间归一 / 差值、字段 diff、可信度评分与规范值选择；
- `tests/test_ingestion_detection.py`：幂等录入、原文不被重复投递覆盖、
  自动检测幂等、显式建组与重叠 409、错误路径；
- `tests/test_merge_workflow.py`：保留（含选择时间来源）、拆分、未知、
  重开、状态机 409、通用 `resolve`、审计；
- `tests/test_preservation.py`：跨全部处置动作的原始记录快照不变、
  关联与级联行为；
- `tests/test_seed.py`：演示数据分级与幂等；
- `tests/test_web_and_admin.py`：静态工作台资源、重置接口、OpenAPI 路由、
  `:memory:` 模式与 `/merge` 别名。

## 本地数据清理

默认数据库写在 `data/timeline.db`（已被 `.gitignore` 忽略）。删除该文件后
重启或重新执行 `python -m app.seed` 即恢复初始演示；也可直接在页面右上角
点击“重置演示数据”，或调用 `POST /api/admin/reset-demo`。
