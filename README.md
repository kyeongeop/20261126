# 事故时间线 · TQL（Timeline Query Language）

一个本地运行的事故时间线应用。在原有的「主机 + 开始时间」筛选之外，新增一门小型查询语言
**TQL**，支持把**事件字段、前后关系、时间窗口、证据标签**自由组合成一条查询。

技术栈：Python 3.12 · FastAPI · SQLite（标准库 `sqlite3`）· pytest。
不依赖 Redis、消息队列或外部账号服务；前端为原生 HTML/CSS/JS，无需构建。

## 快速开始

```bash
# 1) 安装依赖（已用 Python 3.12 验证）
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"        # 或 pip install -r requirements.txt

# 2) 启动服务（首次启动自动建库并写入演示事故数据）
python -m app                  # 默认 http://127.0.0.1:8000
# 等价方式：python main.py  或  uvicorn main:app --reload

# 3) 跑测试
pytest

# 4) 命令行直接查询
python -m app.cli 'level = "error" AFTER #deploy WITHIN 30m'
python -m app.cli '#timeout' --csv > timeout.csv
```

打开 <http://127.0.0.1:8000/> 即是查询控制台：TQL 输入框、示例、带列定位的错误面板、
结果表格、条数上限与 CSV/JSON 导出。

## TQL 语法

一条查询是一个布尔表达式，条件之间用 `AND` / `OR` / `NOT` 和括号组合；关键字大小写不敏感。

### 1. 事件字段

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `id` | 整数 | 事件 ID，支持 `= != > >= < <=` |
| `ts`（别名 `time`/`timestamp`/`at`） | 时间 | ISO8601 或 epoch 秒，支持比较 |
| `host` / `service`（别名 `svc`） / `level`（别名 `severity`） | 字符串 | `= != ~ !~` |
| `message`（别名 `msg`） | 字符串 | 同上，`~` 为忽略大小写的包含匹配 |

```tql
host = "api-01" AND level = "error"
message ~ "timeout"
id > 100
ts >= "2026-11-25T14:00:00Z" AND ts < "2026-11-25T16:00:00Z"
```

含 `-` 等符号的裸值建议加引号；普通单词可以不加：`level = error`。

### 2. 证据标签组合

```tql
#deploy                                   -- 含 deploy 标签
tag = "deploy"                            -- 等价写法
#deploy AND NOT #verified                 -- 组合 / 排除
(#timeout OR #db-lock) AND #metrics       -- 括号分组
all_tags("db-lock", "timeout")            -- 同时含全部标签
any_tags("trace", "metrics")              -- 含任一标签
```

### 3. 前后关系

`A AFTER B`：存在一个满足 `B` 的事件，发生在满足 `A` 的事件之前；
`A BEFORE B` 方向相反。`A`、`B` 都可以是任意条件或括号表达式。

```tql
level = "error" AFTER #deploy
level = "error" AFTER (#config-change OR #rollback)
#timeout BEFORE #rollback
```

### 4. 时间窗口

- 关系窗口：`A AFTER B WITHIN 30m` 把前后间隔限制在窗口内（边界包含）。
- 相对窗口：`LAST 2h` 表示以当前时间（或显式 `now`）为基准的最近一段时间。
- 绝对区间：直接比较 `ts`。

时长单位：`ms` `s`（或 `sec`）`m`（或 `min`）`h` `d`。

```tql
level = "error" AFTER #deploy WITHIN 30m
#timeout BEFORE #rollback WITHIN 60m
LAST 2h AND level = "error"
```

上述能力可以任意组合，例如：

```tql
(#timeout OR #db-lock)
  AND service = "checkout"
  AND level = "error"
  AFTER (#deploy OR #config-change) WITHIN 30m
```

空字符串表示无条件（返回全部事件）。

## 语法错误定位

词法/语法/语义错误都返回结构化位置：`line`、`column`（1 基）、`offset`、`length`、
`fragment`（出错片段）以及带源码行和 `^` 插入符的 `rendered` 文本（CJK 宽度已处理）。

```
TQL 语法错误（syntax）：未知时间单位 'x'  (第 1 行, 第 39 列)
 1 | level = "error" AFTER #deploy WITHIN 5x
   |                                       ^
提示: 支持单位 ms / s / m（分钟）/ h（小时）/ d（天）
```

HTTP 响应为 `400`，body 形如 `{"error": {"kind": "syntax", "line": 1, "column": 39,
"fragment": "x", "rendered": "..."}}`。未知字段、无法解析的时间值等属于 `semantic`
错误，同样带列与片段。

## 数量限制与导出

- 查询接口 `limit` 默认 `100`，硬上限 `500`；超过上限会被截断到 `500` 并在响应中返回
  `"clamped": true`。
- 响应包含 `total`（匹配总数）、`returned`（本页条数）、`truncated`（是否还有更多），
  并支持 `offset` 分页与 `order=asc|desc`。
- 导出接口 `/api/timeline/export?format=csv|json` 复用同一条 TQL，导出上限 `5000`，
  通过 `X-TQL-Total / X-TQL-Exported / X-TQL-Truncated` 响应头告知截断情况；
  CSV 带 UTF-8 BOM，Excel 直接打开不乱码。

## HTTP API

| 方法 & 路径 | 说明 |
| --- | --- |
| `GET /` | 查询控制台页面 |
| `GET /api/timeline/query?q=<TQL>` | 执行 TQL；参数 `limit/offset/order/now` |
| `POST /api/timeline/query` | body：`{"query": "...", "limit": 100, "offset": 0, "order": "asc"}` |
| `GET /api/query` / `POST /api/query` | 上述查询接口的短别名 |
| `GET /api/timeline/export?q=<TQL>&format=csv\|json` | 导出（短别名 `GET /api/export`） |
| `GET /api/events?host=&start=&end=` | 旧版「主机 + 开始时间」筛选 |
| `GET /api/hosts` / `GET /api/tags` | 主机与证据标签元数据 |
| `GET /api/meta` | 字段、运算符、示例、限制常量 |
| `GET /api/health` | 健康检查 |

`now` 可传 ISO8601 或 epoch 秒，用于让 `LAST` 窗口和测试可复现；不传则取服务器当前时间。

## 作为 Python 库使用

```python
from app.tql import parse, compile_query, TQLSyntaxError

try:
    tree = parse('level = "error" AFTER #deploy WITHIN 10m')
except TQLSyntaxError as exc:
    print(exc.line, exc.column, exc.fragment)
    print(exc.render())

where_sql, params = compile_query(tree, now=1764204200.0, source="...")
# 所有用户值均通过 ? 参数绑定；前后关系/标签编译为相关 EXISTS 子查询
```

## 目录结构

```
app/
  main.py            # FastAPI 路由、错误处理、静态页挂载
  config.py          # 本地配置（TIMELINE_DB_PATH 可覆盖数据库路径）
  db.py              # SQLite 连接与 schema（events / event_tags / evidence）
  seed.py            # 演示事故数据 + insert_event 助手
  repository.py      # TQL 执行、经典筛选、limit 上限、证据装配
  exporting.py       # CSV / JSON 序列化
  cli.py             # python -m app.cli
  tql/
    errors.py        # Span / TQLError：行列、片段、插入符渲染
    lexer.py         # 带位置的词法分析
    ast_nodes.py     # AST
    parser.py        # 递归下降解析 + 精确语法错误
    compiler.py      # AST -> 参数化 SQLite WHERE（含语义校验）
  static/            # 原生前端（index.html / styles.css / app.js）
tests/               # pytest：词法、解析定位、语义、执行、API、导出
```

## 设计说明

- TQL 先做词法/语法分析得到 AST，再做字段类型校验并编译成**参数化 SQL**；
  字段名走白名单映射，值全部绑定参数，杜绝注入。
- 前后关系编译为 `EXISTS (SELECT 1 FROM events ...)`，标签同理，因此
  `total` 可以直接用 `COUNT(*)` 得到，分页/截断语义清晰。
- 数据库路径默认 `data/timeline.db`，可用环境变量 `TIMELINE_DB_PATH` 覆盖；
  传 `:memory:` 时使用单连接内存库，适合嵌入式/测试场景。
