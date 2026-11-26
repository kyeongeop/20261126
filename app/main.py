"""FastAPI 入口：TQL 查询/导出 + 旧版主机/开始时间筛选 + 静态页面。"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Query, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import config
from .db import connect, init_db, is_empty
from .exporting import to_csv, to_json
from .repository import (
    DEFAULT_LIMIT,
    EXPORT_MAX_LIMIT,
    MAX_LIMIT,
    LimitError,
    TimelineRepository,
)
from .seed import seed_demo
from .tql import TQLError
from .tql.compiler import parse_time_value

STATIC_DIR = Path(__file__).resolve().parent / "static"


def _coerce_now(value: Any) -> float | None:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value)
    try:
        return parse_time_value(text, None, None)
    except TQLError:
        raise


def create_app(db_path: str | Path | None = None, *, seed: bool = True) -> FastAPI:
    resolved_path = Path(db_path) if db_path else config.DB_PATH
    is_memory = str(resolved_path) == ":memory:"

    # 即时初始化，保证 TestClient 不进入 lifespan 上下文时也有表和示例数据
    memory_conn = None
    if is_memory:
        memory_conn = connect(":memory:")
        init_db(memory_conn)
        if seed and is_empty(memory_conn):
            seed_demo(memory_conn)
    else:
        bootstrap = connect(resolved_path)
        try:
            init_db(bootstrap)
            if seed and is_empty(bootstrap):
                seed_demo(bootstrap)
        finally:
            bootstrap.close()

    app = FastAPI(
        title="事故时间线 TQL",
        version="1.0.0",
        description="支持事件字段、前后关系、时间窗口、证据标签组合查询的本地时间线服务",
    )
    app.state.db_path = resolved_path
    app.state.is_memory = is_memory
    app.state.memory_conn = memory_conn

    def get_repo() -> TimelineRepository:
        if is_memory:
            return TimelineRepository(memory_conn)
        conn = connect(resolved_path)
        return TimelineRepository(conn)

    def close_repo(repo: TimelineRepository) -> None:
        if not is_memory:
            repo.conn.close()

    # -- 错误处理 -------------------------------------------------------
    @app.exception_handler(TQLError)
    async def _tql_error_handler(request: Request, exc: TQLError):
        return JSONResponse(status_code=400, content={"error": exc.to_dict()})

    @app.exception_handler(LimitError)
    async def _limit_error_handler(request: Request, exc: LimitError):
        return JSONResponse(
            status_code=400,
            content={"error": {"kind": "limit_error", "message": str(exc)}},
        )

    # -- 基础 -----------------------------------------------------------
    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "service": "incident-timeline-tql"}

    @app.get("/api/meta")
    def meta() -> dict[str, Any]:
        return {
            "language": "TQL",
            "fields": [
                {"name": "id", "type": "integer"},
                {"name": "ts", "type": "time", "aliases": ["time", "timestamp"]},
                {"name": "host", "type": "string"},
                {"name": "service", "type": "string", "aliases": ["svc"]},
                {"name": "level", "type": "string", "aliases": ["severity"]},
                {"name": "message", "type": "string", "aliases": ["msg"]},
                {"name": "tag", "type": "tag", "note": "tag = \"x\" 或 #x"},
            ],
            "operators": {
                "comparison": ["=", "!=", "<", "<=", ">", ">="],
                "text": ["~ (包含, 忽略大小写)", "!~ (不包含)"],
                "boolean": ["AND", "OR", "NOT", "()"],
                "temporal": ["BEFORE", "AFTER", "WITHIN <duration>"],
                "window": ["LAST <duration>"],
                "tag_functions": ["all_tags(...)", "any_tags(...)"],
                "duration_units": ["ms", "s", "m", "h", "d"],
            },
            "limits": {
                "default_limit": DEFAULT_LIMIT,
                "max_limit": MAX_LIMIT,
                "export_max_limit": EXPORT_MAX_LIMIT,
            },
            "examples": [
                'level = "error"',
                'host = "api-01" AND level = "error"',
                'message ~ "timeout"',
                "#deploy AND NOT #verified",
                "all_tags(\"db-lock\", \"timeout\")",
                'level = "error" AFTER #deploy WITHIN 20m',
                'level = "error" BEFORE #rollback WITHIN 40m',
                "LAST 6h AND service = \"checkout\"",
                "(#timeout OR #db-lock) AND service = \"checkout\"",
                "#timeout BEFORE #rollback WITHIN 45m",
            ],
        }

    @app.get("/api/hosts")
    def hosts() -> dict[str, Any]:
        repo = get_repo()
        try:
            return {"hosts": repo.list_hosts()}
        finally:
            close_repo(repo)

    @app.get("/api/tags")
    def tags() -> dict[str, Any]:
        repo = get_repo()
        try:
            return {"tags": repo.list_tags()}
        finally:
            close_repo(repo)

    _register_query_routes(app, get_repo, close_repo)
    _register_static(app)
    return app


class TQLQueryBody(BaseModel):
    query: str = Field(default="", description="TQL 查询字符串")
    limit: int | None = Field(default=None)
    offset: int = Field(default=0)
    order: str = Field(default="asc")
    now: str | float | None = Field(default=None)


def _register_query_routes(app: FastAPI, get_repo, close_repo) -> None:
    # 路由在 create_app 内注册以闭合 db_path 依赖
    @app.get("/api/events")
    def classic_events(
        host: str | None = None,
        start: str | None = Query(default=None, description="开始时间 ISO8601"),
        start_time: str | None = None,
        end: str | None = None,
        limit: int | None = None,
        order: str = "asc",
    ):
        repo = get_repo()
        try:
            start_value = start if start is not None else start_time
            return repo.list_events(
                host=host, start=start_value, end=end, limit=limit, order=order
            )
        finally:
            close_repo(repo)

    def _run(q: str, limit, offset, order, now_value):
        repo = get_repo()
        try:
            return repo.search_tql(
                q,
                now=_coerce_now(now_value),
                limit=limit,
                offset=offset or 0,
                order=order or "asc",
            )
        finally:
            close_repo(repo)

    @app.get("/api/timeline/query")
    def tql_query_get(
        q: str = "",
        query: str | None = None,
        limit: int | None = None,
        offset: int = 0,
        order: str = "asc",
        now: str | None = None,
    ):
        return _run(query if query is not None else q, limit, offset, order, now)

    @app.post("/api/timeline/query")
    def tql_query_post(body: TQLQueryBody):
        return _run(body.query, body.limit, body.offset, body.order, body.now)

    # 短别名，方便命令行/脚本
    @app.get("/api/query")
    def query_alias_get(
        q: str = "",
        limit: int | None = None,
        offset: int = 0,
        order: str = "asc",
        now: str | None = None,
    ):
        return _run(q, limit, offset, order, now)

    @app.post("/api/query")
    def query_alias_post(body: TQLQueryBody):
        return _run(body.query, body.limit, body.offset, body.order, body.now)

    @app.get("/api/timeline/export")
    @app.get("/api/export")
    def tql_export(
        q: str = "",
        query: str | None = None,
        format: str = "csv",
        limit: int | None = None,
        order: str = "asc",
        now: str | None = None,
    ):
        qstr = query if query is not None else q
        repo = get_repo()
        try:
            result = repo.export_rows(
                qstr,
                now=_coerce_now(now),
                limit=limit,
                order=order,
            )
        finally:
            close_repo(repo)

        fmt = format.lower()
        items = result["items"]
        if fmt == "json":
            payload = to_json(items)
            return Response(
                content=payload,
                media_type="application/json; charset=utf-8",
                headers={
                    "Content-Disposition": 'attachment; filename="timeline-export.json"',
                    "X-TQL-Total": str(result["total"]),
                    "X-TQL-Exported": str(result["returned"]),
                    "X-TQL-Truncated": str(result["truncated"]).lower(),
                },
            )
        if fmt != "csv":
            return JSONResponse(
                status_code=400,
                content={"error": {"kind": "format_error",
                                   "message": f"不支持的导出格式 {format!r}，可选 csv / json"}},
            )
        # BOM 让 Excel 正确识别 UTF-8 中文
        csv_text = "﻿" + to_csv(items)
        filename = f"timeline-export-{time.strftime('%Y%m%d-%H%M%S')}.csv"
        return Response(
            content=csv_text,
            media_type="text/csv; charset=utf-8",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "X-TQL-Total": str(result["total"]),
                "X-TQL-Exported": str(result["returned"]),
                "X-TQL-Truncated": str(result["truncated"]).lower(),
            },
        )


def _register_static(app: FastAPI) -> None:
    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

        @app.get("/")
        def index() -> FileResponse:
            return FileResponse(STATIC_DIR / "index.html")


app = create_app()
