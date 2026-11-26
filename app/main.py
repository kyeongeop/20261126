"""FastAPI application entry point.

Run locally with either::

    python -m app.main
    uvicorn app.main:app --reload

The application factory :func:`create_app` accepts an explicit SQLite path
so tests get an isolated database.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import config
from .api import router as api_router
from .database import connect, init_db, init_database_file
from .errors import ServiceError

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "static"


def create_app(
    database_path: str | Path | None = None,
    *,
    seed: bool | None = None,
) -> FastAPI:
    path = str(database_path if database_path is not None else config.DATABASE_PATH)

    app = FastAPI(
        title="事故时间线 · 冲突事件合并",
        version="1.0.0",
        description=(
            "审查来自两个系统的同一用户登录事件：对比各来源时间与字段差异、"
            "查看可信度，并执行保留合并 / 拆分 / 标记未知。所有处置均保留"
            "各来源的原始记录。"
        ),
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.state.db_path = path
    app.state.mem_conn = None

    if path == ":memory:":
        # A single long-lived connection preserves the in-memory schema/data
        # across request-scoped connections.
        mem_conn = connect(":memory:")
        init_db(mem_conn)
        app.state.mem_conn = mem_conn
    else:
        init_database_file(path)

    @app.exception_handler(ServiceError)
    async def service_error_handler(_: Request, exc: ServiceError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": exc.code,
                "message": exc.message,
                "details": exc.details,
            },
        )

    app.include_router(api_router)

    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

        @app.get("/", include_in_schema=False)
        async def index() -> FileResponse:
            return FileResponse(str(STATIC_DIR / "index.html"))

    should_seed = config.AUTO_SEED if seed is None else seed
    if should_seed:
        from .seed import seed_demo

        if path == ":memory:":
            seed_demo(conn=app.state.mem_conn)
        else:
            seed_demo(path)

    return app


app = create_app()


def main() -> None:
    import uvicorn

    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=False)


if __name__ == "__main__":
    main()
