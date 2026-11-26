from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.db import Database
from app.routes_handover import router as handover_router
from app.routes_timeline import router as timeline_router


def create_app(database_path: str | Path | None = None) -> FastAPI:
    database = Database(database_path)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        database.initialize()
        yield

    application = FastAPI(
        title="事故时间线案件交接",
        version="0.1.0",
        description="支持分析员换班交接清单与只读权限切换的事故时间线服务。",
        lifespan=lifespan,
    )
    application.state.database = database
    application.include_router(timeline_router)
    application.include_router(handover_router)

    static_dir = Path(__file__).resolve().parent / "static"
    if static_dir.exists():
        application.mount("/static", StaticFiles(directory=static_dir), name="static")

        @application.get("/", include_in_schema=False)
        def index() -> FileResponse:
            return FileResponse(static_dir / "index.html")

    @application.get("/health", tags=["system"])
    def health() -> dict[str, str]:
        return {"status": "ok"}

    return application


app = create_app()
