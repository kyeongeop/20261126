from __future__ import annotations

import os
import sqlite3
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.api import router
from app.db import initialize
from app.errors import DomainError


def create_app(
    database_path: str | Path | None = None,
    *,
    max_upload_bytes: int | None = None,
) -> FastAPI:
    resolved_path = Path(
        database_path or os.environ.get("DATABASE_PATH", "data/incident_timeline.db")
    )
    resolved_limit = max_upload_bytes or int(
        os.environ.get("MAX_UPLOAD_BYTES", str(25 * 1024 * 1024))
    )
    initialize(resolved_path)

    app = FastAPI(
        title="Incident Timeline",
        version="0.1.0",
        description=(
            "Incident evidence timeline with immutable versions and a "
            "tamper-evident custody chain."
        ),
    )
    app.state.database_path = resolved_path
    app.state.max_upload_bytes = resolved_limit

    @app.exception_handler(DomainError)
    async def domain_error_handler(request: Request, exc: DomainError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code, content={"detail": exc.message}
        )

    @app.exception_handler(sqlite3.IntegrityError)
    async def integrity_error_handler(
        request: Request, exc: sqlite3.IntegrityError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=409,
            content={
                "detail": f"database integrity rule rejected the operation: {exc}"
            },
        )

    app.include_router(router)
    return app


app = create_app()
