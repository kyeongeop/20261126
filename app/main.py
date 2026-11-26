"""FastAPI application factory and HTTP routes for the incident timeline."""

from __future__ import annotations

from fastapi import FastAPI, HTTPException, status

from .config import Settings
from .database import initialize, seed_users
from .locators import (
    StoredLocator,
    build_hash_locator,
    build_line_locator,
    build_offset_locator,
    ensure_within_base,
    resolve_locator,
)
from .routes import _register_routes
from .security import build_authenticator


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    settings.source_dir.mkdir(parents=True, exist_ok=True)
    initialize(settings.db_path)
    seed_users(settings.db_path)

    app = FastAPI(
        title="Incident Timeline",
        version="0.1.0",
        description="Timeline events with stable, hash-pinned evidence links.",
    )
    authenticate = build_authenticator(settings.db_path)

    def _build_locator(payload) -> StoredLocator:
        try:
            ensure_within_base(settings.source_dir, payload.file_path)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
            )
        full_path = settings.source_dir / payload.file_path
        if not full_path.is_file():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"source file {payload.file_path!r} not found",
            )
        try:
            if payload.kind == "line":
                return build_line_locator(
                    settings.source_dir, payload.file_path,
                    payload.line, payload.end_line,
                )
            if payload.kind == "offset":
                return build_offset_locator(
                    settings.source_dir, payload.file_path,
                    payload.offset, payload.length,
                )
            return build_hash_locator(
                settings.source_dir, payload.file_path,
                payload.search_text, payload.occurrence,
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
            )

    def _resolve(row) -> dict:
        result = resolve_locator(
            settings.source_dir, StoredLocator.from_row(row)
        )
        payload = result.to_dict()
        payload["evidence_id"] = row["id"]
        payload["event_id"] = row["event_id"]
        return payload

    _register_routes(app, settings, authenticate, _build_locator, _resolve)
    return app
