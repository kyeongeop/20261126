from __future__ import annotations

import shutil
import tempfile
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile, status
from fastapi.responses import FileResponse

from . import __version__
from .config import Settings
from .db import init_db
from .evidence import EvidenceGenerationError, create_evidence_package
from .repository import (
    InvalidReferenceError,
    NotFoundError,
    create_event,
    create_incident,
    create_raw_file,
    get_incident,
    get_package_record,
    get_raw_file,
    list_events,
    list_incidents,
    list_package_records,
    list_raw_files,
)
from .schemas import (
    EventCreate,
    EventRead,
    EvidencePackageCreate,
    EvidencePackageRead,
    HealthRead,
    IncidentCreate,
    IncidentRead,
    RawFileRead,
    TimelineRead,
    VerificationRead,
)
from .signing import load_or_create_signing_material
from .storage import safe_archive_name, safe_display_name, write_upload
from .timeutil import iso_utc, to_utc
from .verification import verify_package


def _parse_captured_at(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return iso_utc(to_utc(parsed))
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"captured_at must be an ISO-8601 timestamp with timezone: {exc}",
        ) from exc


def _not_found(exc: NotFoundError) -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved_settings = settings or Settings.from_env()

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        resolved_settings.ensure_directories()
        init_db(resolved_settings.db_path)
        load_or_create_signing_material(resolved_settings.signing_key_path)
        application.state.settings = resolved_settings
        yield

    application = FastAPI(
        title="Incident Evidence",
        version=__version__,
        description=(
            "Incident timeline service with one-call, Ed25519-signed evidence "
            "package export."
        ),
        lifespan=lifespan,
    )

    @application.get("/health", response_model=HealthRead)
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @application.get("/api/incidents", response_model=list[IncidentRead])
    def incidents_index(request: Request) -> list[dict[str, Any]]:
        return list_incidents(request.app.state.settings.db_path)

    @application.post(
        "/api/incidents",
        response_model=IncidentRead,
        status_code=status.HTTP_201_CREATED,
    )
    def incidents_create(
        payload: IncidentCreate, request: Request
    ) -> dict[str, Any]:
        return create_incident(
            request.app.state.settings.db_path,
            title=payload.title,
            description=payload.description,
            source_config=payload.source_config,
        )

    @application.get("/api/incidents/{incident_id}", response_model=IncidentRead)
    def incidents_show(incident_id: str, request: Request) -> dict[str, Any]:
        try:
            return get_incident(request.app.state.settings.db_path, incident_id)
        except NotFoundError as exc:
            raise _not_found(exc) from exc

    @application.post(
        "/api/incidents/{incident_id}/events",
        response_model=EventRead,
        status_code=status.HTTP_201_CREATED,
    )
    def events_create(
        incident_id: str, payload: EventCreate, request: Request
    ) -> dict[str, Any]:
        try:
            return create_event(
                request.app.state.settings.db_path,
                incident_id,
                occurred_at=iso_utc(payload.occurred_at),
                title=payload.title,
                description=payload.description,
                source=payload.source,
                actor=payload.actor,
                artifact_ids=payload.artifact_ids,
            )
        except NotFoundError as exc:
            raise _not_found(exc) from exc
        except InvalidReferenceError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=str(exc),
            ) from exc

    @application.get(
        "/api/incidents/{incident_id}/timeline",
        response_model=TimelineRead,
    )
    def timeline_show(incident_id: str, request: Request) -> dict[str, Any]:
        try:
            events = list_events(request.app.state.settings.db_path, incident_id)
        except NotFoundError as exc:
            raise _not_found(exc) from exc
        return {
            "incident_id": incident_id,
            "events": events,
            "event_count": len(events),
        }

    @application.post(
        "/api/incidents/{incident_id}/raw-files",
        response_model=RawFileRead,
        status_code=status.HTTP_201_CREATED,
    )
    async def raw_files_upload(
        incident_id: str,
        request: Request,
        file: Annotated[UploadFile, File(...)],
        source: Annotated[str, Form()] = "",
        description: Annotated[str, Form()] = "",
        captured_at: Annotated[str | None, Form()] = None,
    ) -> dict[str, Any]:
        app_settings: Settings = request.app.state.settings
        try:
            get_incident(app_settings.db_path, incident_id)
        except NotFoundError as exc:
            raise _not_found(exc) from exc

        original_name = safe_display_name(file.filename or "unnamed")
        stored_name = f"{uuid.uuid4().hex}-{safe_archive_name(original_name)}"
        relative_path = Path("uploads") / incident_id / stored_name
        destination = app_settings.data_dir / relative_path
        try:
            digest, size = write_upload(
                file.file,
                destination,
                app_settings.max_upload_bytes,
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=str(exc),
            ) from exc
        finally:
            await file.close()

        try:
            return create_raw_file(
                app_settings.db_path,
                incident_id,
                original_name=original_name,
                storage_path=relative_path.as_posix(),
                media_type=file.content_type or "application/octet-stream",
                source=source,
                description=description,
                captured_at=_parse_captured_at(captured_at),
                sha256=digest,
                size_bytes=size,
            )
        except BaseException:
            destination.unlink(missing_ok=True)
            raise

    @application.get(
        "/api/incidents/{incident_id}/raw-files",
        response_model=list[RawFileRead],
    )
    def raw_files_index(
        incident_id: str, request: Request
    ) -> list[dict[str, Any]]:
        try:
            return list_raw_files(request.app.state.settings.db_path, incident_id)
        except NotFoundError as exc:
            raise _not_found(exc) from exc

    @application.get("/api/raw-files/{file_id}/download")
    def raw_files_download(file_id: str, request: Request) -> FileResponse:
        app_settings: Settings = request.app.state.settings
        try:
            record = get_raw_file(app_settings.db_path, file_id)
        except NotFoundError as exc:
            raise _not_found(exc) from exc
        path = (app_settings.data_dir / record["storage_path"]).resolve()
        if not path.is_relative_to(app_settings.data_dir) or not path.is_file():
            raise HTTPException(status_code=404, detail="stored raw file is missing")
        return FileResponse(
            path,
            media_type=record["media_type"],
            filename=record["original_name"],
        )

    @application.post(
        "/api/incidents/{incident_id}/evidence-packages",
        response_model=EvidencePackageRead,
        status_code=status.HTTP_201_CREATED,
    )
    def evidence_packages_create(
        incident_id: str,
        payload: EvidencePackageCreate,
        request: Request,
    ) -> dict[str, Any]:
        try:
            return create_evidence_package(
                request.app.state.settings,
                incident_id,
                payload.exporter.model_dump(),
            )
        except NotFoundError as exc:
            raise _not_found(exc) from exc
        except EvidenceGenerationError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(exc),
            ) from exc

    @application.get(
        "/api/incidents/{incident_id}/evidence-packages",
        response_model=list[dict[str, Any]],
    )
    def evidence_packages_index(
        incident_id: str, request: Request
    ) -> list[dict[str, Any]]:
        try:
            return list_package_records(
                request.app.state.settings.db_path, incident_id
            )
        except NotFoundError as exc:
            raise _not_found(exc) from exc

    @application.get("/api/evidence-packages/{package_id}/download")
    def evidence_packages_download(
        package_id: str, request: Request
    ) -> FileResponse:
        app_settings: Settings = request.app.state.settings
        try:
            record = get_package_record(app_settings.db_path, package_id)
        except NotFoundError as exc:
            raise _not_found(exc) from exc
        path = Path(record["package_path"]).resolve()
        if (
            not path.is_relative_to(app_settings.packages_dir.resolve())
            or not path.is_file()
        ):
            raise HTTPException(status_code=404, detail="stored package is missing")
        return FileResponse(
            path,
            media_type="application/zip",
            filename=record["filename"],
        )

    @application.post(
        "/api/evidence-packages/verify",
        response_model=VerificationRead,
    )
    async def evidence_packages_verify(
        request: Request,
        package: Annotated[UploadFile, File(...)],
        public_key: Annotated[UploadFile | None, File()] = None,
    ) -> dict[str, Any]:
        app_settings: Settings = request.app.state.settings
        with tempfile.TemporaryDirectory(
            dir=app_settings.data_dir, prefix=".verify-"
        ) as temporary:
            package_path = Path(temporary) / "package.zip"
            with package_path.open("wb") as handle:
                shutil.copyfileobj(package.file, handle)
            await package.close()
            key_path: Path | None = None
            if public_key is not None:
                key_path = Path(temporary) / "public-key.pem"
                key_path.write_bytes(await public_key.read())
                await public_key.close()
            try:
                result = verify_package(
                    package_path,
                    trusted_public_key=key_path,
                )
            except (OSError, ValueError) as exc:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"cannot verify package: {exc}",
                ) from exc
        return result.as_dict()

    return application


app = create_app()

