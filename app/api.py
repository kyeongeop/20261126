from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from typing import Annotated
from urllib.parse import quote

from fastapi import (
    APIRouter,
    Body,
    Depends,
    File,
    Form,
    Header,
    HTTPException,
    Query,
    Request,
    UploadFile,
)
from fastapi.responses import Response

from app.db import connect
from app.errors import DomainError
from app.repository import (
    OperationContext,
    case_timeline,
    create_case,
    export_evidence,
    get_case,
    get_evidence,
    list_cases,
    list_custody_events,
    list_evidence,
    record_view,
    rename_evidence,
    replace_evidence,
    upload_evidence,
    verify_evidence_chain,
    void_evidence,
)
from app.schemas import (
    CaseCreate,
    CaseResponse,
    CustodyChainResponse,
    DeleteEvidenceRequest,
    EvidenceResponse,
    RenameEvidenceRequest,
    TimelineResponse,
    VerificationResponse,
    VersionSummary,
)

router = APIRouter()


def get_connection(request: Request) -> Iterator[sqlite3.Connection]:
    connection = connect(request.app.state.database_path)
    try:
        yield connection
    finally:
        connection.close()


def get_operation_context(
    request: Request,
    x_actor: Annotated[str | None, Header(alias="X-Actor")] = None,
    x_source: Annotated[str | None, Header(alias="X-Source")] = None,
    x_forwarded_for: Annotated[str | None, Header(alias="X-Forwarded-For")] = None,
) -> OperationContext:
    actor = (x_actor or "").strip()
    if not actor:
        raise HTTPException(status_code=401, detail="X-Actor header is required")
    forwarded = (x_forwarded_for or "").split(",", 1)[0].strip()
    client_ip = forwarded or (request.client.host if request.client else "unknown")
    source = (x_source or "").strip() or client_ip
    return OperationContext(
        actor=actor,
        source=source,
        source_ip=client_ip,
        user_agent=request.headers.get("User-Agent", ""),
        request_method=request.method,
        request_path=request.url.path,
    )


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/")
def service_info() -> dict[str, object]:
    return {
        "name": "incident-timeline",
        "version": "0.1.0",
        "hash_algorithm": "sha256",
        "actor_header": "X-Actor",
    }


@router.post("/cases", response_model=CaseResponse, status_code=201)
def create_case_endpoint(
    payload: CaseCreate,
    context: Annotated[OperationContext, Depends(get_operation_context)],
    connection: Annotated[sqlite3.Connection, Depends(get_connection)],
) -> dict[str, object]:
    return create_case(connection, title=payload.title, context=context)


@router.get("/cases", response_model=list[CaseResponse])
def list_cases_endpoint(
    connection: Annotated[sqlite3.Connection, Depends(get_connection)],
) -> list[dict[str, object]]:
    return list_cases(connection)


@router.get("/cases/{case_id}", response_model=CaseResponse)
def get_case_endpoint(
    case_id: str,
    connection: Annotated[sqlite3.Connection, Depends(get_connection)],
) -> dict[str, object]:
    return get_case(connection, case_id)


def _clean_filename(filename: str | None) -> str:
    candidate = (filename or "").replace("\\", "/").split("/")[-1].strip()
    candidate = candidate.replace("\x00", "")
    return candidate[:255] or "evidence.bin"


async def _read_limited(file: UploadFile, limit: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while chunk := await file.read(1024 * 1024):
        total += len(chunk)
        if total > limit:
            raise DomainError(413, f"uploaded file exceeds {limit} bytes")
        chunks.append(chunk)
    return b"".join(chunks)


def _validate_display_name(value: str | None, fallback: str) -> str:
    name = (value or fallback).strip()
    if not name:
        raise DomainError(422, "evidence display name cannot be empty")
    if len(name) > 500:
        raise DomainError(422, "evidence display name must be at most 500 characters")
    return name


@router.post(
    "/cases/{case_id}/evidence",
    response_model=EvidenceResponse,
    status_code=201,
)
async def upload_evidence_endpoint(
    case_id: str,
    request: Request,
    file: Annotated[UploadFile, File()],
    context: Annotated[OperationContext, Depends(get_operation_context)],
    connection: Annotated[sqlite3.Connection, Depends(get_connection)],
    display_name: Annotated[str | None, Form()] = None,
) -> dict[str, object]:
    filename = _clean_filename(file.filename)
    content = await _read_limited(file, request.app.state.max_upload_bytes)
    return upload_evidence(
        connection,
        case_id=case_id,
        display_name=_validate_display_name(display_name, filename),
        filename=filename,
        content_type=file.content_type or "application/octet-stream",
        content=content,
        context=context,
    )


@router.get("/cases/{case_id}/evidence", response_model=list[EvidenceResponse])
def list_evidence_endpoint(
    case_id: str,
    connection: Annotated[sqlite3.Connection, Depends(get_connection)],
    include_voided: bool = False,
) -> list[dict[str, object]]:
    return list_evidence(
        connection,
        case_id=case_id,
        include_voided=include_voided,
    )


@router.get(
    "/cases/{case_id}/evidence/{evidence_id}",
    response_model=EvidenceResponse,
)
def view_evidence_endpoint(
    case_id: str,
    evidence_id: str,
    context: Annotated[OperationContext, Depends(get_operation_context)],
    connection: Annotated[sqlite3.Connection, Depends(get_connection)],
) -> dict[str, object]:
    evidence = get_evidence(connection, case_id=case_id, evidence_id=evidence_id)
    return record_view(
        connection,
        case_id=case_id,
        evidence_id=evidence_id,
        version_number=evidence["current_version_number"],
        context=context,
    )


@router.patch(
    "/cases/{case_id}/evidence/{evidence_id}",
    response_model=EvidenceResponse,
)
def rename_evidence_endpoint(
    case_id: str,
    evidence_id: str,
    payload: RenameEvidenceRequest,
    context: Annotated[OperationContext, Depends(get_operation_context)],
    connection: Annotated[sqlite3.Connection, Depends(get_connection)],
) -> dict[str, object]:
    return rename_evidence(
        connection,
        case_id=case_id,
        evidence_id=evidence_id,
        new_name=payload.resolved_name(),
        context=context,
    )


@router.delete(
    "/cases/{case_id}/evidence/{evidence_id}",
    response_model=EvidenceResponse,
)
def delete_evidence_endpoint(
    case_id: str,
    evidence_id: str,
    context: Annotated[OperationContext, Depends(get_operation_context)],
    connection: Annotated[sqlite3.Connection, Depends(get_connection)],
    payload: Annotated[DeleteEvidenceRequest | None, Body()] = None,
    reason: Annotated[str | None, Query(max_length=2000)] = None,
) -> dict[str, object]:
    resolved_reason = (
        payload.reason if payload and payload.reason is not None else reason
    )
    return void_evidence(
        connection,
        case_id=case_id,
        evidence_id=evidence_id,
        reason=resolved_reason or "",
        context=context,
    )


@router.post(
    "/cases/{case_id}/evidence/{evidence_id}/versions",
    response_model=EvidenceResponse,
    status_code=201,
)
async def replace_evidence_endpoint(
    case_id: str,
    evidence_id: str,
    request: Request,
    file: Annotated[UploadFile, File()],
    context: Annotated[OperationContext, Depends(get_operation_context)],
    connection: Annotated[sqlite3.Connection, Depends(get_connection)],
) -> dict[str, object]:
    filename = _clean_filename(file.filename)
    content = await _read_limited(file, request.app.state.max_upload_bytes)
    return replace_evidence(
        connection,
        case_id=case_id,
        evidence_id=evidence_id,
        filename=filename,
        content_type=file.content_type or "application/octet-stream",
        content=content,
        context=context,
    )


@router.get(
    "/cases/{case_id}/evidence/{evidence_id}/versions",
    response_model=list[VersionSummary],
)
def list_versions_endpoint(
    case_id: str,
    evidence_id: str,
    connection: Annotated[sqlite3.Connection, Depends(get_connection)],
) -> list[dict[str, object]]:
    evidence = get_evidence(connection, case_id=case_id, evidence_id=evidence_id)
    return evidence["versions"]


def _export_response(exported: dict[str, object]) -> Response:
    filename = (
        str(exported["filename"])
        .replace('"', "_")
        .replace("\r", "_")
        .replace("\n", "_")
    )
    encoded = quote(filename, safe="")
    headers = {
        "Content-Disposition": (
            f'attachment; filename="evidence-{exported["version_number"]}"; '
            f"filename*=UTF-8''{encoded}"
        ),
        "X-Evidence-Version": str(exported["version_number"]),
        "X-Evidence-Status": str(exported["evidence_status"]),
        "X-Evidence-Content-SHA256": str(exported["content_sha256"]),
        "X-Evidence-Version-Digest": str(exported["version_digest"]),
        "X-Custody-Record-Hash": str(exported["record_hash"]),
    }
    return Response(
        content=exported["content"],
        media_type=str(exported["content_type"]),
        headers=headers,
    )


@router.get("/cases/{case_id}/evidence/{evidence_id}/export")
def export_current_endpoint(
    case_id: str,
    evidence_id: str,
    context: Annotated[OperationContext, Depends(get_operation_context)],
    connection: Annotated[sqlite3.Connection, Depends(get_connection)],
) -> Response:
    exported = export_evidence(
        connection,
        case_id=case_id,
        evidence_id=evidence_id,
        version_number=None,
        context=context,
    )
    return _export_response(exported)


@router.get("/cases/{case_id}/evidence/{evidence_id}/versions/{version_number}/export")
def export_version_endpoint(
    case_id: str,
    evidence_id: str,
    version_number: int,
    context: Annotated[OperationContext, Depends(get_operation_context)],
    connection: Annotated[sqlite3.Connection, Depends(get_connection)],
) -> Response:
    exported = export_evidence(
        connection,
        case_id=case_id,
        evidence_id=evidence_id,
        version_number=version_number,
        context=context,
    )
    return _export_response(exported)


@router.get(
    "/cases/{case_id}/evidence/{evidence_id}/custody",
    response_model=CustodyChainResponse,
)
def custody_endpoint(
    case_id: str,
    evidence_id: str,
    connection: Annotated[sqlite3.Connection, Depends(get_connection)],
    action: Annotated[
        str | None, Query(pattern="^(UPLOAD|VIEW|EXPORT|REPLACE|RENAME|DELETE)$")
    ] = None,
) -> dict[str, object]:
    events = list_custody_events(
        connection,
        case_id=case_id,
        evidence_id=evidence_id,
        action=action,
    )
    verification = verify_evidence_chain(
        connection,
        case_id=case_id,
        evidence_id=evidence_id,
    )
    return {
        "case_id": case_id,
        "evidence_id": evidence_id,
        "events": events,
        "verification": verification,
    }


@router.get(
    "/cases/{case_id}/evidence/{evidence_id}/verify",
    response_model=VerificationResponse,
)
def verify_evidence_endpoint(
    case_id: str,
    evidence_id: str,
    connection: Annotated[sqlite3.Connection, Depends(get_connection)],
) -> dict[str, object]:
    return {
        "case_id": case_id,
        "evidence_id": evidence_id,
        "verification": verify_evidence_chain(
            connection,
            case_id=case_id,
            evidence_id=evidence_id,
        ),
    }


@router.get("/cases/{case_id}/timeline", response_model=TimelineResponse)
def timeline_endpoint(
    case_id: str,
    connection: Annotated[sqlite3.Connection, Depends(get_connection)],
    include_voided: bool = True,
) -> dict[str, object]:
    return {
        "case_id": case_id,
        "events": case_timeline(
            connection,
            case_id=case_id,
            include_voided=include_voided,
        ),
    }
