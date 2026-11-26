"""HTTP routes for the conflict-merge workbench and timeline."""

from __future__ import annotations

import sqlite3
from typing import Any

from fastapi import APIRouter, Depends, Header, Query, Request

from . import service
from .database import connect as db_connect
from .schemas import (
    CandidateCreate,
    IncidentCreate,
    KeepRequest,
    RecordBatch,
    RecordIngest,
    ReopenRequest,
    ResolveRequest,
    SourceCreate,
    SplitRequest,
)

router = APIRouter(prefix="/api")


def get_db(request: Request):
    """Yield a request-scoped connection (or the shared in-memory one)."""

    mem_conn: sqlite3.Connection | None = getattr(request.app.state, "mem_conn", None)
    if mem_conn is not None:
        yield mem_conn
        return
    conn = db_connect(request.app.state.db_path)
    try:
        yield conn
    finally:
        conn.close()


def _analyst(body_analyst: str | None, header_analyst: str | None) -> str:
    return body_analyst or header_analyst or "analyst"


# ---------------------------------------------------------------------------
# Health / meta
# ---------------------------------------------------------------------------


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "incident-timeline-merge"}


@router.post("/admin/reset-demo")
def reset_demo(db: sqlite3.Connection = Depends(get_db)) -> dict[str, Any]:
    from .seed import reset_demo as _reset

    return _reset(conn=db)


@router.get("/sources")
def list_sources(db: sqlite3.Connection = Depends(get_db)) -> list[dict[str, Any]]:
    return service.list_sources(db)


@router.post("/sources", status_code=201)
def create_source(
    body: SourceCreate, db: sqlite3.Connection = Depends(get_db)
) -> dict[str, Any]:
    return service.create_source(
        db, code=body.code, name=body.name, reliability=body.reliability
    )


@router.get("/incidents")
def list_incidents(db: sqlite3.Connection = Depends(get_db)) -> list[dict[str, Any]]:
    return service.list_incidents(db)


@router.post("/incidents", status_code=201)
def create_incident(
    body: IncidentCreate, db: sqlite3.Connection = Depends(get_db)
) -> dict[str, Any]:
    return service.create_incident(
        db, incident_id=body.id, title=body.title, severity=body.severity
    )


# ---------------------------------------------------------------------------
# Raw records
# ---------------------------------------------------------------------------


@router.post("/records", status_code=201)
def ingest_record(
    body: RecordIngest, db: sqlite3.Connection = Depends(get_db)
) -> dict[str, Any]:
    record, created = service.ingest_record(
        db,
        source_code=body.source_code,
        external_id=body.external_id,
        event_type=body.event_type,
        user_id=body.user_id,
        occurred_at=body.occurred_at,
        payload=body.payload,
    )
    return {"created": created, "record": record}


@router.post("/records/batch", status_code=201)
def ingest_batch(
    body: RecordBatch, db: sqlite3.Connection = Depends(get_db)
) -> dict[str, Any]:
    ingested: list[dict[str, Any]] = []
    duplicates: list[str] = []
    for item in body.records:
        record, created = service.ingest_record(
            db,
            source_code=item.source_code,
            external_id=item.external_id,
            event_type=item.event_type,
            user_id=item.user_id,
            occurred_at=item.occurred_at,
            payload=item.payload,
        )
        ingested.append(record)
        if not created:
            duplicates.append(record["id"])

    candidates: list[dict[str, Any]] = []
    if body.auto_detect:
        candidates = service.detect_candidates(
            db, window_hours=body.window_hours or 24.0
        )
    return {
        "received": len(body.records),
        "ingested": len(ingested) - len(duplicates),
        "duplicates": len(duplicates),
        "records": ingested,
        "detected_candidates": [c["id"] for c in candidates],
    }


@router.get("/records")
def list_records(
    user_id: str | None = None,
    source_code: str | None = None,
    event_type: str | None = None,
    db: sqlite3.Connection = Depends(get_db),
) -> list[dict[str, Any]]:
    return service.list_records(
        db, user_id=user_id, source_code=source_code, event_type=event_type
    )


@router.get("/records/{record_id}")
def get_record(
    record_id: str, db: sqlite3.Connection = Depends(get_db)
) -> dict[str, Any]:
    return service.get_record(db, record_id)


# ---------------------------------------------------------------------------
# Candidates
# ---------------------------------------------------------------------------


@router.post("/candidates/detect")
def detect_candidates(
    window_hours: float = Query(default=24.0, ge=1.0, le=24 * 30),
    incident_id: str | None = None,
    db: sqlite3.Connection = Depends(get_db),
) -> dict[str, Any]:
    candidates = service.detect_candidates(
        db, window_hours=window_hours, incident_id=incident_id
    )
    return {"created": len(candidates), "candidate_ids": [c["id"] for c in candidates]}


@router.post("/candidates", status_code=201)
def create_candidate(
    body: CandidateCreate, db: sqlite3.Connection = Depends(get_db)
) -> dict[str, Any]:
    return service.create_candidate(
        db, body.record_ids, incident_id=body.incident_id
    )


@router.get("/candidates")
def list_candidates(
    status: str | None = Query(default=None),
    incident_id: str | None = None,
    db: sqlite3.Connection = Depends(get_db),
) -> list[dict[str, Any]]:
    return service.list_candidates(db, status=status, incident_id=incident_id)


@router.get("/candidates/{candidate_id}")
def get_candidate(
    candidate_id: str, db: sqlite3.Connection = Depends(get_db)
) -> dict[str, Any]:
    return service.get_candidate_detail(db, candidate_id)


@router.get("/candidates/{candidate_id}/records")
def candidate_records(
    candidate_id: str, db: sqlite3.Connection = Depends(get_db)
) -> list[dict[str, Any]]:
    detail = service.get_candidate_detail(db, candidate_id)
    return detail["records"]


@router.get("/candidates/{candidate_id}/actions")
def candidate_actions(
    candidate_id: str, db: sqlite3.Connection = Depends(get_db)
) -> list[dict[str, Any]]:
    service.get_candidate_detail(db, candidate_id)
    return service.list_review_actions(db, candidate_id)


@router.post("/candidates/{candidate_id}/keep")
def keep_candidate(
    candidate_id: str,
    body: KeepRequest,
    x_analyst: str | None = Header(default=None),
    db: sqlite3.Connection = Depends(get_db),
) -> dict[str, Any]:
    return service.keep_candidate(
        db,
        candidate_id,
        analyst=_analyst(body.analyst, x_analyst),
        note=body.note,
        title=body.title,
        canonical_time=body.canonical_time,
        time_source_record_id=body.time_source_record_id,
        field_sources=body.field_sources,
        canonical_fields=body.canonical_fields,
    )


# "merge" is an intuitive alias for the 保留/合并 action.
@router.post("/candidates/{candidate_id}/merge")
def merge_candidate_alias(
    candidate_id: str,
    body: KeepRequest,
    x_analyst: str | None = Header(default=None),
    db: sqlite3.Connection = Depends(get_db),
) -> dict[str, Any]:
    return keep_candidate(candidate_id, body, x_analyst, db)


@router.post("/candidates/{candidate_id}/split")
def split_candidate(
    candidate_id: str,
    body: SplitRequest,
    x_analyst: str | None = Header(default=None),
    db: sqlite3.Connection = Depends(get_db),
) -> dict[str, Any]:
    return service.split_candidate(
        db,
        candidate_id,
        analyst=_analyst(body.analyst, x_analyst),
        note=body.note,
        groups=body.groups,
    )


@router.post("/candidates/{candidate_id}/unknown")
def unknown_candidate(
    candidate_id: str,
    body: ReopenRequest,
    x_analyst: str | None = Header(default=None),
    db: sqlite3.Connection = Depends(get_db),
) -> dict[str, Any]:
    return service.mark_unknown(
        db,
        candidate_id,
        analyst=_analyst(body.analyst, x_analyst),
        note=body.note,
    )


@router.post("/candidates/{candidate_id}/reopen")
def reopen_candidate(
    candidate_id: str,
    body: ReopenRequest,
    x_analyst: str | None = Header(default=None),
    db: sqlite3.Connection = Depends(get_db),
) -> dict[str, Any]:
    return service.reopen_candidate(
        db,
        candidate_id,
        analyst=_analyst(body.analyst, x_analyst),
        note=body.note,
    )


@router.post("/candidates/{candidate_id}/resolve")
def resolve_candidate(
    candidate_id: str,
    body: ResolveRequest,
    x_analyst: str | None = Header(default=None),
    db: sqlite3.Connection = Depends(get_db),
) -> dict[str, Any]:
    analyst = _analyst(body.analyst, x_analyst)
    if body.decision in {"keep", "merge"}:
        return service.keep_candidate(
            db,
            candidate_id,
            analyst=analyst,
            note=body.note,
            title=body.title,
            canonical_time=body.canonical_time,
            time_source_record_id=body.time_source_record_id,
            field_sources=body.field_sources,
            canonical_fields=body.canonical_fields,
        )
    if body.decision == "split":
        return service.split_candidate(
            db, candidate_id, analyst=analyst, note=body.note, groups=body.groups
        )
    if body.decision == "unknown":
        return service.mark_unknown(db, candidate_id, analyst=analyst, note=body.note)
    return service.reopen_candidate(db, candidate_id, analyst=analyst, note=body.note)


# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------


@router.get("/timeline")
def timeline(
    incident_id: str | None = None,
    db: sqlite3.Connection = Depends(get_db),
) -> list[dict[str, Any]]:
    return service.list_timeline_events(db, incident_id=incident_id)


@router.get("/timeline/{event_id}")
def timeline_event(
    event_id: str, db: sqlite3.Connection = Depends(get_db)
) -> dict[str, Any]:
    return service.get_timeline_event(db, event_id)


@router.get("/events/{event_id}/records")
def event_originals(
    event_id: str, db: sqlite3.Connection = Depends(get_db)
) -> list[dict[str, Any]]:
    return service.list_originals_for_event(db, event_id)
