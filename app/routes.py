"""HTTP routes for incidents, timeline events and evidence locators."""

from __future__ import annotations

from fastapi import APIRouter, Depends, FastAPI, HTTPException, status

from . import repository as repo
from .config import Settings
from .database import session
from .schemas import (
    EvidenceOut,
    EventCreate,
    EventDetailOut,
    EventOut,
    HashLocatorInput,
    IncidentCreate,
    IncidentOut,
    LineLocatorInput,
    OffsetLocatorInput,
    ResolutionOut,
    TimelineEventOut,
)
from .security import Principal


def _require(authenticate, min_rank: int, rank: dict):
    def _dep(principal: Principal = Depends(authenticate)) -> Principal:
        if rank[principal.role] < min_rank:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="insufficient role for this operation",
            )
        return principal
    return _dep


def _register_routes(
    app: FastAPI,
    settings: Settings,
    authenticate,
    build_locator,
    resolve_row,
) -> None:
    from .security import ROLE_RANK

    reader = _require(authenticate, ROLE_RANK["viewer"], ROLE_RANK)
    writer = _require(authenticate, ROLE_RANK["investigator"], ROLE_RANK)
    admin = _require(authenticate, ROLE_RANK["admin"], ROLE_RANK)
    router = APIRouter()

    @router.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    @router.get("/me")
    def whoami(principal: Principal = Depends(authenticate)) -> dict:
        return {"username": principal.username, "role": principal.role}

    # --- incidents ------------------------------------------------------

    @router.post("/incidents", response_model=IncidentOut,
                 status_code=status.HTTP_201_CREATED)
    def create_incident(payload: IncidentCreate,
                        principal: Principal = Depends(admin)) -> dict:
        with session(settings.db_path) as conn:
            return dict(repo.create_incident(
                conn, payload.title, principal.username))

    @router.get("/incidents", response_model=list[IncidentOut])
    def list_incidents(_: Principal = Depends(reader)) -> list[dict]:
        with session(settings.db_path) as conn:
            return [dict(row) for row in repo.list_incidents(conn)]

    @router.get("/incidents/{incident_id}", response_model=IncidentOut)
    def get_incident(incident_id: int,
                     _: Principal = Depends(reader)) -> dict:
        with session(settings.db_path) as conn:
            row = repo.get_incident(conn, incident_id)
            if row is None:
                raise HTTPException(status.HTTP_404_NOT_FOUND,
                                    "incident not found")
            return dict(row)

    # --- events ---------------------------------------------------------

    @router.post("/incidents/{incident_id}/events",
                 response_model=EventOut,
                 status_code=status.HTTP_201_CREATED)
    def create_event(incident_id: int, payload: EventCreate,
                     principal: Principal = Depends(writer)) -> dict:
        with session(settings.db_path) as conn:
            if repo.get_incident(conn, incident_id) is None:
                raise HTTPException(status.HTTP_404_NOT_FOUND,
                                    "incident not found")
            return dict(repo.create_event(
                conn, incident_id, payload.occurred_at,
                payload.summary, principal.username))

    @router.get("/incidents/{incident_id}/events",
                response_model=list[EventOut])
    def list_events(incident_id: int,
                    _: Principal = Depends(reader)) -> list[dict]:
        with session(settings.db_path) as conn:
            if repo.get_incident(conn, incident_id) is None:
                raise HTTPException(status.HTTP_404_NOT_FOUND,
                                    "incident not found")
            return [dict(row)
                    for row in repo.list_events(conn, incident_id)]

    @router.get("/events/{event_id}", response_model=EventDetailOut)
    def get_event(event_id: int,
                  _: Principal = Depends(reader)) -> dict:
        with session(settings.db_path) as conn:
            event = repo.get_event(conn, event_id)
            if event is None:
                raise HTTPException(status.HTTP_404_NOT_FOUND,
                                    "event not found")
            evidence = [repo.evidence_to_dict(row)
                        for row in repo.list_evidence_for_event(
                            conn, event_id)]
            return {**dict(event), "evidence": evidence}

    # --- evidence locators ---------------------------------------------

    @router.post("/events/{event_id}/evidence",
                 response_model=EvidenceOut,
                 status_code=status.HTTP_201_CREATED)
    def add_evidence(event_id: int,
                     payload: (LineLocatorInput | OffsetLocatorInput
                               | HashLocatorInput),
                     principal: Principal = Depends(writer)) -> dict:
        locator = build_locator(payload)
        with session(settings.db_path) as conn:
            if repo.get_event(conn, event_id) is None:
                raise HTTPException(status.HTTP_404_NOT_FOUND,
                                    "event not found")
            row = repo.add_evidence(
                conn, event_id, locator, payload.label, principal.username)
            return repo.evidence_to_dict(row)

    @router.get("/evidence/{evidence_id}", response_model=ResolutionOut)
    def resolve_evidence(evidence_id: int,
                         _: Principal = Depends(reader)) -> dict:
        with session(settings.db_path) as conn:
            row = repo.get_evidence(conn, evidence_id)
            if row is None:
                raise HTTPException(status.HTTP_404_NOT_FOUND,
                                    "evidence link not found")
            return resolve_row(row)

    @router.delete("/evidence/{evidence_id}",
                   status_code=status.HTTP_204_NO_CONTENT)
    def remove_evidence(evidence_id: int,
                        principal: Principal = Depends(writer)) -> None:
        with session(settings.db_path) as conn:
            if not repo.delete_evidence(conn, evidence_id):
                raise HTTPException(status.HTTP_404_NOT_FOUND,
                                    "evidence link not found")

    # --- timeline with live resolution ---------------------------------

    @router.get("/incidents/{incident_id}/timeline",
                response_model=list[TimelineEventOut])
    def timeline(incident_id: int,
                 _: Principal = Depends(reader)) -> list[dict]:
        with session(settings.db_path) as conn:
            if repo.get_incident(conn, incident_id) is None:
                raise HTTPException(status.HTTP_404_NOT_FOUND,
                                    "incident not found")
            result = []
            for event in repo.list_events(conn, incident_id):
                rows = repo.list_evidence_for_event(conn, event["id"])
                result.append({
                    "event": dict(event),
                    "evidence": [repo.evidence_to_dict(r) for r in rows],
                    "resolutions": [resolve_row(r) for r in rows],
                })
            return result

    app.include_router(router)
