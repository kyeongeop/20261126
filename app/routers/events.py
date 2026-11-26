"""Incident timeline events."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_session
from app.models import Event
from app.schemas import EventCreate, EventOut

router = APIRouter(prefix="/api/events", tags=["events"])


@router.post("", response_model=EventOut, status_code=201)
def create_event(payload: EventCreate, session: Session = Depends(get_session)):
    event = Event(**payload.model_dump())
    session.add(event)
    session.commit()
    session.refresh(event)
    return event


@router.get("", response_model=list[EventOut])
def list_events(session: Session = Depends(get_session)):
    stmt = select(Event).order_by(Event.occurred_at, Event.id)
    return list(session.scalars(stmt))


@router.get("/{event_id}", response_model=EventOut)
def get_event(event_id: int, session: Session = Depends(get_session)):
    event = session.get(Event, event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="event not found")
    return event
