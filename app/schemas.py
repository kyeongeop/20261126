"""Pydantic schemas for request/response bodies."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models import Verdict


class EventCreate(BaseModel):
    occurred_at: datetime
    title: str = Field(min_length=1, max_length=200)
    description: str = ""
    source: str = ""


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    occurred_at: datetime
    title: str
    description: str
    source: str
    created_at: datetime


class HypothesisCreate(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    statement: str = ""


class HypothesisUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=200)
    statement: str | None = None


class HypothesisOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    statement: str
    created_at: datetime


class LinkUpsert(BaseModel):
    verdict: Verdict
    reason: str = ""


class LinkOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    hypothesis_id: int
    event_id: int
    verdict: Verdict
    reason: str
    updated_at: datetime


class JudgedEvent(BaseModel):
    """An event plus its judgment under one hypothesis (read-only view)."""

    event: EventOut
    verdict: Verdict
    reason: str
    link_id: int | None


class HypothesisBoard(BaseModel):
    """Hypothesis card: events grouped by verdict for one hypothesis."""

    hypothesis: HypothesisOut
    support: list[JudgedEvent]
    refute: list[JudgedEvent]
    unknown: list[JudgedEvent]
