"""Pydantic request/response models."""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field


class IncidentCreate(BaseModel):
    title: str = Field(min_length=1, max_length=200)


class IncidentOut(BaseModel):
    id: int
    title: str
    created_at: str
    created_by: str


class EventCreate(BaseModel):
    occurred_at: str = Field(min_length=1, description="ISO-8601 timestamp")
    summary: str = Field(min_length=1, max_length=1000)


class EventOut(BaseModel):
    id: int
    incident_id: int
    occurred_at: str
    summary: str
    created_by: str
    created_at: str


class LineLocatorInput(BaseModel):
    kind: Literal["line"]
    file_path: str = Field(min_length=1)
    line: int = Field(ge=1)
    end_line: Optional[int] = Field(default=None, ge=1)
    label: str = Field(default="", max_length=200)


class OffsetLocatorInput(BaseModel):
    kind: Literal["offset"]
    file_path: str = Field(min_length=1)
    offset: int = Field(ge=0)
    length: int = Field(ge=1)
    label: str = Field(default="", max_length=200)


class HashLocatorInput(BaseModel):
    kind: Literal["hash"]
    file_path: str = Field(min_length=1)
    search_text: str = Field(min_length=1)
    occurrence: int = Field(default=1, ge=1)
    label: str = Field(default="", max_length=200)


class EvidenceOut(BaseModel):
    id: int
    event_id: int
    locator_kind: str
    file_path: str
    line_no: Optional[int]
    end_line: Optional[int]
    byte_offset: Optional[int]
    byte_length: Optional[int]
    content_hash: str
    file_hash: str
    content_hash_prefix: str
    file_hash_prefix: str
    label: str
    created_by: str
    created_at: str


class ResolutionOut(BaseModel):
    evidence_id: int
    event_id: int
    status: Literal["valid", "stale", "missing"]
    kind: str
    file_path: str
    line: Optional[int] = None
    end_line: Optional[int] = None
    offset: Optional[int] = None
    length: Optional[int] = None
    content_hash: Optional[str] = None
    file_hash: Optional[str] = None
    content_hash_prefix: Optional[str] = None
    file_hash_prefix: Optional[str] = None
    snippet: Optional[str] = None
    reason: Optional[str] = None


class EventDetailOut(EventOut):
    evidence: list[EvidenceOut]


class TimelineEventOut(BaseModel):
    event: EventOut
    evidence: list[EvidenceOut]
    resolutions: list[ResolutionOut]
