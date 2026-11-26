"""Request body schemas. Responses are plain JSON-serialisable dicts."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class SourceCreate(BaseModel):
    code: str = Field(min_length=1, max_length=64)
    name: str = Field(min_length=1, max_length=200)
    reliability: float = Field(default=0.8, ge=0.0, le=1.0)


class IncidentCreate(BaseModel):
    id: str = Field(min_length=1, max_length=64)
    title: str = Field(min_length=1, max_length=200)
    severity: str = Field(default="medium")


class RecordIngest(BaseModel):
    source_code: str = Field(min_length=1)
    external_id: str = Field(min_length=1)
    event_type: str = Field(default="user_login")
    user_id: str = Field(min_length=1)
    occurred_at: str = Field(description="ISO-8601，可带偏移量或结尾 Z")
    payload: dict[str, Any] = Field(default_factory=dict)


class RecordBatch(BaseModel):
    records: list[RecordIngest]
    auto_detect: bool = True
    window_hours: float | None = None


class CandidateCreate(BaseModel):
    record_ids: list[str] = Field(min_length=2)
    incident_id: str | None = None


class _AnalystMixin(BaseModel):
    analyst: str | None = None
    note: str | None = None


class KeepRequest(_AnalystMixin):
    title: str | None = None
    canonical_time: str | None = None
    time_source_record_id: str | None = None
    field_sources: dict[str, str] | None = None
    canonical_fields: dict[str, Any] | None = None


class SplitRequest(_AnalystMixin):
    groups: list[list[str]] | None = None


class ReopenRequest(_AnalystMixin):
    pass


class ResolveRequest(KeepRequest):
    """Generic body for ``POST /api/candidates/{id}/resolve``."""

    decision: Literal["keep", "merge", "split", "unknown", "reopen"]
    groups: list[list[str]] | None = None
