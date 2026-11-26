from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .timeutil import to_utc


class IncidentCreate(BaseModel):
    title: str = Field(min_length=1, max_length=300)
    description: str = Field(default="", max_length=20_000)
    source_config: dict[str, Any] = Field(default_factory=dict)


class IncidentRead(BaseModel):
    id: str
    title: str
    description: str
    source_config: dict[str, Any]
    created_at: str


class EventCreate(BaseModel):
    occurred_at: datetime
    title: str = Field(min_length=1, max_length=300)
    description: str = Field(default="", max_length=20_000)
    source: str = Field(default="", max_length=500)
    actor: str = Field(default="", max_length=300)
    artifact_ids: list[str] = Field(default_factory=list)

    @field_validator("occurred_at")
    @classmethod
    def normalize_occurred_at(cls, value: datetime) -> datetime:
        return to_utc(value)


class EventRead(BaseModel):
    id: str
    incident_id: str
    occurred_at: str
    title: str
    description: str
    source: str
    actor: str
    artifact_ids: list[str]
    created_at: str


class RawFileRead(BaseModel):
    id: str
    incident_id: str
    original_name: str
    media_type: str
    source: str
    description: str
    captured_at: str | None
    sha256: str
    size_bytes: int
    created_at: str


class ExporterInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=300)
    email: str = Field(default="", max_length=500)
    organization: str = Field(default="", max_length=500)


class EvidencePackageCreate(BaseModel):
    exporter: ExporterInfo


class VerificationInfo(BaseModel):
    command: str
    public_key_path: str
    public_key_sha256: str
    key_id: str


class EvidencePackageRead(BaseModel):
    id: str
    incident_id: str
    filename: str
    sha256: str
    size_bytes: int
    created_at: str
    download_url: str
    verification: VerificationInfo


class VerificationCheck(BaseModel):
    name: str
    passed: bool
    detail: str


class VerificationRead(BaseModel):
    valid: bool
    package_sha256: str
    key_id: str | None = None
    generated_at: str | None = None
    checks: list[VerificationCheck]
    errors: list[str]


class TimelineEvent(BaseModel):
    id: str
    occurred_at: str
    title: str
    description: str
    source: str
    actor: str
    artifact_ids: list[str]
    created_at: str


class TimelineRead(BaseModel):
    incident_id: str
    events: list[TimelineEvent]
    event_count: int


class HealthRead(BaseModel):
    status: Literal["ok"]
    version: str

