from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class CaseCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1, max_length=500)

    @model_validator(mode="after")
    def require_non_blank_title(self) -> CaseCreate:
        self.title = self.title.strip()
        if not self.title:
            raise ValueError("title cannot be blank")
        return self


class RenameEvidenceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=500)
    display_name: str | None = Field(default=None, min_length=1, max_length=500)

    @model_validator(mode="after")
    def require_exactly_one_name(self) -> RenameEvidenceRequest:
        if (self.name is None) == (self.display_name is None):
            raise ValueError("provide exactly one of name or display_name")
        if not self.resolved_name():
            raise ValueError("evidence name cannot be blank")
        return self

    def resolved_name(self) -> str:
        return (self.display_name or self.name or "").strip()


class DeleteEvidenceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str | None = Field(default=None, max_length=2000)


class VersionSummary(BaseModel):
    id: str
    version_number: int
    filename: str
    content_type: str
    size_bytes: int
    content_sha256: str
    version_digest: str
    previous_version_digest: str | None
    created_at: str
    created_by: str


class CustodyAnchor(BaseModel):
    event_count: int
    chain_head: str
    hash_algorithm: str


class EvidenceResponse(BaseModel):
    id: str
    case_id: str
    name: str
    status: str
    current_version_number: int
    current_version: VersionSummary
    versions: list[VersionSummary] = Field(default_factory=list)
    created_at: str
    created_by: str
    updated_at: str
    custody: CustodyAnchor


class CaseResponse(BaseModel):
    id: str
    title: str
    created_at: str
    created_by: str
    evidence_count: int


class CustodyEventResponse(BaseModel):
    id: str
    case_id: str
    evidence_id: str
    sequence: int
    action: str
    actor: str
    occurred_at: str
    source: str
    source_ip: str
    user_agent: str
    request_method: str
    request_path: str
    version_number: int | None
    version_id: str | None
    version_digest: str | None
    details: dict[str, Any]
    previous_hash: str
    record_hash: str


class CustodyChainResponse(BaseModel):
    case_id: str
    evidence_id: str
    events: list[CustodyEventResponse]
    verification: dict[str, Any]


class TimelineResponse(BaseModel):
    case_id: str
    events: list[CustodyEventResponse]


class VerificationResponse(BaseModel):
    case_id: str
    evidence_id: str
    verification: dict[str, Any]
