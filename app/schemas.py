from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class AnalystCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)


class AnalystOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    created_at: str


class CaseCreate(BaseModel):
    title: str = Field(min_length=1, max_length=240)
    description: str = ""


class CaseOut(BaseModel):
    id: int
    title: str
    description: str
    status: str
    owner_id: int
    owner_name: str
    access_level: str
    created_at: str
    updated_at: str


class EventCreate(BaseModel):
    title: str = Field(min_length=1, max_length=240)
    description: str = ""
    occurred_at: str = Field(min_length=1, max_length=80)
    note: str = ""
    is_confirmed: bool = False


class EventUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=240)
    description: str | None = None
    occurred_at: str | None = Field(default=None, min_length=1, max_length=80)
    note: str | None = None
    is_confirmed: bool | None = None


class EventOut(BaseModel):
    id: int
    case_id: int
    title: str
    description: str
    occurred_at: str
    is_confirmed: bool
    note: str
    created_by: int
    created_at: str
    updated_at: str


class HypothesisCreate(BaseModel):
    statement: str = Field(min_length=1, max_length=4000)
    status: str = Field(default="open", min_length=1, max_length=40)
    note: str = ""


class HypothesisUpdate(BaseModel):
    statement: str | None = Field(default=None, min_length=1, max_length=4000)
    status: str | None = Field(default=None, min_length=1, max_length=40)
    note: str | None = None


class HypothesisOut(BaseModel):
    id: int
    case_id: int
    statement: str
    status: str
    note: str
    created_by: int
    created_at: str
    updated_at: str


class EvidenceCreate(BaseModel):
    title: str = Field(min_length=1, max_length=240)
    description: str = ""
    status: str = Field(default="pending", min_length=1, max_length=40)
    note: str = ""


class EvidenceUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=240)
    description: str | None = None
    status: str | None = Field(default=None, min_length=1, max_length=40)
    note: str | None = None


class EvidenceOut(BaseModel):
    id: int
    case_id: int
    title: str
    description: str
    status: str
    note: str
    created_by: int
    created_at: str
    updated_at: str


class OutgoingChecklistNote(BaseModel):
    category: str
    source_id: int | None = None
    note: str = Field(min_length=1, max_length=10000)


class HandoverCreate(BaseModel):
    to_analyst_id: int
    permission_note: str | None = None
    outgoing_notes: list[OutgoingChecklistNote] = Field(default_factory=list)


class HandoverItemUpdate(BaseModel):
    checked: bool | None = None
    note: str | None = Field(default=None, max_length=10000)
    outgoing_note: str | None = Field(default=None, max_length=10000)
    successor_note: str | None = Field(default=None, max_length=10000)


class ChecklistItemUpdate(BaseModel):
    item_id: int
    checked: bool | None = None
    note: str | None = Field(default=None, max_length=10000)
    outgoing_note: str | None = Field(default=None, max_length=10000)
    successor_note: str | None = Field(default=None, max_length=10000)


class HandoverChecklistUpdate(BaseModel):
    items: list[ChecklistItemUpdate] = Field(min_length=1)


class HandoverConfirm(BaseModel):
    confirmed: bool = True
    note: str | None = Field(default=None, max_length=10000)


class HandoverItemOut(BaseModel):
    id: int
    category: str
    item_key: str
    source_id: int | None
    title: str
    detail: str
    source_status: str
    checked: bool
    checked_by: int | None
    checked_at: str | None
    outgoing_note: str
    successor_note: str
    note: str
    created_at: str
    updated_at: str


class HandoverOut(BaseModel):
    id: int
    case_id: int
    from_analyst: AnalystOut
    to_analyst: AnalystOut
    status: str
    permission_summary: str
    permission_explanation: str
    created_at: str
    confirmed_at: str | None
    items: list[HandoverItemOut]
    checklist: dict[str, object]
