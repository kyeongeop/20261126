from __future__ import annotations

import sqlite3
from typing import Any

from fastapi import APIRouter, HTTPException

from app.access import (
    ActorId,
    DbConnection,
    case_dict,
    require_analyst,
    require_case_access,
)
from app.domain import (
    analyst_dict,
    event_dict,
    evidence_dict,
    hypothesis_dict,
    utc_now,
)
from app.schemas import (
    AnalystCreate,
    AnalystOut,
    CaseCreate,
    CaseOut,
    EventCreate,
    EventOut,
    EventUpdate,
    EvidenceCreate,
    EvidenceOut,
    EvidenceUpdate,
    HypothesisCreate,
    HypothesisOut,
    HypothesisUpdate,
)

router = APIRouter(prefix="/api", tags=["timeline"])


def _fetch_event(connection: sqlite3.Connection, event_id: int) -> sqlite3.Row:
    row = connection.execute(
        "SELECT * FROM events WHERE id = ?", (event_id,)
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="事件不存在")
    return row


def _fetch_hypothesis(
    connection: sqlite3.Connection, hypothesis_id: int
) -> sqlite3.Row:
    row = connection.execute(
        "SELECT * FROM hypotheses WHERE id = ?", (hypothesis_id,)
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="假设不存在")
    return row


def _fetch_evidence(connection: sqlite3.Connection, evidence_id: int) -> sqlite3.Row:
    row = connection.execute(
        "SELECT * FROM evidence WHERE id = ?", (evidence_id,)
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="证据不存在")
    return row


def _case_row(connection: sqlite3.Connection, case_id: int) -> sqlite3.Row:
    case = connection.execute(
        """
        SELECT c.*, a.name AS owner_name
        FROM cases c JOIN analysts a ON a.id = c.owner_id
        WHERE c.id = ?
        """,
        (case_id,),
    ).fetchone()
    if case is None:
        raise HTTPException(status_code=404, detail="案件不存在")
    return case


@router.post("/analysts", response_model=AnalystOut, status_code=201)
def create_analyst(payload: AnalystCreate, connection: DbConnection) -> dict[str, Any]:
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=422, detail="分析员姓名不能为空")
    now = utc_now()
    try:
        cursor = connection.execute(
            "INSERT INTO analysts (name, created_at) VALUES (?, ?)", (name, now)
        )
        connection.commit()
    except sqlite3.IntegrityError as error:
        raise HTTPException(status_code=409, detail="分析员姓名已存在") from error
    return analyst_dict(require_analyst(connection, int(cursor.lastrowid)))


@router.get("/analysts", response_model=list[AnalystOut])
def list_analysts(connection: DbConnection) -> list[dict[str, Any]]:
    rows = connection.execute(
        "SELECT id, name, created_at FROM analysts ORDER BY id"
    ).fetchall()
    return [analyst_dict(row) for row in rows]


@router.post("/cases", response_model=CaseOut, status_code=201)
def create_case(
    payload: CaseCreate, connection: DbConnection, actor_id: ActorId
) -> dict[str, Any]:
    require_analyst(connection, actor_id)
    now = utc_now()
    cursor = connection.execute(
        """
        INSERT INTO cases (title, description, owner_id, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (payload.title.strip(), payload.description, actor_id, now, now),
    )
    connection.execute(
        """
        INSERT INTO case_members (case_id, analyst_id, access_level, joined_at)
        VALUES (?, ?, 'owner', ?)
        """,
        (int(cursor.lastrowid), actor_id, now),
    )
    connection.commit()
    return case_dict(_case_row(connection, int(cursor.lastrowid)), "owner")


@router.get("/cases", response_model=list[CaseOut])
def list_cases(
    connection: DbConnection, actor_id: ActorId
) -> list[dict[str, Any]]:
    require_analyst(connection, actor_id)
    rows = connection.execute(
        """
        SELECT c.*, a.name AS owner_name, cm.access_level
        FROM cases c
        JOIN analysts a ON a.id = c.owner_id
        JOIN case_members cm ON cm.case_id = c.id
        WHERE cm.analyst_id = ?
        ORDER BY c.updated_at DESC, c.id DESC
        """,
        (actor_id,),
    ).fetchall()
    return [case_dict(row, row["access_level"]) for row in rows]


@router.get("/cases/{case_id}", response_model=CaseOut)
def get_case(
    case_id: int, connection: DbConnection, actor_id: ActorId
) -> dict[str, Any]:
    case_row, access_level = require_case_access(
        connection, case_id, actor_id, write=False
    )
    return case_dict(case_row, access_level)


@router.post(
    "/cases/{case_id}/events", response_model=EventOut, status_code=201
)
def create_event(
    case_id: int,
    payload: EventCreate,
    connection: DbConnection,
    actor_id: ActorId,
) -> dict[str, Any]:
    require_case_access(connection, case_id, actor_id, write=True)
    now = utc_now()
    cursor = connection.execute(
        """
        INSERT INTO events (
            case_id, title, description, occurred_at, is_confirmed, note,
            created_by, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            case_id,
            payload.title.strip(),
            payload.description,
            payload.occurred_at,
            int(payload.is_confirmed),
            payload.note,
            actor_id,
            now,
            now,
        ),
    )
    connection.commit()
    return event_dict(_fetch_event(connection, int(cursor.lastrowid)))


@router.get("/cases/{case_id}/events", response_model=list[EventOut])
def list_events(
    case_id: int, connection: DbConnection, actor_id: ActorId
) -> list[dict[str, Any]]:
    require_case_access(connection, case_id, actor_id, write=False)
    rows = connection.execute(
        "SELECT * FROM events WHERE case_id = ? ORDER BY occurred_at, id",
        (case_id,),
    ).fetchall()
    return [event_dict(row) for row in rows]


@router.patch("/cases/{case_id}/events/{event_id}", response_model=EventOut)
def update_event(
    case_id: int,
    event_id: int,
    payload: EventUpdate,
    connection: DbConnection,
    actor_id: ActorId,
) -> dict[str, Any]:
    require_case_access(connection, case_id, actor_id, write=True)
    event = _fetch_event(connection, event_id)
    if event["case_id"] != case_id:
        raise HTTPException(status_code=404, detail="事件不存在")
    values: dict[str, Any] = {}
    for field in ("title", "description", "occurred_at", "note"):
        value = getattr(payload, field)
        if value is not None:
            values[field] = value.strip() if field == "title" else value
    if payload.is_confirmed is not None:
        values["is_confirmed"] = int(payload.is_confirmed)
    if not values:
        raise HTTPException(status_code=400, detail="没有可更新的事件字段")
    values["updated_at"] = utc_now()
    columns = ", ".join(f"{column} = ?" for column in values)
    connection.execute(
        f"UPDATE events SET {columns} WHERE id = ?",
        (*values.values(), event_id),
    )
    connection.commit()
    return event_dict(_fetch_event(connection, event_id))


@router.post(
    "/cases/{case_id}/events/{event_id}/confirm", response_model=EventOut
)
def confirm_event(
    case_id: int,
    event_id: int,
    connection: DbConnection,
    actor_id: ActorId,
) -> dict[str, Any]:
    return update_event(
        case_id,
        event_id,
        EventUpdate(is_confirmed=True),
        connection,
        actor_id,
    )


@router.post(
    "/cases/{case_id}/hypotheses", response_model=HypothesisOut, status_code=201
)
def create_hypothesis(
    case_id: int,
    payload: HypothesisCreate,
    connection: DbConnection,
    actor_id: ActorId,
) -> dict[str, Any]:
    require_case_access(connection, case_id, actor_id, write=True)
    now = utc_now()
    cursor = connection.execute(
        """
        INSERT INTO hypotheses (
            case_id, statement, status, note, created_by, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            case_id,
            payload.statement.strip(),
            payload.status.strip(),
            payload.note,
            actor_id,
            now,
            now,
        ),
    )
    connection.commit()
    return hypothesis_dict(_fetch_hypothesis(connection, int(cursor.lastrowid)))


@router.get("/cases/{case_id}/hypotheses", response_model=list[HypothesisOut])
def list_hypotheses(
    case_id: int, connection: DbConnection, actor_id: ActorId
) -> list[dict[str, Any]]:
    require_case_access(connection, case_id, actor_id, write=False)
    rows = connection.execute(
        "SELECT * FROM hypotheses WHERE case_id = ? ORDER BY id",
        (case_id,),
    ).fetchall()
    return [hypothesis_dict(row) for row in rows]


@router.patch(
    "/cases/{case_id}/hypotheses/{hypothesis_id}", response_model=HypothesisOut
)
def update_hypothesis(
    case_id: int,
    hypothesis_id: int,
    payload: HypothesisUpdate,
    connection: DbConnection,
    actor_id: ActorId,
) -> dict[str, Any]:
    require_case_access(connection, case_id, actor_id, write=True)
    hypothesis = _fetch_hypothesis(connection, hypothesis_id)
    if hypothesis["case_id"] != case_id:
        raise HTTPException(status_code=404, detail="假设不存在")
    values: dict[str, Any] = {}
    if payload.statement is not None:
        values["statement"] = payload.statement.strip()
    if payload.status is not None:
        values["status"] = payload.status.strip()
    if payload.note is not None:
        values["note"] = payload.note
    if not values:
        raise HTTPException(status_code=400, detail="没有可更新的假设字段")
    values["updated_at"] = utc_now()
    columns = ", ".join(f"{column} = ?" for column in values)
    connection.execute(
        f"UPDATE hypotheses SET {columns} WHERE id = ?",
        (*values.values(), hypothesis_id),
    )
    connection.commit()
    return hypothesis_dict(_fetch_hypothesis(connection, hypothesis_id))


@router.post(
    "/cases/{case_id}/evidence", response_model=EvidenceOut, status_code=201
)
def create_evidence(
    case_id: int,
    payload: EvidenceCreate,
    connection: DbConnection,
    actor_id: ActorId,
) -> dict[str, Any]:
    require_case_access(connection, case_id, actor_id, write=True)
    now = utc_now()
    cursor = connection.execute(
        """
        INSERT INTO evidence (
            case_id, title, description, status, note,
            created_by, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            case_id,
            payload.title.strip(),
            payload.description,
            payload.status.strip(),
            payload.note,
            actor_id,
            now,
            now,
        ),
    )
    connection.commit()
    return evidence_dict(_fetch_evidence(connection, int(cursor.lastrowid)))


@router.get("/cases/{case_id}/evidence", response_model=list[EvidenceOut])
def list_evidence(
    case_id: int, connection: DbConnection, actor_id: ActorId
) -> list[dict[str, Any]]:
    require_case_access(connection, case_id, actor_id, write=False)
    rows = connection.execute(
        "SELECT * FROM evidence WHERE case_id = ? ORDER BY id",
        (case_id,),
    ).fetchall()
    return [evidence_dict(row) for row in rows]


@router.patch(
    "/cases/{case_id}/evidence/{evidence_id}", response_model=EvidenceOut
)
def update_evidence(
    case_id: int,
    evidence_id: int,
    payload: EvidenceUpdate,
    connection: DbConnection,
    actor_id: ActorId,
) -> dict[str, Any]:
    require_case_access(connection, case_id, actor_id, write=True)
    evidence = _fetch_evidence(connection, evidence_id)
    if evidence["case_id"] != case_id:
        raise HTTPException(status_code=404, detail="证据不存在")
    values: dict[str, Any] = {}
    if payload.title is not None:
        values["title"] = payload.title.strip()
    if payload.description is not None:
        values["description"] = payload.description
    if payload.status is not None:
        values["status"] = payload.status.strip()
    if payload.note is not None:
        values["note"] = payload.note
    if not values:
        raise HTTPException(status_code=400, detail="没有可更新的证据字段")
    values["updated_at"] = utc_now()
    columns = ", ".join(f"{column} = ?" for column in values)
    connection.execute(
        f"UPDATE evidence SET {columns} WHERE id = ?",
        (*values.values(), evidence_id),
    )
    connection.commit()
    return evidence_dict(_fetch_evidence(connection, evidence_id))
