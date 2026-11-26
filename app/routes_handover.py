from __future__ import annotations

from fastapi import APIRouter

from app.access import ActorId, DbConnection, require_case_access
from app.handover_service import (
    confirm_handover,
    create_handover,
    get_handover_row,
    handover_response,
    refresh_handover,
    update_handover_checklist,
    update_handover_item,
)
from app.schemas import (
    HandoverChecklistUpdate,
    HandoverConfirm,
    HandoverCreate,
    HandoverItemOut,
    HandoverItemUpdate,
    HandoverOut,
)

router = APIRouter(prefix="/api", tags=["handover"])


@router.post(
    "/cases/{case_id}/handovers", response_model=HandoverOut, status_code=201
)
def create_case_handover(
    case_id: int,
    payload: HandoverCreate,
    connection: DbConnection,
    actor_id: ActorId,
) -> dict[str, object]:
    return create_handover(connection, case_id, actor_id, payload)


@router.get(
    "/cases/{case_id}/handovers", response_model=list[HandoverOut]
)
def list_case_handovers(
    case_id: int, connection: DbConnection, actor_id: ActorId
) -> list[dict[str, object]]:
    require_case_access(connection, case_id, actor_id, write=False)
    rows = connection.execute(
        "SELECT id FROM handovers WHERE case_id = ? ORDER BY id DESC",
        (case_id,),
    ).fetchall()
    return [
        handover_response(connection, get_handover_row(connection, case_id, row["id"]))
        for row in rows
    ]


@router.get(
    "/cases/{case_id}/handovers/{handover_id}", response_model=HandoverOut
)
def get_case_handover(
    case_id: int, handover_id: int, connection: DbConnection, actor_id: ActorId
) -> dict[str, object]:
    require_case_access(connection, case_id, actor_id, write=False)
    return handover_response(
        connection, get_handover_row(connection, case_id, handover_id)
    )


@router.patch(
    "/cases/{case_id}/handovers/{handover_id}/items/{item_id}",
    response_model=HandoverItemOut,
)
def patch_checklist_item(
    case_id: int,
    handover_id: int,
    item_id: int,
    payload: HandoverItemUpdate,
    connection: DbConnection,
    actor_id: ActorId,
) -> dict[str, object]:
    return update_handover_item(
        connection, case_id, handover_id, item_id, actor_id, payload
    )


@router.patch(
    "/cases/{case_id}/handovers/{handover_id}/checklist",
    response_model=HandoverOut,
)
def patch_checklist(
    case_id: int,
    handover_id: int,
    payload: HandoverChecklistUpdate,
    connection: DbConnection,
    actor_id: ActorId,
) -> dict[str, object]:
    return update_handover_checklist(
        connection, case_id, handover_id, actor_id, payload
    )


@router.post(
    "/cases/{case_id}/handovers/{handover_id}/refresh",
    response_model=HandoverOut,
)
def refresh_case_handover(
    case_id: int, handover_id: int, connection: DbConnection, actor_id: ActorId
) -> dict[str, object]:
    return refresh_handover(connection, case_id, handover_id, actor_id)


@router.post(
    "/cases/{case_id}/handovers/{handover_id}/confirm",
    response_model=HandoverOut,
)
def confirm_case_handover(
    case_id: int,
    handover_id: int,
    connection: DbConnection,
    actor_id: ActorId,
    payload: HandoverConfirm | None = None,
) -> dict[str, object]:
    return confirm_handover(
        connection,
        case_id,
        handover_id,
        actor_id,
        payload or HandoverConfirm(),
    )
