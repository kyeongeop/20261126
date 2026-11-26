from __future__ import annotations

from sqlite3 import Connection, Row
from typing import Any

from fastapi import HTTPException

from app.access import require_analyst, require_case_access
from app.domain import (
    append_note,
    handover_item_dict,
    is_pending_evidence,
    is_unconfirmed_event,
    is_unfinished_hypothesis,
    permission_summary,
    utc_now,
)
from app.schemas import HandoverCreate

CATEGORY_GROUPS = {
    "event": "unconfirmed_events",
    "hypothesis": "unfinished_hypotheses",
    "evidence": "evidence_to_supplement",
    "permission": "permission",
}


def get_handover_row(
    connection: Connection, case_id: int, handover_id: int
) -> Row:
    row = connection.execute(
        """
        SELECT
            h.*,
            fa.name AS from_name,
            fa.created_at AS from_created_at,
            ta.name AS to_name,
            ta.created_at AS to_created_at
        FROM handovers h
        JOIN analysts fa ON fa.id = h.from_analyst_id
        JOIN analysts ta ON ta.id = h.to_analyst_id
        WHERE h.id = ? AND h.case_id = ?
        """,
        (handover_id, case_id),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="交接记录不存在")
    return row


def _get_item(
    connection: Connection, handover_id: int, item_id: int
) -> Row:
    row = connection.execute(
        "SELECT * FROM handover_items WHERE id = ? AND handover_id = ?",
        (item_id, handover_id),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="交接清单项不存在")
    return row


def _event_items(connection: Connection, case_id: int) -> list[dict[str, Any]]:
    rows = connection.execute(
        "SELECT * FROM events WHERE case_id = ? ORDER BY occurred_at, id",
        (case_id,),
    ).fetchall()
    return [
        {
            "item_key": f"event:{row['id']}",
            "category": "event",
            "source_id": row["id"],
            "title": row["title"],
            "detail": _event_detail(row),
            "source_status": "unconfirmed",
        }
        for row in rows
        if is_unconfirmed_event(row)
    ]


def _hypothesis_items(connection: Connection, case_id: int) -> list[dict[str, Any]]:
    rows = connection.execute(
        "SELECT * FROM hypotheses WHERE case_id = ? ORDER BY id", (case_id,)
    ).fetchall()
    return [
        {
            "item_key": f"hypothesis:{row['id']}",
            "category": "hypothesis",
            "source_id": row["id"],
            "title": row["statement"],
            "detail": f"当前状态：{row['status']}"
            + (f"\n备注：{row['note']}" if row["note"] else ""),
            "source_status": row["status"],
        }
        for row in rows
        if is_unfinished_hypothesis(row)
    ]


def _evidence_items(connection: Connection, case_id: int) -> list[dict[str, Any]]:
    rows = connection.execute(
        "SELECT * FROM evidence WHERE case_id = ? ORDER BY id", (case_id,)
    ).fetchall()
    return [
        {
            "item_key": f"evidence:{row['id']}",
            "category": "evidence",
            "source_id": row["id"],
            "title": row["title"],
            "detail": f"当前状态：{row['status']}"
            + (f"\n说明：{row['description']}" if row["description"] else ""),
            "source_status": row["status"],
        }
        for row in rows
        if is_pending_evidence(row)
    ]


def _event_detail(row: Row) -> str:
    parts = [f"发生时间：{row['occurred_at']}"]
    if row["description"]:
        parts.append(row["description"])
    return "\n".join(parts)


def _permission_item(summary: str) -> dict[str, Any]:
    return {
        "item_key": "permission:access",
        "category": "permission",
        "source_id": None,
        "title": "权限说明",
        "detail": summary,
        "source_status": "pending_confirmation",
    }


def _sync_item(connection: Connection, handover_id: int, item: dict[str, Any]) -> None:
    now = utc_now()
    connection.execute(
        """
        INSERT INTO handover_items (
            handover_id, item_key, category, source_id, title, detail,
            source_status, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(handover_id, item_key) DO UPDATE SET
            category = excluded.category,
            source_id = excluded.source_id,
            title = excluded.title,
            detail = excluded.detail,
            source_status = excluded.source_status,
            updated_at = excluded.updated_at
        """,
        (
            handover_id,
            item["item_key"],
            item["category"],
            item["source_id"],
            item["title"],
            item["detail"],
            item["source_status"],
            now,
            now,
        ),
    )


def sync_checklist(connection: Connection, handover_row: Row) -> None:
    """Refresh generated checklist content while leaving notes untouched."""
    generated = [
        *_event_items(connection, handover_row["case_id"]),
        *_hypothesis_items(connection, handover_row["case_id"]),
        *_evidence_items(connection, handover_row["case_id"]),
        _permission_item(handover_row["permission_summary"]),
    ]
    for item in generated:
        _sync_item(connection, handover_row["id"], item)


def _item_key(category: str, source_id: int | None) -> str:
    if category == "permission":
        return "permission:access"
    if category not in {"event", "hypothesis", "evidence"} or source_id is None:
        raise HTTPException(status_code=400, detail="手写备注对应的清单项无效")
    return f"{category}:{source_id}"


def _append_outgoing_note(
    connection: Connection,
    handover_id: int,
    category: str,
    source_id: int | None,
    note: str,
) -> None:
    key = _item_key(category, source_id)
    item = connection.execute(
        "SELECT id, outgoing_note FROM handover_items "
        "WHERE handover_id = ? AND item_key = ?",
        (handover_id, key),
    ).fetchone()
    if item is None:
        raise HTTPException(status_code=400, detail=f"清单项 {key} 不存在")
    connection.execute(
        "UPDATE handover_items SET outgoing_note = ?, updated_at = ? WHERE id = ?",
        (append_note(item["outgoing_note"], note), utc_now(), item["id"]),
    )


def create_handover(
    connection: Connection, case_id: int, actor_id: int, payload: HandoverCreate
) -> dict[str, Any]:
    _, access_level = require_case_access(connection, case_id, actor_id, write=True)
    if access_level != "owner":
        raise HTTPException(status_code=403, detail="只有案件负责人可以发起交接")
    if payload.to_analyst_id == actor_id:
        raise HTTPException(status_code=400, detail="不能将案件交接给本人")

    to_analyst = require_analyst(connection, payload.to_analyst_id)
    pending = connection.execute(
        "SELECT id FROM handovers WHERE case_id = ? AND status = 'pending'",
        (case_id,),
    ).fetchone()
    if pending is not None:
        raise HTTPException(status_code=409, detail="该案件已有待确认的交接")

    existing_member = connection.execute(
        "SELECT access_level FROM case_members WHERE case_id = ? AND analyst_id = ?",
        (case_id, payload.to_analyst_id),
    ).fetchone()
    if existing_member is not None and existing_member["access_level"] == "owner":
        raise HTTPException(status_code=409, detail="接手人已经是案件负责人")

    now = utc_now()
    summary = permission_summary(
        connection.execute(
            "SELECT name FROM analysts WHERE id = ?", (actor_id,)
        ).fetchone()["name"],
        to_analyst["name"],
    )
    if payload.permission_note:
        summary = f"{summary}\n交接说明：{payload.permission_note}"

    if existing_member is None:
        connection.execute(
            """
            INSERT INTO case_members (case_id, analyst_id, access_level, joined_at)
            VALUES (?, ?, 'read_only', ?)
            """,
            (case_id, payload.to_analyst_id, now),
        )

    cursor = connection.execute(
        """
        INSERT INTO handovers (
            case_id, from_analyst_id, to_analyst_id, permission_summary, created_at
        ) VALUES (?, ?, ?, ?, ?)
        """,
        (case_id, actor_id, payload.to_analyst_id, summary, now),
    )
    handover_row = get_handover_row(connection, case_id, int(cursor.lastrowid))
    sync_checklist(connection, handover_row)

    for outgoing_note in payload.outgoing_notes:
        _append_outgoing_note(
            connection,
            handover_row["id"],
            outgoing_note.category,
            outgoing_note.source_id,
            outgoing_note.note,
        )
    if payload.permission_note:
        _append_outgoing_note(
            connection,
            handover_row["id"],
            "permission",
            None,
            payload.permission_note,
        )

    connection.commit()
    return handover_response(connection, handover_row)


def handover_response(connection: Connection, handover_row: Row) -> dict[str, Any]:
    item_rows = connection.execute(
        "SELECT * FROM handover_items WHERE handover_id = ? ORDER BY id",
        (handover_row["id"],),
    ).fetchall()
    items = [handover_item_dict(row) for row in item_rows]
    checklist: dict[str, list[dict[str, Any]]] = {
        "unconfirmed_events": [],
        "unfinished_hypotheses": [],
        "evidence_to_supplement": [],
        "permission": [],
    }
    for item in items:
        group = CATEGORY_GROUPS[item["category"]]
        checklist[group].append(item)

    return {
        "id": handover_row["id"],
        "case_id": handover_row["case_id"],
        "from_analyst": {
            "id": handover_row["from_analyst_id"],
            "name": handover_row["from_name"],
            "created_at": handover_row["from_created_at"],
        },
        "to_analyst": {
            "id": handover_row["to_analyst_id"],
            "name": handover_row["to_name"],
            "created_at": handover_row["to_created_at"],
        },
        "status": handover_row["status"],
        "permission_summary": handover_row["permission_summary"],
        "permission_explanation": handover_row["permission_summary"],
        "created_at": handover_row["created_at"],
        "confirmed_at": handover_row["confirmed_at"],
        "items": items,
        "checklist": checklist,
    }


def _require_item_update_access(
    connection: Connection,
    handover_row: Row,
    actor_id: int,
) -> None:
    _, access_level = require_case_access(
        connection, handover_row["case_id"], actor_id, write=False
    )
    if handover_row["status"] == "pending":
        if actor_id not in {
            handover_row["from_analyst_id"],
            handover_row["to_analyst_id"],
        }:
            raise HTTPException(status_code=403, detail="当前分析员不是交接参与人")
        return
    if handover_row["status"] == "confirmed":
        if actor_id != handover_row["to_analyst_id"] or access_level != "owner":
            raise HTTPException(status_code=403, detail="交接已确认，旧负责人只有只读权限")
        return
    raise HTTPException(status_code=409, detail="已取消的交接不能修改")


def _apply_item_update(
    connection: Connection,
    handover_row: Row,
    item_id: int,
    actor_id: int,
    payload: Any,
) -> dict[str, Any]:
    _require_item_update_access(connection, handover_row, actor_id)
    item = _get_item(connection, handover_row["id"], item_id)
    changed = False
    updates: dict[str, Any] = {}
    now = utc_now()

    if payload.checked is not None:
        updates["checked"] = 1 if payload.checked else 0
        updates["checked_by"] = actor_id if payload.checked else None
        updates["checked_at"] = now if payload.checked else None
        changed = True

    is_outgoing = actor_id == handover_row["from_analyst_id"]
    generic_note = payload.note
    if generic_note:
        if is_outgoing:
            updates["outgoing_note"] = append_note(item["outgoing_note"], generic_note)
        else:
            updates["successor_note"] = append_note(item["successor_note"], generic_note)
        changed = True

    if payload.outgoing_note:
        if not is_outgoing:
            raise HTTPException(status_code=403, detail="只有发出交接的分析员可以补充手写备注")
        updates["outgoing_note"] = append_note(
            updates.get("outgoing_note", item["outgoing_note"]),
            payload.outgoing_note,
        )
        changed = True

    if payload.successor_note:
        if is_outgoing:
            raise HTTPException(status_code=403, detail="接手人备注不能由旧负责人填写")
        updates["successor_note"] = append_note(
            updates.get("successor_note", item["successor_note"]),
            payload.successor_note,
        )
        changed = True

    if changed:
        updates["updated_at"] = now
        columns = ", ".join(f"{column} = ?" for column in updates)
        connection.execute(
            f"UPDATE handover_items SET {columns} WHERE id = ?",
            (*updates.values(), item_id),
        )
    refreshed = _get_item(connection, handover_row["id"], item_id)
    return handover_item_dict(refreshed)


def update_handover_item(
    connection: Connection,
    case_id: int,
    handover_id: int,
    item_id: int,
    actor_id: int,
    payload: Any,
) -> dict[str, Any]:
    handover_row = get_handover_row(connection, case_id, handover_id)
    result = _apply_item_update(
        connection, handover_row, item_id, actor_id, payload
    )
    connection.commit()
    return result


def update_handover_checklist(
    connection: Connection,
    case_id: int,
    handover_id: int,
    actor_id: int,
    payload: Any,
) -> dict[str, Any]:
    handover_row = get_handover_row(connection, case_id, handover_id)
    for item_update in payload.items:
        _apply_item_update(
            connection, handover_row, item_update.item_id, actor_id, item_update
        )
    connection.commit()
    return handover_response(connection, get_handover_row(connection, case_id, handover_id))


def refresh_handover(
    connection: Connection, case_id: int, handover_id: int, actor_id: int
) -> dict[str, Any]:
    handover_row = get_handover_row(connection, case_id, handover_id)
    if handover_row["status"] == "pending":
        _require_item_update_access(connection, handover_row, actor_id)
    else:
        require_case_access(connection, case_id, actor_id, write=True)
    sync_checklist(connection, handover_row)
    connection.commit()
    return handover_response(connection, handover_row)


def confirm_handover(
    connection: Connection,
    case_id: int,
    handover_id: int,
    actor_id: int,
    payload: Any,
) -> dict[str, Any]:
    handover_row = get_handover_row(connection, case_id, handover_id)
    require_case_access(connection, case_id, actor_id, write=False)
    if handover_row["status"] != "pending":
        raise HTTPException(status_code=409, detail="该交接已经处理，不能重复确认")
    if actor_id != handover_row["to_analyst_id"]:
        raise HTTPException(status_code=403, detail="只有接手人可以确认交接")
    if not payload.confirmed:
        raise HTTPException(status_code=400, detail="接手人必须明确确认交接")

    sync_checklist(connection, handover_row)
    if payload.note:
        permission_item = connection.execute(
            "SELECT id, successor_note FROM handover_items "
            "WHERE handover_id = ? AND item_key = 'permission:access'",
            (handover_id,),
        ).fetchone()
        connection.execute(
            "UPDATE handover_items SET successor_note = ?, updated_at = ? WHERE id = ?",
            (
                append_note(permission_item["successor_note"], payload.note),
                utc_now(),
                permission_item["id"],
            ),
        )

    now = utc_now()
    connection.execute(
        "UPDATE handovers SET status = 'confirmed', confirmed_at = ? WHERE id = ?",
        (now, handover_id),
    )
    connection.execute(
        "UPDATE cases SET owner_id = ?, updated_at = ? WHERE id = ?",
        (actor_id, now, case_id),
    )
    connection.execute(
        """
        UPDATE case_members SET access_level = 'read_only'
        WHERE case_id = ? AND analyst_id = ?
        """,
        (case_id, handover_row["from_analyst_id"]),
    )
    connection.execute(
        """
        INSERT INTO case_members (case_id, analyst_id, access_level, joined_at)
        VALUES (?, ?, 'owner', ?)
        ON CONFLICT(case_id, analyst_id) DO UPDATE SET access_level = 'owner'
        """,
        (case_id, actor_id, now),
    )
    connection.commit()
    return handover_response(
        connection, get_handover_row(connection, case_id, handover_id)
    )
