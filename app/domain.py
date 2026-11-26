from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

FINISHED_HYPOTHESIS_STATUSES = {
    "closed",
    "complete",
    "completed",
    "confirmed",
    "rejected",
    "resolved",
}

COMPLETED_EVIDENCE_STATUSES = {
    "closed",
    "collected",
    "complete",
    "completed",
    "received",
    "verified",
}


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def append_note(existing: str, addition: str | None) -> str:
    """Append a note without ever replacing the text already recorded."""
    if not addition or not addition.strip():
        return existing
    cleaned = addition.strip()
    if not existing:
        return cleaned
    if cleaned in existing.split("\n"):
        return existing
    return f"{existing}\n{cleaned}"


def is_unconfirmed_event(row: Any) -> bool:
    return not bool(row["is_confirmed"])


def is_unfinished_hypothesis(row: Any) -> bool:
    return str(row["status"]).strip().lower() not in FINISHED_HYPOTHESIS_STATUSES


def is_pending_evidence(row: Any) -> bool:
    return str(row["status"]).strip().lower() not in COMPLETED_EVIDENCE_STATUSES


def permission_summary(from_name: str, to_name: str) -> str:
    return (
        f"交接确认前，{from_name} 仍是案件负责人并保留编辑权限，"
        f"{to_name} 仅可查看和核对交接清单。\n"
        f"交接确认后，{to_name} 成为案件负责人，可编辑时间线、假设、证据和交接清单；"
        f"{from_name} 仅保留只读访问权限，不能再修改案件内容或清单。"
    )


def event_dict(row: Any) -> dict[str, Any]:
    return {
        "id": row["id"],
        "case_id": row["case_id"],
        "title": row["title"],
        "description": row["description"],
        "occurred_at": row["occurred_at"],
        "is_confirmed": bool(row["is_confirmed"]),
        "note": row["note"],
        "created_by": row["created_by"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def hypothesis_dict(row: Any) -> dict[str, Any]:
    return {
        "id": row["id"],
        "case_id": row["case_id"],
        "statement": row["statement"],
        "status": row["status"],
        "note": row["note"],
        "created_by": row["created_by"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def evidence_dict(row: Any) -> dict[str, Any]:
    return {
        "id": row["id"],
        "case_id": row["case_id"],
        "title": row["title"],
        "description": row["description"],
        "status": row["status"],
        "note": row["note"],
        "created_by": row["created_by"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def analyst_dict(row: Any) -> dict[str, Any]:
    return {"id": row["id"], "name": row["name"], "created_at": row["created_at"]}


def handover_item_dict(row: Any) -> dict[str, Any]:
    return {
        "id": row["id"],
        "category": row["category"],
        "item_key": row["item_key"],
        "source_id": row["source_id"],
        "title": row["title"],
        "detail": row["detail"],
        "source_status": row["source_status"],
        "checked": bool(row["checked"]),
        "checked_by": row["checked_by"],
        "checked_at": row["checked_at"],
        "outgoing_note": row["outgoing_note"],
        "successor_note": row["successor_note"],
        "note": row["outgoing_note"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }
