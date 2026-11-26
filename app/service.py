"""Application service layer: all SQLite access and merge workflow rules.

Routers stay thin; this module owns transactions and the preservation
invariant that source records are insert-only.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any, Iterable, Sequence
from uuid import uuid4

from . import logic
from .errors import ConflictError, NotFoundError, ValidationError


def new_id(prefix: str = "") -> str:
    return f"{prefix}{uuid4().hex}"


def now_iso() -> str:
    return logic.utc_now_iso()


def _json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)


def _json_loads(text: str | None, default: Any) -> Any:
    if not text:
        return default
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return default


# ---------------------------------------------------------------------------
# Incidents & sources
# ---------------------------------------------------------------------------


def create_incident(
    conn: sqlite3.Connection,
    *,
    incident_id: str,
    title: str,
    severity: str = "medium",
) -> dict[str, Any]:
    conn.execute(
        """
        INSERT INTO incidents (id, title, severity, created_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET title = excluded.title,
                                      severity = excluded.severity
        """,
        (incident_id, title, severity, now_iso()),
    )
    conn.commit()
    return get_incident(conn, incident_id)


def get_incident(conn: sqlite3.Connection, incident_id: str) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    if row is None:
        raise NotFoundError(f"事故不存在: {incident_id}")
    return dict(row)


def list_incidents(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute("SELECT * FROM incidents ORDER BY created_at DESC").fetchall()
    return [dict(row) for row in rows]


def create_source(
    conn: sqlite3.Connection,
    *,
    code: str,
    name: str,
    reliability: float = 0.8,
) -> dict[str, Any]:
    if not 0.0 <= reliability <= 1.0:
        raise ValidationError("reliability 必须位于 0..1 之间")
    conn.execute(
        """
        INSERT INTO sources (code, name, reliability, created_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(code) DO UPDATE SET name = excluded.name,
                                       reliability = excluded.reliability
        """,
        (code, name, reliability, now_iso()),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM sources WHERE code = ?", (code,)).fetchone()
    return dict(row)


def list_sources(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute("SELECT * FROM sources ORDER BY reliability DESC, code").fetchall()
    return [dict(row) for row in rows]


def _source_map(conn: sqlite3.Connection) -> dict[str, dict[str, Any]]:
    return {row["code"]: dict(row) for row in conn.execute("SELECT * FROM sources")}


# ---------------------------------------------------------------------------
# Source records (immutable originals)
# ---------------------------------------------------------------------------


def ingest_record(
    conn: sqlite3.Connection,
    *,
    source_code: str,
    external_id: str,
    event_type: str,
    user_id: str,
    occurred_at: str,
    payload: dict[str, Any] | None = None,
    record_id: str | None = None,
) -> tuple[dict[str, Any], bool]:
    """Insert a raw source record.

    Records are insert-only: re-ingesting the same
    ``(source_code, external_id)`` never overwrites the stored original;
    instead ``(existing_record, created=False)`` is returned.
    """

    source = conn.execute(
        "SELECT code FROM sources WHERE code = ?", (source_code,)
    ).fetchone()
    if source is None:
        raise ValidationError(
            f"未知来源系统: {source_code!r}，请先调用 POST /api/sources 注册"
        )

    try:
        normalized_time = logic.to_utc_iso(occurred_at)
    except (ValueError, TypeError) as exc:
        raise ValidationError(f"无法解析 occurred_at={occurred_at!r}: {exc}") from exc

    rid = record_id or new_id("rec_")
    cursor = conn.execute(
        """
        INSERT OR IGNORE INTO source_records
            (id, source_code, external_id, event_type, user_id,
             occurred_at, occurred_at_raw, ingested_at, payload_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            rid,
            source_code,
            str(external_id),
            event_type,
            user_id,
            normalized_time,
            str(occurred_at),
            now_iso(),
            _json_dumps(payload or {}),
        ),
    )
    created = cursor.rowcount == 1
    conn.commit()

    if not created:
        row = conn.execute(
            "SELECT * FROM source_records WHERE source_code = ? AND external_id = ?",
            (source_code, str(external_id)),
        ).fetchone()
        return serialize_record(conn, row), False

    return get_record(conn, rid), True


def serialize_record(conn: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
    source = conn.execute(
        "SELECT name, reliability FROM sources WHERE code = ?", (row["source_code"],)
    ).fetchone()
    return {
        "id": row["id"],
        "source_code": row["source_code"],
        "source_name": source["name"] if source else row["source_code"],
        "reliability": source["reliability"] if source else 0.8,
        "external_id": row["external_id"],
        "event_type": row["event_type"],
        "user_id": row["user_id"],
        "occurred_at": row["occurred_at"],
        "occurred_at_raw": row["occurred_at_raw"],
        "ingested_at": row["ingested_at"],
        "payload": _json_loads(row["payload_json"], {}),
    }


def get_record(conn: sqlite3.Connection, record_id: str) -> dict[str, Any]:
    row = conn.execute(
        "SELECT * FROM source_records WHERE id = ?", (record_id,)
    ).fetchone()
    if row is None:
        raise NotFoundError(f"原始记录不存在: {record_id}")
    return serialize_record(conn, row)


def list_records(
    conn: sqlite3.Connection,
    *,
    user_id: str | None = None,
    source_code: str | None = None,
    event_type: str | None = None,
    limit: int = 500,
) -> list[dict[str, Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if user_id:
        clauses.append("user_id = ?")
        params.append(user_id)
    if source_code:
        clauses.append("source_code = ?")
        params.append(source_code)
    if event_type:
        clauses.append("event_type = ?")
        params.append(event_type)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    rows = conn.execute(
        f"SELECT * FROM source_records {where} ORDER BY occurred_at ASC LIMIT ?",
        (*params, limit),
    ).fetchall()
    return [serialize_record(conn, row) for row in rows]


def build_view(record: dict[str, Any]) -> dict[str, Any]:
    """Turn a serialized record into the shape consumed by ``app.logic``."""

    payload = record.get("payload") or {}
    return {
        "record_id": record["id"],
        "source_code": record["source_code"],
        "source_name": record.get("source_name"),
        "reliability": record.get("reliability", 0.8),
        "external_id": record.get("external_id"),
        "event_type": record["event_type"],
        "user_id": record["user_id"],
        "occurred_at": record["occurred_at"],
        "occurred_at_raw": record.get("occurred_at_raw"),
        "payload": payload,
        "fields": logic.extract_fields(
            event_type=record["event_type"],
            user_id=record["user_id"],
            occurred_at=record["occurred_at"],
            payload=payload,
        ),
    }


def get_views(conn: sqlite3.Connection, record_ids: Sequence[str]) -> list[dict[str, Any]]:
    records = [get_record(conn, rid) for rid in record_ids]
    return [build_view(record) for record in records]


# ---------------------------------------------------------------------------
# Merge candidates
# ---------------------------------------------------------------------------


def _existing_candidate_for_record_set(
    conn: sqlite3.Connection, record_ids: set[str]
) -> str | None:
    """Return a candidate id whose member set is exactly ``record_ids``."""

    if not record_ids:
        return None
    placeholders = ",".join("?" for _ in record_ids)
    rows = conn.execute(
        f"""
        SELECT candidate_id, COUNT(*) AS n
        FROM candidate_records
        WHERE record_id IN ({placeholders})
        GROUP BY candidate_id
        """,
        tuple(record_ids),
    ).fetchall()
    for row in rows:
        if row["n"] != len(record_ids):
            continue
        members = {
            r["record_id"]
            for r in conn.execute(
                "SELECT record_id FROM candidate_records WHERE candidate_id = ?",
                (row["candidate_id"],),
            ).fetchall()
        }
        if members == record_ids:
            return row["candidate_id"]
    return None


def create_candidate(
    conn: sqlite3.Connection,
    record_ids: Sequence[str],
    *,
    incident_id: str | None = None,
    candidate_id: str | None = None,
) -> dict[str, Any]:
    ids = list(dict.fromkeys(record_ids))  # de-duplicate, preserve order
    if len(ids) < 2:
        raise ValidationError("候选合并至少需要 2 条原始记录")

    # Validate every record exists before inspecting overlap.
    for rid in ids:
        get_record(conn, rid)

    exact = _existing_candidate_for_record_set(conn, set(ids))
    if exact is not None:
        return get_candidate_detail(conn, exact)

    placeholders = ",".join("?" for _ in ids)
    overlap = conn.execute(
        f"""
        SELECT candidate_id, record_id FROM candidate_records
        WHERE record_id IN ({placeholders})
        """,
        tuple(ids),
    ).fetchall()
    if overlap:
        cand_id = overlap[0]["candidate_id"]
        raise ConflictError(
            "部分记录已经属于另一个候选合并组，不能重复分组",
            details={"candidate_id": cand_id},
        )

    views = get_views(conn, ids)
    confidence = logic.score_match(views)
    cid = candidate_id or new_id("cand_")
    conn.execute(
        """
        INSERT INTO merge_candidates
            (id, incident_id, status, confidence_score, confidence_label,
             confidence_json, time_delta_seconds, created_at)
        VALUES (?, ?, 'pending', ?, ?, ?, ?, ?)
        """,
        (
            cid,
            incident_id,
            confidence["score"],
            confidence["label"],
            _json_dumps(confidence),
            confidence["time_delta_seconds"],
            now_iso(),
        ),
    )
    for position, rid in enumerate(ids):
        conn.execute(
            "INSERT INTO candidate_records (candidate_id, record_id, position) VALUES (?, ?, ?)",
            (cid, rid, position),
        )
    conn.commit()
    return get_candidate_detail(conn, cid)


def detect_candidates(
    conn: sqlite3.Connection,
    *,
    window_hours: float = 24.0,
    incident_id: str | None = None,
) -> list[dict[str, Any]]:
    """Group unassigned records by user/type and a bounded time window.

    Only records that are not yet members of any candidate are considered,
    making repeated detection runs idempotent and non-overlapping.
    """

    rows = conn.execute(
        """
        SELECT r.* FROM source_records r
        LEFT JOIN candidate_records cr ON cr.record_id = r.id
        WHERE cr.record_id IS NULL
        ORDER BY r.user_id, r.event_type, r.occurred_at
        """
    ).fetchall()

    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in rows:
        rec = serialize_record(conn, row)
        grouped.setdefault((rec["user_id"], rec["event_type"]), []).append(rec)

    created: list[dict[str, Any]] = []
    window_seconds = float(window_hours) * 3600.0
    for records in grouped.values():
        records.sort(key=lambda r: logic.parse_dt(r["occurred_at"]))
        cluster: list[dict[str, Any]] = []
        anchor_time = None
        for rec in records:
            rec_time = logic.parse_dt(rec["occurred_at"])
            if not cluster:
                cluster = [rec]
                anchor_time = rec_time
                continue
            if (rec_time - anchor_time).total_seconds() <= window_seconds:
                cluster.append(rec)
            else:
                if len(cluster) >= 2:
                    created.append(
                        create_candidate(
                            conn, [r["id"] for r in cluster], incident_id=incident_id
                        )
                    )
                cluster = [rec]
                anchor_time = rec_time
        if len(cluster) >= 2:
            created.append(
                create_candidate(
                    conn, [r["id"] for r in cluster], incident_id=incident_id
                )
            )
    return created


def list_candidates(
    conn: sqlite3.Connection,
    *,
    status: str | None = None,
    incident_id: str | None = None,
) -> list[dict[str, Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if status and status != "all":
        if status not in {"pending", "merged", "split", "unknown"}:
            raise ValidationError(f"非法状态过滤: {status}")
        clauses.append("status = ?")
        params.append(status)
    if incident_id:
        clauses.append("incident_id = ?")
        params.append(incident_id)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    rows = conn.execute(
        f"SELECT * FROM merge_candidates {where} ORDER BY created_at DESC", params
    ).fetchall()

    summaries: list[dict[str, Any]] = []
    for row in rows:
        detail = get_candidate_detail(conn, row["id"])
        summaries.append(
            {
                "id": detail["id"],
                "incident_id": detail["incident_id"],
                "status": detail["status"],
                "user_id": detail["user_id"],
                "event_type": detail["event_type"],
                "confidence": {
                    "score": detail["confidence"]["score"],
                    "percent": detail["confidence"]["percent"],
                    "label": detail["confidence"]["label"],
                    "label_text": detail["confidence"]["label_text"],
                    "trust_adjusted_score": detail["confidence"][
                        "trust_adjusted_score"
                    ],
                },
                "source_count": len(detail["records"]),
                "sources": [
                    {
                        "source_code": r["source_code"],
                        "source_name": r["source_name"],
                        "reliability": r["reliability"],
                    }
                    for r in detail["records"]
                ],
                "time_delta_human": detail["time_comparison"]["delta_human"],
                "conflict_field_count": sum(
                    1 for f in detail["field_diff"] if f["conflict"]
                ),
                "created_at": detail["created_at"],
                "resolved_at": detail["resolved_at"],
                "resolved_by": detail["resolved_by"],
                "canonical_event_id": detail["canonical_event_id"],
            }
        )
    return summaries


ALLOWED_ACTIONS: dict[str, list[str]] = {
    "pending": ["keep", "split", "unknown"],
    "unknown": ["keep", "split", "reopen"],
    "merged": ["reopen"],
    "split": ["reopen"],
}


def get_candidate_detail(conn: sqlite3.Connection, candidate_id: str) -> dict[str, Any]:
    row = conn.execute(
        "SELECT * FROM merge_candidates WHERE id = ?", (candidate_id,)
    ).fetchone()
    if row is None:
        raise NotFoundError(f"候选合并组不存在: {candidate_id}")
    cand = dict(row)

    member_rows = conn.execute(
        """
        SELECT record_id FROM candidate_records
        WHERE candidate_id = ? ORDER BY position, rowid
        """,
        (candidate_id,),
    ).fetchall()
    record_ids = [r["record_id"] for r in member_rows]
    records = [get_record(conn, rid) for rid in record_ids]
    views = [build_view(r) for r in records]

    confidence = logic.score_match(views) if views else _json_loads(
        cand.get("confidence_json"), {}
    )
    time_comparison = logic.build_time_comparison(views)
    field_diff = logic.build_field_diff(views)

    canonical_event = None
    if cand.get("canonical_event_id"):
        canonical_event = get_timeline_event(conn, cand["canonical_event_id"])
    result_events = list_events_for_candidate(conn, candidate_id)

    return {
        "id": cand["id"],
        "incident_id": cand["incident_id"],
        "status": cand["status"],
        "user_id": records[0]["user_id"] if records else None,
        "event_type": records[0]["event_type"] if records else None,
        "confidence": confidence,
        "time_comparison": time_comparison,
        "field_diff": field_diff,
        "records": records,
        "record_ids": record_ids,
        "resolution": _json_loads(cand.get("resolution_json"), None),
        "resolution_note": cand.get("resolution_note"),
        "canonical_event_id": cand.get("canonical_event_id"),
        "canonical_event": canonical_event,
        "events": [
            {
                "id": e["id"],
                "title": e["title"],
                "event_time": e["event_time"],
                "resolution": e["resolution"],
                "record_ids": e["record_ids"],
                "record_count": len(e["record_ids"]),
            }
            for e in result_events
        ],
        "allowed_actions": ALLOWED_ACTIONS.get(cand["status"], []),
        "created_at": cand["created_at"],
        "resolved_at": cand.get("resolved_at"),
        "resolved_by": cand.get("resolved_by"),
    }


def list_review_actions(
    conn: sqlite3.Connection, candidate_id: str
) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM review_actions WHERE candidate_id = ? ORDER BY id",
        (candidate_id,),
    ).fetchall()
    result = []
    for row in rows:
        item = dict(row)
        item["detail"] = _json_loads(item.pop("detail_json", None), None)
        result.append(item)
    return result


def _record_action(
    conn: sqlite3.Connection,
    candidate_id: str,
    action: str,
    analyst: str | None,
    detail: dict[str, Any] | None,
) -> None:
    conn.execute(
        """
        INSERT INTO review_actions (candidate_id, action, analyst, detail_json, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (candidate_id, action, analyst, _json_dumps(detail or {}), now_iso()),
    )


EVENT_TYPE_LABELS = {"user_login": "用户登录"}


def _event_label(event_type: str) -> str:
    return EVENT_TYPE_LABELS.get(event_type, event_type)


def _load_members(
    conn: sqlite3.Connection, candidate_id: str
) -> tuple[sqlite3.Row, list[str], list[dict[str, Any]], list[dict[str, Any]]]:
    row = conn.execute(
        "SELECT * FROM merge_candidates WHERE id = ?", (candidate_id,)
    ).fetchone()
    if row is None:
        raise NotFoundError(f"候选合并组不存在: {candidate_id}")
    member_rows = conn.execute(
        "SELECT record_id FROM candidate_records WHERE candidate_id = ? ORDER BY position, rowid",
        (candidate_id,),
    ).fetchall()
    record_ids = [r["record_id"] for r in member_rows]
    views = get_views(conn, record_ids)
    field_diff = logic.build_field_diff(views)
    return row, record_ids, views, field_diff


def _create_timeline_event(
    conn: sqlite3.Connection,
    *,
    incident_id: str | None,
    event_type: str,
    user_id: str,
    title: str,
    event_time: str,
    time_basis: str | None,
    resolution: str,
    candidate_id: str | None,
    canonical_fields: dict[str, Any],
    field_sources: dict[str, str],
    record_ids: Sequence[str],
) -> str:
    event_id = new_id("evt_")
    conn.execute(
        """
        INSERT INTO timeline_events
            (id, incident_id, event_type, user_id, title, event_time, time_basis,
             resolution, candidate_id, canonical_fields_json, field_sources_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event_id,
            incident_id,
            event_type,
            user_id,
            title,
            logic.to_utc_iso(event_time),
            time_basis,
            resolution,
            candidate_id,
            _json_dumps(canonical_fields),
            _json_dumps(field_sources),
            now_iso(),
        ),
    )
    conn.executemany(
        "INSERT INTO timeline_event_records (event_id, record_id) VALUES (?, ?)",
        [(event_id, rid) for rid in record_ids],
    )
    return event_id


def keep_candidate(
    conn: sqlite3.Connection,
    candidate_id: str,
    *,
    analyst: str = "analyst",
    note: str | None = None,
    title: str | None = None,
    canonical_time: str | None = None,
    time_source_record_id: str | None = None,
    field_sources: dict[str, str] | None = None,
    canonical_fields: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """保留并合并：all raw records become one canonical timeline event."""

    cand, record_ids, views, field_diff = _load_members(conn, candidate_id)
    if cand["status"] not in {"pending", "unknown"}:
        raise ConflictError(
            f"候选当前状态为 {cand['status']}，请先重新打开再执行保留/合并",
            details={"status": cand["status"]},
        )

    values, sources = logic.choose_canonical_values(field_diff, views)
    records_by_id = {rid: get_record(conn, rid) for rid in record_ids}

    # Analyst picks a value for a field by naming the source record.
    for field_name, source_record_id in (field_sources or {}).items():
        if source_record_id not in records_by_id:
            raise ValidationError(
                f"field_sources[{field_name}] 指向了不属于该候选组的记录: {source_record_id}"
            )
        source_view = build_view(records_by_id[source_record_id])
        source_fields = source_view["fields"]
        if field_name not in source_fields:
            raise ValidationError(
                f"来源记录 {source_record_id} 未提供字段 {field_name}"
            )
        values[field_name] = source_fields[field_name]
        sources[field_name] = source_record_id

    # Analyst supplies literal canonical values (highest override priority).
    for field_name, literal in (canonical_fields or {}).items():
        values[field_name] = literal
        sources[field_name] = "analyst"

    # Explicit time source / literal time stay easy to target from the UI.
    if time_source_record_id:
        if time_source_record_id not in records_by_id:
            raise ValidationError("time_source_record_id 不属于该候选组")
        chosen_time = records_by_id[time_source_record_id]["occurred_at"]
        values["occurred_at"] = chosen_time
        sources["occurred_at"] = time_source_record_id
    if canonical_time:
        try:
            values["occurred_at"] = logic.to_utc_iso(canonical_time)
        except (ValueError, TypeError) as exc:
            raise ValidationError(f"无法解析 canonical_time: {exc}") from exc
        sources["occurred_at"] = "analyst"

    user_id = views[0]["user_id"]
    source_count = len(record_ids)
    event_title = title or (
        f"{_event_label(views[0]['event_type'])} · {user_id}（合并 {source_count} 个来源）"
    )
    event_time = logic.to_utc_iso(values.get("occurred_at") or views[0]["occurred_at"])

    event_id = _create_timeline_event(
        conn,
        incident_id=cand["incident_id"],
        event_type=views[0]["event_type"],
        user_id=user_id,
        title=event_title,
        event_time=event_time,
        time_basis=sources.get("occurred_at"),
        resolution="merged",
        candidate_id=candidate_id,
        canonical_fields=values,
        field_sources=sources,
        record_ids=record_ids,
    )

    resolution = {
        "decision": "keep",
        "canonical_event_id": event_id,
        "time_basis": sources.get("occurred_at"),
        "field_sources": sources,
        "note": note,
    }
    conn.execute(
        """
        UPDATE merge_candidates
        SET status='merged', resolved_at=?, resolved_by=?, resolution_note=?,
            resolution_json=?, canonical_event_id=?
        WHERE id=?
        """,
        (now_iso(), analyst, note, _json_dumps(resolution), event_id, candidate_id),
    )
    _record_action(
        conn,
        candidate_id,
        "keep",
        analyst,
        {"event_id": event_id, "note": note, "time_basis": sources.get("occurred_at")},
    )
    conn.commit()
    return get_candidate_detail(conn, candidate_id)


def split_candidate(
    conn: sqlite3.Connection,
    candidate_id: str,
    *,
    analyst: str = "analyst",
    note: str | None = None,
    groups: Sequence[Sequence[str]] | None = None,
) -> dict[str, Any]:
    """拆分：each group becomes its own timeline event.

    With no explicit ``groups`` every raw source record becomes a separate
    event (the common two-system conflict case).
    """

    cand, record_ids, _views, _diff = _load_members(conn, candidate_id)
    if cand["status"] not in {"pending", "unknown"}:
        raise ConflictError(
            f"候选当前状态为 {cand['status']}，请先重新打开再执行拆分",
            details={"status": cand["status"]},
        )

    if groups is None:
        partition: list[list[str]] = [[rid] for rid in record_ids]
    else:
        partition = [list(group) for group in groups if group]

    flat = [rid for group in partition for rid in group]
    if sorted(flat) != sorted(record_ids) or len(flat) != len(set(flat)):
        raise ValidationError(
            "groups 必须是对候选组全部记录的完整且不重复的划分",
            details={"expected": record_ids, "received": flat},
        )

    event_ids: list[str] = []
    group_descriptions: list[list[str]] = []
    for group_ids in partition:
        group_views = get_views(conn, group_ids)
        group_diff = logic.build_field_diff(group_views)
        values, sources = logic.choose_canonical_values(group_diff, group_views)
        event_time = logic.to_utc_iso(
            values.get("occurred_at") or group_views[0]["occurred_at"]
        )
        source_names = " / ".join(
            sorted({v.get("source_name") or v["source_code"] for v in group_views})
        )
        if len(group_ids) == 1:
            title = (
                f"{_event_label(group_views[0]['event_type'])} · "
                f"{group_views[0]['user_id']}（{source_names}）"
            )
        else:
            title = (
                f"{_event_label(group_views[0]['event_type'])} · "
                f"{group_views[0]['user_id']}（拆分组 {len(group_ids)} 条记录）"
            )
        event_id = _create_timeline_event(
            conn,
            incident_id=cand["incident_id"],
            event_type=group_views[0]["event_type"],
            user_id=group_views[0]["user_id"],
            title=title,
            event_time=event_time,
            time_basis=sources.get("occurred_at"),
            resolution="split",
            candidate_id=candidate_id,
            canonical_fields=values,
            field_sources=sources,
            record_ids=group_ids,
        )
        event_ids.append(event_id)
        group_descriptions.append(list(group_ids))

    resolution = {
        "decision": "split",
        "groups": group_descriptions,
        "event_ids": event_ids,
        "note": note,
    }
    conn.execute(
        """
        UPDATE merge_candidates
        SET status='split', resolved_at=?, resolved_by=?, resolution_note=?,
            resolution_json=?, canonical_event_id=NULL
        WHERE id=?
        """,
        (now_iso(), analyst, note, _json_dumps(resolution), candidate_id),
    )
    _record_action(
        conn,
        candidate_id,
        "split",
        analyst,
        {"event_ids": event_ids, "groups": group_descriptions, "note": note},
    )
    conn.commit()
    return get_candidate_detail(conn, candidate_id)


def mark_unknown(
    conn: sqlite3.Connection,
    candidate_id: str,
    *,
    analyst: str = "analyst",
    note: str | None = None,
) -> dict[str, Any]:
    """标记未知：no canonical event is asserted; records stay available."""

    cand = conn.execute(
        "SELECT id, status, incident_id FROM merge_candidates WHERE id = ?",
        (candidate_id,),
    ).fetchone()
    if cand is None:
        raise NotFoundError(f"候选合并组不存在: {candidate_id}")
    if cand["status"] != "pending":
        raise ConflictError(
            f"候选当前状态为 {cand['status']}，无法直接标记未知；如已处置请先重新打开",
            details={"status": cand["status"]},
        )

    resolution = {"decision": "unknown", "note": note}
    conn.execute(
        """
        UPDATE merge_candidates
        SET status='unknown', resolved_at=?, resolved_by=?, resolution_note=?,
            resolution_json=?
        WHERE id=?
        """,
        (now_iso(), analyst, note, _json_dumps(resolution), candidate_id),
    )
    _record_action(conn, candidate_id, "unknown", analyst, {"note": note})
    conn.commit()
    return get_candidate_detail(conn, candidate_id)


def reopen_candidate(
    conn: sqlite3.Connection,
    candidate_id: str,
    *,
    analyst: str = "analyst",
    note: str | None = None,
) -> dict[str, Any]:
    """Undo a derived resolution.

    Only derived timeline events are deleted; ``source_records`` and
    ``candidate_records`` are never touched, so no original is lost.
    """

    cand = conn.execute(
        "SELECT id, status FROM merge_candidates WHERE id = ?", (candidate_id,)
    ).fetchone()
    if cand is None:
        raise NotFoundError(f"候选合并组不存在: {candidate_id}")
    if cand["status"] == "pending":
        raise ConflictError("候选已处于待处理状态，无需重新打开")

    conn.execute("DELETE FROM timeline_events WHERE candidate_id = ?", (candidate_id,))
    conn.execute(
        """
        UPDATE merge_candidates
        SET status='pending', resolved_at=NULL, resolved_by=NULL,
            resolution_note=NULL, resolution_json=NULL, canonical_event_id=NULL
        WHERE id=?
        """,
        (candidate_id,),
    )
    _record_action(conn, candidate_id, "reopen", analyst, {"note": note})
    conn.commit()
    return get_candidate_detail(conn, candidate_id)


# ---------------------------------------------------------------------------
# Timeline events
# ---------------------------------------------------------------------------


def _linked_record_ids(conn: sqlite3.Connection, event_id: str) -> list[str]:
    rows = conn.execute(
        "SELECT record_id FROM timeline_event_records WHERE event_id = ? ORDER BY rowid",
        (event_id,),
    ).fetchall()
    return [r["record_id"] for r in rows]


def list_events_for_candidate(
    conn: sqlite3.Connection, candidate_id: str
) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT id FROM timeline_events WHERE candidate_id = ? ORDER BY event_time",
        (candidate_id,),
    ).fetchall()
    return [get_timeline_event(conn, row["id"]) for row in rows]


def list_timeline_events(
    conn: sqlite3.Connection, *, incident_id: str | None = None
) -> list[dict[str, Any]]:
    if incident_id:
        rows = conn.execute(
            "SELECT * FROM timeline_events WHERE incident_id = ? ORDER BY event_time ASC",
            (incident_id,),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM timeline_events ORDER BY event_time ASC"
        ).fetchall()

    events: list[dict[str, Any]] = []
    for row in rows:
        record_ids = _linked_record_ids(conn, row["id"])
        originals = [get_record(conn, rid) for rid in record_ids]
        events.append(
            {
                "id": row["id"],
                "incident_id": row["incident_id"],
                "event_type": row["event_type"],
                "user_id": row["user_id"],
                "title": row["title"],
                "event_time": row["event_time"],
                "time_basis": row["time_basis"],
                "resolution": row["resolution"],
                "candidate_id": row["candidate_id"],
                "record_count": len(record_ids),
                "record_ids": record_ids,
                "sources": [
                    {
                        "record_id": r["id"],
                        "source_code": r["source_code"],
                        "source_name": r["source_name"],
                        "reliability": r["reliability"],
                        "source_time": r["occurred_at"],
                    }
                    for r in originals
                ],
                "created_at": row["created_at"],
            }
        )
    return events


def get_timeline_event(conn: sqlite3.Connection, event_id: str) -> dict[str, Any]:
    row = conn.execute(
        "SELECT * FROM timeline_events WHERE id = ?", (event_id,)
    ).fetchone()
    if row is None:
        raise NotFoundError(f"时间线事件不存在: {event_id}")
    event = dict(row)

    record_ids = _linked_record_ids(conn, event_id)
    originals = [get_record(conn, rid) for rid in record_ids]
    views = [build_view(r) for r in originals]

    event["canonical_fields"] = _json_loads(event.pop("canonical_fields_json", "{}"), {})
    event["field_sources"] = _json_loads(event.pop("field_sources_json", "{}"), {})
    event["record_ids"] = record_ids
    # Full, byte-faithful raw records — the preservation guarantee.
    event["originals"] = originals
    event["time_comparison"] = logic.build_time_comparison(views) if views else None
    event["field_diff"] = logic.build_field_diff(views) if views else []
    return event


def list_originals_for_event(
    conn: sqlite3.Connection, event_id: str
) -> list[dict[str, Any]]:
    # Raises NotFound if the event does not exist.
    get_timeline_event(conn, event_id)
    record_ids = _linked_record_ids(conn, event_id)
    return [get_record(conn, rid) for rid in record_ids]
