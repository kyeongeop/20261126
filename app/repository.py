from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from app.custody import (
    GENESIS_HASH,
    HASH_ALGORITHM,
    canonical_json,
    event_hash,
    event_payload,
    sha256_bytes,
    utc_now,
    verify_evidence,
    version_digest,
    version_manifest,
)
from app.db import transaction
from app.errors import DomainError


@dataclass(frozen=True)
class OperationContext:
    actor: str
    source: str
    source_ip: str
    user_agent: str
    request_method: str
    request_path: str


def _version_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "version_number": row["version_number"],
        "filename": row["filename"],
        "content_type": row["content_type"],
        "size_bytes": row["size_bytes"],
        "content_sha256": row["content_sha256"],
        "version_digest": row["version_digest"],
        "previous_version_digest": row["previous_version_digest"],
        "created_at": row["created_at"],
        "created_by": row["created_by"],
    }


def _event_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "case_id": row["case_id"],
        "evidence_id": row["evidence_id"],
        "sequence": row["sequence"],
        "action": row["action"],
        "actor": row["actor"],
        "occurred_at": row["occurred_at"],
        "source": row["source"],
        "source_ip": row["source_ip"],
        "user_agent": row["user_agent"],
        "request_method": row["request_method"],
        "request_path": row["request_path"],
        "version_number": row["version_number"],
        "version_id": row["version_id"],
        "version_digest": row["version_digest"],
        "details": json.loads(row["details"]),
        "previous_hash": row["previous_hash"],
        "record_hash": row["record_hash"],
    }


def _case_dict(connection: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
    count = connection.execute(
        "SELECT COUNT(*) FROM evidence WHERE case_id = ?",
        (row["id"],),
    ).fetchone()[0]
    return {
        "id": row["id"],
        "title": row["title"],
        "created_at": row["created_at"],
        "created_by": row["created_by"],
        "evidence_count": count,
    }


def _get_case_row(connection: sqlite3.Connection, case_id: str) -> sqlite3.Row:
    row = connection.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
    if row is None:
        raise DomainError(404, "case not found")
    return row


def _get_evidence_row(
    connection: sqlite3.Connection, case_id: str, evidence_id: str
) -> sqlite3.Row:
    row = connection.execute(
        "SELECT * FROM evidence WHERE id = ? AND case_id = ?",
        (evidence_id, case_id),
    ).fetchone()
    if row is None:
        raise DomainError(404, "evidence not found")
    return row


def _evidence_dict(connection: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
    versions = connection.execute(
        """
        SELECT * FROM evidence_versions
        WHERE evidence_id = ?
        ORDER BY version_number
        """,
        (row["id"],),
    ).fetchall()
    if not versions:
        raise DomainError(500, "evidence has no stored version")
    current = next(
        (
            version
            for version in versions
            if version["version_number"] == row["current_version_number"]
        ),
        versions[-1],
    )
    custody = connection.execute(
        """
        SELECT record_hash
        FROM custody_events
        WHERE evidence_id = ?
        ORDER BY sequence DESC
        LIMIT 1
        """,
        (row["id"],),
    ).fetchone()
    event_count = connection.execute(
        "SELECT COUNT(*) FROM custody_events WHERE evidence_id = ?",
        (row["id"],),
    ).fetchone()[0]
    return {
        "id": row["id"],
        "case_id": row["case_id"],
        "name": row["display_name"],
        "status": row["status"],
        "current_version_number": row["current_version_number"],
        "current_version": _version_dict(current),
        "versions": [_version_dict(version) for version in versions],
        "created_at": row["created_at"],
        "created_by": row["created_by"],
        "updated_at": row["updated_at"],
        "custody": {
            "event_count": event_count,
            "chain_head": (
                custody["record_hash"]
                if custody is not None and custody["record_hash"]
                else GENESIS_HASH
            ),
            "hash_algorithm": HASH_ALGORITHM,
        },
    }


def create_case(
    connection: sqlite3.Connection,
    *,
    title: str,
    context: OperationContext,
) -> dict[str, Any]:
    case_id = str(uuid4())
    now = utc_now()
    with transaction(connection):
        connection.execute(
            "INSERT INTO cases (id, title, created_at, created_by) VALUES (?, ?, ?, ?)",
            (case_id, title.strip(), now, context.actor),
        )
    return _case_dict(connection, _get_case_row(connection, case_id))


def list_cases(connection: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = connection.execute("SELECT * FROM cases ORDER BY created_at, id").fetchall()
    return [_case_dict(connection, row) for row in rows]


def get_case(connection: sqlite3.Connection, case_id: str) -> dict[str, Any]:
    return _case_dict(connection, _get_case_row(connection, case_id))


def list_evidence(
    connection: sqlite3.Connection,
    *,
    case_id: str,
    include_voided: bool = False,
) -> list[dict[str, Any]]:
    _get_case_row(connection, case_id)
    sql = "SELECT * FROM evidence WHERE case_id = ?"
    parameters: list[Any] = [case_id]
    if not include_voided:
        sql += " AND status = 'active'"
    sql += " ORDER BY created_at, id"
    rows = connection.execute(sql, parameters).fetchall()
    return [_evidence_dict(connection, row) for row in rows]


def get_evidence(
    connection: sqlite3.Connection, *, case_id: str, evidence_id: str
) -> dict[str, Any]:
    return _evidence_dict(
        connection, _get_evidence_row(connection, case_id, evidence_id)
    )


def _insert_version(
    connection: sqlite3.Connection,
    *,
    evidence_id: str,
    version_number: int,
    filename: str,
    content_type: str,
    content: bytes,
    previous_version_digest: str | None,
    created_at: str,
    actor: str,
) -> sqlite3.Row:
    version_id = str(uuid4())
    content_sha256 = sha256_bytes(content)
    manifest = version_manifest(
        evidence_id=evidence_id,
        version_number=version_number,
        filename=filename,
        content_type=content_type,
        size_bytes=len(content),
        content_sha256=content_sha256,
        previous_version_digest=previous_version_digest,
        created_at=created_at,
        created_by=actor,
    )
    digest = version_digest(manifest)
    connection.execute(
        """
        INSERT INTO evidence_versions (
            id, evidence_id, version_number, filename, content_type,
            size_bytes, content_sha256, version_digest,
            previous_version_digest, content, created_at, created_by
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            version_id,
            evidence_id,
            version_number,
            filename,
            content_type,
            len(content),
            content_sha256,
            digest,
            previous_version_digest,
            content,
            created_at,
            actor,
        ),
    )
    return connection.execute(
        "SELECT * FROM evidence_versions WHERE id = ?", (version_id,)
    ).fetchone()


def _append_event(
    connection: sqlite3.Connection,
    *,
    case_id: str,
    evidence_id: str,
    action: str,
    context: OperationContext,
    version: sqlite3.Row,
    details: dict[str, Any],
    occurred_at: str | None = None,
) -> dict[str, Any]:
    sequence = connection.execute(
        """
        SELECT COALESCE(MAX(sequence), 0) + 1
        FROM custody_events WHERE evidence_id = ?
        """,
        (evidence_id,),
    ).fetchone()[0]
    previous = connection.execute(
        """
        SELECT record_hash FROM custody_events
        WHERE evidence_id = ? ORDER BY sequence DESC LIMIT 1
        """,
        (evidence_id,),
    ).fetchone()
    previous_hash = previous["record_hash"] if previous else GENESIS_HASH
    timestamp = occurred_at or utc_now()
    record = {
        "id": str(uuid4()),
        "case_id": case_id,
        "evidence_id": evidence_id,
        "sequence": sequence,
        "action": action,
        "actor": context.actor,
        "occurred_at": timestamp,
        "source": context.source,
        "source_ip": context.source_ip,
        "user_agent": context.user_agent,
        "request_method": context.request_method,
        "request_path": context.request_path,
        "version_number": version["version_number"],
        "version_id": version["id"],
        "version_digest": version["version_digest"],
        "details": details,
    }
    digest = event_hash(previous_hash, event_payload(record))
    connection.execute(
        """
        INSERT INTO custody_events (
            id, case_id, evidence_id, sequence, action, actor, occurred_at,
            source, source_ip, user_agent, request_method, request_path,
            version_number, version_id, version_digest, details,
            previous_hash, record_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            record["id"],
            case_id,
            evidence_id,
            sequence,
            action,
            context.actor,
            timestamp,
            context.source,
            context.source_ip,
            context.user_agent,
            context.request_method,
            context.request_path,
            version["version_number"],
            version["id"],
            version["version_digest"],
            canonical_json(details),
            previous_hash,
            digest,
        ),
    )
    return _event_dict(
        connection.execute(
            "SELECT * FROM custody_events WHERE id = ?", (record["id"],)
        ).fetchone()
    )


def upload_evidence(
    connection: sqlite3.Connection,
    *,
    case_id: str,
    display_name: str,
    filename: str,
    content_type: str,
    content: bytes,
    context: OperationContext,
) -> dict[str, Any]:
    evidence_id = str(uuid4())
    now = utc_now()
    with transaction(connection):
        _get_case_row(connection, case_id)
        connection.execute(
            """
            INSERT INTO evidence (
                id, case_id, display_name, status, current_version_number,
                created_at, created_by, updated_at
            ) VALUES (?, ?, ?, 'active', 1, ?, ?, ?)
            """,
            (evidence_id, case_id, display_name, now, context.actor, now),
        )
        version = _insert_version(
            connection,
            evidence_id=evidence_id,
            version_number=1,
            filename=filename,
            content_type=content_type,
            content=content,
            previous_version_digest=None,
            created_at=now,
            actor=context.actor,
        )
        _append_event(
            connection,
            case_id=case_id,
            evidence_id=evidence_id,
            action="UPLOAD",
            context=context,
            version=version,
            details={
                "display_name": display_name,
                "filename": filename,
                "size_bytes": len(content),
                "content_sha256": version["content_sha256"],
            },
            occurred_at=now,
        )
    return _evidence_dict(
        connection, _get_evidence_row(connection, case_id, evidence_id)
    )


def replace_evidence(
    connection: sqlite3.Connection,
    *,
    case_id: str,
    evidence_id: str,
    filename: str,
    content_type: str,
    content: bytes,
    context: OperationContext,
) -> dict[str, Any]:
    now = utc_now()
    with transaction(connection):
        evidence = _get_evidence_row(connection, case_id, evidence_id)
        if evidence["status"] != "active":
            raise DomainError(409, "voided evidence cannot be replaced")
        previous = connection.execute(
            """
            SELECT * FROM evidence_versions
            WHERE evidence_id = ? ORDER BY version_number DESC LIMIT 1
            """,
            (evidence_id,),
        ).fetchone()
        next_number = previous["version_number"] + 1
        version = _insert_version(
            connection,
            evidence_id=evidence_id,
            version_number=next_number,
            filename=filename,
            content_type=content_type,
            content=content,
            previous_version_digest=previous["version_digest"],
            created_at=now,
            actor=context.actor,
        )
        connection.execute(
            """
            UPDATE evidence
            SET current_version_number = ?, updated_at = ?
            WHERE id = ? AND case_id = ?
            """,
            (next_number, now, evidence_id, case_id),
        )
        _append_event(
            connection,
            case_id=case_id,
            evidence_id=evidence_id,
            action="REPLACE",
            context=context,
            version=version,
            details={
                "filename": filename,
                "size_bytes": len(content),
                "content_sha256": version["content_sha256"],
                "previous_version_number": previous["version_number"],
                "previous_version_digest": previous["version_digest"],
            },
            occurred_at=now,
        )
    return _evidence_dict(
        connection, _get_evidence_row(connection, case_id, evidence_id)
    )


def _get_version_row(
    connection: sqlite3.Connection,
    *,
    evidence_id: str,
    version_number: int,
) -> sqlite3.Row:
    row = connection.execute(
        """
        SELECT * FROM evidence_versions
        WHERE evidence_id = ? AND version_number = ?
        """,
        (evidence_id, version_number),
    ).fetchone()
    if row is None:
        raise DomainError(404, "evidence version not found")
    return row


def record_view(
    connection: sqlite3.Connection,
    *,
    case_id: str,
    evidence_id: str,
    version_number: int,
    context: OperationContext,
) -> dict[str, Any]:
    with transaction(connection):
        _get_evidence_row(connection, case_id, evidence_id)
        version = _get_version_row(
            connection,
            evidence_id=evidence_id,
            version_number=version_number,
        )
        _append_event(
            connection,
            case_id=case_id,
            evidence_id=evidence_id,
            action="VIEW",
            context=context,
            version=version,
            details={"version_number": version_number},
        )
    return _evidence_dict(
        connection, _get_evidence_row(connection, case_id, evidence_id)
    )


def export_evidence(
    connection: sqlite3.Connection,
    *,
    case_id: str,
    evidence_id: str,
    version_number: int | None,
    context: OperationContext,
) -> dict[str, Any]:
    with transaction(connection):
        evidence = _get_evidence_row(connection, case_id, evidence_id)
        selected_number = version_number or evidence["current_version_number"]
        version = _get_version_row(
            connection,
            evidence_id=evidence_id,
            version_number=selected_number,
        )
        event = _append_event(
            connection,
            case_id=case_id,
            evidence_id=evidence_id,
            action="EXPORT",
            context=context,
            version=version,
            details={
                "version_number": selected_number,
                "evidence_status": evidence["status"],
            },
        )
    return {
        "content": bytes(version["content"]),
        "filename": version["filename"],
        "content_type": version["content_type"],
        "version_number": selected_number,
        "content_sha256": version["content_sha256"],
        "version_digest": version["version_digest"],
        "record_hash": event["record_hash"],
        "evidence_status": evidence["status"],
    }


def rename_evidence(
    connection: sqlite3.Connection,
    *,
    case_id: str,
    evidence_id: str,
    new_name: str,
    context: OperationContext,
) -> dict[str, Any]:
    now = utc_now()
    with transaction(connection):
        evidence = _get_evidence_row(connection, case_id, evidence_id)
        if evidence["status"] != "active":
            raise DomainError(409, "voided evidence cannot be renamed")
        if evidence["display_name"] == new_name:
            raise DomainError(409, "new evidence name must differ from current name")
        connection.execute(
            "UPDATE evidence SET display_name = ?, updated_at = ? WHERE id = ?",
            (new_name, now, evidence_id),
        )
        version = _get_version_row(
            connection,
            evidence_id=evidence_id,
            version_number=evidence["current_version_number"],
        )
        _append_event(
            connection,
            case_id=case_id,
            evidence_id=evidence_id,
            action="RENAME",
            context=context,
            version=version,
            details={
                "old_name": evidence["display_name"],
                "new_name": new_name,
                "version_number": version["version_number"],
            },
            occurred_at=now,
        )
    return _evidence_dict(
        connection, _get_evidence_row(connection, case_id, evidence_id)
    )


def void_evidence(
    connection: sqlite3.Connection,
    *,
    case_id: str,
    evidence_id: str,
    reason: str,
    context: OperationContext,
) -> dict[str, Any]:
    now = utc_now()
    with transaction(connection):
        evidence = _get_evidence_row(connection, case_id, evidence_id)
        if evidence["status"] == "voided":
            raise DomainError(409, "evidence is already voided")
        connection.execute(
            """
            UPDATE evidence
            SET status = 'voided', updated_at = ?
            WHERE id = ? AND case_id = ?
            """,
            (now, evidence_id, case_id),
        )
        version = _get_version_row(
            connection,
            evidence_id=evidence_id,
            version_number=evidence["current_version_number"],
        )
        _append_event(
            connection,
            case_id=case_id,
            evidence_id=evidence_id,
            action="DELETE",
            context=context,
            version=version,
            details={
                "effect": "voided",
                "reason": reason.strip(),
                "preserved_versions": evidence["current_version_number"],
            },
            occurred_at=now,
        )
    return _evidence_dict(
        connection, _get_evidence_row(connection, case_id, evidence_id)
    )


def list_custody_events(
    connection: sqlite3.Connection,
    *,
    case_id: str,
    evidence_id: str,
    action: str | None = None,
) -> list[dict[str, Any]]:
    _get_evidence_row(connection, case_id, evidence_id)
    sql = "SELECT * FROM custody_events WHERE case_id = ? AND evidence_id = ?"
    parameters: list[Any] = [case_id, evidence_id]
    if action:
        sql += " AND action = ?"
        parameters.append(action)
    sql += " ORDER BY sequence"
    return [_event_dict(row) for row in connection.execute(sql, parameters).fetchall()]


def verify_evidence_chain(
    connection: sqlite3.Connection, *, case_id: str, evidence_id: str
) -> dict[str, Any]:
    _get_evidence_row(connection, case_id, evidence_id)
    return verify_evidence(
        connection,
        case_id=case_id,
        evidence_id=evidence_id,
    )


def case_timeline(
    connection: sqlite3.Connection,
    *,
    case_id: str,
    include_voided: bool = True,
) -> list[dict[str, Any]]:
    _get_case_row(connection, case_id)
    sql = """
        SELECT event.*
        FROM custody_events AS event
        JOIN evidence AS item ON item.id = event.evidence_id
        WHERE event.case_id = ?
    """
    parameters: list[Any] = [case_id]
    if not include_voided:
        sql += " AND item.status = 'active'"
    sql += " ORDER BY event.occurred_at, event.sequence, event.id"
    return [_event_dict(row) for row in connection.execute(sql, parameters).fetchall()]
