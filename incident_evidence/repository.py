from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

from .db import connect, row_to_event, row_to_incident, row_to_raw_file, transaction
from .timeutil import utc_now_iso


class NotFoundError(LookupError):
    pass


class InvalidReferenceError(ValueError):
    pass


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def create_incident(
    db_path: Path,
    *,
    title: str,
    description: str,
    source_config: dict[str, Any],
) -> dict[str, Any]:
    incident_id = _new_id("inc")
    created_at = utc_now_iso()
    with transaction(db_path) as connection:
        connection.execute(
            """
            INSERT INTO incidents (id, title, description, source_config_json, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                incident_id,
                title,
                description,
                json.dumps(source_config, ensure_ascii=False, sort_keys=True),
                created_at,
            ),
        )
    return {
        "id": incident_id,
        "title": title,
        "description": description,
        "source_config": source_config,
        "created_at": created_at,
    }


def list_incidents(db_path: Path) -> list[dict[str, Any]]:
    with connect(db_path) as connection:
        rows = connection.execute(
            "SELECT * FROM incidents ORDER BY created_at DESC, id"
        ).fetchall()
    return [row_to_incident(row) for row in rows]


def get_incident(db_path: Path, incident_id: str) -> dict[str, Any]:
    with connect(db_path) as connection:
        row = connection.execute(
            "SELECT * FROM incidents WHERE id = ?", (incident_id,)
        ).fetchone()
    if row is None:
        raise NotFoundError(f"incident {incident_id} was not found")
    return row_to_incident(row)


def create_event(
    db_path: Path,
    incident_id: str,
    *,
    occurred_at: str,
    title: str,
    description: str,
    source: str,
    actor: str,
    artifact_ids: list[str],
) -> dict[str, Any]:
    event_id = _new_id("evt")
    created_at = utc_now_iso()
    unique_artifact_ids = list(dict.fromkeys(artifact_ids))
    with transaction(db_path) as connection:
        incident = connection.execute(
            "SELECT id FROM incidents WHERE id = ?", (incident_id,)
        ).fetchone()
        if incident is None:
            raise NotFoundError(f"incident {incident_id} was not found")
        if unique_artifact_ids:
            placeholders = ",".join("?" for _ in unique_artifact_ids)
            rows = connection.execute(
                f"""
                SELECT id FROM raw_files
                WHERE incident_id = ? AND id IN ({placeholders})
                """,
                (incident_id, *unique_artifact_ids),
            ).fetchall()
            found = {row["id"] for row in rows}
            missing = [item for item in unique_artifact_ids if item not in found]
            if missing:
                raise InvalidReferenceError(
                    "artifact ids do not belong to this incident: "
                    + ", ".join(missing)
                )
        connection.execute(
            """
            INSERT INTO events (
                id, incident_id, occurred_at, title, description, source,
                actor, artifact_ids_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                incident_id,
                occurred_at,
                title,
                description,
                source,
                actor,
                json.dumps(unique_artifact_ids),
                created_at,
            ),
        )
    return {
        "id": event_id,
        "incident_id": incident_id,
        "occurred_at": occurred_at,
        "title": title,
        "description": description,
        "source": source,
        "actor": actor,
        "artifact_ids": unique_artifact_ids,
        "created_at": created_at,
    }


def list_events(db_path: Path, incident_id: str) -> list[dict[str, Any]]:
    get_incident(db_path, incident_id)
    with connect(db_path) as connection:
        rows = connection.execute(
            """
            SELECT * FROM events
            WHERE incident_id = ?
            ORDER BY occurred_at, created_at, id
            """,
            (incident_id,),
        ).fetchall()
    return [row_to_event(row) for row in rows]


def create_raw_file(
    db_path: Path,
    incident_id: str,
    *,
    original_name: str,
    storage_path: str,
    media_type: str,
    source: str,
    description: str,
    captured_at: str | None,
    sha256: str,
    size_bytes: int,
) -> dict[str, Any]:
    file_id = _new_id("raw")
    created_at = utc_now_iso()
    with transaction(db_path) as connection:
        incident = connection.execute(
            "SELECT id FROM incidents WHERE id = ?", (incident_id,)
        ).fetchone()
        if incident is None:
            raise NotFoundError(f"incident {incident_id} was not found")
        connection.execute(
            """
            INSERT INTO raw_files (
                id, incident_id, original_name, storage_path, media_type,
                source, description, captured_at, sha256, size_bytes, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                file_id,
                incident_id,
                original_name,
                storage_path,
                media_type,
                source,
                description,
                captured_at,
                sha256,
                size_bytes,
                created_at,
            ),
        )
    return {
        "id": file_id,
        "incident_id": incident_id,
        "original_name": original_name,
        "storage_path": storage_path,
        "media_type": media_type,
        "source": source,
        "description": description,
        "captured_at": captured_at,
        "sha256": sha256,
        "size_bytes": size_bytes,
        "created_at": created_at,
    }


def list_raw_files(db_path: Path, incident_id: str) -> list[dict[str, Any]]:
    get_incident(db_path, incident_id)
    with connect(db_path) as connection:
        rows = connection.execute(
            """
            SELECT * FROM raw_files
            WHERE incident_id = ?
            ORDER BY COALESCE(captured_at, created_at), created_at, id
            """,
            (incident_id,),
        ).fetchall()
    return [row_to_raw_file(row) for row in rows]


def get_raw_file(db_path: Path, file_id: str) -> dict[str, Any]:
    with connect(db_path) as connection:
        row = connection.execute(
            "SELECT * FROM raw_files WHERE id = ?", (file_id,)
        ).fetchone()
    if row is None:
        raise NotFoundError(f"raw file {file_id} was not found")
    return row_to_raw_file(row)


def save_package_record(
    db_path: Path,
    *,
    package_id: str,
    incident_id: str,
    filename: str,
    package_path: Path,
    sha256: str,
    size_bytes: int,
    key_id: str,
    exporter: dict[str, str],
) -> dict[str, Any]:
    created_at = utc_now_iso()
    with transaction(db_path) as connection:
        connection.execute(
            """
            INSERT INTO evidence_packages (
                id, incident_id, filename, package_path, sha256, size_bytes,
                key_id, exporter_name, exporter_email, exporter_organization,
                created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                package_id,
                incident_id,
                filename,
                str(package_path),
                sha256,
                size_bytes,
                key_id,
                exporter["name"],
                exporter.get("email", ""),
                exporter.get("organization", ""),
                created_at,
            ),
        )
    return {
        "id": package_id,
        "incident_id": incident_id,
        "filename": filename,
        "package_path": str(package_path),
        "sha256": sha256,
        "size_bytes": size_bytes,
        "key_id": key_id,
        "created_at": created_at,
    }


def get_package_record(db_path: Path, package_id: str) -> dict[str, Any]:
    with connect(db_path) as connection:
        row = connection.execute(
            "SELECT * FROM evidence_packages WHERE id = ?", (package_id,)
        ).fetchone()
    if row is None:
        raise NotFoundError(f"evidence package {package_id} was not found")
    return dict(row)


def list_package_records(db_path: Path, incident_id: str) -> list[dict[str, Any]]:
    get_incident(db_path, incident_id)
    with connect(db_path) as connection:
        rows = connection.execute(
            """
            SELECT * FROM evidence_packages
            WHERE incident_id = ?
            ORDER BY created_at DESC, id
            """,
            (incident_id,),
        ).fetchall()
    return [
        {
            key: row[key]
            for key in row.keys()
            if key != "package_path"
        }
        for row in rows
    ]

