from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

GENESIS_HASH = "0" * 64
HASH_ALGORITHM = "sha256"
VERSION_SCHEMA = "evidence-version/v1"
EVENT_SCHEMA = "custody-event/v1"


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def version_manifest(
    *,
    evidence_id: str,
    version_number: int,
    filename: str,
    content_type: str,
    size_bytes: int,
    content_sha256: str,
    previous_version_digest: str | None,
    created_at: str,
    created_by: str,
) -> dict[str, Any]:
    return {
        "schema": VERSION_SCHEMA,
        "evidence_id": evidence_id,
        "version_number": version_number,
        "filename": filename,
        "content_type": content_type,
        "size_bytes": size_bytes,
        "content_sha256": content_sha256,
        "previous_version_digest": previous_version_digest,
        "created_at": created_at,
        "created_by": created_by,
    }


def version_digest(manifest: Mapping[str, Any]) -> str:
    return sha256_bytes(canonical_json(manifest).encode("utf-8"))


def event_payload(event: Mapping[str, Any]) -> dict[str, Any]:
    details = event["details"]
    if isinstance(details, str):
        details = json.loads(details)
    return {
        "schema": EVENT_SCHEMA,
        "id": event["id"],
        "case_id": event["case_id"],
        "evidence_id": event["evidence_id"],
        "sequence": event["sequence"],
        "action": event["action"],
        "actor": event["actor"],
        "occurred_at": event["occurred_at"],
        "source": event["source"],
        "source_ip": event["source_ip"],
        "user_agent": event["user_agent"],
        "request_method": event["request_method"],
        "request_path": event["request_path"],
        "version_number": event["version_number"],
        "version_id": event["version_id"],
        "version_digest": event["version_digest"],
        "details": details,
    }


def event_hash(previous_hash: str, payload: Mapping[str, Any]) -> str:
    material = f"{previous_hash}\n{canonical_json(payload)}".encode()
    return sha256_bytes(material)


def verify_evidence(
    connection: sqlite3.Connection,
    *,
    case_id: str,
    evidence_id: str,
) -> dict[str, Any]:
    errors: list[str] = []
    evidence = connection.execute(
        "SELECT * FROM evidence WHERE id = ? AND case_id = ?",
        (evidence_id, case_id),
    ).fetchone()
    if evidence is None:
        return {
            "valid": False,
            "errors": ["evidence not found"],
            "checked_versions": 0,
            "checked_events": 0,
            "chain_head": GENESIS_HASH,
        }

    versions = connection.execute(
        """
        SELECT * FROM evidence_versions
        WHERE evidence_id = ?
        ORDER BY version_number
        """,
        (evidence_id,),
    ).fetchall()
    previous_digest: str | None = None
    versions_by_number: dict[int, sqlite3.Row] = {}
    for expected_number, version in enumerate(versions, start=1):
        versions_by_number[version["version_number"]] = version
        if version["version_number"] != expected_number:
            errors.append(
                f"version sequence gap: expected {expected_number}, "
                f"found {version['version_number']}"
            )
        actual_content_hash = sha256_bytes(bytes(version["content"]))
        if actual_content_hash != version["content_sha256"]:
            errors.append(
                f"content digest mismatch in version {version['version_number']}"
            )
        if int(version["size_bytes"]) != len(version["content"]):
            errors.append(f"size mismatch in version {version['version_number']}")
        if version["previous_version_digest"] != previous_digest:
            errors.append(
                f"previous version digest mismatch in version {version['version_number']}"
            )
        manifest = version_manifest(
            evidence_id=evidence_id,
            version_number=version["version_number"],
            filename=version["filename"],
            content_type=version["content_type"],
            size_bytes=version["size_bytes"],
            content_sha256=version["content_sha256"],
            previous_version_digest=version["previous_version_digest"],
            created_at=version["created_at"],
            created_by=version["created_by"],
        )
        expected_digest = version_digest(manifest)
        if expected_digest != version["version_digest"]:
            errors.append(
                f"version digest mismatch in version {version['version_number']}"
            )
        previous_digest = expected_digest

    if (
        versions
        and evidence["current_version_number"] != versions[-1]["version_number"]
    ):
        errors.append("current version pointer does not match latest version")
    if not versions:
        errors.append("evidence has no versions")

    events = connection.execute(
        """
        SELECT * FROM custody_events
        WHERE evidence_id = ?
        ORDER BY sequence
        """,
        (evidence_id,),
    ).fetchall()
    previous_hash = GENESIS_HASH
    expected_name: str | None = None
    expected_status = "active"
    upload_created_at: str | None = None
    upload_created_by: str | None = None
    for expected_sequence, event in enumerate(events, start=1):
        if event["sequence"] != expected_sequence:
            errors.append(
                f"custody sequence gap: expected {expected_sequence}, "
                f"found {event['sequence']}"
            )
        if event["previous_hash"] != previous_hash:
            errors.append(
                f"custody previous hash mismatch at sequence {event['sequence']}"
            )
        try:
            payload = event_payload(event)
            expected_hash = event_hash(previous_hash, payload)
        except (TypeError, ValueError, json.JSONDecodeError):
            errors.append(f"custody payload is invalid at sequence {event['sequence']}")
            payload = {}
            expected_hash = ""
        if expected_hash != event["record_hash"]:
            errors.append(
                f"custody record hash mismatch at sequence {event['sequence']}"
            )
        if event["version_number"] is not None:
            version = versions_by_number.get(event["version_number"])
            if version is None:
                errors.append(
                    f"custody event references a missing version at sequence {event['sequence']}"
                )
            elif event["version_digest"] != version["version_digest"]:
                errors.append(
                    f"custody version digest mismatch at sequence {event['sequence']}"
                )
            elif event["version_id"] != version["id"]:
                errors.append(
                    f"custody version id mismatch at sequence {event['sequence']}"
                )
            elif (
                event["action"] in {"UPLOAD", "REPLACE"}
                and version["created_by"] != event["actor"]
            ):
                errors.append(
                    f"version creator mismatch at custody sequence {event['sequence']}"
                )
        details = payload.get("details")
        if not isinstance(details, dict):
            details = {}
        if event["action"] == "UPLOAD":
            expected_name = details.get("display_name")
            upload_created_at = event["occurred_at"]
            upload_created_by = event["actor"]
            if event["sequence"] != 1:
                errors.append("upload must be the first custody event")
            if expected_name is None:
                errors.append(
                    f"upload display name missing at sequence {event['sequence']}"
                )
        elif event["action"] == "RENAME":
            if details.get("old_name") != expected_name:
                errors.append(f"rename source mismatch at sequence {event['sequence']}")
            expected_name = details.get("new_name")
            if expected_name is None:
                errors.append(f"rename target missing at sequence {event['sequence']}")
        elif event["action"] == "DELETE":
            expected_status = "voided"
        if (
            event["action"] in {"UPLOAD", "REPLACE"}
            and event["version_number"] is not None
        ):
            version = versions_by_number.get(event["version_number"])
            if version is not None:
                if details.get("content_sha256") != version["content_sha256"]:
                    errors.append(
                        f"version content digest mismatch at sequence {event['sequence']}"
                    )
                if details.get("filename") != version["filename"]:
                    errors.append(
                        f"version filename mismatch at sequence {event['sequence']}"
                    )
                if details.get("size_bytes") != version["size_bytes"]:
                    errors.append(
                        f"version size mismatch at sequence {event['sequence']}"
                    )
        previous_hash = expected_hash or GENESIS_HASH

    if not events:
        errors.append("evidence has no custody events")
    if expected_name is not None and expected_name != evidence["display_name"]:
        errors.append("evidence display name does not match custody history")
    if expected_status != evidence["status"]:
        errors.append("evidence status does not match custody history")
    if upload_created_at is not None and upload_created_at != evidence["created_at"]:
        errors.append("evidence creation time does not match upload history")
    if upload_created_by is not None and upload_created_by != evidence["created_by"]:
        errors.append("evidence creator does not match upload history")

    return {
        "valid": not errors,
        "errors": errors,
        "checked_versions": len(versions),
        "checked_events": len(events),
        "chain_head": events[-1]["record_hash"] if events else GENESIS_HASH,
        "current_version_number": evidence["current_version_number"],
        "status": evidence["status"],
        "hash_algorithm": HASH_ALGORITHM,
    }
