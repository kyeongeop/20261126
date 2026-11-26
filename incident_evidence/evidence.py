from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import shlex
import shutil
import tempfile
import uuid
import zipfile
from pathlib import Path
from typing import Any

from .config import Settings
from .db import connect, row_to_event, row_to_incident, row_to_raw_file
from .repository import NotFoundError, save_package_record
from .signing import (
    SigningMaterial,
    encode_signature,
    load_or_create_signing_material,
    sign_bytes,
)
from .storage import safe_archive_name, sha256_file
from .timeutil import utc_now_iso

SCHEMA_VERSION = "incident-evidence/v1"


class EvidenceGenerationError(RuntimeError):
    """Raised when a consistent evidence package cannot be produced."""


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def pretty_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")


def verification_command(package_path: Path, public_key_path: Path) -> str:
    return (
        "python3 -m incident_evidence.cli verify "
        f"{shlex.quote(str(package_path))} "
        f"--public-key {shlex.quote(str(public_key_path))}"
    )


def _snapshot(
    settings: Settings, incident_id: str
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    connection = connect(settings.db_path)
    try:
        connection.execute("BEGIN")
        incident_row = connection.execute(
            "SELECT * FROM incidents WHERE id = ?", (incident_id,)
        ).fetchone()
        if incident_row is None:
            raise NotFoundError(f"incident {incident_id} was not found")
        event_rows = connection.execute(
            """
            SELECT * FROM events
            WHERE incident_id = ?
            ORDER BY occurred_at, created_at, id
            """,
            (incident_id,),
        ).fetchall()
        raw_rows = connection.execute(
            """
            SELECT * FROM raw_files
            WHERE incident_id = ?
            ORDER BY COALESCE(captured_at, created_at), created_at, id
            """,
            (incident_id,),
        ).fetchall()
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.close()
    return (
        row_to_incident(incident_row),
        [row_to_event(row) for row in event_rows],
        [row_to_raw_file(row) for row in raw_rows],
    )


def _timeline_csv(events: list[dict[str, Any]]) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(
        [
            "event_id",
            "occurred_at",
            "title",
            "description",
            "source",
            "actor",
            "artifact_ids",
        ]
    )
    for event in events:
        writer.writerow(
            [
                event["id"],
                event["occurred_at"],
                event["title"],
                event["description"],
                event["source"],
                event["actor"],
                ";".join(event["artifact_ids"]),
            ]
        )
    return output.getvalue().encode("utf-8")


def _write_bytes(root: Path, relative: str, payload: bytes) -> Path:
    destination = root / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(payload)
    return destination


def _verify_source_file(settings: Settings, raw_file: dict[str, Any]) -> Path:
    source = (settings.data_dir / raw_file["storage_path"]).resolve()
    data_root = settings.data_dir.resolve()
    if not source.is_relative_to(data_root):
        raise EvidenceGenerationError(
            f"raw file {raw_file['id']} points outside the data directory"
        )
    if not source.is_file():
        raise EvidenceGenerationError(
            f"raw file {raw_file['id']} is missing from local storage"
        )
    digest, size = sha256_file(source)
    if digest != raw_file["sha256"] or size != raw_file["size_bytes"]:
        raise EvidenceGenerationError(
            f"raw file {raw_file['id']} changed after ingestion; "
            "refusing to create a misleading evidence package"
        )
    return source


def _copy_raw_files(
    settings: Settings,
    raw_files: list[dict[str, Any]],
    staging: Path,
) -> list[dict[str, Any]]:
    manifest_entries: list[dict[str, Any]] = []
    for index, raw_file in enumerate(raw_files, start=1):
        source = _verify_source_file(settings, raw_file)
        archive_name = (
            f"raw/{index:04d}-{raw_file['sha256'][:12]}-"
            f"{safe_archive_name(raw_file['original_name'])}"
        )
        destination = _write_bytes(staging, archive_name, b"")
        shutil.copyfile(source, destination)
        copied_digest, copied_size = sha256_file(destination)
        if copied_digest != raw_file["sha256"] or copied_size != raw_file["size_bytes"]:
            raise EvidenceGenerationError(
                f"raw file {raw_file['id']} changed while it was being copied"
            )
        manifest_entries.append(
            {
                "artifact_id": raw_file["id"],
                "path": archive_name,
                "original_name": raw_file["original_name"],
                "media_type": raw_file["media_type"],
                "source": raw_file["source"],
                "description": raw_file["description"],
                "captured_at": raw_file["captured_at"],
                "size_bytes": raw_file["size_bytes"],
                "sha256": raw_file["sha256"],
            }
        )
    return manifest_entries


def _checksum_entry(path: Path, archive_path: str) -> dict[str, Any]:
    digest, size = sha256_file(path)
    return {"path": archive_path, "size_bytes": size, "sha256": digest}


def _build_verify_markdown(
    *,
    command: str,
    signing: SigningMaterial,
    incident: dict[str, Any],
) -> bytes:
    text = f"""# Evidence package verification

Incident: {incident["title"]} (`{incident["id"]}`)
Signing key id: `{signing.key_id}`
Public key SHA-256: `{signing.public_key_sha256}`

Run the command below from a host where `incident_evidence` is installed.
The `--public-key` file must be obtained independently from the package owner.

```sh
{command}
```

The verifier checks the Ed25519 signature over `manifest.json`, requires every
archive entry to appear exactly once in the signed checksum list, and recomputes
the size and SHA-256 of every listed file. Any replaced, added, duplicate, or
missing file causes verification to fail.

For a manual checksum check after extraction:

```sh
sha256sum -c checksums.sha256
```
"""
    return text.encode("utf-8")


def create_evidence_package(
    settings: Settings,
    incident_id: str,
    exporter: dict[str, str],
) -> dict[str, Any]:
    settings.ensure_directories()
    incident, events, raw_files = _snapshot(settings, incident_id)
    signing = load_or_create_signing_material(settings.signing_key_path)

    package_id = f"pkg_{uuid.uuid4().hex}"
    generated_at = utc_now_iso()
    timestamp_tag = (
        generated_at.replace("-", "").replace(":", "").replace(".", "")
    )
    filename = (
        f"evidence-{incident_id[:16]}-{timestamp_tag}-{package_id[-8:]}.zip"
    )
    package_path = (settings.packages_dir / filename).resolve()
    command = verification_command(package_path, settings.public_key_path.resolve())

    with tempfile.TemporaryDirectory(
        dir=settings.packages_dir, prefix=".evidence-build-"
    ) as temporary:
        staging = Path(temporary)
        timeline_payload = {
            "incident_id": incident_id,
            "events": events,
            "event_count": len(events),
        }
        timeline_path = _write_bytes(
            staging, "timeline.json", pretty_json_bytes(timeline_payload)
        )
        timeline_csv_path = _write_bytes(
            staging, "timeline.csv", _timeline_csv(events)
        )
        source_config_path = _write_bytes(
            staging,
            "source_config.json",
            pretty_json_bytes(incident["source_config"]),
        )
        exporter_path = _write_bytes(
            staging, "exporter.json", pretty_json_bytes(exporter)
        )
        raw_manifest_entries = _copy_raw_files(settings, raw_files, staging)
        raw_manifest_path = _write_bytes(
            staging, "raw-files.json", pretty_json_bytes(raw_manifest_entries)
        )
        public_key_path = _write_bytes(
            staging, "public_key.pem", signing.public_key_pem
        )
        verify_md_path = _write_bytes(
            staging,
            "VERIFY.md",
            _build_verify_markdown(
                command=command,
                signing=signing,
                incident=incident,
            ),
        )

        checksum_paths = {
            "timeline.json": timeline_path,
            "timeline.csv": timeline_csv_path,
            "source_config.json": source_config_path,
            "exporter.json": exporter_path,
            "raw-files.json": raw_manifest_path,
            "public_key.pem": public_key_path,
            "VERIFY.md": verify_md_path,
        }
        for entry in raw_manifest_entries:
            checksum_paths[entry["path"]] = staging / entry["path"]

        checksum_entries = [
            _checksum_entry(path, archive_path)
            for archive_path, path in sorted(checksum_paths.items())
        ]
        checksums_lines = "".join(
            f"{entry['sha256']}  {entry['path']}\n"
            for entry in checksum_entries
        )
        checksums_path = _write_bytes(
            staging, "checksums.sha256", checksums_lines.encode("utf-8")
        )
        checksum_entries.append(
            _checksum_entry(checksums_path, "checksums.sha256")
        )
        checksum_entries.sort(key=lambda entry: entry["path"])

        manifest = {
            "schema_version": SCHEMA_VERSION,
            "package_id": package_id,
            "incident_id": incident_id,
            "generated_at": generated_at,
            "exporter": exporter,
            "incident": {
                "id": incident["id"],
                "title": incident["title"],
                "description": incident["description"],
                "created_at": incident["created_at"],
            },
            "source_config": incident["source_config"],
            "timeline": events,
            "raw_files": raw_manifest_entries,
            "checksums": checksum_entries,
            "signing": {
                "algorithm": "Ed25519",
                "key_id": signing.key_id,
                "public_key_sha256": signing.public_key_sha256,
                "manifest": "manifest.json",
                "signature": "signature.json",
            },
            "verification": {
                "command": command,
                "instructions": "VERIFY.md",
            },
        }
        manifest_bytes = canonical_json_bytes(manifest)
        _write_bytes(staging, "manifest.json", manifest_bytes)

        signature = sign_bytes(signing.private_key, manifest_bytes)
        signature_payload = {
            "algorithm": "Ed25519",
            "key_id": signing.key_id,
            "public_key_sha256": signing.public_key_sha256,
            "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "signature": encode_signature(signature),
        }
        _write_bytes(
            staging, "signature.json", pretty_json_bytes(signature_payload)
        )

        temporary_zip = package_path.with_name(f".{package_path.name}.part")
        try:
            with zipfile.ZipFile(
                temporary_zip,
                mode="w",
                compression=zipfile.ZIP_DEFLATED,
                compresslevel=9,
            ) as archive:
                for path in sorted(staging.rglob("*")):
                    if not path.is_file():
                        continue
                    archive.write(path, path.relative_to(staging).as_posix())
            os.replace(temporary_zip, package_path)
        finally:
            temporary_zip.unlink(missing_ok=True)

    package_sha256, package_size = sha256_file(package_path)
    try:
        record = save_package_record(
            settings.db_path,
            package_id=package_id,
            incident_id=incident_id,
            filename=filename,
            package_path=package_path,
            sha256=package_sha256,
            size_bytes=package_size,
            key_id=signing.key_id,
            exporter=exporter,
        )
    except BaseException:
        package_path.unlink(missing_ok=True)
        raise

    return {
        "id": package_id,
        "incident_id": incident_id,
        "filename": filename,
        "package_path": str(record["package_path"]),
        "sha256": package_sha256,
        "size_bytes": package_size,
        "created_at": record["created_at"],
        "download_url": f"/api/evidence-packages/{package_id}/download",
        "verification": {
            "command": command,
            "public_key_path": str(settings.public_key_path.resolve()),
            "public_key_sha256": signing.public_key_sha256,
            "key_id": signing.key_id,
        },
    }

