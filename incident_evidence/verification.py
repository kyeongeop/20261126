from __future__ import annotations

import binascii
import hashlib
import json
import re
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .signing import (
    decode_signature,
    key_id_for,
    load_public_key,
    load_public_key_bytes,
    public_key_fingerprint,
    verify_bytes,
)
from .storage import sha256_file

_HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_METADATA_BYTES = 64 * 1024 * 1024
_REQUIRED_METADATA = (
    "timeline.json",
    "source_config.json",
    "exporter.json",
    "raw-files.json",
)


@dataclass(slots=True)
class VerificationCheck:
    name: str
    passed: bool
    detail: str


@dataclass(slots=True)
class VerificationResult:
    valid: bool
    package_sha256: str
    key_id: str | None = None
    generated_at: str | None = None
    checks: list[VerificationCheck] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _safe_member_name(name: str) -> bool:
    if not name or "\\" in name or "\x00" in name:
        return False
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        return False
    return not any(ord(character) < 32 for character in name)


def _archive_sha256(archive: zipfile.ZipFile, name: str) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with archive.open(name, mode="r") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _load_json(payload: bytes, label: str) -> Any:
    try:
        return json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not valid UTF-8 JSON: {exc}") from exc


def _add_check(
    result: VerificationResult,
    name: str,
    passed: bool,
    detail: str,
) -> None:
    result.checks.append(VerificationCheck(name=name, passed=passed, detail=detail))
    if not passed:
        result.errors.append(detail)


def _resolve_trusted_key(
    trusted_public_key: Path | str | Ed25519PublicKey | None,
) -> Ed25519PublicKey | None:
    if trusted_public_key is None:
        return None
    if isinstance(trusted_public_key, Ed25519PublicKey):
        return trusted_public_key
    path = Path(trusted_public_key)
    return load_public_key(path)


def verify_package(
    package_path: Path | str,
    *,
    trusted_public_key: Path | str | Ed25519PublicKey | None = None,
) -> VerificationResult:
    path = Path(package_path)

    if not path.is_file():
        return VerificationResult(
            valid=False,
            package_sha256="",
            checks=[VerificationCheck("package_present", False, "package does not exist")],
            errors=["package does not exist"],
        )

    try:
        package_digest, _ = sha256_file(path)
    except OSError as exc:
        return VerificationResult(
            valid=False,
            package_sha256="",
            checks=[VerificationCheck("package_readable", False, str(exc))],
            errors=[str(exc)],
        )

    result = VerificationResult(valid=False, package_sha256=package_digest)
    trusted_key: Ed25519PublicKey | None = None
    try:
        trusted_key = _resolve_trusted_key(trusted_public_key)
    except (OSError, ValueError) as exc:
        _add_check(result, "trusted_public_key", False, f"cannot load trusted key: {exc}")

    try:
        archive = zipfile.ZipFile(path, "r")
    except (OSError, zipfile.BadZipFile) as exc:
        _add_check(result, "zip_open", False, f"not a readable ZIP archive: {exc}")
        return result

    with archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        try:
            crc_failure = archive.testzip()
        except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
            _add_check(result, "zip_integrity", False, f"cannot read ZIP: {exc}")
            return result
        _add_check(
            result,
            "zip_integrity",
            crc_failure is None,
            "ZIP central directory and member CRCs are intact",
        )
        duplicate_names = len(names) != len(set(names))
        folded_duplicates = len(names) != len({name.casefold() for name in names})
        _add_check(
            result,
            "unique_member_names",
            not duplicate_names and not folded_duplicates,
            "archive member names are unique",
        )
        unsafe = [name for name in names if not _safe_member_name(name)]
        _add_check(
            result,
            "safe_member_paths",
            not unsafe,
            "all archive paths are relative and traversal-free",
        )
        bad_members = [
            info.filename
            for info in infos
            if info.flag_bits & 0x1
            or ((info.external_attr >> 16) & 0o170000) == 0o120000
        ]
        _add_check(
            result,
            "regular_unencrypted_members",
            not bad_members,
            "archive contains no encrypted or symbolic-link members",
        )
        if (
            crc_failure is not None
            or duplicate_names
            or folded_duplicates
            or unsafe
            or bad_members
        ):
            result.valid = False
            return result

        files = {
            info.filename: info
            for info in infos
            if not info.is_dir()
        }
        oversized_metadata = [
            name
            for name, info in files.items()
            if not name.startswith("raw/")
            and info.file_size > _MAX_METADATA_BYTES
        ]
        _add_check(
            result,
            "metadata_size_limit",
            not oversized_metadata,
            "JSON and key metadata files are within the 64 MiB safety limit",
        )
        if oversized_metadata:
            result.valid = False
            return result
        try:
            manifest_bytes = (
                archive.read("manifest.json") if "manifest.json" in files else None
            )
            signature_bytes = (
                archive.read("signature.json") if "signature.json" in files else None
            )
            package_public_key_bytes = (
                archive.read("public_key.pem") if "public_key.pem" in files else None
            )
        except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
            _add_check(result, "envelope_read", False, f"cannot read envelope: {exc}")
            return result
        _add_check(
            result,
            "required_envelope_files",
            manifest_bytes is not None
            and signature_bytes is not None
            and package_public_key_bytes is not None,
            "manifest.json, signature.json and public_key.pem are present",
        )
        if (
            manifest_bytes is None
            or signature_bytes is None
            or package_public_key_bytes is None
        ):
            result.valid = False
            return result

        try:
            manifest = _load_json(manifest_bytes, "manifest.json")
            signature = _load_json(signature_bytes, "signature.json")
            if not isinstance(manifest, dict) or not isinstance(signature, dict):
                raise ValueError("manifest and signature must be JSON objects")
        except ValueError as exc:
            _add_check(result, "json_parse", False, str(exc))
            return result
        _add_check(result, "json_parse", True, "manifest and signature JSON parsed")
        expected_signature_bytes = (
            json.dumps(
                signature,
                ensure_ascii=False,
                sort_keys=True,
                indent=2,
            )
            + "\n"
        ).encode("utf-8")
        _add_check(
            result,
            "signature_canonical_form",
            signature_bytes == expected_signature_bytes,
            "signature.json uses the exact canonical serialization",
        )

        signature_key_value = signature.get("key_id")
        generated_at_value = manifest.get("generated_at")
        result.key_id = (
            signature_key_value if isinstance(signature_key_value, str) else None
        )
        result.generated_at = (
            generated_at_value if isinstance(generated_at_value, str) else None
        )
        try:
            package_key = load_public_key_bytes(package_public_key_bytes)
        except (TypeError, ValueError) as exc:
            _add_check(
                result,
                "public_key_parse",
                False,
                f"public_key.pem is not a valid Ed25519 public key: {exc}",
            )
            return result
        package_key_sha = public_key_fingerprint(package_key)
        manifest_signing = manifest.get("signing", {})
        if not isinstance(manifest_signing, dict):
            _add_check(
                result,
                "signing_key_identity",
                False,
                "manifest signing metadata must be an object",
            )
            manifest_signing = {}
        claimed_sha = signature.get("public_key_sha256")
        signature_key_id = signature.get("key_id")
        fingerprint_matches = (
            claimed_sha == package_key_sha == manifest_signing.get("public_key_sha256")
            and signature_key_id
            == manifest_signing.get("key_id")
            == key_id_for(package_key)
        )
        _add_check(
            result,
            "signing_key_identity",
            fingerprint_matches,
            "manifest, signature and bundled public key identify the same key",
        )

        selected_key = package_key
        if trusted_key is not None:
            trusted_sha = public_key_fingerprint(trusted_key)
            if trusted_sha != claimed_sha:
                _add_check(
                    result,
                    "trusted_public_key",
                    False,
                    "trusted public key does not match the package signing key",
                )
            else:
                selected_key = trusted_key
                _add_check(
                    result,
                    "trusted_public_key",
                    True,
                    "external trust anchor matches the package signing key",
                )
        elif trusted_public_key is None:
            _add_check(
                result,
                "trusted_public_key",
                True,
                "no external key supplied; bundled key is self-consistent only",
            )

        try:
            raw_signature = decode_signature(str(signature.get("signature", "")))
            signature_ok = (
                signature.get("algorithm") == "Ed25519"
                and verify_bytes(selected_key, raw_signature, manifest_bytes)
            )
        except (ValueError, TypeError, binascii.Error):
            signature_ok = False
        _add_check(
            result,
            "manifest_signature",
            signature_ok,
            "Ed25519 signature over the exact manifest bytes is valid",
        )
        _add_check(
            result,
            "signed_manifest_digest",
            signature.get("manifest_sha256")
            == hashlib.sha256(manifest_bytes).hexdigest(),
            "signature record binds the exact manifest digest",
        )

        _verify_checksums(
            result,
            archive,
            files,
            manifest,
        )
        _verify_content_consistency(result, archive, files, manifest)

    result.valid = not result.errors
    return result


def _verify_checksums(
    result: VerificationResult,
    archive: zipfile.ZipFile,
    files: dict[str, zipfile.ZipInfo],
    manifest: dict[str, Any],
) -> None:
    entries = manifest.get("checksums")
    if not isinstance(entries, list):
        _add_check(result, "checksum_manifest", False, "checksums must be a list")
        return

    seen: set[str] = set()
    malformed: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict):
            malformed.append(repr(entry))
            continue
        archive_path = entry.get("path")
        digest = entry.get("sha256")
        size = entry.get("size_bytes")
        if (
            not isinstance(archive_path, str)
            or not _safe_member_name(archive_path)
            or archive_path in ("manifest.json", "signature.json")
            or archive_path in seen
            or not isinstance(digest, str)
            or not _HEX_SHA256.fullmatch(digest)
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
        ):
            malformed.append(str(archive_path))
            continue
        seen.add(archive_path)
    _add_check(
        result,
        "checksum_manifest_shape",
        not malformed,
        "checksum paths, digests and sizes are well-formed and unique",
    )

    expected_members = seen | {"manifest.json", "signature.json"}
    actual_members = set(files)
    missing = sorted(expected_members - actual_members)
    extra = sorted(actual_members - expected_members)
    _add_check(
        result,
        "complete_file_coverage",
        not missing and not extra,
        "every archive file is signed and no unsigned files exist"
        + (f"; missing={missing}" if missing else "")
        + (f"; extra={extra}" if extra else ""),
    )

    for entry in entries:
        if not isinstance(entry, dict) or entry.get("path") not in seen:
            continue
        name = entry["path"]
        if name not in files:
            continue
        try:
            actual_digest, actual_size = _archive_sha256(archive, name)
        except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
            _add_check(
                result,
                f"file_checksum:{name}",
                False,
                f"{name} cannot be read for verification: {exc}",
            )
            return
        if actual_digest != entry["sha256"] or actual_size != entry["size_bytes"]:
            _add_check(
                result,
                f"file_checksum:{name}",
                False,
                f"{name} was replaced or modified",
            )
            return
    _add_check(
        result,
        "all_file_checksums",
        True,
        f"all {len(entries)} file checksums and sizes match",
    )


def _verify_content_consistency(
    result: VerificationResult,
    archive: zipfile.ZipFile,
    files: dict[str, zipfile.ZipInfo],
    manifest: dict[str, Any],
) -> None:
    if not all(name in files for name in _REQUIRED_METADATA):
        _add_check(
            result,
            "metadata_files",
            False,
            "timeline.json, source_config.json, exporter.json and raw-files.json are required",
        )
        return

    try:
        timeline = _load_json(archive.read("timeline.json"), "timeline.json")
        source_config = _load_json(
            archive.read("source_config.json"), "source_config.json"
        )
        exporter = _load_json(archive.read("exporter.json"), "exporter.json")
        raw_files = _load_json(archive.read("raw-files.json"), "raw-files.json")
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        _add_check(result, "metadata_files", False, f"cannot read metadata: {exc}")
        return
    except ValueError as exc:
        _add_check(result, "metadata_files", False, str(exc))
        return

    manifest_timeline = manifest.get("timeline")
    consistent = (
        isinstance(timeline, dict)
        and isinstance(manifest_timeline, list)
        and timeline.get("events") == manifest_timeline
        and timeline.get("event_count") == len(manifest_timeline)
        and source_config == manifest.get("source_config")
        and exporter == manifest.get("exporter")
        and raw_files == manifest.get("raw_files")
    )
    _add_check(
        result,
        "metadata_consistency",
        consistent,
        "timeline, source config, exporter info and raw-file manifest match the signed manifest",
    )

    manifest_checksums = manifest.get("checksums")
    checksum_entries = (
        manifest_checksums if isinstance(manifest_checksums, list) else []
    )
    checksum_map = {
        entry["path"]: entry
        for entry in checksum_entries
        if isinstance(entry, dict) and isinstance(entry.get("path"), str)
    }
    raw_errors: list[str] = []
    raw_entries = manifest.get("raw_files", [])
    if not isinstance(raw_entries, list):
        raw_errors.append("raw_files must be a list")
    else:
        seen: set[str] = set()
        for entry in raw_entries:
            if not isinstance(entry, dict):
                raw_errors.append("raw file entry is not an object")
                continue
            name = entry.get("path")
            checksum = checksum_map.get(name)
            if (
                not isinstance(name, str)
                or not name.startswith("raw/")
                or name in seen
                or name not in files
                or checksum is None
                or checksum.get("sha256") != entry.get("sha256")
                or checksum.get("size_bytes") != entry.get("size_bytes")
            ):
                raw_errors.append(str(name))
            else:
                seen.add(name)
    _add_check(
        result,
        "raw_file_manifest",
        not raw_errors,
        "every raw-file entry is present and bound to its signed checksum",
    )

