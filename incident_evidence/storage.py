from __future__ import annotations

import hashlib
import os
import re
import tempfile
from pathlib import Path

_UNSAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def safe_display_name(value: str) -> str:
    name = Path(value).name.replace("\x00", "").strip()
    return name[:240] or "unnamed"


def safe_archive_name(value: str) -> str:
    name = safe_display_name(value)
    name = _UNSAFE_NAME.sub("_", name).strip("._") or "file"
    return name[:180]


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def write_upload(
    source,
    destination: Path,
    max_bytes: int,
) -> tuple[str, int]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    size = 0
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=destination.parent, prefix=".upload-", delete=False
        ) as handle:
            temporary = Path(handle.name)
            while chunk := source.read(1024 * 1024):
                size += len(chunk)
                if size > max_bytes:
                    raise ValueError(f"file exceeds the {max_bytes} byte limit")
                digest.update(chunk)
                handle.write(chunk)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
        temporary = None
        return digest.hexdigest(), size
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)

