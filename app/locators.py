"""Stable source locators and their strict resolution rules.

A locator points at evidence inside a source file using one of three
anchors. Every anchor is additionally pinned by content hashes, so a file
update can never silently move the link to a similar position:

* ``line``   - 1-based line number; the exact line bytes must still hash
  to ``content_hash``.
* ``offset`` - 0-based byte offset plus a byte length; the span must still
  hash to ``content_hash``.
* ``hash``   - content-hash prefix anchor; the prefixed line must still be
  present in the file and the full content hash must still match.

Resolution outcomes:

* ``valid``   - the anchor resolves and every hash matches.
* ``stale``   - the file exists, but the anchor moved or a hash differs.
* ``missing`` - the source file no longer exists.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional

from .hashing import hash_bytes, shorten, verify_prefix


class LocatorKind(str, Enum):
    LINE = "line"
    OFFSET = "offset"
    HASH = "hash"


class SourceStatus(str, Enum):
    VALID = "valid"
    STALE = "stale"
    MISSING = "missing"


@dataclass(frozen=True)
class ResolvedLocation:
    """Outcome of resolving a locator against the current file on disk."""

    status: SourceStatus
    kind: LocatorKind
    file_path: str
    line: Optional[int] = None
    end_line: Optional[int] = None
    offset: Optional[int] = None
    length: Optional[int] = None
    content_hash: Optional[str] = None
    file_hash: Optional[str] = None
    content_hash_prefix: Optional[str] = None
    file_hash_prefix: Optional[str] = None
    snippet: Optional[str] = None
    reason: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "status": self.status.value,
            "kind": self.kind.value,
            "file_path": self.file_path,
            "line": self.line,
            "end_line": self.end_line,
            "offset": self.offset,
            "length": self.length,
            "content_hash": self.content_hash,
            "file_hash": self.file_hash,
            "content_hash_prefix": self.content_hash_prefix,
            "file_hash_prefix": self.file_hash_prefix,
            "snippet": self.snippet,
            "reason": self.reason,
        }


def _split_lines(data: bytes) -> list[bytes]:
    """Split keeping line endings, mirroring common editor line semantics."""
    return data.splitlines(keepends=True)


def _line_spans(data: bytes) -> list[tuple[int, int, bytes]]:
    """Return (start_offset, end_offset, line_bytes) per 1-based line."""
    spans: list[tuple[int, int, bytes]] = []
    start = 0
    for line in _split_lines(data):
        end = start + len(line)
        spans.append((start, end, line))
        start = end
    return spans


def _decode_snippet(data: bytes, limit: int = 400) -> str:
    text = data.decode("utf-8", errors="replace")
    if len(text) > limit:
        return text[:limit] + "\u2026"
    return text


@dataclass(frozen=True)
class StoredLocator:
    """Locator fields as persisted in the database."""

    kind: LocatorKind
    file_path: str
    line: Optional[int]
    end_line: Optional[int]
    offset: Optional[int]
    length: Optional[int]
    content_hash: str
    file_hash: str

    @classmethod
    def from_row(cls, row) -> "StoredLocator":
        return cls(
            kind=LocatorKind(row["locator_kind"]),
            file_path=row["file_path"],
            line=row["line_no"],
            end_line=row["end_line"],
            offset=row["byte_offset"],
            length=row["byte_length"],
            content_hash=row["content_hash"],
            file_hash=row["file_hash"],
        )


def build_line_locator(base_dir: Path, rel_path: str, line: int,
                       end_line: Optional[int] = None) -> StoredLocator:
    """Create a line-anchored locator, validating it against the file."""
    target = (base_dir / rel_path).resolve()
    data = target.read_bytes()
    spans = _line_spans(data)
    if line < 1 or line > len(spans):
        raise ValueError(f"line {line} is out of range for {rel_path}")
    last = end_line if end_line is not None else line
    if last < line or last > len(spans):
        raise ValueError(f"end_line {last} is out of range for {rel_path}")
    start_off = spans[line - 1][0]
    end_off = spans[last - 1][1]
    content = data[start_off:end_off]
    return StoredLocator(
        kind=LocatorKind.LINE,
        file_path=rel_path,
        line=line,
        end_line=last,
        offset=None,
        length=None,
        content_hash=hash_bytes(content),
        file_hash=hash_bytes(data),
    )


def build_offset_locator(base_dir: Path, rel_path: str, offset: int,
                         length: int) -> StoredLocator:
    """Create a byte-offset-anchored locator, validating the span."""
    target = (base_dir / rel_path).resolve()
    data = target.read_bytes()
    if offset < 0 or length < 0 or offset + length > len(data):
        raise ValueError(
            f"offset/length {offset}+{length} out of range for {rel_path}"
        )
    content = data[offset:offset + length]
    return StoredLocator(
        kind=LocatorKind.OFFSET,
        file_path=rel_path,
        line=None,
        end_line=None,
        offset=offset,
        length=length,
        content_hash=hash_bytes(content),
        file_hash=hash_bytes(data),
    )


def build_hash_locator(base_dir: Path, rel_path: str,
                       search_text: str,
                       occurrence: int = 1) -> StoredLocator:
    """Create a hash-prefix locator anchored on a matching line.

    ``search_text`` identifies the line at creation time; the stored anchor
    is the line's full content hash, so later resolution never depends on
    fuzzy text matching.
    """
    target = (base_dir / rel_path).resolve()
    data = target.read_bytes()
    wanted = search_text.encode("utf-8")
    matched: Optional[bytes] = None
    seen = 0
    for _, _, line_bytes in _line_spans(data):
        if wanted in line_bytes:
            seen += 1
            if seen == occurrence:
                matched = line_bytes
                break
    if matched is None:
        raise ValueError(
            f"text {search_text!r} not found in {rel_path}"
            + ("" if occurrence == 1 else f" (occurrence {occurrence})")
        )
    return StoredLocator(
        kind=LocatorKind.HASH,
        file_path=rel_path,
        line=None,
        end_line=None,
        offset=None,
        length=None,
        content_hash=hash_bytes(matched.rstrip(b"\r\n")),
        file_hash=hash_bytes(data),
    )


def _stale(locator: StoredLocator, reason: str,
           current_file_hash: Optional[str]) -> ResolvedLocation:
    return ResolvedLocation(
        status=SourceStatus.STALE,
        kind=locator.kind,
        file_path=locator.file_path,
        content_hash=locator.content_hash,
        file_hash=current_file_hash,
        content_hash_prefix=shorten(locator.content_hash),
        file_hash_prefix=(shorten(current_file_hash)
                          if current_file_hash else None),
        reason=reason,
    )


def resolve_locator(base_dir: Path, locator: StoredLocator) -> ResolvedLocation:
    """Resolve a stored locator against the file as it exists now.

    No fuzzy re-anchoring is performed: any mismatch yields ``stale``.
    """
    target = (base_dir / locator.file_path)
    if not target.is_file():
        return ResolvedLocation(
            status=SourceStatus.MISSING,
            kind=locator.kind,
            file_path=locator.file_path,
            content_hash=locator.content_hash,
            file_hash=locator.file_hash,
            content_hash_prefix=shorten(locator.content_hash),
            file_hash_prefix=shorten(locator.file_hash),
            reason="source file no longer exists",
        )

    data = target.read_bytes()
    current_file_hash = hash_bytes(data)
    spans = _line_spans(data)

    if locator.kind is LocatorKind.LINE:
        last = locator.end_line or locator.line
        if locator.line is None or locator.line < 1 or last > len(spans):
            return _stale(locator, "line range no longer exists in file",
                          current_file_hash)
        start_off = spans[locator.line - 1][0]
        end_off = spans[last - 1][1]
        current = data[start_off:end_off]
        current_hash = hash_bytes(current)
        if current_hash != locator.content_hash:
            return _stale(
                locator,
                "line content changed since the locator was created",
                current_file_hash,
            )
        return ResolvedLocation(
            status=SourceStatus.VALID,
            kind=locator.kind,
            file_path=locator.file_path,
            line=locator.line,
            end_line=last,
            offset=start_off,
            length=len(current),
            content_hash=current_hash,
            file_hash=current_file_hash,
            content_hash_prefix=shorten(current_hash),
            file_hash_prefix=shorten(current_file_hash),
            snippet=_decode_snippet(current),
        )

    if locator.kind is LocatorKind.OFFSET:
        if (locator.offset is None or locator.length is None
                or locator.offset < 0
                or locator.offset + locator.length > len(data)):
            return _stale(locator, "byte offset span no longer exists",
                          current_file_hash)
        current = data[locator.offset:locator.offset + locator.length]
        current_hash = hash_bytes(current)
        if current_hash != locator.content_hash:
            return _stale(
                locator,
                "bytes at stored offset changed since the locator was created",
                current_file_hash,
            )
        line_no = _line_for_offset(spans, locator.offset)
        return ResolvedLocation(
            status=SourceStatus.VALID,
            kind=locator.kind,
            file_path=locator.file_path,
            line=line_no,
            end_line=line_no,
            offset=locator.offset,
            length=locator.length,
            content_hash=current_hash,
            file_hash=current_file_hash,
            content_hash_prefix=shorten(current_hash),
            file_hash_prefix=shorten(current_file_hash),
            snippet=_decode_snippet(current),
        )

    # HASH anchor: find a line whose *full* content hash matches exactly.
    for index, (start_off, end_off, line_bytes) in enumerate(spans, start=1):
        line_content = line_bytes.rstrip(b"\r\n")
        current_hash = hash_bytes(line_content)
        if verify_prefix(current_hash, shorten(locator.content_hash)) \
                and current_hash == locator.content_hash:
            return ResolvedLocation(
                status=SourceStatus.VALID,
                kind=locator.kind,
                file_path=locator.file_path,
                line=index,
                end_line=index,
                offset=start_off,
                length=end_off - start_off,
                content_hash=current_hash,
                file_hash=current_file_hash,
                content_hash_prefix=shorten(current_hash),
                file_hash_prefix=shorten(current_file_hash),
                snippet=_decode_snippet(line_bytes),
            )
    return _stale(
        locator,
        "no line with the pinned content hash exists in the current file",
        current_file_hash,
    )


def _line_for_offset(spans, offset: int) -> int:
    for index, (start, end, _) in enumerate(spans, start=1):
        if start <= offset < end:
            return index
    return len(spans) if spans else 1


def ensure_within_base(base_dir: Path, rel_path: str) -> Path:
    """Resolve ``rel_path`` and reject path traversal outside ``base_dir``."""
    base = base_dir.resolve()
    target = (base / rel_path).resolve()
    if os.path.commonpath([str(base), str(target)]) != str(base):
        raise ValueError(f"path {rel_path!r} escapes the source directory")
    return target
