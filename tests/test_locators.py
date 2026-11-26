"""Unit tests for locator construction and strict resolution semantics."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.locators import (
    LocatorKind,
    SourceStatus,
    build_hash_locator,
    build_line_locator,
    build_offset_locator,
    ensure_within_base,
    resolve_locator,
)


SAMPLE = "line one\nline two\nalert: disk full\nline four\n"


@pytest.fixture()
def sample_file(source_dir: Path) -> Path:
    path = source_dir / "logs" / "app.log"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(SAMPLE, encoding="utf-8")
    return path


def test_line_locator_resolves_while_unchanged(source_dir, sample_file):
    locator = build_line_locator(source_dir, "logs/app.log", 3)
    assert locator.kind is LocatorKind.LINE
    result = resolve_locator(source_dir, locator)
    assert result.status is SourceStatus.VALID
    assert result.line == 3
    assert "disk full" in result.snippet
    assert result.content_hash_prefix == locator.content_hash[:12]


def test_line_locator_goes_stale_when_line_content_changes(
    source_dir, sample_file
):
    locator = build_line_locator(source_dir, "logs/app.log", 3)
    updated = SAMPLE.replace("alert: disk full", "alert: disk OK")
    sample_file.write_text(updated, encoding="utf-8")

    result = resolve_locator(source_dir, locator)
    assert result.status is SourceStatus.STALE
    assert result.reason is not None
    assert "changed" in result.reason


def test_line_locator_does_not_jump_to_similar_position(
    source_dir, sample_file
):
    locator = build_line_locator(source_dir, "logs/app.log", 3)
    # Insert a line before the target: same content shifts to line 4,
    # while line 3 now holds different text. The locator must go stale
    # rather than following the text to its new line number.
    updated = SAMPLE.replace(
        "alert: disk full\n", "new header\nalert: disk full\n", 1
    )
    sample_file.write_text(updated, encoding="utf-8")

    result = resolve_locator(source_dir, locator)
    assert result.status is SourceStatus.STALE


def test_offset_locator_detects_byte_change(source_dir, sample_file):
    locator = build_offset_locator(source_dir, "logs/app.log", 0, 9)
    assert locator.kind is LocatorKind.OFFSET
    valid = resolve_locator(source_dir, locator)
    assert valid.status is SourceStatus.VALID
    assert valid.offset == 0

    data = sample_file.read_bytes()
    sample_file.write_bytes(b"X" + data[1:])
    stale = resolve_locator(source_dir, locator)
    assert stale.status is SourceStatus.STALE


def test_hash_locator_finds_line_even_after_moves(source_dir, sample_file):
    locator = build_hash_locator(
        source_dir, "logs/app.log", "disk full"
    )
    assert locator.kind is LocatorKind.HASH

    moved = "new header\n" + SAMPLE
    sample_file.write_text(moved, encoding="utf-8")
    result = resolve_locator(source_dir, locator)
    assert result.status is SourceStatus.VALID
    assert result.line == 4


def test_hash_locator_goes_stale_when_content_edited(
    source_dir, sample_file
):
    locator = build_hash_locator(
        source_dir, "logs/app.log", "disk full"
    )
    sample_file.write_text(
        SAMPLE.replace("disk full", "disk empty"), encoding="utf-8"
    )
    result = resolve_locator(source_dir, locator)
    assert result.status is SourceStatus.STALE
    assert "pinned content hash" in result.reason


def test_missing_file_is_reported_not_guessed(source_dir, sample_file):
    locator = build_line_locator(source_dir, "logs/app.log", 2)
    sample_file.unlink()
    result = resolve_locator(source_dir, locator)
    assert result.status is SourceStatus.MISSING
    assert "no longer exists" in result.reason


def test_line_range_out_of_bounds_is_stale(source_dir, sample_file):
    locator = build_line_locator(source_dir, "logs/app.log", 4)
    sample_file.write_text("only one line\n", encoding="utf-8")
    result = resolve_locator(source_dir, locator)
    assert result.status is SourceStatus.STALE
    assert "no longer exists" in result.reason


def test_path_traversal_is_rejected(source_dir):
    with pytest.raises(ValueError):
        ensure_within_base(source_dir, "../../etc/passwd")


def test_multi_line_locator_covers_full_span(source_dir, sample_file):
    locator = build_line_locator(
        source_dir, "logs/app.log", 2, 3
    )
    result = resolve_locator(source_dir, locator)
    assert result.status is SourceStatus.VALID
    assert result.line == 2 and result.end_line == 3


def test_invalid_construction_inputs_raise(source_dir, sample_file):
    with pytest.raises(ValueError):
        build_line_locator(source_dir, "logs/app.log", 99)
    with pytest.raises(ValueError):
        build_offset_locator(source_dir, "logs/app.log", 10_000, 5)
    with pytest.raises(ValueError):
        build_hash_locator(source_dir, "logs/app.log", "needle missing")
