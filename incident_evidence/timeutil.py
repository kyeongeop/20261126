from __future__ import annotations

from datetime import datetime, timezone


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def to_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return value.astimezone(timezone.utc)


def iso_utc(value: datetime) -> str:
    normalized = to_utc(value)
    return normalized.isoformat(timespec="microseconds").replace("+00:00", "Z")


def utc_now_iso() -> str:
    return iso_utc(utc_now())

