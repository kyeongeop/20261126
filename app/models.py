"""ORM models for the incident timeline."""

from __future__ import annotations

import enum
from datetime import datetime, timezone

from sqlalchemy import DateTime, Enum, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Verdict(str, enum.Enum):
    SUPPORT = "support"
    REFUTE = "refute"
    UNKNOWN = "unknown"


class Event(Base):
    """An immutable-by-link incident timeline event.

    Linking an event to a hypothesis never mutates this row.
    """

    __tablename__ = "events"

    id: Mapped[int] = mapped_column(primary_key=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(200), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    links: Mapped[list["HypothesisEventLink"]] = relationship(
        back_populates="event", cascade="all, delete-orphan"
    )


class Hypothesis(Base):
    __tablename__ = "hypotheses"

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    statement: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    links: Mapped[list["HypothesisEventLink"]] = relationship(
        back_populates="hypothesis", cascade="all, delete-orphan"
    )


class HypothesisEventLink(Base):
    """A judgment tying one event to one hypothesis, with a reason."""

    __tablename__ = "hypothesis_event_links"
    __table_args__ = (
        UniqueConstraint("hypothesis_id", "event_id", name="uq_hypothesis_event"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    hypothesis_id: Mapped[int] = mapped_column(
        ForeignKey("hypotheses.id", ondelete="CASCADE"), index=True
    )
    event_id: Mapped[int] = mapped_column(
        ForeignKey("events.id", ondelete="CASCADE"), index=True
    )
    verdict: Mapped[Verdict] = mapped_column(Enum(Verdict), default=Verdict.UNKNOWN)
    reason: Mapped[str] = mapped_column(Text, default="")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    hypothesis: Mapped[Hypothesis] = relationship(back_populates="links")
    event: Mapped[Event] = relationship(back_populates="links")
