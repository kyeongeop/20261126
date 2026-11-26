"""Judgment links between hypotheses and events."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_session
from app.models import Event, Hypothesis, HypothesisEventLink
from app.schemas import LinkOut, LinkUpsert

router = APIRouter(prefix="/api/hypotheses", tags=["links"])


def _get_link(session: Session, hypothesis_id: int, event_id: int):
    stmt = select(HypothesisEventLink).where(
        HypothesisEventLink.hypothesis_id == hypothesis_id,
        HypothesisEventLink.event_id == event_id,
    )
    return session.scalars(stmt).first()


@router.put("/{hypothesis_id}/events/{event_id}", response_model=LinkOut)
def upsert_link(
    hypothesis_id: int,
    event_id: int,
    payload: LinkUpsert,
    session: Session = Depends(get_session),
):
    """Create or replace the judgment for one (hypothesis, event) pair."""
    if session.get(Hypothesis, hypothesis_id) is None:
        raise HTTPException(status_code=404, detail="hypothesis not found")
    if session.get(Event, event_id) is None:
        raise HTTPException(status_code=404, detail="event not found")

    link = _get_link(session, hypothesis_id, event_id)
    if link is None:
        link = HypothesisEventLink(hypothesis_id=hypothesis_id, event_id=event_id)
        session.add(link)
    link.verdict = payload.verdict
    link.reason = payload.reason
    session.commit()
    session.refresh(link)
    return link


@router.get("/{hypothesis_id}/links", response_model=list[LinkOut])
def list_links(hypothesis_id: int, session: Session = Depends(get_session)):
    if session.get(Hypothesis, hypothesis_id) is None:
        raise HTTPException(status_code=404, detail="hypothesis not found")
    stmt = (
        select(HypothesisEventLink)
        .where(HypothesisEventLink.hypothesis_id == hypothesis_id)
        .order_by(HypothesisEventLink.id)
    )
    return list(session.scalars(stmt))


@router.delete("/{hypothesis_id}/events/{event_id}", status_code=204)
def delete_link(
    hypothesis_id: int, event_id: int, session: Session = Depends(get_session)
):
    link = _get_link(session, hypothesis_id, event_id)
    if link is None:
        raise HTTPException(status_code=404, detail="link not found")
    session.delete(link)
    session.commit()
