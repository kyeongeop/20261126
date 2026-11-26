"""Hypotheses and the hypothesis-card board view."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_session
from app.models import Event, Hypothesis, HypothesisEventLink, Verdict
from app.schemas import (
    HypothesisBoard,
    HypothesisCreate,
    HypothesisOut,
    HypothesisUpdate,
    JudgedEvent,
)

router = APIRouter(prefix="/api/hypotheses", tags=["hypotheses"])


def _get_hypothesis_or_404(session: Session, hypothesis_id: int) -> Hypothesis:
    hypothesis = session.get(Hypothesis, hypothesis_id)
    if hypothesis is None:
        raise HTTPException(status_code=404, detail="hypothesis not found")
    return hypothesis


@router.post("", response_model=HypothesisOut, status_code=201)
def create_hypothesis(
    payload: HypothesisCreate, session: Session = Depends(get_session)
):
    hypothesis = Hypothesis(**payload.model_dump())
    session.add(hypothesis)
    session.commit()
    session.refresh(hypothesis)
    return hypothesis


@router.get("", response_model=list[HypothesisOut])
def list_hypotheses(session: Session = Depends(get_session)):
    stmt = select(Hypothesis).order_by(Hypothesis.id)
    return list(session.scalars(stmt))


@router.get("/{hypothesis_id}", response_model=HypothesisOut)
def get_hypothesis(hypothesis_id: int, session: Session = Depends(get_session)):
    return _get_hypothesis_or_404(session, hypothesis_id)


@router.patch("/{hypothesis_id}", response_model=HypothesisOut)
def update_hypothesis(
    hypothesis_id: int,
    payload: HypothesisUpdate,
    session: Session = Depends(get_session),
):
    hypothesis = _get_hypothesis_or_404(session, hypothesis_id)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(hypothesis, field, value)
    session.commit()
    session.refresh(hypothesis)
    return hypothesis


@router.delete("/{hypothesis_id}", status_code=204)
def delete_hypothesis(hypothesis_id: int, session: Session = Depends(get_session)):
    hypothesis = _get_hypothesis_or_404(session, hypothesis_id)
    session.delete(hypothesis)
    session.commit()


@router.get("/{hypothesis_id}/board", response_model=HypothesisBoard)
def get_board(hypothesis_id: int, session: Session = Depends(get_session)):
    """Hypothesis card: every event shown under this hypothesis's verdicts.

    Purely a read-only projection - switching hypotheses never touches events.
    """
    hypothesis = _get_hypothesis_or_404(session, hypothesis_id)

    events = list(session.scalars(select(Event).order_by(Event.occurred_at, Event.id)))
    links = list(
        session.scalars(
            select(HypothesisEventLink).where(
                HypothesisEventLink.hypothesis_id == hypothesis_id
            )
        )
    )
    links_by_event = {link.event_id: link for link in links}

    board: dict[Verdict, list[JudgedEvent]] = {
        Verdict.SUPPORT: [],
        Verdict.REFUTE: [],
        Verdict.UNKNOWN: [],
    }
    for event in events:
        link = links_by_event.get(event.id)
        verdict = link.verdict if link else Verdict.UNKNOWN
        judged = JudgedEvent(
            event=event,
            verdict=verdict,
            reason=link.reason if link else "",
            link_id=link.id if link else None,
        )
        board[verdict].append(judged)

    return HypothesisBoard(
        hypothesis=hypothesis,
        support=board[Verdict.SUPPORT],
        refute=board[Verdict.REFUTE],
        unknown=board[Verdict.UNKNOWN],
    )
