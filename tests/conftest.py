from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_session
from app.main import create_app


@pytest.fixture()
def client():
    # StaticPool shares one in-memory database across connections.
    engine = create_engine(
        "sqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    TestingSession = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    Base.metadata.create_all(engine)

    app = create_app()

    def override_session():
        session = TestingSession()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_session] = override_session
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture()
def event_factory(client):
    counter = {"n": 0}

    def create(**overrides):
        counter["n"] += 1
        payload = {
            "occurred_at": f"2026-11-26T08:0{counter['n']}:00Z",
            "title": f"event-{counter['n']}",
            "description": "something happened",
            "source": "monitor",
        }
        payload.update(overrides)
        resp = client.post("/api/events", json=payload)
        assert resp.status_code == 201, resp.text
        return resp.json()

    return create


@pytest.fixture()
def hypothesis_factory(client):
    counter = {"n": 0}

    def create(**overrides):
        counter["n"] += 1
        payload = {
            "title": f"hypothesis-{counter['n']}",
            "statement": "a possible cause",
        }
        payload.update(overrides)
        resp = client.post("/api/hypotheses", json=payload)
        assert resp.status_code == 201, resp.text
        return resp.json()

    return create
