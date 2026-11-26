import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.db import Store
from app.main import build_redactor, create_app

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def load_fixture(name: str):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


@pytest.fixture
def store():
    store = Store(":memory:")
    for rule in load_fixture("rules.json"):
        store.upsert_rule(rule["name"], rule["spec"])
    yield store
    store.close()


@pytest.fixture
def redactor(store):
    return build_redactor(store)


@pytest.fixture
def client(store):
    return TestClient(create_app(store))


@pytest.fixture
def seeded_client(client):
    incident_id = client.post("/incidents", json={"title": "web outage"}).json()["id"]
    event_ids = []
    for event in load_fixture("events.json"):
        resp = client.post(f"/incidents/{incident_id}/events", json=event)
        event_ids.append(resp.json()["id"])
    client.fixture_event_ids = event_ids
    return client
