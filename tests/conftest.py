from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import create_app


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    application = create_app(tmp_path / "incident-timeline.db")
    with TestClient(application) as test_client:
        yield test_client


def analyst_headers(analyst_id: int) -> dict[str, str]:
    return {"X-Analyst-Id": str(analyst_id)}


def create_analyst(client: TestClient, name: str) -> dict[str, object]:
    response = client.post("/api/analysts", json={"name": name})
    assert response.status_code == 201
    return response.json()


def create_case(client: TestClient, owner_id: int, title: str = "事故案件") -> int:
    response = client.post(
        "/api/cases",
        json={"title": title, "description": "时间线测试"},
        headers=analyst_headers(owner_id),
    )
    assert response.status_code == 201
    return int(response.json()["id"])
