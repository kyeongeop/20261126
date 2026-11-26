"""Shared pytest fixtures: isolated app, temp sources and API clients."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


TOKENS = {
    "admin": "token-admin-alice",
    "investigator": "token-investigator-bob",
    "viewer": "token-viewer-carol",
}


@pytest.fixture()
def tmp_settings(tmp_path: Path) -> Settings:
    source_dir = tmp_path / "sources"
    source_dir.mkdir()
    return Settings(
        base_dir=tmp_path,
        source_dir=source_dir,
        db_path=tmp_path / "timeline.db",
    )


@pytest.fixture()
def client(tmp_settings: Settings) -> TestClient:
    app = create_app(tmp_settings)
    return TestClient(app)


@pytest.fixture()
def source_dir(tmp_settings: Settings) -> Path:
    return tmp_settings.source_dir


def auth(role: str) -> dict:
    return {"X-API-Token": TOKENS[role]}


@pytest.fixture()
def incident_id(client: TestClient) -> int:
    resp = client.post(
        "/incidents",
        headers=auth("admin"),
        json={"title": "DB outage INC-42"},
    )
    assert resp.status_code == 201
    return resp.json()["id"]


@pytest.fixture()
def event_id(client: TestClient, incident_id: int) -> int:
    resp = client.post(
        f"/incidents/{incident_id}/events",
        headers=auth("investigator"),
        json={
            "occurred_at": "2026-11-26T01:30:00+08:00",
            "summary": "Primary database failover triggered",
        },
    )
    assert resp.status_code == 201
    return resp.json()["id"]
