from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from incident_evidence.config import Settings
from incident_evidence.main import create_app

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    data_dir = tmp_path / "data"
    return Settings(
        data_dir=data_dir,
        db_path=data_dir / "incidents.sqlite3",
        signing_key_path=data_dir / "keys" / "evidence-signing-key.pem",
        max_upload_bytes=2 * 1024 * 1024,
    )


@pytest.fixture
def client(settings: Settings) -> Iterator[TestClient]:
    with TestClient(create_app(settings)) as test_client:
        yield test_client


@pytest.fixture
def sample() -> dict[str, Any]:
    return json.loads((FIXTURES / "sample_incident.json").read_text("utf-8"))


@pytest.fixture
def seeded(client: TestClient, sample: dict[str, Any]) -> dict[str, Any]:
    created = client.post(
        "/api/incidents",
        json={
            "title": sample["title"],
            "description": sample["description"],
            "source_config": sample["source_config"],
        },
    )
    assert created.status_code == 201, created.text
    incident = created.json()

    artifact_ids: list[str] = []
    for path in (
        FIXTURES / "raw" / "checkout-api.log",
        FIXTURES / "raw" / "edge-proxy.log",
    ):
        with path.open("rb") as handle:
            response = client.post(
                f"/api/incidents/{incident['id']}/raw-files",
                files={"file": (path.name, handle, "text/plain")},
                data={
                    "source": "fixture",
                    "description": f"captured {path.name}",
                    "captured_at": "2026-11-25T08:25:00Z",
                },
            )
        assert response.status_code == 201, response.text
        artifact_ids.append(response.json()["id"])

    event_ids: list[str] = []
    for index, event in enumerate(sample["events"]):
        payload = dict(event)
        if index == 0:
            payload["artifact_ids"] = artifact_ids
        response = client.post(
            f"/api/incidents/{incident['id']}/events",
            json=payload,
        )
        assert response.status_code == 201, response.text
        event_ids.append(response.json()["id"])

    return {
        "incident": incident,
        "artifact_ids": artifact_ids,
        "event_ids": event_ids,
        "sample": sample,
    }


@pytest.fixture
def exported(
    client: TestClient,
    settings: Settings,
    seeded: dict[str, Any],
) -> dict[str, Any]:
    response = client.post(
        f"/api/incidents/{seeded['incident']['id']}/evidence-packages",
        json={"exporter": seeded["sample"]["exporter"]},
    )
    assert response.status_code == 201, response.text
    metadata = response.json()
    package_path = settings.packages_dir / metadata["filename"]
    return {
        "metadata": metadata,
        "path": package_path,
        "public_key": settings.public_key_path,
        "seeded": seeded,
    }

