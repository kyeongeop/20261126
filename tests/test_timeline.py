from __future__ import annotations

from fastapi.testclient import TestClient


def test_health(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_incident_and_timeline_are_sorted(
    client: TestClient,
    seeded: dict,
) -> None:
    incident_id = seeded["incident"]["id"]
    incident = client.get(f"/api/incidents/{incident_id}")
    assert incident.status_code == 200
    assert incident.json()["source_config"]["environment"] == "production"

    timeline = client.get(f"/api/incidents/{incident_id}/timeline")
    assert timeline.status_code == 200
    payload = timeline.json()
    assert payload["event_count"] == 3
    occurred = [event["occurred_at"] for event in payload["events"]]
    assert occurred == sorted(occurred)
    assert payload["events"][0]["artifact_ids"] == seeded["artifact_ids"]
    assert payload["events"][0]["occurred_at"] == "2026-11-25T08:02:00.000000Z"


def test_rejects_artifact_from_another_incident(
    client: TestClient,
    seeded: dict,
) -> None:
    other = client.post(
        "/api/incidents",
        json={
            "title": "Other incident",
            "description": "",
            "source_config": {},
        },
    ).json()
    response = client.post(
        f"/api/incidents/{other['id']}/events",
        json={
            "occurred_at": "2026-11-25T09:00:00Z",
            "title": "Cross-linked event",
            "artifact_ids": seeded["artifact_ids"],
        },
    )
    assert response.status_code == 422
    assert "do not belong" in response.json()["detail"]


def test_naive_timestamp_is_rejected(
    client: TestClient,
    seeded: dict,
) -> None:
    response = client.post(
        f"/api/incidents/{seeded['incident']['id']}/events",
        json={
            "occurred_at": "2026-11-25T09:00:00",
            "title": "No timezone",
        },
    )
    assert response.status_code == 422


def test_missing_incident_returns_404(client: TestClient) -> None:
    response = client.get("/api/incidents/inc_missing")
    assert response.status_code == 404

