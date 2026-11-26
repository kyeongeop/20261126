from __future__ import annotations


def _source(client, code="idp"):
    client.post(
        "/api/sources",
        json={"code": code, "name": code.upper(), "reliability": 0.9},
    )


def test_unknown_source_is_rejected(client):
    r = client.post(
        "/api/records",
        json={
            "source_code": "ghost",
            "external_id": "x1",
            "user_id": "u",
            "occurred_at": "2026-11-20T09:00:00Z",
        },
    )
    assert r.status_code == 422


def test_duplicate_ingestion_never_overwrites_original(client):
    _source(client)
    payload = {"ip_address": "203.0.113.1", "nested": {"k": [1, 2, 3]}}
    first = client.post(
        "/api/records",
        json={
            "source_code": "idp",
            "external_id": "EVT-1",
            "user_id": "alice",
            "occurred_at": "2026-11-20T09:00:00Z",
            "payload": payload,
        },
    ).json()
    assert first["created"] is True

    second = client.post(
        "/api/records",
        json={
            "source_code": "idp",
            "external_id": "EVT-1",
            "user_id": "alice",
            # A conflicting re-delivery must not mutate the stored original.
            "occurred_at": "2030-01-01T00:00:00Z",
            "payload": {"tampered": True},
        },
    ).json()
    assert second["created"] is False
    assert second["record"]["id"] == first["record"]["id"]
    assert second["record"]["occurred_at"] == "2026-11-20T09:00:00Z"
    assert second["record"]["payload"] == payload


def test_batch_auto_detects_candidate(client):
    client.post("/api/sources", json={"code": "a", "name": "A", "reliability": 0.9})
    client.post("/api/sources", json={"code": "b", "name": "B", "reliability": 0.7})
    r = client.post(
        "/api/records/batch",
        json={
            "auto_detect": True,
            "records": [
                {
                    "source_code": "a",
                    "external_id": "1",
                    "user_id": "zoe",
                    "occurred_at": "2026-11-20T09:00:00Z",
                    "payload": {"ip_address": "10.0.0.1"},
                },
                {
                    "source_code": "b",
                    "external_id": "2",
                    "user_id": "zoe",
                    "occurred_at": "2026-11-20T09:03:00Z",
                    "payload": {"ip_address": "10.0.0.1"},
                },
            ],
        },
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["ingested"] == 2
    assert len(body["detected_candidates"]) == 1

    # Detection is idempotent: no second group on re-run.
    again = client.post("/api/candidates/detect").json()
    assert again["created"] == 0


def test_explicit_candidate_requires_two_records(client):
    r = client.post("/api/candidates", json={"record_ids": ["only-one"]})
    assert r.status_code == 422


def test_overlapping_candidate_groups_conflict(client, two_source_pair):
    pair = two_source_pair(user="ivan")
    idp_id = pair["idp"]["id"]
    # A third record so we can attempt an overlapping group.
    third = client.post(
        "/api/records",
        json={
            "source_code": "vpn",
            "external_id": "VPN-ivan-2",
            "user_id": "ivan",
            "occurred_at": "2026-11-20T11:00:00Z",
        },
    ).json()["record"]
    r = client.post("/api/candidates", json={"record_ids": [idp_id, third["id"]]})
    assert r.status_code == 409


def test_missing_candidate_returns_404(client):
    assert client.get("/api/candidates/nope").status_code == 404
    assert client.post("/api/candidates/nope/keep", json={}).status_code == 404
