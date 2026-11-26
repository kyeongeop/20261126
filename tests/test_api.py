def test_create_incident_and_events(seeded_client):
    incident_id = 1
    resp = seeded_client.get(f"/incidents/{incident_id}/events")
    assert resp.status_code == 200
    assert len(resp.json()["events"]) == 3


def test_rules_seeded_from_fixtures(seeded_client):
    resp = seeded_client.get("/rules")
    names = {r["name"] for r in resp.json()["rules"]}
    assert names == {
        "internal-hostname",
        "email-address",
        "api-token",
        "reporter-email-field",
    }


def test_export_preview_redacts_and_counts(seeded_client):
    event_id = seeded_client.fixture_event_ids[0]
    resp = seeded_client.get(f"/events/{event_id}/export/preview")
    assert resp.status_code == 200
    body = resp.json()
    assert body["preview"] is True
    message = body["event"]["payload"]["message"]
    assert "web-01.prod.internal" not in message
    assert "alice.chen@corp.example.net" not in message
    assert body["replacements"]["internal-hostname"] == 1
    assert body["replacements"]["email-address"] == 1
    assert body["replacements"]["reporter-email-field"] == 1
    assert body["total_replacements"] == 3


def test_export_respects_exceptions(seeded_client):
    event_id = seeded_client.fixture_event_ids[2]
    body = seeded_client.get(f"/events/{event_id}/export").json()
    payload = body["event"]["payload"]
    assert "status.prod.internal" in payload["links"][1]
    assert "team@example.com" in payload["message"]
    assert "tok_0000example00001" in payload["runbook"]
    assert "db-03.prod.internal" not in payload["message"]
    assert "bob.li@corp.example.net" not in payload["message"]


def test_repeated_export_is_identical(seeded_client):
    event_id = seeded_client.fixture_event_ids[1]
    first = seeded_client.get(f"/events/{event_id}/export").json()
    second = seeded_client.get(f"/events/{event_id}/export").json()
    assert first == second
    message = first["event"]["payload"]["message"]
    assert "tok_a1b2c3d4e5f6g7h8" not in message
    assert first["replacements"]["api-token"] == 1


def test_preview_and_export_match(seeded_client):
    event_id = seeded_client.fixture_event_ids[0]
    preview = seeded_client.get(f"/events/{event_id}/export/preview").json()
    final = seeded_client.get(f"/events/{event_id}/export").json()
    assert preview["event"] == final["event"]
    assert preview["replacements"] == final["replacements"]


def test_export_unknown_event_404(seeded_client):
    assert seeded_client.get("/events/999/export").status_code == 404


def test_add_rule_via_api(seeded_client):
    resp = seeded_client.put(
        "/rules/internal-ip",
        json={
            "spec": {"type": "regex", "label": "ip", "pattern": r"\b10\.\d+\.\d+\.\d+\b"}
        },
    )
    assert resp.status_code == 200
    incident_id = 1
    resp = seeded_client.post(
        f"/incidents/{incident_id}/events",
        json={
            "occurred_at": "2026-11-20T11:00:00Z",
            "payload": {"message": "ssh into 10.1.2.3 failed"},
        },
    )
    event_id = resp.json()["id"]
    body = seeded_client.get(f"/events/{event_id}/export").json()
    assert "10.1.2.3" not in body["event"]["payload"]["message"]
    assert body["replacements"]["internal-ip"] == 1


def test_invalid_rule_rejected(seeded_client):
    resp = seeded_client.put("/rules/bad", json={"spec": {"type": "magic"}})
    assert resp.status_code == 422


def test_duplicate_event_ingest_is_idempotent(seeded_client):
    event = {
        "occurred_at": "2026-11-20T09:15:00Z",
        "actor": "oncall-bot",
        "payload": {
            "message": "Alert fired on web-01.prod.internal; notified alice.chen@corp.example.net",
            "reporter": {"name": "Alice Chen", "email": "alice.chen@corp.example.net"},
            "severity": "sev2",
        },
    }
    resp = seeded_client.post("/incidents/1/events", json=event)
    assert resp.json()["id"] == seeded_client.fixture_event_ids[0]
    events = seeded_client.get("/incidents/1/events").json()["events"]
    assert len(events) == 3
