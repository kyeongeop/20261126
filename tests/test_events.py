def test_create_and_list_events(client, event_factory):
    first = event_factory(title="disk alert", occurred_at="2026-11-26T08:01:00Z")
    second = event_factory(title="deploy started", occurred_at="2026-11-26T08:00:00Z")

    resp = client.get("/api/events")
    assert resp.status_code == 200
    events = resp.json()
    assert [e["id"] for e in events] == [second["id"], first["id"]]
    assert events[1]["title"] == "disk alert"


def test_get_event(client, event_factory):
    created = event_factory()
    resp = client.get(f"/api/events/{created['id']}")
    assert resp.status_code == 200
    assert resp.json()["title"] == created["title"]


def test_get_missing_event_returns_404(client):
    assert client.get("/api/events/999").status_code == 404


def test_event_title_required(client):
    resp = client.post(
        "/api/events",
        json={"occurred_at": "2026-11-26T08:00:00Z", "title": ""},
    )
    assert resp.status_code == 422
