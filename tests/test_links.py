"""Judgment links: verdicts, reasons, and the hypothesis-card board view."""


def _board(client, hypothesis_id):
    resp = client.get(f"/api/hypotheses/{hypothesis_id}/board")
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_upsert_link_creates_then_updates(client, event_factory, hypothesis_factory):
    event = event_factory()
    hyp = hypothesis_factory()

    resp = client.put(
        f"/api/hypotheses/{hyp['id']}/events/{event['id']}",
        json={"verdict": "support", "reason": "timing matches"},
    )
    assert resp.status_code == 200
    link = resp.json()
    assert link["verdict"] == "support"
    assert link["reason"] == "timing matches"

    resp = client.put(
        f"/api/hypotheses/{hyp['id']}/events/{event['id']}",
        json={"verdict": "refute", "reason": "log contradicts"},
    )
    assert resp.status_code == 200
    updated = resp.json()
    assert updated["id"] == link["id"]
    assert updated["verdict"] == "refute"
    assert updated["reason"] == "log contradicts"

    links = client.get(f"/api/hypotheses/{hyp['id']}/links").json()
    assert len(links) == 1


def test_link_rejects_invalid_verdict(client, event_factory, hypothesis_factory):
    event = event_factory()
    hyp = hypothesis_factory()
    resp = client.put(
        f"/api/hypotheses/{hyp['id']}/events/{event['id']}",
        json={"verdict": "maybe", "reason": ""},
    )
    assert resp.status_code == 422


def test_link_requires_existing_records(client, event_factory, hypothesis_factory):
    event = event_factory()
    hyp = hypothesis_factory()
    assert (
        client.put(
            f"/api/hypotheses/999/events/{event['id']}",
            json={"verdict": "support"},
        ).status_code
        == 404
    )
    assert (
        client.put(
            f"/api/hypotheses/{hyp['id']}/events/999",
            json={"verdict": "support"},
        ).status_code
        == 404
    )


def test_delete_link(client, event_factory, hypothesis_factory):
    event = event_factory()
    hyp = hypothesis_factory()
    client.put(
        f"/api/hypotheses/{hyp['id']}/events/{event['id']}",
        json={"verdict": "unknown", "reason": "not sure"},
    )
    resp = client.delete(f"/api/hypotheses/{hyp['id']}/events/{event['id']}")
    assert resp.status_code == 204
    assert (
        client.delete(f"/api/hypotheses/{hyp['id']}/events/{event['id']}").status_code
        == 404
    )


def test_board_groups_events_by_verdict(client, event_factory, hypothesis_factory):
    e1 = event_factory(title="e1")
    e2 = event_factory(title="e2")
    e3 = event_factory(title="e3")
    hyp = hypothesis_factory()

    client.put(
        f"/api/hypotheses/{hyp['id']}/events/{e1['id']}",
        json={"verdict": "support", "reason": "r1"},
    )
    client.put(
        f"/api/hypotheses/{hyp['id']}/events/{e2['id']}",
        json={"verdict": "refute", "reason": "r2"},
    )
    # e3 has no judgment yet -> unknown bucket.

    board = _board(client, hyp["id"])
    assert board["hypothesis"]["id"] == hyp["id"]
    assert [j["event"]["id"] for j in board["support"]] == [e1["id"]]
    assert board["support"][0]["reason"] == "r1"
    assert [j["event"]["id"] for j in board["refute"]] == [e2["id"]]
    assert [j["event"]["id"] for j in board["unknown"]] == [e3["id"]]
    assert board["unknown"][0]["link_id"] is None


def test_judgments_are_scoped_per_hypothesis(
    client, event_factory, hypothesis_factory
):
    event = event_factory()
    hyp_a = hypothesis_factory(title="A")
    hyp_b = hypothesis_factory(title="B")

    client.put(
        f"/api/hypotheses/{hyp_a['id']}/events/{event['id']}",
        json={"verdict": "support", "reason": "fits A"},
    )

    board_a = _board(client, hyp_a["id"])
    board_b = _board(client, hyp_b["id"])
    assert [j["event"]["id"] for j in board_a["support"]] == [event["id"]]
    assert [j["event"]["id"] for j in board_b["unknown"]] == [event["id"]]


def test_judging_never_modifies_events(client, event_factory, hypothesis_factory):
    """Switching hypotheses and changing judgments must not touch events."""
    event = event_factory(title="deploy", description="v2 rollout")
    before = client.get(f"/api/events/{event['id']}").json()

    hyp_a = hypothesis_factory(title="A")
    hyp_b = hypothesis_factory(title="B")
    client.put(
        f"/api/hypotheses/{hyp_a['id']}/events/{event['id']}",
        json={"verdict": "support", "reason": "x"},
    )
    client.put(
        f"/api/hypotheses/{hyp_a['id']}/events/{event['id']}",
        json={"verdict": "refute", "reason": "y"},
    )
    _board(client, hyp_a["id"])
    _board(client, hyp_b["id"])
    client.delete(f"/api/hypotheses/{hyp_a['id']}/events/{event['id']}")

    after = client.get(f"/api/events/{event['id']}").json()
    assert after == before


def test_deleting_hypothesis_keeps_events(client, event_factory, hypothesis_factory):
    event = event_factory()
    hyp = hypothesis_factory()
    client.put(
        f"/api/hypotheses/{hyp['id']}/events/{event['id']}",
        json={"verdict": "support", "reason": "x"},
    )
    assert client.delete(f"/api/hypotheses/{hyp['id']}").status_code == 204
    resp = client.get(f"/api/events/{event['id']}")
    assert resp.status_code == 200
    assert resp.json()["id"] == event["id"]
