def test_hypothesis_crud(client, hypothesis_factory):
    created = hypothesis_factory(title="cache regression")
    assert created["title"] == "cache regression"

    resp = client.get("/api/hypotheses")
    assert [h["id"] for h in resp.json()] == [created["id"]]

    resp = client.patch(
        f"/api/hypotheses/{created['id']}", json={"statement": "bad deploy"}
    )
    assert resp.status_code == 200
    assert resp.json()["statement"] == "bad deploy"
    assert resp.json()["title"] == "cache regression"

    resp = client.delete(f"/api/hypotheses/{created['id']}")
    assert resp.status_code == 204
    assert client.get(f"/api/hypotheses/{created['id']}").status_code == 404


def test_update_missing_hypothesis_returns_404(client):
    resp = client.patch("/api/hypotheses/999", json={"title": "x"})
    assert resp.status_code == 404
