from __future__ import annotations


def test_index_and_static_assets_are_served(client):
    index = client.get("/")
    assert index.status_code == 200
    assert "冲突事件合并".encode() in index.content

    js = client.get("/static/app.js")
    assert js.status_code == 200
    assert b"decide" in js.content

    css = client.get("/static/styles.css")
    assert css.status_code == 200


def test_reset_demo_rebuilds_seed_data(client):
    # Start from an empty app, add junk, then reset to the deterministic demo.
    client.post("/api/sources", json={"code": "x", "name": "X", "reliability": 0.5})
    res = client.post("/api/admin/reset-demo")
    assert res.status_code == 200
    assert res.json()["seeded"] is True

    candidates = client.get("/api/candidates").json()
    assert len(candidates) == 4
    records = client.get("/api/records").json()
    assert len(records) == 8

    # Reset again stays deterministic and does not duplicate rows.
    client.post("/api/admin/reset-demo")
    assert len(client.get("/api/records").json()) == 8


def test_openapi_lists_core_routes(client):
    spec = client.get("/openapi.json").json()
    paths = spec["paths"]
    for path in (
        "/api/candidates",
        "/api/candidates/{candidate_id}/keep",
        "/api/candidates/{candidate_id}/split",
        "/api/candidates/{candidate_id}/unknown",
        "/api/timeline",
        "/api/events/{event_id}/records",
    ):
        assert path in paths


def test_merge_alias_and_memory_app_work():
    from fastapi.testclient import TestClient

    from app.main import create_app

    app = create_app(":memory:", seed=True)
    with TestClient(app) as mem_client:
        candidates = mem_client.get("/api/candidates?status=pending").json()
        alice = next(c for c in candidates if c["id"] == "cand-alice")
        r = mem_client.post(f"/api/candidates/{alice['id']}/merge", json={})
        assert r.status_code == 200, r.text
        assert r.json()["status"] == "merged"
        timeline = mem_client.get("/api/timeline").json()
        # Seeded dave + merged alice.
        assert len(timeline) == 2
