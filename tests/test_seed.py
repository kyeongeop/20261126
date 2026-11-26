from __future__ import annotations


def test_seeded_demo_is_reviewable(seeded_client):
    candidates = seeded_client.get("/api/candidates").json()
    by_id = {c["id"]: c for c in candidates}
    assert set(by_id) == {"cand-alice", "cand-bob", "cand-carol", "cand-dave"}

    assert by_id["cand-alice"]["status"] == "pending"
    assert by_id["cand-alice"]["confidence"]["label"] == "high"
    assert by_id["cand-bob"]["confidence"]["label"] == "low"
    assert by_id["cand-carol"]["confidence"]["label"] == "medium"
    assert by_id["cand-dave"]["status"] == "merged"


def test_seeded_merged_event_retains_both_records(seeded_client):
    timeline = seeded_client.get("/api/timeline").json()
    assert len(timeline) == 1
    event = seeded_client.get(f"/api/timeline/{timeline[0]['id']}").json()
    assert event["resolution"] == "merged"
    assert len(event["originals"]) == 2
    sources = {o["source_code"] for o in event["originals"]}
    assert sources == {"corp_idp", "vpn_gw"}


def test_seed_is_idempotent(tmp_path):
    from app.database import connect, init_db
    from app.seed import seed_demo

    db = tmp_path / "seed-idem.db"
    conn = connect(str(db))
    init_db(conn)
    first = seed_demo(conn=conn)
    second = seed_demo(conn=conn)
    assert first["seeded"] is True
    assert second["seeded"] is False
    count = conn.execute("SELECT COUNT(*) AS n FROM source_records").fetchone()["n"]
    assert count == 8
    conn.close()
