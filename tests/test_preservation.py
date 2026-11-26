"""The core promise: resolving a conflict never loses a raw source record."""

from __future__ import annotations

import json


def test_raw_rows_are_never_deleted_or_updated(client, conn, two_source_pair):
    pair = two_source_pair(user="preserve")
    cid = pair["candidate"]["id"]
    raw_ids = [pair["idp"]["id"], pair["vpn"]["id"]]

    def snapshot():
        rows = conn.execute(
            "SELECT id, occurred_at, payload_json FROM source_records "
            "WHERE id IN (?, ?) ORDER BY id",
            raw_ids,
        ).fetchall()
        return [(r["id"], r["occurred_at"], r["payload_json"]) for r in rows]

    before = snapshot()
    assert len(before) == 2

    # Exercise every resolution path in sequence.
    client.post(f"/api/candidates/{cid}/keep", json={"note": "m"})
    assert snapshot() == before

    client.post(f"/api/candidates/{cid}/reopen", json={})
    assert snapshot() == before

    client.post(f"/api/candidates/{cid}/split", json={})
    assert snapshot() == before

    client.post(f"/api/candidates/{cid}/reopen", json={})
    assert snapshot() == before

    client.post(f"/api/candidates/{cid}/unknown", json={})
    assert snapshot() == before

    # Payload JSON remains parseable and identical in content.
    for rid, when, payload_text in before:
        via_api = client.get(f"/api/records/{rid}").json()
        assert via_api["occurred_at"] == when
        assert via_api["payload"] == json.loads(payload_text)

    # Candidate still references both originals even when marked unknown.
    detail = client.get(f"/api/candidates/{cid}").json()
    assert len(detail["records"]) == 2


def test_merged_event_traceability_links_every_source(client, conn, two_source_pair):
    pair = two_source_pair(user="trace")
    cid = pair["candidate"]["id"]
    event_id = client.post(f"/api/candidates/{cid}/keep", json={}).json()[
        "canonical_event_id"
    ]

    link_count = conn.execute(
        "SELECT COUNT(*) AS n FROM timeline_event_records WHERE event_id = ?",
        (event_id,),
    ).fetchone()["n"]
    assert link_count == 2

    # Deleting the derived event (e.g. via reopen) cascades only links,
    # never the source records.
    client.post(f"/api/candidates/{cid}/reopen", json={})
    remaining_links = conn.execute(
        "SELECT COUNT(*) AS n FROM timeline_event_records WHERE event_id = ?",
        (event_id,),
    ).fetchone()["n"]
    assert remaining_links == 0
    raw_count = conn.execute("SELECT COUNT(*) AS n FROM source_records").fetchone()["n"]
    assert raw_count == 2
