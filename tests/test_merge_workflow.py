from __future__ import annotations


def test_candidate_detail_exposes_times_diff_confidence(two_source_pair):
    pair = two_source_pair()
    cid = pair["candidate"]["id"]

    detail = pair["candidate"]
    assert detail["status"] == "pending"

    # Per-source times are present and ordered earliest-first.
    times = detail["time_comparison"]
    assert [e["source_code"] for e in times["entries"]] == ["idp", "vpn"]
    assert times["delta_seconds"] > 0

    # Field differences are explicitly represented.
    diff = {f["field"]: f for f in detail["field_diff"]}
    assert diff["session_id"]["conflict"] is True
    assert diff["ip_address"]["conflict"] is False

    # Confidence carries a score, label and explanation components.
    conf = detail["confidence"]
    assert 0 <= conf["score"] <= 1
    assert conf["label"] in {"high", "medium", "low"}
    assert len(conf["components"]) == 3

    # Both raw records are embedded for the review screen.
    assert {r["id"] for r in detail["records"]} == {
        pair["idp"]["id"],
        pair["vpn"]["id"],
    }


def test_keep_merges_and_preserves_all_originals(client, two_source_pair):
    pair = two_source_pair()
    cid = pair["candidate"]["id"]

    response = client.post(
        f"/api/candidates/{cid}/keep",
        json={"analyst": "lin", "note": "clock skew, same laptop"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "merged"
    event_id = body["canonical_event_id"]
    assert event_id

    # One merged timeline event references BOTH sources.
    event = client.get(f"/api/timeline/{event_id}").json()
    assert event["resolution"] == "merged"
    assert set(event["record_ids"]) == {pair["idp"]["id"], pair["vpn"]["id"]}
    assert len(event["originals"]) == 2

    # Dedicated originals endpoint returns the same immutable records.
    originals = client.get(f"/api/events/{event_id}/records").json()
    assert len(originals) == 2
    by_id = {r["id"]: r for r in originals}
    assert by_id[pair["idp"]["id"]]["payload"]["device_id"] == "dev-77"
    assert by_id[pair["vpn"]["id"]]["source_code"] == "vpn"

    # Timeline list contains exactly the one merged event for this pair.
    timeline = client.get("/api/timeline").json()
    mine = [e for e in timeline if e["candidate_id"] == cid]
    assert len(mine) == 1
    assert mine[0]["record_count"] == 2


def test_keep_can_choose_which_source_time_wins(client, two_source_pair):
    pair = two_source_pair()
    cid = pair["candidate"]["id"]

    body = client.post(
        f"/api/candidates/{cid}/keep",
        json={"time_source_record_id": pair["vpn"]["id"]},
    ).json()
    event = client.get(f"/api/timeline/{body['canonical_event_id']}").json()
    assert event["event_time"] == "2026-11-20T09:04:57Z"
    assert event["field_sources"]["occurred_at"] == pair["vpn"]["id"]


def test_split_creates_independent_events_without_losing_records(
    client, two_source_pair
):
    pair = two_source_pair()
    cid = pair["candidate"]["id"]

    response = client.post(f"/api/candidates/{cid}/split", json={"analyst": "lin"})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "split"
    assert len(body["events"]) == 2
    assert {e["record_count"] for e in body["events"]} == {1}

    timeline = client.get("/api/timeline").json()
    mine = [e for e in timeline if e["candidate_id"] == cid]
    assert len(mine) == 2

    # Each split event keeps its own original, and both raw rows still exist.
    all_originals: list[dict] = []
    for event in mine:
        recs = client.get(f"/api/events/{event['id']}/records").json()
        assert len(recs) == 1
        all_originals.extend(recs)
    assert {r["id"] for r in all_originals} == {
        pair["idp"]["id"],
        pair["vpn"]["id"],
    }
    raw_records = client.get("/api/records").json()
    assert len(raw_records) == 2


def test_mark_unknown_keeps_records_but_adds_no_event(client, two_source_pair):
    pair = two_source_pair()
    cid = pair["candidate"]["id"]

    response = client.post(
        f"/api/candidates/{cid}/unknown", json={"note": "need EDR correlation"}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "unknown"
    assert body["canonical_event_id"] is None
    assert body["allowed_actions"] == ["keep", "split", "reopen"]

    # Unknown candidate still exposes both originals.
    records = client.get(f"/api/candidates/{cid}/records").json()
    assert len(records) == 2
    assert client.get("/api/timeline").json() == []


def test_reopen_after_merge_deletes_only_derived_event(client, two_source_pair):
    pair = two_source_pair()
    cid = pair["candidate"]["id"]
    kept = client.post(f"/api/candidates/{cid}/keep", json={}).json()
    event_id = kept["canonical_event_id"]
    assert client.get(f"/api/timeline/{event_id}").status_code == 200

    reopened = client.post(f"/api/candidates/{cid}/reopen", json={}).json()
    assert reopened["status"] == "pending"
    assert client.get(f"/api/timeline/{event_id}").status_code == 404

    # Raw originals survive the reopen untouched.
    raw = {r["id"]: r for r in client.get("/api/records").json()}
    assert pair["idp"]["id"] in raw and pair["vpn"]["id"] in raw

    # Analyst can now split instead.
    split = client.post(f"/api/candidates/{cid}/split", json={}).json()
    assert split["status"] == "split"
    assert len(split["events"]) == 2


def test_resolved_candidate_rejects_second_decision_until_reopen(
    client, two_source_pair
):
    pair = two_source_pair()
    cid = pair["candidate"]["id"]
    assert client.post(f"/api/candidates/{cid}/keep", json={}).status_code == 200
    assert client.post(f"/api/candidates/{cid}/split", json={}).status_code == 409


def test_generic_resolve_endpoint_supports_all_decisions(client, two_source_pair):
    pair = two_source_pair(user="bob")
    cid = pair["candidate"]["id"]
    r = client.post(
        f"/api/candidates/{cid}/resolve", json={"decision": "unknown"}
    )
    assert r.status_code == 200 and r.json()["status"] == "unknown"

    r = client.post(
        f"/api/candidates/{cid}/resolve", json={"decision": "keep", "analyst": "x"}
    )
    assert r.status_code == 200 and r.json()["status"] == "merged"

    cid2 = two_source_pair(user="carol")["candidate"]["id"]
    r = client.post(
        f"/api/candidates/{cid2}/resolve", json={"decision": "split"}
    )
    assert r.status_code == 200 and r.json()["status"] == "split"


def test_audit_actions_are_recorded(client, two_source_pair):
    pair = two_source_pair()
    cid = pair["candidate"]["id"]
    client.post(f"/api/candidates/{cid}/keep", json={"analyst": "lin"})
    actions = client.get(f"/api/candidates/{cid}/actions").json()
    assert [a["action"] for a in actions] == ["keep"]
    assert actions[0]["analyst"] == "lin"
