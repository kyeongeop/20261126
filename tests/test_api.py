"""End-to-end API tests: auth, RBAC, evidence lifecycle and staleness."""

from __future__ import annotations

from pathlib import Path

from conftest import auth


def _write_source(source_dir: Path, name: str, text: str) -> None:
    path = source_dir / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_health_is_open(client):
    resp = client.get("/health")
    assert resp.status_code == 200


def test_missing_and_invalid_tokens_are_rejected(client):
    assert client.get("/incidents").status_code == 401
    resp = client.get("/incidents", headers={"X-API-Token": "nope"})
    assert resp.status_code == 401


def test_bearer_authorization_header_works(client):
    resp = client.get(
        "/me", headers={"Authorization": "Bearer token-viewer-carol"}
    )
    assert resp.status_code == 200
    assert resp.json()["role"] == "viewer"


def test_role_hierarchy_enforced(client, incident_id):
    # viewer cannot create incidents or events
    denied = client.post(
        "/incidents", headers=auth("viewer"), json={"title": "x"}
    )
    assert denied.status_code == 403
    denied_event = client.post(
        f"/incidents/{incident_id}/events",
        headers=auth("viewer"),
        json={"occurred_at": "2026-11-26T00:00:00Z", "summary": "x"},
    )
    assert denied_event.status_code == 403

    # investigator cannot create incidents
    denied_inc = client.post(
        "/incidents", headers=auth("investigator"),
        json={"title": "x"},
    )
    assert denied_inc.status_code == 403

    # but investigator can read
    ok = client.get("/incidents", headers=auth("investigator"))
    assert ok.status_code == 200


def test_full_evidence_lifecycle_and_timeline_status(
    client, source_dir, incident_id, event_id
):
    _write_source(
        source_dir, "logs/app.log",
        "boot ok\nalert: disk full\nshutdown\n",
    )

    created = client.post(
        f"/events/{event_id}/evidence",
        headers=auth("investigator"),
        json={
            "kind": "line",
            "file_path": "logs/app.log",
            "line": 2,
            "label": "disk alert line",
        },
    )
    assert created.status_code == 201
    evidence = created.json()
    assert evidence["content_hash_prefix"]
    assert evidence["file_hash_prefix"]
    evidence_id = evidence["id"]

    resolution = client.get(
        f"/evidence/{evidence_id}", headers=auth("viewer")
    )
    assert resolution.status_code == 200
    body = resolution.json()
    assert body["status"] == "valid"
    assert body["line"] == 2
    assert "disk full" in body["snippet"]

    timeline = client.get(
        f"/incidents/{incident_id}/timeline", headers=auth("viewer")
    )
    assert timeline.status_code == 200
    entry = timeline.json()[0]
    assert entry["resolutions"][0]["status"] == "valid"

    # File update: stale must be surfaced through both endpoints.
    _write_source(
        source_dir, "logs/app.log",
        "boot ok\nnew header\nalert: disk full\nshutdown\n",
    )
    stale = client.get(
        f"/evidence/{evidence_id}", headers=auth("viewer")
    ).json()
    assert stale["status"] == "stale"
    assert stale["reason"]

    timeline_stale = client.get(
        f"/incidents/{incident_id}/timeline", headers=auth("viewer")
    ).json()
    assert timeline_stale[0]["resolutions"][0]["status"] == "stale"

    # Delete requires a writer role.
    assert client.delete(
        f"/evidence/{evidence_id}", headers=auth("viewer")
    ).status_code == 403
    assert client.delete(
        f"/evidence/{evidence_id}", headers=auth("admin")
    ).status_code == 204
    assert client.get(
        f"/evidence/{evidence_id}", headers=auth("viewer")
    ).status_code == 404


def test_three_locator_kinds_via_api(client, source_dir, event_id):
    text = "alpha\nbeta alert\ngamma\n"
    _write_source(source_dir, "data/trace.txt", text)

    line = client.post(
        f"/events/{event_id}/evidence",
        headers=auth("investigator"),
        json={"kind": "line", "file_path": "data/trace.txt", "line": 2},
    )
    assert line.status_code == 201

    offset = client.post(
        f"/events/{event_id}/evidence",
        headers=auth("investigator"),
        json={
            "kind": "offset", "file_path": "data/trace.txt",
            "offset": 6, "length": 4,
        },
    )
    assert offset.status_code == 201

    hash_link = client.post(
        f"/events/{event_id}/evidence",
        headers=auth("investigator"),
        json={
            "kind": "hash", "file_path": "data/trace.txt",
            "search_text": "beta",
        },
    )
    assert hash_link.status_code == 201

    detail = client.get(
        f"/events/{event_id}", headers=auth("viewer")
    ).json()
    assert {e["locator_kind"] for e in detail["evidence"]} == {
        "line", "offset", "hash"
    }


def test_missing_source_returns_missing_status(
    client, source_dir, event_id
):
    _write_source(source_dir, "old.txt", "evidence here\n")
    created = client.post(
        f"/events/{event_id}/evidence",
        headers=auth("investigator"),
        json={"kind": "line", "file_path": "old.txt", "line": 1},
    ).json()
    (source_dir / "old.txt").unlink()

    result = client.get(
        f"/evidence/{created['id']}", headers=auth("viewer")
    ).json()
    assert result["status"] == "missing"


def test_unknown_file_rejected_at_creation(client, event_id):
    resp = client.post(
        f"/events/{event_id}/evidence",
        headers=auth("investigator"),
        json={"kind": "line", "file_path": "ghost.txt", "line": 1},
    )
    assert resp.status_code == 404


def test_traversal_rejected_at_creation(client, source_dir, event_id):
    _write_source(source_dir, "ok.txt", "x\n")
    resp = client.post(
        f"/events/{event_id}/evidence",
        headers=auth("investigator"),
        json={"kind": "line", "file_path": "../ok.txt", "line": 1},
    )
    assert resp.status_code == 400
