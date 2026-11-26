from __future__ import annotations

import hashlib
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

ACTOR_HEADER = "X-Actor"


def headers(
    actor: str,
    source: str,
    *,
    forwarded_for: str = "203.0.113.9",
) -> dict[str, str]:
    return {
        ACTOR_HEADER: actor,
        "X-Source": source,
        "X-Forwarded-For": f"{forwarded_for}, 10.0.0.2",
        "User-Agent": "custody-pytest/1.0",
    }


def create_case(
    client: TestClient,
    case_fixture: dict[str, Any],
    *,
    actor: str,
    source: str,
) -> str:
    response = client.post(
        "/cases",
        json={"title": case_fixture["title"]},
        headers=headers(actor, source),
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def upload(
    client: TestClient,
    case_id: str,
    *,
    filename: str,
    content: bytes,
    display_name: str,
    actor: str,
    source: str,
) -> dict[str, Any]:
    response = client.post(
        f"/cases/{case_id}/evidence",
        files={"file": (filename, content, "text/plain")},
        data={"display_name": display_name},
        headers=headers(actor, source),
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_complete_custody_chain_and_voided_history(
    client: TestClient,
    case_fixture: dict[str, Any],
    fixture_root: Path,
) -> None:
    uploader = case_fixture["actors"]["uploader"]
    reviewer = case_fixture["actors"]["reviewer"]
    upload_source = case_fixture["sources"]["upload"]
    review_source = case_fixture["sources"]["review"]
    evidence_fixture = case_fixture["evidence"]
    original = (fixture_root / evidence_fixture["filename"]).read_bytes()
    replacement = (fixture_root / evidence_fixture["replacement_filename"]).read_bytes()
    case_id = create_case(
        client,
        case_fixture,
        actor=uploader,
        source=upload_source,
    )

    uploaded = upload(
        client,
        case_id,
        filename=Path(evidence_fixture["filename"]).name,
        content=original,
        display_name=evidence_fixture["display_name"],
        actor=uploader,
        source=upload_source,
    )
    evidence_id = uploaded["id"]
    first_version = uploaded["current_version"]
    assert first_version["content_sha256"] == hashlib.sha256(original).hexdigest()
    assert len(first_version["version_digest"]) == 64
    assert uploaded["custody"]["event_count"] == 1

    viewed = client.get(
        f"/cases/{case_id}/evidence/{evidence_id}",
        headers=headers(reviewer, review_source),
    )
    assert viewed.status_code == 200, viewed.text
    assert viewed.json()["name"] == evidence_fixture["display_name"]

    exported = client.get(
        f"/cases/{case_id}/evidence/{evidence_id}/export",
        headers=headers(reviewer, review_source),
    )
    assert exported.status_code == 200
    assert exported.content == original
    assert (
        exported.headers["X-Evidence-Content-SHA256"] == first_version["content_sha256"]
    )
    assert (
        exported.headers["X-Evidence-Version-Digest"] == first_version["version_digest"]
    )

    renamed = client.patch(
        f"/cases/{case_id}/evidence/{evidence_id}",
        json={"display_name": "Gateway log (normalized label)"},
        headers=headers(uploader, upload_source),
    )
    assert renamed.status_code == 200, renamed.text
    assert renamed.json()["name"] == "Gateway log (normalized label)"

    replaced = client.post(
        f"/cases/{case_id}/evidence/{evidence_id}/versions",
        files={
            "file": (
                Path(evidence_fixture["replacement_filename"]).name,
                replacement,
                "text/plain",
            )
        },
        headers=headers(uploader, upload_source),
    )
    assert replaced.status_code == 201, replaced.text
    replaced_body = replaced.json()
    assert replaced_body["current_version_number"] == 2
    assert len(replaced_body["versions"]) == 2
    assert (
        replaced_body["versions"][1]["previous_version_digest"]
        == first_version["version_digest"]
    )
    assert (
        replaced_body["current_version"]["content_sha256"]
        == hashlib.sha256(replacement).hexdigest()
    )

    deleted = client.request(
        "DELETE",
        f"/cases/{case_id}/evidence/{evidence_id}",
        json={"reason": case_fixture["void_reason"]},
        headers=headers(uploader, upload_source),
    )
    assert deleted.status_code == 200, deleted.text
    assert deleted.json()["status"] == "voided"
    assert deleted.json()["current_version_number"] == 2
    assert len(deleted.json()["versions"]) == 2

    default_list = client.get(f"/cases/{case_id}/evidence")
    assert default_list.status_code == 200
    assert default_list.json() == []
    all_evidence = client.get(
        f"/cases/{case_id}/evidence",
        params={"include_voided": "true"},
    )
    assert [item["id"] for item in all_evidence.json()] == [evidence_id]

    custody = client.get(f"/cases/{case_id}/evidence/{evidence_id}/custody")
    assert custody.status_code == 200, custody.text
    body = custody.json()
    expected_events = [
        ("UPLOAD", uploader, upload_source, "POST"),
        ("VIEW", reviewer, review_source, "GET"),
        ("EXPORT", reviewer, review_source, "GET"),
        ("RENAME", uploader, upload_source, "PATCH"),
        ("REPLACE", uploader, upload_source, "POST"),
        ("DELETE", uploader, upload_source, "DELETE"),
    ]
    actual_events = [
        (event["action"], event["actor"], event["source"], event["request_method"])
        for event in body["events"]
    ]
    assert actual_events == expected_events
    for event in body["events"]:
        assert event["source_ip"] == "203.0.113.9"
        assert event["user_agent"] == "custody-pytest/1.0"
        assert event["request_path"]
        assert event["occurred_at"].endswith("Z")
        datetime.fromisoformat(event["occurred_at"])
        assert len(event["record_hash"]) == 64
    assert body["verification"]["valid"] is True
    assert body["verification"]["checked_versions"] == 2
    assert body["verification"]["checked_events"] == 6
    assert body["verification"]["chain_head"] == body["events"][-1]["record_hash"]

    old_export = client.get(
        f"/cases/{case_id}/evidence/{evidence_id}/versions/1/export",
        headers=headers(reviewer, review_source),
    )
    assert old_export.status_code == 200
    assert old_export.content == original
    assert old_export.headers["X-Evidence-Version"] == "1"
    assert old_export.headers["X-Evidence-Status"] == "voided"

    final_custody = client.get(
        f"/cases/{case_id}/evidence/{evidence_id}/custody"
    ).json()
    assert final_custody["events"][-1]["action"] == "EXPORT"
    assert final_custody["verification"]["valid"] is True
    assert final_custody["verification"]["checked_events"] == 7


def test_incident_timeline_uses_custody_events(
    client: TestClient,
    case_fixture: dict[str, Any],
    fixture_root: Path,
) -> None:
    actor = case_fixture["actors"]["uploader"]
    source = case_fixture["sources"]["upload"]
    evidence_fixture = case_fixture["evidence"]
    case_id = create_case(client, case_fixture, actor=actor, source=source)
    upload(
        client,
        case_id,
        filename=Path(evidence_fixture["filename"]).name,
        content=(fixture_root / evidence_fixture["filename"]).read_bytes(),
        display_name=evidence_fixture["display_name"],
        actor=actor,
        source=source,
    )
    timeline = client.get(f"/cases/{case_id}/timeline")
    assert timeline.status_code == 200
    events = timeline.json()["events"]
    assert [event["action"] for event in events] == ["UPLOAD"]
    assert events[0]["actor"] == actor
    assert events[0]["source"] == source


def test_voided_evidence_rejects_mutation(
    client: TestClient,
    case_fixture: dict[str, Any],
    fixture_root: Path,
) -> None:
    actor = case_fixture["actors"]["uploader"]
    source = case_fixture["sources"]["upload"]
    evidence_fixture = case_fixture["evidence"]
    case_id = create_case(client, case_fixture, actor=actor, source=source)
    evidence = upload(
        client,
        case_id,
        filename=Path(evidence_fixture["filename"]).name,
        content=(fixture_root / evidence_fixture["filename"]).read_bytes(),
        display_name=evidence_fixture["display_name"],
        actor=actor,
        source=source,
    )
    evidence_id = evidence["id"]
    base = f"/cases/{case_id}/evidence/{evidence_id}"
    assert (
        client.request(
            "DELETE", base, json={"reason": "duplicate"}, headers=headers(actor, source)
        ).status_code
        == 200
    )
    assert (
        client.request(
            "DELETE", base, json={"reason": "again"}, headers=headers(actor, source)
        ).status_code
        == 409
    )
    assert (
        client.patch(
            base,
            json={"name": "cannot rename"},
            headers=headers(actor, source),
        ).status_code
        == 409
    )
    assert (
        client.post(
            f"{base}/versions",
            files={"file": ("new.log", b"new\n", "text/plain")},
            headers=headers(actor, source),
        ).status_code
        == 409
    )


def test_actor_is_required_for_every_custodied_operation(
    client: TestClient,
    case_fixture: dict[str, Any],
    fixture_root: Path,
) -> None:
    actor = case_fixture["actors"]["uploader"]
    source = case_fixture["sources"]["upload"]
    evidence_fixture = case_fixture["evidence"]
    case_id = create_case(client, case_fixture, actor=actor, source=source)
    evidence = upload(
        client,
        case_id,
        filename=Path(evidence_fixture["filename"]).name,
        content=(fixture_root / evidence_fixture["filename"]).read_bytes(),
        display_name=evidence_fixture["display_name"],
        actor=actor,
        source=source,
    )
    evidence_id = evidence["id"]
    base = f"/cases/{case_id}/evidence/{evidence_id}"
    calls = [
        client.get(base),
        client.get(f"{base}/export"),
        client.patch(base, json={"name": "renamed"}),
        client.request("DELETE", base),
        client.post(
            f"{base}/versions",
            files={"file": ("new.log", b"new\n", "text/plain")},
        ),
    ]
    assert [response.status_code for response in calls] == [401, 401, 401, 401, 401]
    assert (
        client.post(
            f"/cases/{case_id}/evidence",
            files={"file": ("new.log", b"new\n", "text/plain")},
        ).status_code
        == 401
    )


def test_database_rejects_physical_history_deletion(
    client: TestClient,
    db_path: Path,
    case_fixture: dict[str, Any],
    fixture_root: Path,
) -> None:
    actor = case_fixture["actors"]["uploader"]
    source = case_fixture["sources"]["upload"]
    evidence_fixture = case_fixture["evidence"]
    case_id = create_case(client, case_fixture, actor=actor, source=source)
    evidence = upload(
        client,
        case_id,
        filename=Path(evidence_fixture["filename"]).name,
        content=(fixture_root / evidence_fixture["filename"]).read_bytes(),
        display_name=evidence_fixture["display_name"],
        actor=actor,
        source=source,
    )

    statements = [
        "DELETE FROM evidence WHERE id = ?",
        "DELETE FROM evidence_versions WHERE evidence_id = ?",
        "DELETE FROM custody_events WHERE evidence_id = ?",
    ]
    for statement in statements:
        with (
            sqlite3.connect(db_path) as connection,
            pytest.raises(sqlite3.IntegrityError, match="cannot be deleted|immutable"),
        ):
            connection.execute(statement, (evidence["id"],))


def test_verification_detects_stored_content_tampering(
    client: TestClient,
    db_path: Path,
    case_fixture: dict[str, Any],
    fixture_root: Path,
) -> None:
    actor = case_fixture["actors"]["uploader"]
    source = case_fixture["sources"]["upload"]
    evidence_fixture = case_fixture["evidence"]
    case_id = create_case(client, case_fixture, actor=actor, source=source)
    evidence = upload(
        client,
        case_id,
        filename=Path(evidence_fixture["filename"]).name,
        content=(fixture_root / evidence_fixture["filename"]).read_bytes(),
        display_name=evidence_fixture["display_name"],
        actor=actor,
        source=source,
    )
    with sqlite3.connect(db_path) as connection:
        connection.execute("DROP TRIGGER versions_no_update")
        connection.execute(
            "UPDATE evidence_versions SET content = ? WHERE evidence_id = ?",
            (b"tampered evidence", evidence["id"]),
        )

    verification = client.get(f"/cases/{case_id}/evidence/{evidence['id']}/verify")
    assert verification.status_code == 200
    body = verification.json()["verification"]
    assert body["valid"] is False
    assert any("content digest mismatch" in error for error in body["errors"])


def test_verification_detects_event_chain_tampering(
    client: TestClient,
    db_path: Path,
    case_fixture: dict[str, Any],
    fixture_root: Path,
) -> None:
    actor = case_fixture["actors"]["uploader"]
    source = case_fixture["sources"]["upload"]
    evidence_fixture = case_fixture["evidence"]
    case_id = create_case(client, case_fixture, actor=actor, source=source)
    evidence = upload(
        client,
        case_id,
        filename=Path(evidence_fixture["filename"]).name,
        content=(fixture_root / evidence_fixture["filename"]).read_bytes(),
        display_name=evidence_fixture["display_name"],
        actor=actor,
        source=source,
    )
    with sqlite3.connect(db_path) as connection:
        connection.execute("DROP TRIGGER custody_no_update")
        connection.execute(
            "UPDATE custody_events SET actor = 'mallory' WHERE evidence_id = ?",
            (evidence["id"],),
        )

    body = client.get(f"/cases/{case_id}/evidence/{evidence['id']}/verify").json()[
        "verification"
    ]
    assert body["valid"] is False
    assert any("custody record hash mismatch" in error for error in body["errors"])


def test_verification_detects_evidence_metadata_tampering(
    client: TestClient,
    db_path: Path,
    case_fixture: dict[str, Any],
    fixture_root: Path,
) -> None:
    actor = case_fixture["actors"]["uploader"]
    source = case_fixture["sources"]["upload"]
    evidence_fixture = case_fixture["evidence"]
    case_id = create_case(client, case_fixture, actor=actor, source=source)
    evidence = upload(
        client,
        case_id,
        filename=Path(evidence_fixture["filename"]).name,
        content=(fixture_root / evidence_fixture["filename"]).read_bytes(),
        display_name=evidence_fixture["display_name"],
        actor=actor,
        source=source,
    )
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "UPDATE evidence SET display_name = 'unrecorded rename' WHERE id = ?",
            (evidence["id"],),
        )

    body = client.get(f"/cases/{case_id}/evidence/{evidence['id']}/verify").json()[
        "verification"
    ]
    assert body["valid"] is False
    assert any("display name does not match" in error for error in body["errors"])
