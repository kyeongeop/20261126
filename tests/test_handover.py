from __future__ import annotations

from fastapi.testclient import TestClient

from tests.conftest import analyst_headers, create_analyst, create_case


def _create_handover(
    client: TestClient, case_id: int, owner_id: int, successor_id: int
) -> dict[str, object]:
    response = client.post(
        f"/api/cases/{case_id}/handovers",
        json={"to_analyst_id": successor_id},
        headers=analyst_headers(owner_id),
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_handover_checklist_contains_only_open_items_and_permissions(
    client: TestClient,
) -> None:
    owner = create_analyst(client, "林分析员")
    owner_id = int(owner["id"])
    successor = create_analyst(client, "周分析员")
    successor_id = int(successor["id"])
    case_id = create_case(client, owner_id)
    headers = analyst_headers(owner_id)

    event_url = f"/api/cases/{case_id}/events"
    client.post(
        event_url,
        json={"title": "未确认事件", "occurred_at": "2026-11-25T09:00:00+08:00"},
        headers=headers,
    )
    client.post(
        event_url,
        json={
            "title": "已确认事件",
            "occurred_at": "2026-11-25T10:00:00+08:00",
            "is_confirmed": True,
        },
        headers=headers,
    )

    hypothesis_url = f"/api/cases/{case_id}/hypotheses"
    client.post(
        hypothesis_url,
        json={"statement": "未完成假设", "status": "investigating"},
        headers=headers,
    )
    client.post(
        hypothesis_url,
        json={"statement": "已完成假设", "status": "resolved"},
        headers=headers,
    )

    evidence_url = f"/api/cases/{case_id}/evidence"
    client.post(
        evidence_url,
        json={"title": "待补证据", "status": "pending"},
        headers=headers,
    )
    client.post(
        evidence_url,
        json={"title": "已核验证据", "status": "verified"},
        headers=headers,
    )

    handover = _create_handover(client, case_id, owner_id, successor_id)
    checklist = handover["checklist"]
    assert [item["title"] for item in checklist["unconfirmed_events"]] == ["未确认事件"]
    assert [item["title"] for item in checklist["unfinished_hypotheses"]] == ["未完成假设"]
    assert [item["title"] for item in checklist["evidence_to_supplement"]] == ["待补证据"]
    assert len(checklist["permission"]) == 1
    assert "只读访问" in checklist["permission"][0]["detail"]
    assert handover["status"] == "pending"


def test_checklist_updates_never_overwrite_previous_analyst_notes(
    client: TestClient,
) -> None:
    owner = create_analyst(client, "甲分析员")
    owner_id = int(owner["id"])
    successor = create_analyst(client, "乙分析员")
    successor_id = int(successor["id"])
    case_id = create_case(client, owner_id)
    headers = analyst_headers(owner_id)

    client.post(
        f"/api/cases/{case_id}/events",
        json={"title": "待确认线索", "occurred_at": "2026-11-25T11:00:00+08:00"},
        headers=headers,
    )
    handover = _create_handover(client, case_id, owner_id, successor_id)
    handover_id = int(handover["id"])
    event_item = handover["checklist"]["unconfirmed_events"][0]
    item_url = (
        f"/api/cases/{case_id}/handovers/{handover_id}/items/{event_item['id']}"
    )

    first = client.patch(item_url, json={"note": "原始手写备注"}, headers=headers)
    assert first.status_code == 200
    assert first.json()["outgoing_note"] == "原始手写备注"

    second = client.patch(
        item_url,
        json={"note": "补充复核备注"},
        headers=headers,
    )
    assert second.status_code == 200
    assert second.json()["outgoing_note"] == "原始手写备注\n补充复核备注"

    successor_headers = analyst_headers(successor_id)
    checked = client.patch(
        item_url,
        json={"checked": True, "note": "接手人核对完成"},
        headers=successor_headers,
    )
    assert checked.status_code == 200
    assert checked.json()["outgoing_note"] == "原始手写备注\n补充复核备注"
    assert checked.json()["successor_note"] == "接手人核对完成"

    client.post(
        f"/api/cases/{case_id}/hypotheses",
        json={"statement": "新假设", "status": "open"},
        headers=headers,
    )
    refreshed = client.post(
        f"/api/cases/{case_id}/handovers/{handover_id}/refresh",
        headers=headers,
    )
    assert refreshed.status_code == 200
    refreshed_item = next(
        item for item in refreshed.json()["items"] if item["id"] == event_item["id"]
    )
    assert refreshed_item["outgoing_note"] == "原始手写备注\n补充复核备注"
    assert refreshed_item["successor_note"] == "接手人核对完成"
    assert refreshed_item["checked"] is True


def test_confirmation_transfers_write_access_and_keeps_old_owner_read_only(
    client: TestClient,
) -> None:
    owner = create_analyst(client, "旧负责人")
    owner_id = int(owner["id"])
    successor = create_analyst(client, "新负责人")
    successor_id = int(successor["id"])
    case_id = create_case(client, owner_id)
    owner_headers = analyst_headers(owner_id)
    successor_headers = analyst_headers(successor_id)

    client.post(
        f"/api/cases/{case_id}/events",
        json={"title": "交接前线索", "occurred_at": "2026-11-25T11:30:00+08:00"},
        headers=owner_headers,
    )
    handover = _create_handover(client, case_id, owner_id, successor_id)
    handover_id = int(handover["id"])
    event_item = handover["checklist"]["unconfirmed_events"][0]
    item_url = (
        f"/api/cases/{case_id}/handovers/{handover_id}/items/{event_item['id']}"
    )
    client.patch(
        item_url,
        json={"note": "交接前手写检查记录"},
        headers=owner_headers,
    )

    before = client.get(f"/api/cases/{case_id}", headers=successor_headers)
    assert before.status_code == 200
    assert before.json()["access_level"] == "read_only"

    before_owner_write = client.post(
        f"/api/cases/{case_id}/events",
        json={"title": "确认前可写", "occurred_at": "2026-11-25T12:00:00+08:00"},
        headers=owner_headers,
    )
    assert before_owner_write.status_code == 201

    confirmation = client.post(
        f"/api/cases/{case_id}/handovers/{handover_id}/confirm",
        headers=successor_headers,
    )
    assert confirmation.status_code == 200
    assert confirmation.json()["status"] == "confirmed"

    old_owner_view = client.get(f"/api/cases/{case_id}", headers=owner_headers)
    assert old_owner_view.status_code == 200
    assert old_owner_view.json()["access_level"] == "read_only"
    assert old_owner_view.json()["owner_id"] == successor_id

    old_owner_write = client.post(
        f"/api/cases/{case_id}/events",
        json={"title": "确认后禁写", "occurred_at": "2026-11-25T13:00:00+08:00"},
        headers=owner_headers,
    )
    assert old_owner_write.status_code == 403
    assert "只读" in old_owner_write.json()["detail"]

    new_owner_write = client.post(
        f"/api/cases/{case_id}/events",
        json={"title": "新负责人可写", "occurred_at": "2026-11-25T14:00:00+08:00"},
        headers=successor_headers,
    )
    assert new_owner_write.status_code == 201

    checklist_update = client.patch(
        f"/api/cases/{case_id}/handovers/{handover_id}/checklist",
        json={
            "items": [
                {
                    "item_id": event_item["id"],
                    "checked": True,
                    "note": "新负责人逐项核对",
                }
            ]
        },
        headers=successor_headers,
    )
    assert checklist_update.status_code == 200
    updated_item = next(
        item
        for item in checklist_update.json()["items"]
        if item["id"] == event_item["id"]
    )
    assert updated_item["outgoing_note"] == "交接前手写检查记录"
    assert updated_item["successor_note"] == "新负责人逐项核对"
    assert updated_item["checked"] is True

    old_owner_checklist_write = client.patch(
        item_url,
        json={"checked": False},
        headers=owner_headers,
    )
    assert old_owner_checklist_write.status_code == 403
    old_owner_handover_view = client.get(
        f"/api/cases/{case_id}/handovers/{handover_id}",
        headers=owner_headers,
    )
    assert old_owner_handover_view.status_code == 200

    duplicate_confirmation = client.post(
        f"/api/cases/{case_id}/handovers/{handover_id}/confirm",
        headers=successor_headers,
    )
    assert duplicate_confirmation.status_code == 409
