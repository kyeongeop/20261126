"""Shared pytest fixtures.

Environment variables are set before any ``app`` import so the module-level
ASGI app never seeds or writes into the working tree during tests.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

os.environ["TIMELINE_AUTO_SEED"] = "0"
os.environ.setdefault(
    "TIMELINE_DB", str(Path(tempfile.gettempdir()) / "timeline_pytest_global.db")
)

from app.database import connect  # noqa: E402
from app.main import create_app  # noqa: E402


@pytest.fixture()
def db_path(tmp_path: Path) -> str:
    return str(tmp_path / "test_timeline.db")


@pytest.fixture()
def app(db_path: str):
    application = create_app(db_path, seed=False)
    return application


@pytest.fixture()
def client(app) -> TestClient:
    return TestClient(app)


@pytest.fixture()
def conn(app):
    connection = connect(app.state.db_path)
    connection.isolation_level = None  # autocommit: always read latest commits
    try:
        yield connection
    finally:
        connection.close()


@pytest.fixture()
def seeded_client(tmp_path: Path) -> TestClient:
    application = create_app(str(tmp_path / "seeded.db"), seed=True)
    return TestClient(application)


@pytest.fixture()
def two_source_pair(client: TestClient):
    """Create two sources and the classic two-system login pair.

    Returns a helper dict with ids and the raw record payloads.
    """

    client.post("/api/sources", json={"code": "idp", "name": "IdP", "reliability": 0.95})
    client.post(
        "/api/sources", json={"code": "vpn", "name": "VPN", "reliability": 0.8}
    )

    def _make(
        user: str = "alice",
        idp_time: str = "2026-11-20T09:00:12Z",
        vpn_time: str = "2026-11-20T09:04:57Z",
        idp_payload: dict | None = None,
        vpn_payload: dict | None = None,
    ) -> dict:
        idp_payload = idp_payload or {
            "ip_address": "203.0.113.8",
            "device_id": "dev-77",
            "session_id": "sess-A",
            "result": "success",
            "mfa_method": "totp",
        }
        vpn_payload = vpn_payload or {
            "ip_address": "203.0.113.8",
            "device_id": "dev-77",
            "session_id": "sess-Z",
            "result": "success",
            "auth_method": "certificate",
        }
        r1 = client.post(
            "/api/records",
            json={
                "source_code": "idp",
                "external_id": f"IDP-{user}",
                "event_type": "user_login",
                "user_id": user,
                "occurred_at": idp_time,
                "payload": idp_payload,
            },
        ).json()["record"]
        r2 = client.post(
            "/api/records",
            json={
                "source_code": "vpn",
                "external_id": f"VPN-{user}",
                "event_type": "user_login",
                "user_id": user,
                "occurred_at": vpn_time,
                "payload": vpn_payload,
            },
        ).json()["record"]
        candidate = client.post(
            "/api/candidates", json={"record_ids": [r1["id"], r2["id"]]}
        ).json()
        return {"idp": r1, "vpn": r2, "candidate": candidate}

    return _make
