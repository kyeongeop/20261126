from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.main import create_app

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixture_root() -> Path:
    return FIXTURES


@pytest.fixture
def case_fixture(fixture_root: Path) -> dict[str, Any]:
    return json.loads((fixture_root / "cases" / "checkout-latency.json").read_text())


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "timeline.db"


@pytest.fixture
def app(db_path: Path):
    return create_app(db_path, max_upload_bytes=2 * 1024 * 1024)


@pytest.fixture
def client(app):
    with TestClient(app) as test_client:
        yield test_client
