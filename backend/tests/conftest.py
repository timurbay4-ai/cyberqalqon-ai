from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app
from app.schemas.auth import AnalystCreate, AnalystRole


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
TEST_ORIGIN = "http://localhost:5173"
TEST_PASSWORD = "Correct-Horse-Battery-77"


def bootstrap_and_login(
    test_client: TestClient,
    *,
    username: str = "admin",
    display_name: str = "Test Administrator",
    password: str = TEST_PASSWORD,
) -> dict:
    test_client.app.state.auth_repository.bootstrap_first_admin(
        AnalystCreate(
            username=username,
            display_name=display_name,
            password=password,
            role=AnalystRole.ADMIN,
        )
    )
    response = test_client.post(
        "/api/v1/auth/login",
        headers={"Origin": TEST_ORIGIN},
        json={"username": username, "password": password},
    )
    assert response.status_code == 200, response.text
    session = response.json()
    test_client.headers.update(
        {"Origin": TEST_ORIGIN, "X-CSRF-Token": session["csrf_token"]}
    )
    return session


@pytest.fixture
def sample_alert() -> dict:
    path = REPOSITORY_ROOT / "wazuh" / "samples" / "authentication-failure.json"
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture
def database_path(tmp_path: Path) -> Path:
    return tmp_path / "alerts.db"


@pytest.fixture
def client(database_path: Path) -> Iterator[TestClient]:
    settings = Settings(
        database_url=f"sqlite:///{database_path.as_posix()}",
        wazuh_ingest_api_key="test-ingest-key",
        allow_m14_schema_migration=True,
    )
    with TestClient(create_app(settings)) as test_client:
        bootstrap_and_login(test_client)
        yield test_client


@pytest.fixture
def unauthenticated_client(database_path: Path) -> Iterator[TestClient]:
    settings = Settings(
        database_url=f"sqlite:///{database_path.as_posix()}",
        wazuh_ingest_api_key="test-ingest-key",
        allow_m14_schema_migration=True,
    )
    with TestClient(create_app(settings)) as test_client:
        yield test_client


@pytest.fixture
def auth_headers() -> dict[str, str]:
    return {"X-API-Key": "test-ingest-key"}
