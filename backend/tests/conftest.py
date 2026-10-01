import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.core.config import get_settings


@pytest.fixture
def session_factory():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    yield factory
    Base.metadata.drop_all(engine)
    engine.dispose()


@pytest.fixture
def client(session_factory):
    def override_get_db():
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def wazuh_alert():
    path = Path(__file__).parent / "fixtures" / "authentication_failure.json"
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture
def configured_tokens(monkeypatch):
    monkeypatch.setenv("API_ACCESS_TOKEN", "frontend-test-token")
    monkeypatch.setenv("WAZUH_INGEST_TOKEN", "wazuh-test-token")
    get_settings.cache_clear()
    yield {
        "api": {"Authorization": "Bearer frontend-test-token"},
        "wazuh": {"Authorization": "Bearer wazuh-test-token"},
    }
    get_settings.cache_clear()
