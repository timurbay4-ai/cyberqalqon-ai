from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from app.core.config import Settings


def test_health_and_readiness_are_minimal_and_database_aware(client: TestClient) -> None:
    assert client.get("/health").json() == {
        "status": "ok",
        "service": "cyberqalqon-backend",
    }
    assert client.get("/readiness").json() == {"status": "ready"}

    client.app.state.alert_repository.is_ready = lambda: False
    unavailable = client.get("/readiness")
    assert unavailable.status_code == 503
    assert unavailable.json() == {"status": "not_ready"}


def test_ingestion_secret_can_be_supplied_by_file(
    tmp_path: Path, monkeypatch
) -> None:
    secret = tmp_path / "ingestion-key"
    secret.write_text("synthetic-file-secret\n", encoding="utf-8")
    monkeypatch.delenv("WAZUH_INGEST_API_KEY", raising=False)
    monkeypatch.setenv("WAZUH_INGEST_API_KEY_FILE", str(secret))

    assert Settings.from_env().wazuh_ingest_api_key == "synthetic-file-secret"


def test_direct_and_file_ingestion_secrets_are_mutually_exclusive(
    tmp_path: Path, monkeypatch
) -> None:
    secret = tmp_path / "ingestion-key"
    secret.write_text("file-secret", encoding="utf-8")
    monkeypatch.setenv("WAZUH_INGEST_API_KEY", "direct-secret")
    monkeypatch.setenv("WAZUH_INGEST_API_KEY_FILE", str(secret))

    try:
        Settings.from_env()
    except ValueError as exc:
        assert "Configure only one" in str(exc)
    else:
        raise AssertionError("conflicting secret sources must fail")
