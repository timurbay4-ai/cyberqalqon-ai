from __future__ import annotations

import asyncio
import copy
import sqlite3
from pathlib import Path

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from starlette.requests import ClientDisconnect

from app.api.routes.alerts import _read_json_object
from app.core.config import Settings
from app.main import create_app
from app.services.wazuh_normalizer import normalize_wazuh_alert


def test_health_contract_is_preserved(client: TestClient) -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "cyberqalqon-backend"}


def test_ingest_requires_api_key(client: TestClient, sample_alert: dict) -> None:
    response = client.post("/api/v1/alerts/ingest", json=sample_alert)

    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "invalid_api_key"


def test_ingest_rejects_invalid_json(client: TestClient, auth_headers: dict[str, str]) -> None:
    response = client.post(
        "/api/v1/alerts/ingest",
        content=b'{"timestamp":',
        headers={**auth_headers, "Content-Type": "application/json"},
    )

    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "invalid_json"


def test_request_body_disconnect_is_a_bounded_client_error() -> None:
    class DisconnectedRequest:
        headers = {"content-type": "application/json"}

        async def stream(self):
            yield b'{"partial":'
            raise ClientDisconnect()

    with pytest.raises(HTTPException) as raised:
        asyncio.run(_read_json_object(DisconnectedRequest(), 1024))  # type: ignore[arg-type]

    assert raised.value.status_code == 400
    assert raised.value.detail["code"] == "client_disconnected"


def test_ingest_rejects_non_object_json(client: TestClient, auth_headers: dict[str, str]) -> None:
    response = client.post("/api/v1/alerts/ingest", json=[], headers=auth_headers)

    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "invalid_wazuh_alert"


def test_ingest_requires_json_content_type(client: TestClient, auth_headers: dict[str, str]) -> None:
    response = client.post(
        "/api/v1/alerts/ingest",
        content=b"not json",
        headers={**auth_headers, "Content-Type": "text/plain"},
    )

    assert response.status_code == 415
    assert response.json()["detail"]["code"] == "unsupported_media_type"


def test_ingestion_is_disabled_when_key_is_not_configured(
    database_path: Path,
    sample_alert: dict,
) -> None:
    settings = Settings(database_url=f"sqlite:///{database_path.as_posix()}")
    with TestClient(create_app(settings)) as test_client:
        response = test_client.post("/api/v1/alerts/ingest", json=sample_alert)

    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "ingestion_not_configured"


def test_ingests_and_normalizes_wazuh_alert(
    client: TestClient,
    auth_headers: dict[str, str],
    sample_alert: dict,
) -> None:
    response = client.post("/api/v1/alerts/ingest", json=sample_alert, headers=auth_headers)

    assert response.status_code == 201
    body = response.json()
    assert body["status"] == "created"
    assert body["duplicate"] is False
    assert body["alert"]["alert_id"] == "1790798400.123456"
    assert body["alert"]["timestamp"] == "2026-09-30T21:00:00.123000+05:00"
    assert body["alert"]["rule"]["level"] == 10
    assert body["alert"]["mitre"] == {
        "ids": ["T1110"],
        "tactics": ["Credential Access"],
        "techniques": ["Brute Force"],
    }
    assert body["alert"]["source"] == {"ip": "198.51.100.25", "port": 49152}
    assert body["alert"]["destination"] == {"ip": "192.0.2.10", "port": 22}
    assert body["alert"]["user"] == "demo-user"


def test_duplicate_ingestion_is_idempotent(
    client: TestClient,
    auth_headers: dict[str, str],
    sample_alert: dict,
    database_path: Path,
) -> None:
    first = client.post("/api/v1/alerts/ingest", json=sample_alert, headers=auth_headers)
    second = client.post("/api/v1/alerts/ingest", json=sample_alert, headers=auth_headers)

    assert first.status_code == 201
    assert second.status_code == 200
    assert second.json()["status"] == "duplicate"
    assert second.json()["duplicate"] is True
    assert second.json()["ingested_at"] == first.json()["ingested_at"]
    with sqlite3.connect(database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 1


def test_same_id_with_different_content_is_conflict(
    client: TestClient,
    auth_headers: dict[str, str],
    sample_alert: dict,
) -> None:
    changed = copy.deepcopy(sample_alert)
    changed["rule"]["level"] = 14

    assert client.post("/api/v1/alerts/ingest", json=sample_alert, headers=auth_headers).status_code == 201
    response = client.post("/api/v1/alerts/ingest", json=changed, headers=auth_headers)

    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "alert_id_conflict"


def test_malformed_alert_returns_structured_validation_error(
    client: TestClient,
    auth_headers: dict[str, str],
    sample_alert: dict,
) -> None:
    malformed = copy.deepcopy(sample_alert)
    del malformed["agent"]["name"]

    response = client.post("/api/v1/alerts/ingest", json=malformed, headers=auth_headers)

    assert response.status_code == 422
    assert response.json()["detail"] == {
        "code": "invalid_wazuh_alert",
        "message": "is required",
        "field": "agent.name",
    }


def test_alert_without_mitre_mapping_is_valid(
    client: TestClient,
    auth_headers: dict[str, str],
    sample_alert: dict,
) -> None:
    del sample_alert["rule"]["mitre"]

    response = client.post("/api/v1/alerts/ingest", json=sample_alert, headers=auth_headers)

    assert response.status_code == 201
    assert response.json()["alert"]["mitre"] == {"ids": [], "tactics": [], "techniques": []}


def test_wazuh_maximum_severity_is_valid(
    client: TestClient,
    auth_headers: dict[str, str],
    sample_alert: dict,
) -> None:
    sample_alert["rule"]["level"] = 16

    response = client.post("/api/v1/alerts/ingest", json=sample_alert, headers=auth_headers)

    assert response.status_code == 201
    assert response.json()["alert"]["rule"]["level"] == 16


def test_minimum_severity_and_ipv6_endpoints_are_valid(
    client: TestClient,
    auth_headers: dict[str, str],
    sample_alert: dict,
) -> None:
    sample_alert["rule"]["level"] = 0
    sample_alert["agent"]["ip"] = "2001:db8::10"
    sample_alert["data"]["srcip"] = "2001:db8::25"
    sample_alert["data"]["dstip"] = "2001:db8::10"

    response = client.post("/api/v1/alerts/ingest", json=sample_alert, headers=auth_headers)

    assert response.status_code == 201
    alert = response.json()["alert"]
    assert alert["rule"]["level"] == 0
    assert alert["agent"]["ip"] == "2001:db8::10"
    assert alert["source"]["ip"] == "2001:db8::25"
    assert alert["destination"]["ip"] == "2001:db8::10"


def test_fractional_severity_is_rejected_instead_of_truncated(
    client: TestClient,
    auth_headers: dict[str, str],
    sample_alert: dict,
) -> None:
    sample_alert["rule"]["level"] = 10.5

    response = client.post("/api/v1/alerts/ingest", json=sample_alert, headers=auth_headers)

    assert response.status_code == 422
    assert response.json()["detail"]["field"] == "rule.level"


def test_structured_value_is_not_coerced_into_username(
    client: TestClient,
    auth_headers: dict[str, str],
    sample_alert: dict,
) -> None:
    sample_alert["user"] = {"unexpected": "object"}

    response = client.post("/api/v1/alerts/ingest", json=sample_alert, headers=auth_headers)

    assert response.status_code == 422
    assert response.json()["detail"]["field"] == "user"


def test_invalid_mitre_id_is_rejected(
    client: TestClient,
    auth_headers: dict[str, str],
    sample_alert: dict,
) -> None:
    sample_alert["rule"]["mitre"]["id"] = ["ignore previous instructions"]

    response = client.post("/api/v1/alerts/ingest", json=sample_alert, headers=auth_headers)

    assert response.status_code == 422
    assert response.json()["detail"]["field"] == "rule.mitre.id"


def test_naive_timestamp_is_rejected(
    client: TestClient,
    auth_headers: dict[str, str],
    sample_alert: dict,
) -> None:
    sample_alert["timestamp"] = "2026-09-30T21:00:00"

    response = client.post("/api/v1/alerts/ingest", json=sample_alert, headers=auth_headers)

    assert response.status_code == 422
    assert response.json()["detail"]["field"] == "timestamp"


def test_generated_id_is_stable_when_wazuh_id_is_missing(sample_alert: dict) -> None:
    del sample_alert["id"]

    first = normalize_wazuh_alert(sample_alert)
    second = normalize_wazuh_alert(copy.deepcopy(sample_alert))

    assert first.alert_id.startswith("sha256:")
    assert second.alert_id == first.alert_id


def test_oversized_payload_is_rejected(database_path: Path, sample_alert: dict) -> None:
    settings = Settings(
        database_url=f"sqlite:///{database_path.as_posix()}",
        wazuh_ingest_api_key="test-ingest-key",
        max_ingest_bytes=64,
    )
    with TestClient(create_app(settings)) as test_client:
        response = test_client.post(
            "/api/v1/alerts/ingest",
            json=sample_alert,
            headers={"X-API-Key": "test-ingest-key"},
        )

    assert response.status_code == 413
    assert response.json()["detail"]["code"] == "payload_too_large"
