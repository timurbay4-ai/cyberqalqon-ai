from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx
import pytest

from app.core.config import Settings
from app.schemas.operations import ComponentObservation, OperationalSnapshot
from app.services.wazuh_api import WazuhApiClient


def _snapshot(state: str, observed_at: datetime) -> OperationalSnapshot:
    return OperationalSnapshot(
        collected_at=observed_at,
        components=[
            ComponentObservation(
                component_key="event-shipper",
                component_kind="event_shipper",
                state=state,
                authority="DURABLE_SHIPPER_STATE",
                summary=f"Shipper is {state.lower()}.",
                metrics={"archive_lag_bytes": 42, "malformed_json": 1},
                last_error="retry blocked" if state != "HEALTHY" else None,
                observed_at=observed_at,
            )
        ],
    )


def test_operational_overview_requires_authentication(unauthenticated_client) -> None:
    response = unauthenticated_client.get("/api/v1/operations/overview")
    assert response.status_code == 401


def test_operational_transitions_are_deduplicated_and_recover(client) -> None:
    repository = client.app.state.operational_repository
    started = datetime(2026, 10, 9, 12, 0, tzinfo=timezone.utc)

    assert repository.record_snapshot(_snapshot("DEGRADED", started)) == 1
    assert repository.record_snapshot(_snapshot("DEGRADED", started + timedelta(seconds=5))) == 0
    assert repository.record_snapshot(_snapshot("HEALTHY", started + timedelta(seconds=10))) == 1
    assert repository.record_snapshot(_snapshot("DEGRADED", started + timedelta(seconds=20))) == 1
    assert repository.record_snapshot(_snapshot("UNAVAILABLE", started)) == 0

    response = client.get("/api/v1/operations/overview")
    assert response.status_code == 200
    payload = response.json()
    assert payload["components"][0]["state"] == "DEGRADED"
    assert [item["event_type"] for item in payload["recent_events"]] == ["ISSUE", "RECOVERY", "ISSUE"]
    assert payload["recent_events"][0]["details"]["notification_suppressed_by_cooldown"] is True
    assert payload["data_quality"]["malformed_events"] == 1
    assert payload["wazuh_inventory"]["state"] == "UNAVAILABLE"

    notices = client.get("/api/v1/notifications").json()["items"]
    assert [item["category"] for item in notices] == [
        "OPERATIONAL_RECOVERY",
        "OPERATIONAL_ISSUE",
    ]
    assert all(item["target_type"] == "operational" for item in notices)


def test_operational_event_limit_is_bounded(client) -> None:
    assert client.get("/api/v1/operations/overview?event_limit=0").status_code == 422
    assert client.get("/api/v1/operations/overview?event_limit=101").status_code == 422


def test_wazuh_api_missing_credentials_preserves_unavailable_state() -> None:
    result = WazuhApiClient(Settings()).fetch_inventory()
    assert result.available is False
    assert "credentials" in result.reason


@pytest.mark.parametrize(
    "settings",
    [
        {"wazuh_api_url": "http://127.0.0.1:55000"},
        {"wazuh_api_url": "https://wazuh.example:55000"},
        {"wazuh_api_username": "reader"},
        {"wazuh_api_password": "secret"},
    ],
)
def test_wazuh_api_configuration_rejects_unsafe_or_partial_values(settings) -> None:
    with pytest.raises(ValueError):
        Settings(**settings)


def test_wazuh_api_reads_only_bounded_inventory(monkeypatch) -> None:
    requests: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append((request.method, request.url.path))
        if request.url.path == "/security/user/authenticate":
            return httpx.Response(200, text="signed-token")
        if request.url.path == "/agents":
            return httpx.Response(
                200,
                json={
                    "data": {
                        "affected_items": [
                            {
                                "id": "001",
                                "name": "linux-agent",
                                "status": "active",
                                "ip": "127.0.0.1",
                                "manager": "lab-manager",
                                "lastKeepAlive": "2026-10-09T12:00:00Z",
                                "os": {"name": "Linux", "platform": "linux", "version": "1"},
                            }
                        ]
                    }
                },
            )
        if request.url.path == "/manager/info":
            return httpx.Response(200, json={"data": {"affected_items": [{"name": "lab-manager"}]}})
        return httpx.Response(404)

    settings = Settings(wazuh_api_username="reader", wazuh_api_password="secret-value")
    client = WazuhApiClient(settings)
    monkeypatch.setattr(
        client,
        "_client",
        lambda: httpx.Client(
            base_url="https://127.0.0.1:55000",
            transport=httpx.MockTransport(handler),
        ),
    )

    result = client.fetch_inventory()
    assert result.available is True
    assert result.manager_identity == "lab-manager"
    assert result.agents[0].last_keepalive == "2026-10-09T12:00:00Z"
    assert requests == [
        ("GET", "/security/user/authenticate"),
        ("GET", "/agents"),
        ("GET", "/manager/info"),
    ]
