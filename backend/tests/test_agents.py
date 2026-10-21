from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.services.wazuh_api import WazuhAgentRecord, WazuhInventoryResult


def _result(status: str, observed_at: datetime) -> WazuhInventoryResult:
    return WazuhInventoryResult(
        available=True,
        reason="Read-only Wazuh API inventory retrieved successfully.",
        observed_at=observed_at,
        manager_identity="lab-manager",
        manager_version="v4.14.8",
        manager_health="HEALTHY",
        agents=(
            WazuhAgentRecord(
                agent_id="001",
                name="cyberqalqon-test-web",
                status=status,
                ip="127.0.0.1",
                os_name="Kali GNU/Linux",
                os_platform="linux",
                os_version="2026",
                agent_version="Wazuh v4.14.8",
                groups=("linux", "web"),
                manager="lab-manager",
                last_keepalive=observed_at.isoformat(),
                disconnected_at=None,
                enrolled_at=(observed_at - timedelta(days=1)).isoformat(),
            ),
        ),
    )


def test_agent_routes_require_authentication(unauthenticated_client) -> None:
    assert unauthenticated_client.get("/api/v1/agents").status_code == 401
    assert unauthenticated_client.get("/api/v1/integrations/wazuh/status").status_code == 401


def test_agent_inventory_is_namespaced_filterable_and_read_only(client) -> None:
    repository = client.app.state.agent_repository
    now = datetime.now(timezone.utc)
    repository.record_inventory(_result("active", now))

    response = client.get(
        "/api/v1/agents",
        params={"os": "linux", "connection_status": "ONLINE", "manager": "lab"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["authoritative_inventory"] is True
    assert body["page"]["total"] == 1
    item = body["items"][0]
    assert item["agent_id"] == "001"
    assert item["connection_status"] == "ONLINE"
    assert item["status_authority"] == "WAZUH_API"
    assert item["agent_key"].startswith("wazuh_")

    detail = client.get(f"/api/v1/agents/{item['agent_key']}")
    assert detail.status_code == 200
    assert detail.json()["groups"] == ["linux", "web"]
    assert "enrollment" not in " ".join(detail.json()["troubleshooting"]).casefold()

    health = client.get(f"/api/v1/agents/{item['agent_key']}/health")
    assert health.status_code == 200
    assert health.json()["items"][0]["connection_status"] == "ONLINE"

    integration = client.get("/api/v1/integrations/wazuh/status").json()
    assert integration["state"] == "AVAILABLE"
    assert integration["read_only"] is True
    assert integration["manager_version"] == "v4.14.8"


def test_agent_transition_creates_bounded_recovery_notifications(client) -> None:
    repository = client.app.state.agent_repository
    started = datetime.now(timezone.utc) - timedelta(minutes=2)
    repository.record_inventory(_result("active", started))
    repository.record_inventory(_result("disconnected", started + timedelta(seconds=10)))
    repository.record_inventory(_result("active", started + timedelta(seconds=20)))

    agents = client.get("/api/v1/agents").json()["items"]
    key = agents[0]["agent_key"]
    history = client.get(f"/api/v1/agents/{key}/health").json()["items"]
    assert [item["connection_status"] for item in history[:3]] == [
        "ONLINE",
        "DISCONNECTED",
        "ONLINE",
    ]
    categories = [item["category"] for item in client.get("/api/v1/notifications").json()["items"]]
    assert "OPERATIONAL_ISSUE" in categories
    assert "OPERATIONAL_RECOVERY" in categories


def test_unavailable_wazuh_api_never_infers_online(client, auth_headers) -> None:
    raw = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "id": "observed-agent-event",
        "agent": {"id": "009", "name": "observed-only"},
        "manager": {"name": "lab-manager"},
        "rule": {"id": "100120", "level": 8, "description": "Observed event"},
        "data": {},
    }
    assert client.post("/api/v1/events/ingest", headers=auth_headers, json=raw).status_code == 201
    body = client.get("/api/v1/agents?connection_status=UNKNOWN").json()
    observed = next(item for item in body["items"] if item["agent_id"] == "009")
    assert observed["observed_only"] is True
    assert observed["status_authority"] == "TELEMETRY_EVIDENCE"
    assert observed["connection_status"] == "UNKNOWN"
    assert body["authoritative_inventory"] is False


def test_stale_authoritative_cache_downgrades_current_connection_to_unknown(client) -> None:
    repository = client.app.state.agent_repository
    expired = datetime.now(timezone.utc) - timedelta(minutes=5)
    repository.record_inventory(_result("active", expired))

    body = client.get("/api/v1/agents").json()
    item = next(agent for agent in body["items"] if agent["agent_id"] == "001")
    assert body["authoritative_inventory"] is False
    assert body["partial"] is True
    assert item["status_authority"] == "WAZUH_API"
    assert item["cache_stale"] is True
    assert item["connection_status"] == "UNKNOWN"

    history = client.get(f"/api/v1/agents/{item['agent_key']}/health").json()
    assert history["items"][0]["connection_status"] == "ONLINE"


def test_agent_query_bounds_and_identifier_validation(client) -> None:
    assert client.get("/api/v1/agents?limit=101").status_code == 422
    assert client.get("/api/v1/agents?sort=sql%20injection").status_code == 422
    assert client.get("/api/v1/agents/not-an-agent-key").status_code == 422
