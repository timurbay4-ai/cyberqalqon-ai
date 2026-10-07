from __future__ import annotations

import copy
from urllib.parse import quote

from fastapi.testclient import TestClient


def _ingest(
    client: TestClient,
    auth_headers: dict[str, str],
    template: dict,
    *,
    alert_id: str,
    timestamp: str,
    level: int = 10,
    agent_id: str = "001",
    agent_name: str = "demo-linux-host",
    description: str = "Multiple authentication failures",
    mitre_id: str | None = "T1110",
) -> None:
    payload = copy.deepcopy(template)
    payload["id"] = alert_id
    payload["timestamp"] = timestamp
    payload["rule"]["level"] = level
    payload["rule"]["description"] = description
    payload["agent"]["id"] = agent_id
    payload["agent"]["name"] = agent_name
    if mitre_id is None:
        payload["rule"].pop("mitre", None)
    else:
        payload["rule"]["mitre"] = {
            "id": [mitre_id],
            "tactic": ["Credential Access"],
            "technique": ["Brute Force"],
        }
    response = client.post("/api/v1/alerts/ingest", json=payload, headers=auth_headers)
    assert response.status_code == 201, response.text


def test_empty_alert_list_has_typed_page_metadata(client: TestClient) -> None:
    response = client.get("/api/v1/alerts")

    assert response.status_code == 200
    assert response.json() == {
        "items": [],
        "page": {"limit": 50, "next_cursor": None, "total": 0},
    }


def test_alert_detail_and_structured_not_found(
    client: TestClient,
    auth_headers: dict[str, str],
    sample_alert: dict,
) -> None:
    _ingest(
        client,
        auth_headers,
        sample_alert,
        alert_id="detail-alert",
        timestamp="2026-10-01T10:00:00+00:00",
    )

    detail = client.get(f"/api/v1/alerts/{quote('detail-alert', safe='')}")
    missing = client.get("/api/v1/alerts/missing-alert")

    assert detail.status_code == 200
    assert detail.json()["alert_id"] == "detail-alert"
    assert "full_log" not in detail.text
    assert "Sanitized failed login event" not in detail.text
    assert missing.status_code == 404
    assert missing.json()["detail"] == {
        "code": "alert_not_found",
        "message": "No alert exists with the requested identifier",
        "field": "alert_id",
    }


def test_cursor_pagination_is_newest_first_with_alert_id_tiebreaker(
    client: TestClient,
    auth_headers: dict[str, str],
    sample_alert: dict,
) -> None:
    for alert_id, timestamp in (
        ("alert-a", "2026-10-01T10:00:00+00:00"),
        ("alert-b", "2026-10-01T10:00:00+00:00"),
        ("alert-c", "2026-10-02T10:00:00+00:00"),
    ):
        _ingest(
            client,
            auth_headers,
            sample_alert,
            alert_id=alert_id,
            timestamp=timestamp,
        )

    first = client.get("/api/v1/alerts", params={"limit": 2})
    first_body = first.json()
    second = client.get(
        "/api/v1/alerts",
        params={"limit": 2, "cursor": first_body["page"]["next_cursor"]},
    )

    assert first.status_code == 200
    assert [item["alert_id"] for item in first_body["items"]] == ["alert-c", "alert-b"]
    assert first_body["page"]["total"] == 3
    assert first_body["page"]["next_cursor"]
    assert second.status_code == 200
    assert [item["alert_id"] for item in second.json()["items"]] == ["alert-a"]
    assert second.json()["page"] == {"limit": 2, "next_cursor": None, "total": 3}


def test_alert_filters_cover_level_agent_mitre_time_and_search(
    client: TestClient,
    auth_headers: dict[str, str],
    sample_alert: dict,
) -> None:
    _ingest(
        client,
        auth_headers,
        sample_alert,
        alert_id="critical-alpha",
        timestamp="2026-10-03T10:00:00+00:00",
        level=14,
        agent_id="alpha-id",
        agent_name="ALPHA-HOST",
        description="Encoded PowerShell execution",
        mitre_id="T1059.001",
    )
    _ingest(
        client,
        auth_headers,
        sample_alert,
        alert_id="medium-beta",
        timestamp="2026-10-02T10:00:00+00:00",
        level=8,
        agent_id="beta-id",
        agent_name="BETA-HOST",
        description="Configuration changed",
        mitre_id=None,
    )
    _ingest(
        client,
        auth_headers,
        sample_alert,
        alert_id="low-alpha",
        timestamp="2026-10-01T10:00:00+00:00",
        level=5,
        agent_id="alpha-id",
        agent_name="ALPHA-HOST",
        description="Network connection denied",
        mitre_id="T1110",
    )

    levels = client.get(
        "/api/v1/alerts",
        params=[("rule_level", "14"), ("rule_level", "5")],
    ).json()
    agent = client.get("/api/v1/alerts", params={"agent": "alpha-host"}).json()
    unmapped = client.get("/api/v1/alerts", params={"mitre_mapped": "false"}).json()
    mitre_id = client.get("/api/v1/alerts", params={"mitre_id": "t1059.001"}).json()
    time_range = client.get(
        "/api/v1/alerts",
        params={
            "start_time": "2026-10-02T00:00:00+00:00",
            "end_time": "2026-10-02T23:59:59+00:00",
        },
    ).json()
    search = client.get("/api/v1/alerts", params={"search": "powershell"}).json()

    assert [item["alert_id"] for item in levels["items"]] == ["critical-alpha", "low-alpha"]
    assert [item["alert_id"] for item in agent["items"]] == ["critical-alpha", "low-alpha"]
    assert [item["alert_id"] for item in unmapped["items"]] == ["medium-beta"]
    assert [item["alert_id"] for item in mitre_id["items"]] == ["critical-alpha"]
    assert [item["alert_id"] for item in time_range["items"]] == ["medium-beta"]
    assert [item["alert_id"] for item in search["items"]] == ["critical-alpha"]


def test_search_treats_sql_wildcards_as_literal_text(
    client: TestClient,
    auth_headers: dict[str, str],
    sample_alert: dict,
) -> None:
    _ingest(
        client,
        auth_headers,
        sample_alert,
        alert_id="percent-alert",
        timestamp="2026-10-02T10:00:00+00:00",
        description="100% of checks blocked",
    )
    _ingest(
        client,
        auth_headers,
        sample_alert,
        alert_id="numeric-alert",
        timestamp="2026-10-01T10:00:00+00:00",
        description="1000 checks blocked",
    )

    response = client.get("/api/v1/alerts", params={"search": "100%"})
    injection = client.get("/api/v1/alerts", params={"search": "' OR 1=1 --"})

    assert response.status_code == 200
    assert [item["alert_id"] for item in response.json()["items"]] == ["percent-alert"]
    assert injection.status_code == 200
    assert injection.json()["items"] == []


def test_invalid_read_parameters_return_structured_errors(client: TestClient) -> None:
    invalid_level = client.get("/api/v1/alerts", params={"rule_level": 17})
    invalid_mitre = client.get("/api/v1/alerts", params={"mitre_id": "not-mitre"})
    invalid_time = client.get(
        "/api/v1/alerts",
        params={
            "start_time": "2026-10-03T00:00:00+00:00",
            "end_time": "2026-10-02T00:00:00+00:00",
        },
    )
    invalid_cursor = client.get("/api/v1/alerts", params={"cursor": "not-a-cursor"})

    assert invalid_level.status_code == 422
    assert invalid_level.json()["detail"]["code"] == "invalid_request"
    assert invalid_mitre.status_code == 422
    assert invalid_mitre.json()["detail"]["field"] == "mitre_id"
    assert invalid_time.status_code == 422
    assert invalid_time.json()["detail"]["field"] == "start_time"
    assert invalid_cursor.status_code == 422
    assert invalid_cursor.json()["detail"] == {
        "code": "invalid_cursor",
        "message": "cursor is malformed",
        "field": "cursor",
    }
