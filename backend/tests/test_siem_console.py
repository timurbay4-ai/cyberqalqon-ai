from __future__ import annotations

from datetime import datetime, timedelta, timezone
import copy

from fastapi.testclient import TestClient

from app.api.routes.siem import _safe_cell


def _event(now: datetime, *, agent_name: str = "cyberqalqon-test-web") -> dict:
    return {
        "timestamp": now.isoformat(),
        "id": "siem-console-event-1",
        "agent": {"id": "001", "name": agent_name},
        "rule": {"id": "100111", "level": 10, "description": "TCP port scan"},
        "decoder": {"name": "json"},
        "location": "CQ-NETSCAN",
        "data": {"srcip": "127.0.0.1", "dstip": "127.0.0.1", "dstport": "80"},
        "full_log": "CQ-NETSCAN src=127.0.0.1 dst=127.0.0.1 dstport=80",
    }


def test_inventory_catalog_and_report_use_persisted_data(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    now = datetime.now(timezone.utc)
    assert client.post("/api/v1/events/ingest", headers=auth_headers, json=_event(now)).status_code == 201

    sources = client.get("/api/v1/sources")
    assert sources.status_code == 200
    assert sources.json()[0]["source_health"] == "ACTIVE"
    assert sources.json()[0]["agent_status"] == "UNKNOWN"

    hosts = client.get("/api/v1/hosts")
    assert hosts.status_code == 200
    assert hosts.json()[0]["hostname"] == "cyberqalqon-test-web"
    assert hosts.json()[0]["platform"] == "LINUX"
    assert hosts.json()[0]["event_count"] == 1

    rules = client.get("/api/v1/rules")
    assert rules.status_code == 200
    assert {rule["rule_id"] for rule in rules.json()} == {
        "100101", "100111", "100120", "100130", "100131",
        "CORR-001", "CORR-002", "CORR-003", "CORR-004",
    }
    assert all(rule["editable"] is False for rule in rules.json())

    params = {
        "start_time": (now - timedelta(hours=1)).isoformat(),
        "end_time": (now + timedelta(minutes=1)).isoformat(),
    }
    report = client.get("/api/v1/reports/security-activity", params=params)
    assert report.status_code == 200
    assert report.json()["total_events"] == 1
    csv_response = client.get("/api/v1/reports/security-activity.csv", params=params)
    assert csv_response.status_code == 200
    assert csv_response.headers["content-disposition"].startswith("attachment;")
    assert "total_events,1" in csv_response.text
    json_response = client.get("/api/v1/reports/security-activity.json", params=params)
    assert json_response.status_code == 200
    assert json_response.headers["content-disposition"].endswith('.json')
    assert json_response.headers["cache-control"] == "no-store"
    assert json_response.json()["total_events"] == 1


def test_csv_neutralizes_spreadsheet_formulas(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    now = datetime.now(timezone.utc)
    assert client.post(
        "/api/v1/events/ingest",
        headers=auth_headers,
        json=_event(now, agent_name="=2+5"),
    ).status_code == 201
    response = client.get(
        "/api/v1/reports/security-activity.csv",
        params={
            "start_time": (now - timedelta(minutes=1)).isoformat(),
            "end_time": (now + timedelta(minutes=1)).isoformat(),
        },
    )
    assert response.status_code == 200
    assert "host_activity,'=2+5,1" in response.text
    assert "host_activity,=2+5,1" not in response.text
    assert _safe_cell(" \t=WEBSERVICE(\"https://example.invalid\")").startswith("'")


def test_siem_read_models_require_authentication_and_bound_ranges(
    unauthenticated_client: TestClient, client: TestClient
) -> None:
    for endpoint in ("/api/v1/sources", "/api/v1/hosts", "/api/v1/rules", "/api/v1/reports/security-activity", "/api/v1/reports/security-activity.csv", "/api/v1/reports/security-activity.json"):
        assert unauthenticated_client.get(endpoint).status_code == 401
    too_wide = client.get(
        "/api/v1/reports/security-activity",
        params={"start_time": "2026-01-01T00:00:00Z", "end_time": "2026-03-01T00:00:00Z"},
    )
    assert too_wide.status_code == 422


def test_reports_apply_host_rule_and_severity_filters_and_audit_csv(
    client: TestClient,
    auth_headers: dict[str, str],
) -> None:
    now = datetime.now(timezone.utc)
    assert client.post("/api/v1/events/ingest", headers=auth_headers, json=_event(now)).status_code == 201
    other = _event(now + timedelta(seconds=1), agent_name="other-host")
    other["id"] = "siem-console-event-2"
    other["rule"] = {"id": "100120", "level": 8, "description": "Sensitive path"}
    assert client.post("/api/v1/events/ingest", headers=auth_headers, json=other).status_code == 201
    params = {
        "start_time": (now - timedelta(minutes=1)).isoformat(),
        "end_time": (now + timedelta(minutes=1)).isoformat(),
        "host": "cyberqalqon-test-web",
        "rule_id": "100111",
        "severity_min": 10,
        "severity_max": 10,
    }
    report = client.get("/api/v1/reports/security-activity", params=params)
    assert report.status_code == 200, report.text
    assert report.json()["total_events"] == 1
    assert report.json()["filters"]["host"] == "cyberqalqon-test-web"
    exported = client.get("/api/v1/reports/security-activity.csv", params=params)
    assert exported.status_code == 200
    assert "filter,host,cyberqalqon-test-web" in exported.text
    audit = client.get("/api/v1/audit-events").json()["items"]
    assert audit[0]["action"] == "SECURITY_ACTIVITY_EXPORTED"


def test_rule_catalog_uses_latest_alert_evidence(
    client: TestClient,
    auth_headers: dict[str, str],
    sample_alert: dict,
) -> None:
    now = datetime.now(timezone.utc)
    older = copy.deepcopy(sample_alert)
    older["id"] = "rule-catalog-old"
    older["timestamp"] = (now - timedelta(minutes=2)).isoformat()
    older["rule"]["id"] = "100101"
    older["rule"]["description"] = "Older description"
    newer = copy.deepcopy(older)
    newer["id"] = "rule-catalog-new"
    newer["timestamp"] = (now - timedelta(minutes=1)).isoformat()
    newer["rule"]["description"] = "Newest description"
    assert client.post("/api/v1/alerts/ingest", headers=auth_headers, json=older).status_code == 201
    assert client.post("/api/v1/alerts/ingest", headers=auth_headers, json=newer).status_code == 201
    rules = client.get("/api/v1/rules").json()
    observed = next(rule for rule in rules if rule["rule_id"] == "100101")
    assert observed["description"] == "Newest description"
    assert observed["alert_count"] == 2
