from __future__ import annotations

import copy
import sqlite3
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from app.services.event_normalizer import normalize_wazuh_event
from app.db.events import EventRepository


def archive_event(*, event_id: str = "1791469000.1", timestamp: str = "2026-10-08T14:30:00+00:00") -> dict:
    return {
        "timestamp": timestamp,
        "id": event_id,
        "agent": {"id": "001", "name": "cyberqalqon-test-web", "ip": "127.0.0.1"},
        "rule": {
            "id": "100120",
            "level": 8,
            "description": "Sensitive path probe",
            "groups": ["web", "attack"],
        },
        "decoder": {"name": "nginx-accesslog"},
        "location": "/var/log/nginx/access.log",
        "data": {
            "srcip": "127.0.0.1",
            "dstip": "127.0.0.1",
            "srcport": "49152",
            "dstport": "80",
            "url": "/.env?token=do-not-store",
            "password": "do-not-store",
        },
        "full_log": "GET /.env?token=do-not-store HTTP/1.1",
    }


def test_event_normalizer_preserves_fields_and_redacts_sensitive_values() -> None:
    event = normalize_wazuh_event(archive_event())
    assert event.source_type == "web"
    assert event.rule_id == "100120"
    assert event.severity == 8
    assert str(event.source_ip) == "127.0.0.1"
    assert event.source_port == 49152
    assert event.raw_payload["data"]["password"] == "[REDACTED]"
    assert "do-not-store" not in event.raw_payload["data"]["url"]
    assert "do-not-store" not in event.raw_payload["full_log"]


def test_authenticated_event_ingestion_deduplication_and_detail(
    client: TestClient,
    auth_headers: dict[str, str],
) -> None:
    payload = archive_event()
    created = client.post("/api/v1/events/ingest", headers=auth_headers, json=payload)
    assert created.status_code == 201, created.text
    event_id = created.json()["event"]["event_id"]

    duplicate = client.post("/api/v1/events/ingest", headers=auth_headers, json=payload)
    assert duplicate.status_code == 200
    assert duplicate.json()["duplicate"] is True

    detail = client.get(f"/api/v1/events/{event_id}")
    assert detail.status_code == 200
    body = detail.json()
    assert body["source_event_id"] == "1791469000.1"
    assert body["structured_payload"]["data"]["password"] == "[REDACTED]"
    assert "do-not-store" not in str(body["raw_payload"])


def test_event_search_filters_fts_sort_and_cursor(
    client: TestClient,
    auth_headers: dict[str, str],
) -> None:
    first = archive_event(event_id="source-old", timestamp="2026-10-08T14:00:00+00:00")
    second = archive_event(event_id="source-new", timestamp="2026-10-08T15:00:00+00:00")
    second["data"]["srcip"] = "192.0.2.44"
    second["data"]["outcome"] = "failure"
    assert client.post("/api/v1/events/ingest", headers=auth_headers, json=first).status_code == 201
    assert client.post("/api/v1/events/ingest", headers=auth_headers, json=second).status_code == 201

    filtered = client.get(
        "/api/v1/events",
        params={
            "source_ip": "192.0.2.44",
            "hostname": "cyberqalqon-test-web",
            "rule_id": "100120",
            "source_type": "web",
            "event_category": "WEB",
            "outcome": "FAILURE",
            "search": "sensitive path",
        },
    )
    assert filtered.status_code == 200, filtered.text
    assert [item["source_event_id"] for item in filtered.json()["items"]] == ["source-new"]

    page_one = client.get("/api/v1/events", params={"limit": 1, "sort": "oldest"}).json()
    assert page_one["items"][0]["source_event_id"] == "source-old"
    page_two = client.get(
        "/api/v1/events",
        params={"limit": 1, "sort": "oldest", "cursor": page_one["page"]["next_cursor"]},
    ).json()
    assert page_two["items"][0]["source_event_id"] == "source-new"


def test_event_search_rejects_invalid_ranges_and_cursor(client: TestClient) -> None:
    invalid_range = client.get(
        "/api/v1/events",
        params={"start_time": "2026-10-09T00:00:00Z", "end_time": "2026-10-08T00:00:00Z"},
    )
    assert invalid_range.status_code == 422
    assert invalid_range.json()["detail"]["field"] == "start_time"
    assert client.get("/api/v1/events", params={"source_ip": "not-an-ip"}).status_code == 422
    assert client.get("/api/v1/events", params={"cursor": "not-a-cursor"}).status_code == 422


def test_event_ingest_rejects_outside_retention_and_far_future_events(
    client: TestClient,
    auth_headers: dict[str, str],
) -> None:
    now = datetime.now(timezone.utc)
    old = client.post(
        "/api/v1/events/ingest",
        headers=auth_headers,
        json=archive_event(timestamp=(now - timedelta(days=31)).isoformat()),
    )
    assert old.status_code == 422
    assert old.json()["detail"]["code"] == "outside_retention_window"
    future = client.post(
        "/api/v1/events/ingest",
        headers=auth_headers,
        json=archive_event(event_id="future", timestamp=(now + timedelta(days=2)).isoformat()),
    )
    assert future.status_code == 422
    assert future.json()["detail"]["field"] == "timestamp"


def test_record_limit_is_enforced_between_scheduled_retention_runs(
    client: TestClient,
    database_path,
) -> None:
    repository = EventRepository(database_path, retention_days=30, max_records=2)
    now = datetime.now(timezone.utc)
    for offset in range(3):
        payload = archive_event(
            event_id=f"bounded-{offset}",
            timestamp=(now + timedelta(seconds=offset)).isoformat(),
        )
        repository.ingest(normalize_wazuh_event(payload), now=now + timedelta(seconds=offset))
    with sqlite3.connect(database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0] == 2
        retained, deleted = connection.execute(
            "SELECT retained_records, last_deleted_count FROM security_event_store_state"
        ).fetchone()
    assert retained == 2
    assert deleted == 1


def test_saved_searches_are_user_scoped_csrf_protected_and_audited(
    client: TestClient,
) -> None:
    payload = {
        "name": "Failed web probes",
        "query": {
            "relative_minutes": 1440,
            "event_category": "web",
            "outcome": "failure",
            "severity_min": 7,
            "sort": "newest",
        },
    }
    created = client.post("/api/v1/events/saved-searches", json=payload)
    assert created.status_code == 201, created.text
    saved_id = created.json()["saved_search_id"]
    assert client.get("/api/v1/events/saved-searches").json()[0]["name"] == payload["name"]
    assert client.post("/api/v1/events/saved-searches", json=payload).status_code == 409

    updated = client.patch(
        f"/api/v1/events/saved-searches/{saved_id}",
        json={**payload, "name": "Updated web probes"},
    )
    assert updated.status_code == 200
    audit = client.get("/api/v1/audit-events")
    assert audit.status_code == 200
    assert {item["action"] for item in audit.json()["items"]} >= {
        "SAVED_SEARCH_CREATED", "SAVED_SEARCH_UPDATED"
    }
    viewer_password = "Viewer-Saved-Search-Password-88"
    viewer = client.post(
        "/api/v1/auth/analysts",
        json={"username": "saved.viewer", "display_name": "Saved Viewer", "password": viewer_password, "role": "VIEWER"},
    )
    assert viewer.status_code == 201
    logged_in = client.post(
        "/api/v1/auth/login",
        headers={"Origin": "http://localhost:5173"},
        json={"username": "saved.viewer", "password": viewer_password},
    )
    assert logged_in.status_code == 200
    client.headers.update({"X-CSRF-Token": logged_in.json()["csrf_token"]})
    assert client.get("/api/v1/events/saved-searches").json() == []
    assert client.delete(f"/api/v1/events/saved-searches/{saved_id}").status_code == 404


def test_event_category_query_uses_v02_index(client: TestClient, database_path) -> None:
    with sqlite3.connect(database_path) as connection:
        plan = connection.execute(
            "EXPLAIN QUERY PLAN SELECT * FROM security_events e "
            "WHERE e.event_category = ? COLLATE NOCASE "
            "ORDER BY e.occurred_at DESC, e.event_id DESC LIMIT 51",
            ("web",),
        ).fetchall()
    assert any("idx_security_events_category" in str(row) for row in plan)


def test_rule_query_uses_exact_v02_index(client: TestClient, database_path) -> None:
    with sqlite3.connect(database_path) as connection:
        plan = connection.execute(
            "EXPLAIN QUERY PLAN SELECT * FROM security_events e "
            "WHERE e.rule_id = ? "
            "ORDER BY e.occurred_at DESC, e.event_id DESC LIMIT 51",
            ("100111",),
        ).fetchall()
    assert any("idx_security_events_rule" in str(row) for row in plan)


def test_event_reads_require_analyst_session_and_ingest_requires_machine_key(
    unauthenticated_client: TestClient,
) -> None:
    assert unauthenticated_client.get("/api/v1/events").status_code == 401
    assert unauthenticated_client.get("/api/v1/overview").status_code == 401
    denied = unauthenticated_client.post(
        "/api/v1/events/ingest",
        headers={"X-API-Key": "wrong-key"},
        json=archive_event(),
    )
    assert denied.status_code == 401


def test_alert_ingestion_projects_related_security_event(
    client: TestClient,
    auth_headers: dict[str, str],
    sample_alert: dict,
) -> None:
    created = client.post("/api/v1/alerts/ingest", headers=auth_headers, json=sample_alert)
    assert created.status_code == 201
    alert_id = created.json()["alert"]["alert_id"]

    related = client.get("/api/v1/events", params={"related_alert_id": alert_id})
    assert related.status_code == 200
    assert related.json()["page"]["total"] == 1
    event_id = related.json()["items"][0]["event_id"]
    detail = client.get(f"/api/v1/events/{event_id}").json()
    assert detail["related_alert_id"] == alert_id


def test_overview_uses_real_event_alert_and_incident_aggregates(
    client: TestClient,
    auth_headers: dict[str, str],
    sample_alert: dict,
) -> None:
    now = datetime.now(timezone.utc)
    payload = archive_event(timestamp=(now - timedelta(minutes=1)).isoformat())
    assert client.post("/api/v1/events/ingest", headers=auth_headers, json=payload).status_code == 201

    alert = copy.deepcopy(sample_alert)
    alert["timestamp"] = (now - timedelta(minutes=2)).isoformat()
    assert client.post("/api/v1/alerts/ingest", headers=auth_headers, json=alert).status_code == 201

    response = client.get(
        "/api/v1/overview",
        params={
            "start_time": (now - timedelta(hours=1)).isoformat(),
            "end_time": (now + timedelta(minutes=1)).isoformat(),
        },
    )
    assert response.status_code == 200, response.text
    overview = response.json()
    assert overview["total_events"] == 2
    assert overview["total_alerts"] == 1
    assert overview["reporting_agents"] == 1
    assert overview["ingestion"]["state"] == "ACTIVE"
    assert {item["name"] for item in overview["event_sources"]} == {"authentication", "web"}
