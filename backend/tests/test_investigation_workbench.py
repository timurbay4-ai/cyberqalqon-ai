from __future__ import annotations

import copy
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from app.schemas.auth import AnalystCreate, AnalystRole
from app.db.investigation_workbench import InvestigationWorkbenchRepository
from app.db.migrations import MIGRATIONS
from app.schemas.investigation_workbench import WorkbenchRequest
from tests.conftest import TEST_ORIGIN, TEST_PASSWORD
from tests.test_security_events import archive_event


def _ingest_event(client: TestClient, payload: dict) -> str:
    response = client.post(
        "/api/v1/events/ingest", headers={"X-API-Key": "test-ingest-key"}, json=payload
    )
    assert response.status_code == 201, response.text
    return response.json()["event"]["event_id"]


def _workbench(client: TestClient, payload: dict) -> dict:
    response = client.post("/api/v1/investigations/workbench", json=payload)
    assert response.status_code == 200, response.text
    return response.json()


def _windows_failure(timestamp: datetime, suffix: str, source_ip: str = "192.0.2.44") -> dict:
    return {
        "timestamp": timestamp.isoformat(), "id": f"m12-4625-{suffix}",
        "agent": {"id": "002", "name": "WIN-M12"},
        "manager": {"name": "lab-manager"}, "decoder": {"name": "windows_eventchannel"},
        "rule": {"id": "60122", "level": 5, "description": "Windows failed logon"},
        "data": {"win": {
            "system": {"providerName": "Microsoft-Windows-Security-Auditing", "eventID": "4625",
                       "channel": "Security", "computer": "WIN-M12"},
            "eventdata": {"targetUserName": "alice", "targetDomainName": "LAB",
                          "ipAddress": source_ip, "logonType": "3", "targetLogonId": "0x123"},
        }},
    }


def test_event_workbench_relates_only_real_indexed_entities_and_preserves_redaction(
    client: TestClient, database_path
) -> None:
    now = datetime.now(timezone.utc)
    primary = archive_event(event_id="m12-primary", timestamp=(now - timedelta(minutes=10)).isoformat())
    primary["data"]["srcip"] = "192.0.2.10"
    primary["data"]["url"] = "/login?token=fixture-secret"
    related = archive_event(event_id="m12-related", timestamp=(now - timedelta(minutes=9)).isoformat())
    related["agent"]["name"] = "different-host"
    related["data"]["srcip"] = "192.0.2.10"
    related["rule"]["id"] = "100121"
    unrelated = archive_event(event_id="m12-unrelated", timestamp=(now - timedelta(minutes=8)).isoformat())
    unrelated["agent"]["id"] = "099"
    unrelated["agent"]["name"] = "unrelated-host"
    unrelated["data"]["srcip"] = "198.51.100.20"
    unrelated["data"]["dstip"] = "198.51.100.21"
    unrelated["rule"]["id"] = "999999"
    primary_id = _ingest_event(client, primary)
    related_id = _ingest_event(client, related)
    unrelated_id = _ingest_event(client, unrelated)

    before = sqlite3.connect(database_path).execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    result = _workbench(client, {
        "target_type": "EVENT", "target_id": primary_id, "relative_minutes": 1440,
        "related_limit": 10, "timeline_limit": 20, "sort": "oldest",
    })
    after = sqlite3.connect(database_path).execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

    assert result["primary_event"]["event_id"] == primary_id
    assert "fixture-secret" not in str(result["primary_event"]["raw_payload"])
    by_id = {item["event"]["event_id"]: item for item in result["related_events"]}
    assert "SAME_SOURCE_IP" in by_id[related_id]["relationship_types"]
    assert unrelated_id not in by_id
    assert any(item["entity_type"] == "IPV4" and item["sensitive"] for item in result["entities"])
    assert result["timeline"][0]["source_id"] == primary_id
    assert result["summary"]["interpretations"] == [
        "These facts support investigation but do not by themselves establish attacker intent or confirmed compromise."
    ]
    assert after == before == 0


def test_related_events_use_stable_bound_cursor_pages_without_cross_page_duplicates(
    client: TestClient,
) -> None:
    now = datetime.now(timezone.utc)
    primary = archive_event(
        event_id="m13-page-primary", timestamp=(now - timedelta(minutes=10)).isoformat()
    )
    primary["data"]["srcip"] = "192.0.2.130"
    primary_id = _ingest_event(client, primary)
    expected_ids: set[str] = set()
    for index in range(6):
        payload = archive_event(
            event_id=f"m13-page-{index}",
            timestamp=(now - timedelta(minutes=9 - index)).isoformat(),
        )
        payload["data"]["srcip"] = "192.0.2.130"
        expected_ids.add(_ingest_event(client, payload))

    request = {
        "target_type": "EVENT",
        "target_id": primary_id,
        "relative_minutes": 1440,
        "related_limit": 2,
        "timeline_limit": 20,
    }
    first = _workbench(client, request)
    seen: list[str] = [item["event"]["event_id"] for item in first["related_events"]]
    timestamps = [item["event"]["timestamp"] for item in first["related_events"]]
    assert timestamps == sorted(timestamps, reverse=True)
    cursor = first["query"]["related_next_cursor"]
    assert cursor
    assert "192.0.2.130" not in cursor
    assert first["query"]["related_truncated"] is True

    page = first
    while page["query"].get("related_next_cursor"):
        response = client.post(
            "/api/v1/investigations/workbench",
            json={
                **request,
                "relative_minutes": None,
                "start_time": first["query"]["start_time"],
                "end_time": first["query"]["end_time"],
                "related_cursor": page["query"]["related_next_cursor"],
            },
        )
        assert response.status_code == 200, response.text
        page = response.json()
        page_ids = [item["event"]["event_id"] for item in page["related_events"]]
        assert not set(seen).intersection(page_ids)
        seen.extend(page_ids)

    assert expected_ids.issubset(set(seen))
    assert len(seen) == len(set(seen))

    invalid = client.post(
        "/api/v1/investigations/workbench",
        json={
            **request,
            "relative_minutes": None,
            "start_time": first["query"]["start_time"],
            "end_time": first["query"]["end_time"],
            "related_cursor": cursor[:-1] + ("A" if cursor[-1] != "A" else "B"),
        },
    )
    assert invalid.status_code == 422
    assert invalid.json()["detail"]["code"] == "invalid_cursor"

    moving_window = client.post(
        "/api/v1/investigations/workbench",
        json={**request, "related_cursor": cursor},
    )
    assert moving_window.status_code == 422


def test_alert_incident_case_and_correlation_context_are_composed_without_duplication(
    client: TestClient, sample_alert: dict, database_path: Path
) -> None:
    sample = copy.deepcopy(sample_alert)
    sample["timestamp"] = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
    sample["id"] = "m12-linked-alert"
    ingested = client.post("/api/v1/alerts/ingest", headers={"X-API-Key": "test-ingest-key"}, json=sample)
    assert ingested.status_code == 201, ingested.text
    alert_id = ingested.json()["alert"]["alert_id"]
    second = copy.deepcopy(sample_alert)
    second["timestamp"] = (datetime.now(timezone.utc) - timedelta(minutes=4)).isoformat()
    second["id"] = "m12-linked-alert-second"
    second["agent"] = {"id": "099", "name": "different-m12-host", "ip": "198.51.100.99"}
    second["rule"] = {"id": "999991", "level": 4, "description": "Distinct linked evidence", "groups": ["m12"]}
    second["data"] = {"srcip": "198.51.100.45", "dstip": "203.0.113.55", "srcport": "50000", "dstport": "443"}
    second_ingested = client.post(
        "/api/v1/alerts/ingest", headers={"X-API-Key": "test-ingest-key"}, json=second
    )
    assert second_ingested.status_code == 201, second_ingested.text
    second_alert_id = second_ingested.json()["alert"]["alert_id"]
    incident = client.post("/api/v1/incidents", json={
        "title": "M12 linked incident", "description": "Real linked records", "severity": "HIGH",
        "alert_ids": [alert_id, second_alert_id],
    })
    assert incident.status_code == 201, incident.text
    incident_id = incident.json()["incident_id"]
    case = client.post("/api/v1/cases", json={
        "title": "M12 linked case", "description": "Real case relationship", "severity": "HIGH",
        "priority": "HIGH", "source_type": "INCIDENT", "source_id": incident_id,
    })
    assert case.status_code == 201, case.text

    result = _workbench(client, {
        "target_type": "ALERT", "target_id": alert_id, "relative_minutes": 1440,
        "related_limit": 20, "timeline_limit": 100,
    })
    links = {(item["target_type"], item["target_id"]) for item in result["links"]}
    assert ("ALERT", alert_id) in links
    assert ("INCIDENT", incident_id) in links
    assert ("CASE", case.json()["case_id"]) in links
    timeline_keys = [(item["item_type"], item["item_id"]) for item in result["timeline"]]
    assert len(timeline_keys) == len(set(timeline_keys))
    assert {item["timestamp_kind"] for item in result["timeline"]} == {"EVENT_TIME", "ANALYST_ACTION_TIME"}
    with sqlite3.connect(database_path) as connection:
        second_event_id = connection.execute(
            "SELECT event_id FROM security_events WHERE related_alert_id = ?", (second_alert_id,)
        ).fetchone()[0]
    related = {item["event"]["event_id"]: item["relationship_types"] for item in result["related_events"]}
    assert "SAME_INCIDENT" in related[second_event_id]
    assert "SAME_CASE" in related[second_event_id]


def test_m11_finding_is_re_evaluated_and_explained_without_live_side_effects(client: TestClient) -> None:
    base = datetime.now(timezone.utc) - timedelta(minutes=20)
    for index in range(5):
        _ingest_event(client, _windows_failure(base + timedelta(seconds=index * 30), str(index)))
    dry_run = client.post(
        "/api/v1/detection-engineering/advanced-rules/DET-001/dry-run",
        json={"relative_minutes": 1440, "max_events": 1000, "max_findings": 100},
    )
    assert dry_run.status_code == 200, dry_run.text
    finding = dry_run.json()["findings"][0]

    result = _workbench(client, {
        "target_type": "M11_FINDING", "rule_id": "DET-001",
        "finding_key": finding["deduplication_key"], "relative_minutes": 1440,
        "related_limit": 25, "timeline_limit": 100,
    })
    context = result["detection_context"]
    assert context["rule"]["enabled"] is False
    assert context["rule"]["activation_state"] == "DISABLED_BY_POLICY"
    assert context["finding"]["event_ids"] == finding["event_ids"]
    assert context["finding"]["threshold"] == 5
    assert context["side_effects"] is False
    assert any(item["item_type"] == "DETECTION_FINDING" for item in result["timeline"])
    assert client.get("/api/v1/alerts").json()["page"]["total"] == 0
    assert client.get("/api/v1/incidents").json()["page"]["total"] == 0
    assert client.get("/api/v1/cases").json()["total"] == 0


def test_workbench_requires_session_origin_csrf_and_accepts_viewer_read(
    client: TestClient, unauthenticated_client: TestClient
) -> None:
    now = datetime.now(timezone.utc)
    event_id = _ingest_event(client, archive_event(event_id="m12-rbac", timestamp=now.isoformat()))
    payload = {"target_type": "EVENT", "target_id": event_id, "relative_minutes": 1440}
    assert unauthenticated_client.post("/api/v1/investigations/workbench", json=payload).status_code == 401
    csrf = client.headers.pop("X-CSRF-Token")
    assert client.post("/api/v1/investigations/workbench", json=payload).status_code == 403
    client.headers["X-CSRF-Token"] = csrf
    client.app.state.auth_repository.create_analyst(AnalystCreate(
        username="m12-viewer", display_name="M12 Viewer", password=TEST_PASSWORD, role=AnalystRole.VIEWER,
    ))
    client.cookies.clear()
    login = client.post("/api/v1/auth/login", headers={"Origin": TEST_ORIGIN}, json={
        "username": "m12-viewer", "password": TEST_PASSWORD,
    })
    client.headers["X-CSRF-Token"] = login.json()["csrf_token"]
    assert client.post("/api/v1/investigations/workbench", json=payload).status_code == 200


def test_workbench_rejects_malformed_targets_and_uses_pivot_indexes(client: TestClient, database_path) -> None:
    malformed = client.post("/api/v1/investigations/workbench", json={
        "target_type": "ENTITY", "entity_type": "USERNAME", "entity_value": "x' OR 1=1 --",
        "relative_minutes": 1440, "related_limit": 101,
    })
    assert malformed.status_code == 422
    missing = client.post("/api/v1/investigations/workbench", json={
        "target_type": "EVENT", "target_id": "missing-event", "relative_minutes": 1440,
    })
    assert missing.status_code == 404
    with sqlite3.connect(database_path) as connection:
        names = {row[1] for row in connection.execute("PRAGMA index_list(security_events)")}
        plan = connection.execute(
            "EXPLAIN QUERY PLAN SELECT event_id FROM security_events WHERE process_name = ? COLLATE NOCASE "
            "AND occurred_at BETWEEN ? AND ? ORDER BY occurred_at DESC, event_id DESC LIMIT 25",
            ("powershell.exe", "2026-01-01T00:00:00+00:00", "2026-12-31T00:00:00+00:00"),
        ).fetchall()
    assert "idx_security_events_process_name_time" in names
    assert any("idx_security_events_process_name_time" in str(row) for row in plan)


def test_schema_15_remains_readable_without_claiming_unindexed_process_relations(tmp_path: Path) -> None:
    database_path = tmp_path / "schema-15.db"
    occurred_at = datetime.now(timezone.utc) - timedelta(minutes=2)
    with sqlite3.connect(database_path) as connection:
        connection.row_factory = sqlite3.Row
        for migration in MIGRATIONS[:15]:
            migration.apply(connection)
            connection.commit()
        connection.execute("PRAGMA user_version = 15")
        connection.execute(
            """
            INSERT INTO security_events (
                event_id, deduplication_id, source_event_id, event_code,
                occurred_at, ingested_at, source_type, hostname, agent_id, agent_name,
                source_ip, destination_ip, source_port, destination_port, username,
                event_category, event_action, outcome, rule_id, severity, message,
                structured_json, raw_event_json, ingestion_source, related_alert_id,
                raw_size_bytes, search_text, manager_identity, event_provider,
                event_channel, process_name, process_id, parent_process_name,
                parent_process_id, normalization_schema
            ) VALUES (?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "EVT-SCHEMA15", "a" * 64, "4625", occurred_at.isoformat(),
                occurred_at.isoformat(), "windows_event", "WIN-SCHEMA15", "002",
                "WIN-SCHEMA15", "192.0.2.15", "192.0.2.20", "alice", "authentication",
                "logon-failed", "failure", "60122", 5, "Failed logon", "{}", "{}",
                "wazuh_archives", 2, "failed logon alice powershell.exe", "lab-manager",
                "Microsoft-Windows-Security-Auditing", "Security", "powershell.exe", "42",
                "explorer.exe", "1", "wazuh-event-v1",
            ),
        )
        connection.commit()

    result = InvestigationWorkbenchRepository(database_path).build(
        WorkbenchRequest(target_type="EVENT", target_id="EVT-SCHEMA15", relative_minutes=1440),
        start=occurred_at - timedelta(hours=1),
        end=occurred_at + timedelta(hours=1),
    )

    assert result.primary_event.operating_system is None
    assert result.primary_event.process_name == "powershell.exe"
    assert result.query.schema_version == 15
    assert "SAME_PROCESS_NAME" in result.query.unavailable_relationships
    assert "SAME_PROCESS_ID" in result.query.unavailable_relationships


def test_duplicate_replay_and_concurrent_readers_return_one_stable_investigation(
    client: TestClient, database_path: Path
) -> None:
    now = datetime.now(timezone.utc)
    payload = archive_event(event_id="m12-replay", timestamp=now.isoformat())
    first = client.post("/api/v1/events/ingest", headers={"X-API-Key": "test-ingest-key"}, json=payload)
    replay = client.post("/api/v1/events/ingest", headers={"X-API-Key": "test-ingest-key"}, json=payload)
    assert first.status_code == 201
    assert replay.status_code == 200
    assert replay.json()["duplicate"] is True
    event_id = first.json()["event"]["event_id"]
    repository = InvestigationWorkbenchRepository(database_path)
    request = WorkbenchRequest(
        target_type="EVENT", target_id=event_id, relative_minutes=1440,
        related_limit=25, timeline_limit=100,
    )

    def read_once() -> tuple[str, tuple[tuple[str, str], ...]]:
        result = repository.build(
            request, start=now - timedelta(hours=1), end=now + timedelta(hours=1)
        )
        return result.primary_event.event_id, tuple(
            (item.item_type, item.item_id) for item in result.timeline
        )

    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(lambda _: read_once(), range(8)))

    assert all(result == results[0] for result in results)
    assert results[0][0] == event_id
    with sqlite3.connect(database_path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM security_events WHERE event_id = ?", (event_id,)
        ).fetchone()[0] == 1
