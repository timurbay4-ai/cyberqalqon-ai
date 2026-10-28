from __future__ import annotations

import copy
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.services.event_normalizer import normalize_wazuh_event
from app.services.event_normalizer import EventNormalizationError
from app.db.events import EventFilters, EventRepository, RetentionCapacityError


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


def windows_archive_event() -> dict:
    fixture = Path(__file__).resolve().parents[2] / "wazuh" / "fixtures" / "windows-eventchannel" / "security-4625.json"
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "id": "windows-security-4625",
        "agent": {"id": "002", "name": "WIN-M10-SYNTHETIC"},
        "manager": {"name": "lab-manager"},
        "decoder": {"name": "windows_eventchannel"},
        "rule": {"id": "60122", "level": 5, "description": "Windows failed logon"},
        "data": json.loads(fixture.read_text(encoding="utf-8")),
    }


def endpoint_fixture(*parts: str) -> dict:
    fixture = Path(__file__).resolve().parents[2] / "wazuh" / "fixtures"
    return json.loads(fixture.joinpath(*parts).read_text(encoding="utf-8"))


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


def test_windows_event_normalization_preserves_provenance_and_unknowns() -> None:
    raw = windows_archive_event()
    raw["data"]["win"]["eventdata"].update(
        {
            "processName": "C:\\Program Files\\CyberQalqon\\қалқон.exe",
            "processId": "0x4d2",
            "parentProcessName": "C:\\Windows\\explorer.exe",
            "parentProcessId": "512",
        }
    )
    event = normalize_wazuh_event(raw)
    assert event.source_type == "windows_event"
    assert event.event_code == "4625"
    assert event.event_provider == "Microsoft-Windows-Security-Auditing"
    assert event.event_channel == "Security"
    assert event.event_category == "windows_security"
    assert event.manager_identity == "lab-manager"
    assert event.process_name.endswith("қалқон.exe")
    assert event.process_id == "0x4d2"
    assert event.parent_process_name.endswith("explorer.exe")
    assert event.parent_process_id == "512"
    assert event.operating_system == "windows"
    assert event.event_action == "logon"
    assert event.outcome == "failure"
    assert event.normalization_schema == "wazuh-event-v3"


def test_process_creation_normalization_preserves_redacted_execution_context() -> None:
    raw = windows_archive_event()
    raw["data"] = endpoint_fixture("windows-eventchannel", "security-4688.json")
    raw["data"]["win"]["eventdata"]["commandLine"] += " password=fixture-secret"
    raw["rule"]["mitre"] = {
        "id": ["T1059.001"],
        "tactic": ["Execution"],
        "technique": ["PowerShell"],
    }

    event = normalize_wazuh_event(raw)

    assert event.event_code == "4688"
    assert event.event_action == "process_start"
    assert event.outcome == "success"
    assert event.process_path == r"C:\Windows\System32\whoami.exe"
    assert event.command_line == "whoami.exe /all password=[REDACTED]"
    assert event.parent_process_path and event.parent_process_path.endswith("powershell.exe")
    assert event.mitre.ids == ["T1059.001"]


@pytest.mark.parametrize(
    ("event_code", "action", "outcome"),
    [
        ("4624", "logon", "success"),
        ("4634", "logoff", "success"),
        ("4648", "explicit_credentials", "observed"),
        ("4672", "privileged_logon", "success"),
        ("4720", "account_create", "success"),
        ("4726", "account_delete", "success"),
        ("4732", "group_member_add", "success"),
        ("4103", "powershell_module", "observed"),
        ("4104", "powershell_script_block", "observed"),
        ("7045", "service_install", "success"),
        ("1116", "malware_detect", "detected"),
        ("1117", "malware_remediate", "remediated"),
    ],
)
def test_windows_event_semantics_are_stable(event_code: str, action: str, outcome: str) -> None:
    raw = windows_archive_event()
    raw["data"]["win"]["system"]["eventID"] = event_code
    event = normalize_wazuh_event(raw)
    assert (event.event_action, event.outcome) == (action, outcome)


@pytest.mark.parametrize(
    ("fixture_name", "category", "action", "outcome"),
    [
        ("ssh-failed.json", "linux_ssh", "authenticate", "failure"),
        ("sudo-command.json", "linux_sudo", "privilege_escalation", "success"),
    ],
)
def test_linux_event_normalization(fixture_name: str, category: str, action: str, outcome: str) -> None:
    event = normalize_wazuh_event(endpoint_fixture("linux", fixture_name))
    assert event.operating_system == "Ubuntu 24.04"
    assert event.event_category == category
    assert event.event_action == action
    assert event.outcome == outcome
    if fixture_name == "ssh-failed.json":
        assert event.mitre.ids == ["T1110"]
    else:
        assert event.command_line == "/usr/bin/systemctl status ssh"


def test_windows_event_malformed_nested_identifier_fails_closed() -> None:
    raw = windows_archive_event()
    raw["data"]["win"]["eventdata"]["processId"] = ["not", "text"]
    with pytest.raises(EventNormalizationError) as error:
        normalize_wazuh_event(raw)
    assert error.value.field == "process_id"


def test_invalid_event_mitre_identifier_fails_closed() -> None:
    raw = windows_archive_event()
    raw["rule"]["mitre"] = {"id": ["NOT-A-TECHNIQUE"]}
    with pytest.raises(EventNormalizationError) as error:
        normalize_wazuh_event(raw)
    assert error.value.field == "rule.mitre.id"


def test_windows_event_ingest_exposes_provenance_without_creating_alert(client, auth_headers) -> None:
    created = client.post("/api/v1/events/ingest", headers=auth_headers, json=windows_archive_event())
    assert created.status_code == 201, created.text
    event_id = created.json()["event"]["event_id"]
    detail = client.get(f"/api/v1/events/{event_id}").json()
    assert detail["event_provider"] == "Microsoft-Windows-Security-Auditing"
    assert detail["event_channel"] == "Security"
    assert detail["raw_evidence_ref"] == event_id
    assert detail["normalization_schema"] == "wazuh-event-v3"
    assert client.get("/api/v1/alerts").json()["page"]["total"] == 0


def test_endpoint_context_filters_are_server_side_and_exact(client, auth_headers) -> None:
    raw = windows_archive_event()
    raw["data"] = endpoint_fixture("windows-eventchannel", "security-4688.json")
    created = client.post("/api/v1/events/ingest", headers=auth_headers, json=raw)
    assert created.status_code == 201, created.text

    response = client.get(
        "/api/v1/events",
        params={
            "operating_system": "WINDOWS",
            "event_provider": "microsoft-windows-security-auditing",
            "event_channel": "security",
            "process_name": r"C:\Windows\System32\whoami.exe",
            "event_action": "PROCESS_START",
        },
    )

    assert response.status_code == 200, response.text
    assert response.json()["page"]["total"] == 1
    assert response.json()["items"][0]["command_line"] == "whoami.exe /all"


def test_telemetry_coverage_reports_only_observed_event_evidence(client, auth_headers) -> None:
    now = datetime.now(timezone.utc)
    windows = windows_archive_event()
    windows["timestamp"] = (now - timedelta(minutes=2)).isoformat()
    linux = endpoint_fixture("linux", "ssh-failed.json")
    linux["timestamp"] = (now - timedelta(minutes=1)).isoformat()
    assert client.post("/api/v1/events/ingest", headers=auth_headers, json=windows).status_code == 201
    assert client.post("/api/v1/events/ingest", headers=auth_headers, json=linux).status_code == 201

    response = client.get(
        "/api/v1/events/coverage",
        params={
            "start_time": (now - timedelta(hours=1)).isoformat(),
            "end_time": now.isoformat(),
        },
    )

    assert response.status_code == 200, response.text
    report = response.json()
    assert report["total_events"] == 2
    assert {entry["event_category"] for entry in report["entries"]} == {
        "windows_security",
        "linux_ssh",
    }
    assert {entry["evidence"] for entry in report["entries"]} == {"STORED_EVENTS"}
    assert {entry["state"] for entry in report["entries"]} == {"OBSERVED"}


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


def test_concurrent_event_reads_and_ingestion_preserve_cap_and_integrity(
    client: TestClient,
    database_path: Path,
) -> None:
    repository = EventRepository(database_path, retention_days=30, max_records=25)
    now = datetime.now(timezone.utc)
    for offset in range(20):
        repository.ingest(
            normalize_wazuh_event(
                archive_event(
                    event_id=f"concurrent-seed-{offset}",
                    timestamp=(now + timedelta(milliseconds=offset)).isoformat(),
                )
            ),
            now=now + timedelta(milliseconds=offset),
        )

    def ingest(offset: int) -> str:
        stored = repository.ingest(
            normalize_wazuh_event(
                archive_event(
                    event_id=f"concurrent-new-{offset}",
                    timestamp=(now + timedelta(seconds=1, milliseconds=offset)).isoformat(),
                )
            ),
            now=now + timedelta(seconds=1, milliseconds=offset),
        )
        return stored.event.event_id

    def read() -> int:
        return repository.list(
            EventFilters(), limit=25, sort="newest"
        ).total

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(ingest, offset) for offset in range(10)]
        futures.extend(executor.submit(read) for _ in range(12))
        results = [future.result(timeout=20) for future in futures]

    assert len({item for item in results[:10] if isinstance(item, str)}) == 10
    with sqlite3.connect(database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0] == 25
        assert connection.execute("PRAGMA quick_check").fetchone()[0] == "ok"
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_retention_preserves_case_evidence_and_audits_protected_pressure(
    client: TestClient,
    database_path: Path,
) -> None:
    repository = EventRepository(database_path, retention_days=30, max_records=2)
    now = datetime.now(timezone.utc)
    protected_ids: list[str] = []
    for offset, event_id in enumerate(("protected-link", "protected-evidence")):
        payload = archive_event(
            event_id=event_id,
            timestamp=(now - timedelta(seconds=3 - offset)).isoformat(),
        )
        protected_ids.append(
            repository.ingest(normalize_wazuh_event(payload), now=now).event.event_id
        )

    created = client.post(
        "/api/v1/cases",
        json={
            "title": "Retention evidence protection",
            "description": "Forensic references must outlive ordinary FIFO cleanup.",
            "severity": "HIGH",
            "priority": "HIGH",
        },
    )
    assert created.status_code == 201, created.text
    case_id = created.json()["case_id"]
    linked = client.post(
        f"/api/v1/cases/{case_id}/related/event",
        json={"reference_id": protected_ids[0], "expected_version": 1},
    )
    assert linked.status_code == 201, linked.text
    acquired = client.post(
        f"/api/v1/cases/{case_id}/evidence",
        json={
            "reference_type": "EVENT",
            "reference_id": protected_ids[1],
            "annotation": "Preserve this raw event.",
            "expected_version": 2,
        },
    )
    assert acquired.status_code == 201, acquired.text

    newest = archive_event(event_id="preserved-ingest", timestamp=now.isoformat())
    with sqlite3.connect(database_path) as connection:
        audit_before = connection.execute(
            "SELECT details_json FROM security_audit_events WHERE action='SECURITY_EVENT_RETENTION' ORDER BY occurred_at"
        ).fetchall()
    with pytest.raises(RetentionCapacityError):
        repository.ingest(normalize_wazuh_event(newest), now=now)

    with sqlite3.connect(database_path) as connection:
        event_ids = {
            row[0] for row in connection.execute("SELECT event_id FROM security_events")
        }
        retained, deleted = connection.execute(
            "SELECT retained_records, last_deleted_count FROM security_event_store_state"
        ).fetchone()
        audit_rows = connection.execute(
            "SELECT details_json FROM security_audit_events "
            "WHERE action = 'SECURITY_EVENT_RETENTION' ORDER BY occurred_at"
        ).fetchall()

    assert event_ids == set(protected_ids)
    assert retained == 2
    assert deleted == 0
    # A rejected/rolled-back insert must not commit a fictitious over-cap state.
    assert audit_rows == audit_before


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


def test_retention_preserves_event_linked_to_alert(
    client: TestClient,
    auth_headers: dict[str, str],
    sample_alert: dict,
    database_path: Path,
) -> None:
    alert = copy.deepcopy(sample_alert)
    alert["timestamp"] = (datetime.now(timezone.utc) - timedelta(minutes=2)).isoformat()
    created = client.post("/api/v1/alerts/ingest", headers=auth_headers, json=alert)
    assert created.status_code == 201, created.text
    alert_id = created.json()["alert"]["alert_id"]
    related = client.get("/api/v1/events", params={"related_alert_id": alert_id}).json()
    protected_event_id = related["items"][0]["event_id"]

    repository = EventRepository(database_path, retention_days=30, max_records=1)
    now = datetime.now(timezone.utc)
    with sqlite3.connect(database_path) as connection:
        audit_before = connection.execute(
            "SELECT details_json FROM security_audit_events WHERE action='SECURITY_EVENT_RETENTION' ORDER BY occurred_at DESC LIMIT 1"
        ).fetchone()
    with pytest.raises(RetentionCapacityError):
        repository.ingest(
            normalize_wazuh_event(
                archive_event(event_id="new-at-alert-cap", timestamp=now.isoformat())
            ), now=now,
        )

    with sqlite3.connect(database_path) as connection:
        event_ids = {
            row[0] for row in connection.execute("SELECT event_id FROM security_events")
        }
        audit = connection.execute(
                "SELECT details_json FROM security_audit_events "
                "WHERE action='SECURITY_EVENT_RETENTION' "
                "ORDER BY occurred_at DESC LIMIT 1"
            ).fetchone()
        assert connection.execute('SELECT retained_records FROM security_event_store_state').fetchone()[0] == 1
        assert connection.execute('PRAGMA foreign_key_check').fetchall() == []
    assert event_ids == {protected_event_id}
    assert audit == audit_before


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
