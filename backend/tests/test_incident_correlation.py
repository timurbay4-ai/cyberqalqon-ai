from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.db.alerts import AlertRepository
from app.main import create_app
from app.services.incident_correlation import IncidentCorrelationEngine, normalize_ip
from app.services.wazuh_normalizer import normalize_wazuh_alert, raw_event_fingerprint
from tests.conftest import bootstrap_and_login


INGEST_HEADERS = {"X-API-Key": "test-ingest-key"}


def _raw(
    alert_id: str,
    rule_id: str,
    occurred_at: datetime,
    *,
    source: str | None = "198.51.100.10",
    destination: str | None = "192.0.2.20",
    agent_id: str = "001",
    path: str | None = None,
) -> dict:
    data: dict[str, str] = {}
    if source is not None:
        data["srcip"] = source
    if destination is not None:
        data["dstip"] = destination
    descriptions = {
        "100111": "TCP port scan",
        "100101": "Web directory enumeration",
        "100120": "Sensitive path probe",
        "100130": "File created",
        "100131": "File modified",
        "999999": "Unrelated high severity event",
    }
    payload: dict = {
        "id": alert_id,
        "timestamp": occurred_at.isoformat(),
        "agent": {"id": agent_id, "name": f"agent-{agent_id}", "ip": "127.0.0.1"},
        "rule": {"id": rule_id, "level": 10, "description": descriptions[rule_id], "groups": []},
        "data": data,
        "location": "synthetic-test",
    }
    if path is not None:
        payload["syscheck"] = {"path": path, "event": "added" if rule_id == "100130" else "modified"}
    return payload


def _post(client: TestClient, payload: dict) -> None:
    response = client.post("/api/v1/alerts/ingest", headers=INGEST_HEADERS, json=payload)
    assert response.status_code == 201, response.text


def _client(database_path: Path, **settings_changes) -> TestClient:
    values = {
        "database_url": f"sqlite:///{database_path.as_posix()}",
        "wazuh_ingest_api_key": "test-ingest-key",
    }
    values.update(settings_changes)
    return TestClient(create_app(Settings(**values)))


def _incident_rows(database_path: Path) -> list[sqlite3.Row]:
    connection = sqlite3.connect(database_path)
    connection.row_factory = sqlite3.Row
    rows = connection.execute(
        "SELECT i.*, ic.correlation_rule, ic.classification FROM incidents i "
        "JOIN incident_correlations ic ON ic.incident_id = i.incident_id ORDER BY i.created_at"
    ).fetchall()
    connection.close()
    return rows


def test_correlation_resource_bounds_are_validated() -> None:
    with pytest.raises(ValueError, match="correlation_window_seconds"):
        Settings(correlation_window_seconds=86_401)
    with pytest.raises(ValueError, match="correlation_max_candidates"):
        Settings(correlation_max_candidates=2)
    with pytest.raises(ValueError, match="correlation_max_links"):
        Settings(correlation_max_links=101)
    with pytest.raises(ValueError, match="must not exceed"):
        Settings(correlation_max_candidates=3, correlation_max_links=4)


def test_complete_recon_chain_creates_explainable_incident_and_timeline(database_path: Path) -> None:
    start = datetime(2026, 10, 8, 10, 0, tzinfo=timezone.utc)
    with _client(database_path) as client:
        bootstrap_and_login(client)
        _post(client, _raw("scan", "100111", start))
        _post(client, _raw("enum", "100101", start + timedelta(seconds=30)))
        _post(client, _raw("probe", "100120", start + timedelta(seconds=60)))
        incidents = client.get("/api/v1/incidents").json()["items"]
        assert len(incidents) == 1
        assert incidents[0]["auto_correlated"] is True
        assert incidents[0]["correlation_rule"] == "CORR-001"
        detail = client.get(f"/api/v1/incidents/{incidents[0]['incident_id']}").json()
    assert detail["classification"] == "MULTI_STAGE_RECONNAISSANCE"
    assert detail["correlation"]["confidence"] == "EXACT_MATCH"
    assert "not confirmation of compromise" in detail["correlation"]["explanation"]
    assert [item["alert_id"] for item in detail["timeline"]] == ["scan", "enum", "probe"]
    assert [event["event_type"] for event in detail["history"]] == [
        "CREATED", "ALERT_LINKED", "ALERT_LINKED", "ALERT_LINKED"
    ]
    assert all(event["actor"] == "system:correlation" for event in detail["history"])


@pytest.mark.parametrize(
    ("events", "expected_rule"),
    [
        (("100101", "100120"), "CORR-003"),
        (("100101", "100101"), "CORR-002"),
    ],
)
def test_web_correlation_rules(database_path: Path, events: tuple[str, str], expected_rule: str) -> None:
    start = datetime(2026, 10, 8, 10, 0, tzinfo=timezone.utc)
    with _client(database_path) as client:
        for index, rule_id in enumerate(events):
            _post(client, _raw(f"a-{index}", rule_id, start + timedelta(seconds=index * 10)))
    rows = _incident_rows(database_path)
    assert len(rows) == 1
    assert rows[0]["correlation_rule"] == expected_rule


def test_fim_requires_exact_agent_and_path(database_path: Path) -> None:
    start = datetime(2026, 10, 8, 10, 0, tzinfo=timezone.utc)
    with _client(database_path) as client:
        _post(client, _raw("create", "100130", start, source=None, destination=None, path="/etc/app.conf"))
        _post(client, _raw("modify", "100131", start + timedelta(seconds=2), source=None, destination=None, path="/etc/app.conf"))
    rows = _incident_rows(database_path)
    assert len(rows) == 1
    assert rows[0]["correlation_rule"] == "CORR-004"
    assert rows[0]["severity"] == "MEDIUM"


@pytest.mark.parametrize(
    "second_changes",
    [
        {"source": "198.51.100.11"},
        {"agent_id": "002"},
        {"destination": "192.0.2.21"},
        {"source": None},
    ],
)
def test_recon_fails_closed_for_incompatible_or_missing_identity(
    database_path: Path, second_changes: dict
) -> None:
    start = datetime(2026, 10, 8, 10, 0, tzinfo=timezone.utc)
    with _client(database_path) as client:
        _post(client, _raw("enum", "100101", start))
        _post(client, _raw("probe", "100120", start + timedelta(seconds=1), **second_changes))
    assert _incident_rows(database_path) == []


def test_ip_normalization_and_loopback_agent_scoping(database_path: Path) -> None:
    assert normalize_ip("::ffff:192.0.2.9") == "192.0.2.9"
    assert normalize_ip("2001:0db8:0:0::1") == "2001:db8::1"
    start = datetime(2026, 10, 8, 10, 0, tzinfo=timezone.utc)
    with _client(database_path) as client:
        _post(client, _raw("a", "100101", start, source="::ffff:127.0.0.1", agent_id="001"))
        _post(client, _raw("b", "100101", start + timedelta(seconds=1), source="127.0.0.1", agent_id="001"))
        _post(client, _raw("c", "100101", start + timedelta(seconds=2), source="127.0.0.1", agent_id="002"))
    rows = _incident_rows(database_path)
    assert len(rows) == 1
    with sqlite3.connect(database_path) as connection:
        identity = connection.execute("SELECT source_identity FROM incident_correlations").fetchone()[0]
    assert identity == "agent:001|source:127.0.0.1"


def test_out_of_order_delayed_delivery_upgrades_existing_incident(database_path: Path) -> None:
    start = datetime(2026, 10, 8, 10, 0, tzinfo=timezone.utc)
    with _client(database_path) as client:
        _post(client, _raw("enum", "100101", start + timedelta(seconds=30)))
        _post(client, _raw("probe", "100120", start + timedelta(seconds=60)))
        first_id = _incident_rows(database_path)[0]["incident_id"]
        _post(client, _raw("scan-delayed", "100111", start))
    rows = _incident_rows(database_path)
    assert len(rows) == 1
    assert rows[0]["incident_id"] == first_id
    assert rows[0]["correlation_rule"] == "CORR-001"


def test_duplicate_delivery_and_window_boundary(database_path: Path) -> None:
    start = datetime(2026, 10, 8, 10, 0, tzinfo=timezone.utc)
    with _client(database_path, correlation_window_seconds=60) as client:
        first = _raw("enum", "100101", start)
        _post(client, first)
        duplicate = client.post("/api/v1/alerts/ingest", headers=INGEST_HEADERS, json=first)
        assert duplicate.status_code == 200
        _post(client, _raw("at-boundary", "100101", start + timedelta(seconds=60)))
        _post(client, _raw("outside", "100101", start + timedelta(seconds=121)))
    rows = _incident_rows(database_path)
    assert len(rows) == 1
    with sqlite3.connect(database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM auto_correlation_alerts").fetchone()[0] == 2


def test_closed_incident_and_assignment_are_preserved(database_path: Path) -> None:
    start = datetime(2026, 10, 8, 10, 0, tzinfo=timezone.utc)
    with _client(database_path) as client:
        bootstrap_and_login(client)
        _post(client, _raw("enum", "100101", start))
        _post(client, _raw("probe", "100120", start + timedelta(seconds=1)))
        incident_id = _incident_rows(database_path)[0]["incident_id"]
        assert client.patch(
            f"/api/v1/incidents/{incident_id}/assignment", json={"assigned_to": "analyst-a"}
        ).status_code == 200
        assert client.patch(f"/api/v1/incidents/{incident_id}/status", json={"status": "TRIAGED"}).status_code == 200
        assert client.patch(f"/api/v1/incidents/{incident_id}/status", json={"status": "RESOLVED"}).status_code == 200
        _post(client, _raw("later-probe", "100120", start + timedelta(seconds=2)))
        detail = client.get(f"/api/v1/incidents/{incident_id}").json()
    assert detail["status"] == "RESOLVED"
    assert detail["assigned_to"] == "analyst-a"
    assert detail["alert_count"] == 2
    assert len(_incident_rows(database_path)) == 1


def test_manual_incident_membership_is_not_modified(database_path: Path) -> None:
    start = datetime(2026, 10, 8, 10, 0, tzinfo=timezone.utc)
    with _client(database_path) as client:
        bootstrap_and_login(client)
        _post(client, _raw("enum", "100101", start))
        response = client.post(
            "/api/v1/incidents",
            json={"title": "Manual case", "description": "", "severity": "LOW", "alert_ids": ["enum"]},
        )
        assert response.status_code == 201
        incident_id = response.json()["incident_id"]
        _post(client, _raw("probe", "100120", start + timedelta(seconds=1)))
        detail = client.get(f"/api/v1/incidents/{incident_id}").json()
    assert detail["auto_correlated"] is False
    assert detail["alert_ids"] == ["enum"]
    assert _incident_rows(database_path) == []


def test_correlation_transaction_rolls_back_on_audit_failure(database_path: Path, monkeypatch) -> None:
    repository = AlertRepository(f"sqlite:///{database_path.as_posix()}")
    repository.initialize()
    start = datetime(2026, 10, 8, 10, 0, tzinfo=timezone.utc)
    for payload in (_raw("enum", "100101", start), _raw("probe", "100120", start + timedelta(seconds=1))):
        alert = normalize_wazuh_alert(payload)
        repository.ingest(alert, payload, raw_event_fingerprint(payload))
    engine = IncidentCorrelationEngine(database_path)
    monkeypatch.setattr(engine, "_append_system_history", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("audit failed")))
    with pytest.raises(RuntimeError, match="audit failed"):
        engine.correlate("probe")
    with sqlite3.connect(database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM incident_correlations").fetchone()[0] == 0


def test_ingestion_isolated_from_correlation_failure(database_path: Path) -> None:
    with _client(database_path) as client:
        class FailingEngine:
            def correlate(self, alert_id: str) -> None:
                raise RuntimeError("synthetic failure")

        client.app.state.correlation_engine = FailingEngine()
        response = client.post(
            "/api/v1/alerts/ingest",
            headers=INGEST_HEADERS,
            json=_raw("survives", "100101", datetime.now(timezone.utc)),
        )
        assert response.status_code == 201
        assert client.get("/api/v1/alerts/survives").status_code == 401
    with sqlite3.connect(database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM alerts WHERE alert_id = 'survives'").fetchone()[0] == 1


def test_concurrent_correlation_creates_one_incident(database_path: Path) -> None:
    repository = AlertRepository(f"sqlite:///{database_path.as_posix()}")
    repository.initialize()
    start = datetime(2026, 10, 8, 10, 0, tzinfo=timezone.utc)
    for payload in (_raw("enum", "100101", start), _raw("probe", "100120", start + timedelta(seconds=1))):
        alert = normalize_wazuh_alert(payload)
        repository.ingest(alert, payload, raw_event_fingerprint(payload))
    engine = IncidentCorrelationEngine(database_path)
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(engine.correlate, ["probe", "probe"]))
    assert {result.status for result in results} <= {"created", "updated"}
    assert len(_incident_rows(database_path)) == 1


def test_high_severity_alone_never_correlates(database_path: Path) -> None:
    with _client(database_path) as client:
        _post(client, _raw("unrelated", "999999", datetime.now(timezone.utc)))
    assert _incident_rows(database_path) == []
