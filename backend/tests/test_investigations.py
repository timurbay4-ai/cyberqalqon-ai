from __future__ import annotations

import copy

from fastapi.testclient import TestClient

from app.schemas.auth import AnalystCreate, AnalystRole
from tests.conftest import TEST_ORIGIN, TEST_PASSWORD
from tests.test_security_events import archive_event


def _ingest_alert(client: TestClient, payload: dict, alert_id: str) -> str:
    alert = copy.deepcopy(payload)
    alert["id"] = alert_id
    response = client.post(
        "/api/v1/alerts/ingest", headers={"X-API-Key": "test-ingest-key"}, json=alert
    )
    assert response.status_code == 201, response.text
    return response.json()["alert"]["alert_id"]


def _incident(client: TestClient, alert_id: str) -> str:
    response = client.post(
        "/api/v1/incidents",
        json={"title": "Investigation workspace", "severity": "HIGH", "alert_ids": [alert_id]},
    )
    assert response.status_code == 201, response.text
    return response.json()["incident_id"]


def _login(client: TestClient, username: str) -> None:
    response = client.post(
        "/api/v1/auth/login",
        headers={"Origin": TEST_ORIGIN},
        json={"username": username, "password": TEST_PASSWORD},
    )
    assert response.status_code == 200
    client.headers.update(
        {"Origin": TEST_ORIGIN, "X-CSRF-Token": response.json()["csrf_token"]}
    )


def test_checklist_is_versioned_reorderable_and_audited(
    client: TestClient, sample_alert: dict
) -> None:
    alert_id = _ingest_alert(client, sample_alert, "investigation-checklist")
    incident_id = _incident(client, alert_id)
    analyst_id = client.get("/api/v1/auth/analysts").json()[0]["analyst_id"]

    empty = client.get(f"/api/v1/incidents/{incident_id}/investigation")
    assert empty.status_code == 200
    assert empty.json()["checklist_total"] == 0

    assert client.post(
        f"/api/v1/incidents/{incident_id}/investigation/checklist",
        json={"body": "   "},
    ).status_code == 422
    assert client.post(
        f"/api/v1/incidents/{incident_id}/investigation/checklist",
        json={"body": "x" * 1025},
    ).status_code == 422

    created = client.post(
        f"/api/v1/incidents/{incident_id}/investigation/checklist",
        json={"body": "Validate affected host", "assigned_to": analyst_id},
    )
    assert created.status_code == 201, created.text
    first = created.json()["checklist_items"][0]
    assert first["assigned_to"]["analyst_id"] == analyst_id
    assert first["version"] == 1

    second_response = client.post(
        f"/api/v1/incidents/{incident_id}/investigation/checklist",
        json={"body": "Preserve evidence"},
    )
    second = second_response.json()["checklist_items"][1]

    completed = client.patch(
        f"/api/v1/incidents/{incident_id}/investigation/checklist/{first['checklist_item_id']}",
        json={"is_completed": True, "expected_version": 1},
    )
    assert completed.status_code == 200
    updated_first = completed.json()["checklist_items"][0]
    assert updated_first["completed_at"] is not None
    assert updated_first["version"] == 2

    unchanged = client.patch(
        f"/api/v1/incidents/{incident_id}/investigation/checklist/{first['checklist_item_id']}",
        json={"expected_version": 2},
    )
    assert unchanged.status_code == 422

    stale = client.patch(
        f"/api/v1/incidents/{incident_id}/investigation/checklist/{first['checklist_item_id']}",
        json={"body": "Stale edit", "expected_version": 1},
    )
    assert stale.status_code == 409
    assert stale.json()["detail"]["code"] == "version_conflict"

    reordered = client.post(
        f"/api/v1/incidents/{incident_id}/investigation/checklist/reorder",
        json={"items": [
            {"checklist_item_id": second["checklist_item_id"], "expected_version": 1},
            {"checklist_item_id": first["checklist_item_id"], "expected_version": 2},
        ]},
    )
    assert reordered.status_code == 200, reordered.text
    assert [item["body"] for item in reordered.json()["checklist_items"]] == [
        "Preserve evidence", "Validate affected host"
    ]

    timeline = client.get(
        f"/api/v1/incidents/{incident_id}/investigation/timeline", params={"limit": 2}
    )
    assert timeline.status_code == 200, timeline.text
    assert timeline.json()["total"] >= 5
    assert timeline.json()["next_cursor"] is not None
    activity_types = {
        item["activity_type"]
        for item in client.get(
            f"/api/v1/incidents/{incident_id}/investigation/timeline", params={"limit": 100}
        ).json()["items"]
    }
    assert {"CHECKLIST_CREATED", "CHECKLIST_COMPLETED", "CHECKLIST_REORDERED"} <= activity_types


def test_evidence_references_are_validated_immutable_and_private_to_incident(
    client: TestClient, sample_alert: dict
) -> None:
    alert_id = _ingest_alert(client, sample_alert, "investigation-evidence")
    incident_id = _incident(client, alert_id)
    event_response = client.post(
        "/api/v1/events/ingest",
        headers={"X-API-Key": "test-ingest-key"},
        json=archive_event(event_id="investigation-event"),
    )
    event_id = event_response.json()["event"]["event_id"]

    for evidence_type, evidence_id in (
        ("EVENT", event_id),
        ("ALERT", alert_id),
        ("INCIDENT_EVIDENCE", alert_id),
    ):
        response = client.post(
            f"/api/v1/incidents/{incident_id}/investigation/evidence",
            json={"evidence_type": evidence_type, "evidence_id": evidence_id, "annotation": "Review source"},
        )
        assert response.status_code == 201, response.text

    workspace = response.json()
    assert len(workspace["evidence_pins"]) == 3
    pin = next(item for item in workspace["evidence_pins"] if item["evidence_type"] == "EVENT")
    assert pin["source_timestamp"] is not None

    duplicate = client.post(
        f"/api/v1/incidents/{incident_id}/investigation/evidence",
        json={"evidence_type": "EVENT", "evidence_id": event_id},
    )
    assert duplicate.status_code == 409
    missing = client.post(
        f"/api/v1/incidents/{incident_id}/investigation/evidence",
        json={"evidence_type": "EVENT", "evidence_id": "missing"},
    )
    assert missing.status_code == 404

    annotated = client.patch(
        f"/api/v1/incidents/{incident_id}/investigation/evidence/{pin['evidence_pin_id']}",
        json={"annotation": "Verified against source", "expected_version": pin["version"]},
    )
    assert annotated.status_code == 200
    current = next(
        item for item in annotated.json()["evidence_pins"]
        if item["evidence_pin_id"] == pin["evidence_pin_id"]
    )
    assert current["evidence_id"] == event_id
    assert current["version"] == 2

    unpinned = client.post(
        f"/api/v1/incidents/{incident_id}/investigation/evidence/{pin['evidence_pin_id']}/unpin",
        json={"expected_version": 2},
    )
    assert unpinned.status_code == 200
    assert all(
        item["evidence_pin_id"] != pin["evidence_pin_id"]
        for item in unpinned.json()["evidence_pins"]
    )


def test_investigation_viewer_reads_but_cannot_mutate(
    client: TestClient, sample_alert: dict
) -> None:
    alert_id = _ingest_alert(client, sample_alert, "investigation-rbac")
    incident_id = _incident(client, alert_id)
    client.app.state.auth_repository.create_analyst(
        AnalystCreate(
            username="investigation-viewer", display_name="Investigation Viewer",
            password=TEST_PASSWORD, role=AnalystRole.VIEWER,
        )
    )
    client.cookies.clear()
    _login(client, "investigation-viewer")
    assert client.get(f"/api/v1/incidents/{incident_id}/investigation").status_code == 200
    denied = client.post(
        f"/api/v1/incidents/{incident_id}/investigation/checklist",
        json={"body": "Unauthorized"},
    )
    assert denied.status_code == 403


def test_preferences_are_isolated_validated_and_versioned(client: TestClient) -> None:
    initial = client.get("/api/v1/preferences")
    assert initial.status_code == 200
    assert initial.json()["discover_columns"] == [
        "time", "source", "host", "identity", "rule", "event"
    ]
    updated = client.put(
        "/api/v1/preferences",
        json={
            "dashboard_range": "7d", "discover_page_size": 50,
            "alert_page_size": 50, "incident_page_size": 25,
            "table_density": "COMPACT", "time_display": "UTC",
            "alert_default_sort": "severity_desc",
            "discover_columns": ["event", "time", "host", "rule"],
            "expected_version": 1,
        },
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["version"] == 2
    assert updated.json()["discover_columns"] == ["event", "time", "host", "rule"]

    stale = client.put(
        "/api/v1/preferences",
        json={**{key: value for key, value in updated.json().items() if key != "version"}, "expected_version": 1},
    )
    assert stale.status_code == 409
    invalid = client.put(
        "/api/v1/preferences",
        json={
            "dashboard_range": "7d", "discover_page_size": 50,
            "alert_page_size": 50, "incident_page_size": 25,
            "table_density": "COMPACT", "time_display": "UTC",
            "alert_default_sort": "severity_desc",
            "discover_columns": ["host", "rule"], "expected_version": 2,
        },
    )
    assert invalid.status_code == 422

    client.app.state.auth_repository.create_analyst(
        AnalystCreate(
            username="preference-viewer", display_name="Preference Viewer",
            password=TEST_PASSWORD, role=AnalystRole.VIEWER,
        )
    )
    client.cookies.clear()
    _login(client, "preference-viewer")
    private = client.get("/api/v1/preferences")
    assert private.status_code == 200
    assert private.json()["dashboard_range"] == "24h"
    assert private.json()["version"] == 1
