from __future__ import annotations

import copy
import sqlite3
from pathlib import Path

from fastapi.testclient import TestClient

from app.schemas.auth import AnalystCreate, AnalystRole
from tests.conftest import TEST_ORIGIN, TEST_PASSWORD


def _ingest(client: TestClient, payload: dict, alert_id: str) -> dict:
    event = copy.deepcopy(payload)
    event["id"] = alert_id
    response = client.post(
        "/api/v1/alerts/ingest",
        headers={"X-API-Key": "test-ingest-key"},
        json=event,
    )
    assert response.status_code == 201, response.text
    return response.json()["alert"]


def _login(client: TestClient, username: str, password: str = TEST_PASSWORD) -> dict:
    response = client.post(
        "/api/v1/auth/login",
        headers={"Origin": TEST_ORIGIN},
        json={"username": username, "password": password},
    )
    assert response.status_code == 200, response.text
    session = response.json()
    client.headers.update(
        {"Origin": TEST_ORIGIN, "X-CSRF-Token": session["csrf_token"]}
    )
    return session


def test_alert_lifecycle_is_durable_audited_and_versioned(
    client: TestClient,
    sample_alert: dict,
    database_path: Path,
) -> None:
    alert = _ingest(client, sample_alert, "workflow-001")

    listed = client.get("/api/v1/alert-workflows")
    assert listed.status_code == 200
    body = listed.json()
    assert body["items"][0]["alert"]["alert_id"] == alert["alert_id"]
    assert body["items"][0]["status"] == "NEW"
    assert body["items"][0]["version"] == 1
    assert body["counts"] == {
        "total": 1,
        "actionable": 1,
        "unassigned": 1,
        "by_status": {
            "NEW": 1,
            "ACKNOWLEDGED": 0,
            "IN_PROGRESS": 0,
            "RESOLVED": 0,
            "FALSE_POSITIVE": 0,
        },
    }

    acknowledged = client.patch(
        f"/api/v1/alert-workflows/{alert['alert_id']}/status",
        json={"status": "ACKNOWLEDGED", "expected_version": 1},
    )
    assert acknowledged.status_code == 200, acknowledged.text
    assert acknowledged.json()["version"] == 2

    stale = client.patch(
        f"/api/v1/alert-workflows/{alert['alert_id']}/status",
        json={"status": "IN_PROGRESS", "expected_version": 1},
    )
    assert stale.status_code == 409
    assert stale.json()["detail"]["code"] == "version_conflict"

    analyst_id = client.get("/api/v1/auth/analysts").json()[0]["analyst_id"]
    assigned = client.patch(
        f"/api/v1/alert-workflows/{alert['alert_id']}/assignment",
        json={"assigned_to": analyst_id, "expected_version": 2},
    )
    assert assigned.status_code == 200, assigned.text
    assert assigned.json()["assignee"]["analyst_id"] == analyst_id
    assert assigned.json()["version"] == 3

    noted = client.post(
        f"/api/v1/alert-workflows/{alert['alert_id']}/notes",
        json={"body": "Validated against the source host.", "expected_version": 3},
    )
    assert noted.status_code == 201, noted.text
    detail = noted.json()
    assert detail["version"] == 4
    assert detail["notes"][0]["body"] == "Validated against the source host."
    assert [event["event_type"] for event in detail["history"]] == [
        "STATUS_CHANGED",
        "ASSIGNMENT_CHANGED",
        "NOTE_ADDED",
    ]

    resolved = client.patch(
        f"/api/v1/alert-workflows/{alert['alert_id']}/status",
        json={"status": "RESOLVED", "expected_version": 4},
    )
    assert resolved.status_code == 200
    assert resolved.json()["status"] == "RESOLVED"
    invalid_reopen = client.patch(
        f"/api/v1/alert-workflows/{alert['alert_id']}/status",
        json={"status": "IN_PROGRESS", "expected_version": 5},
    )
    assert invalid_reopen.status_code == 409
    assert invalid_reopen.json()["detail"]["code"] == "invalid_status_transition"

    filtered = client.get(
        "/api/v1/alert-workflows",
        params={"status": "RESOLVED", "assigned_to": analyst_id, "sort": "severity_desc"},
    )
    assert filtered.status_code == 200
    assert filtered.json()["page"]["total"] == 1

    with sqlite3.connect(database_path) as connection:
        actions = [
            row[0]
            for row in connection.execute(
                "SELECT action FROM security_audit_events "
                "WHERE target_type = 'alert' AND target_id = ? ORDER BY occurred_at",
                (alert["alert_id"],),
            )
        ]
    assert actions == [
        "ALERT_STATUS_CHANGED",
        "ALERT_ASSIGNMENT_CHANGED",
        "ALERT_NOTE_ADDED",
        "ALERT_STATUS_CHANGED",
    ]


def test_bulk_update_is_bounded_atomic_and_reports_each_failure(
    client: TestClient,
    sample_alert: dict,
) -> None:
    first = _ingest(client, sample_alert, "bulk-001")
    second = _ingest(client, sample_alert, "bulk-002")
    payload = {
        "action": "ACKNOWLEDGE",
        "items": [
            {"alert_id": first["alert_id"], "expected_version": 1},
            {"alert_id": second["alert_id"], "expected_version": 1},
        ],
    }
    response = client.post("/api/v1/alert-workflows/bulk", json=payload)
    assert response.status_code == 200, response.text
    assert response.json()["selected_count"] == 2
    assert response.json()["updated_count"] == 2

    rejected = client.post(
        "/api/v1/alert-workflows/bulk",
        json={
            "action": "SET_STATUS",
            "status": "IN_PROGRESS",
            "items": [
                {"alert_id": first["alert_id"], "expected_version": 2},
                {"alert_id": second["alert_id"], "expected_version": 1},
            ],
        },
    )
    assert rejected.status_code == 409
    detail = rejected.json()["detail"]
    assert detail["code"] == "bulk_operation_rejected"
    assert detail["failures"] == [
        {
            "alert_id": second["alert_id"],
            "code": "version_conflict",
            "message": "Expected version 1; current version is 2",
        }
    ]
    assert client.get(f"/api/v1/alert-workflows/{first['alert_id']}").json()["status"] == "ACKNOWLEDGED"

    oversized = client.post(
        "/api/v1/alert-workflows/bulk",
        json={
            "action": "ACKNOWLEDGE",
            "items": [
                {"alert_id": f"a-{index}", "expected_version": 1}
                for index in range(51)
            ],
        },
    )
    assert oversized.status_code == 422


def test_viewer_cannot_mutate_and_csrf_is_required(
    client: TestClient,
    sample_alert: dict,
) -> None:
    alert = _ingest(client, sample_alert, "rbac-001")
    client.app.state.auth_repository.create_analyst(
        AnalystCreate(
            username="readonly-viewer",
            display_name="Read Only Viewer",
            password=TEST_PASSWORD,
            role=AnalystRole.VIEWER,
        )
    )
    client.cookies.clear()
    _login(client, "readonly-viewer")

    assert client.get("/api/v1/alert-workflows").status_code == 200
    forbidden = client.patch(
        f"/api/v1/alert-workflows/{alert['alert_id']}/status",
        json={"status": "ACKNOWLEDGED", "expected_version": 1},
    )
    assert forbidden.status_code == 403
    assert forbidden.json()["detail"]["code"] == "permission_denied"

    client.headers["X-CSRF-Token"] = "wrong-token"
    csrf = client.post("/api/v1/notifications/read-all")
    assert csrf.status_code == 403
    assert csrf.json()["detail"]["code"] == "invalid_csrf_token"


def test_notifications_are_deduplicated_and_private(
    client: TestClient,
    sample_alert: dict,
    database_path: Path,
) -> None:
    viewer = client.app.state.auth_repository.create_analyst(
        AnalystCreate(
            username="notification-viewer",
            display_name="Notification Viewer",
            password=TEST_PASSWORD,
            role=AnalystRole.ANALYST,
        )
    )
    alert = _ingest(client, sample_alert, "notification-001")

    admin_notifications = client.get("/api/v1/notifications").json()
    assert admin_notifications["unread_count"] == 1
    assert admin_notifications["items"][0]["target_id"] == alert["alert_id"]

    assigned = client.patch(
        f"/api/v1/alert-workflows/{alert['alert_id']}/assignment",
        json={"assigned_to": viewer.analyst_id, "expected_version": 1},
    )
    assert assigned.status_code == 200

    client.cookies.clear()
    _login(client, "notification-viewer")
    private = client.get("/api/v1/notifications").json()
    assert private["unread_count"] == 2
    assert {item["category"] for item in private["items"]} == {
        "HIGH_ALERT",
        "ALERT_ASSIGNED",
    }

    notification_id = private["items"][0]["notification_id"]
    with sqlite3.connect(database_path) as connection:
        connection.executemany(
            """
            INSERT INTO security_audit_events (
                audit_id, action, actor_id, actor_display, target_type,
                target_id, outcome, occurred_at, details_json
            ) VALUES (?, 'TEST_EVENT', NULL, 'test', 'test', NULL,
                      'SUCCESS', ?, '{}')
            """,
            [
                (f"AUD-BOUND-{index:05d}", f"2026-01-01T00:00:{index:05d}+00:00")
                for index in range(10_000)
            ],
        )
    marked = client.patch(f"/api/v1/notifications/{notification_id}/read")
    assert marked.status_code == 200
    assert marked.json()["read_at"] is not None
    marked_again = client.patch(f"/api/v1/notifications/{notification_id}/read")
    assert marked_again.status_code == 200
    assert client.get("/api/v1/notifications").json()["unread_count"] == 1
    all_read = client.post("/api/v1/notifications/read-all")
    assert all_read.status_code == 200
    assert all_read.json()["updated_count"] == 1
    assert client.get("/api/v1/notifications").json()["unread_count"] == 0

    missing = client.patch("/api/v1/notifications/NTF-NOT-OWNED/read")
    assert missing.status_code == 404
    with sqlite3.connect(database_path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM security_audit_events"
        ).fetchone()[0] == 10_000
