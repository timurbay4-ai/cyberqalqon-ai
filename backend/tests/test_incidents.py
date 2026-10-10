from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app
from app.db.migrations import MIGRATIONS
from tests.conftest import bootstrap_and_login


def _create_incident(
    client: TestClient,
    *,
    title: str = "Repeated authentication failures",
    severity: str = "HIGH",
    alert_ids: list[str] | None = None,
    assigned_to: str | None = None,
) -> dict:
    response = client.post(
        "/api/v1/incidents",
        json={
            "title": title,
            "description": "Investigate the affected endpoint.",
            "severity": severity,
            "assigned_to": assigned_to,
            "alert_ids": alert_ids or [],
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _ingest_sample(client: TestClient, sample_alert: dict, auth_headers: dict[str, str]) -> str:
    response = client.post(
        "/api/v1/alerts/ingest",
        headers=auth_headers,
        json=sample_alert,
    )
    assert response.status_code == 201, response.text
    return response.json()["alert"]["alert_id"]


def test_incident_creation_and_retrieval_preserve_untrusted_text(client: TestClient) -> None:
    created = _create_incident(
        client,
        title="<script>alert('untrusted')</script>",
        assigned_to="soc-analyst",
    )

    assert created["incident_id"].startswith("INC-")
    assert created["title"] == "<script>alert('untrusted')</script>"
    assert created["status"] == "NEW"
    assert created["severity"] == "HIGH"
    assert created["assigned_to"] == "soc-analyst"
    assert created["alert_count"] == 0
    assert created["alert_ids"] == []
    assert created["notes"] == []
    assert [event["event_type"] for event in created["history"]] == [
        "CREATED",
        "ASSIGNMENT_CHANGED",
    ]

    response = client.get(f"/api/v1/incidents/{created['incident_id']}")
    assert response.status_code == 200
    assert response.json() == created


def test_create_incident_with_alert_link_and_missing_alert_is_atomic(
    client: TestClient,
    sample_alert: dict,
    auth_headers: dict[str, str],
) -> None:
    alert_id = _ingest_sample(client, sample_alert, auth_headers)

    created = _create_incident(client, alert_ids=[alert_id])
    assert created["alert_ids"] == [alert_id]
    assert created["alert_count"] == 1
    assert [event["event_type"] for event in created["history"]] == [
        "CREATED",
        "ALERT_LINKED",
    ]

    response = client.post(
        "/api/v1/incidents",
        json={
            "title": "Must roll back",
            "severity": "LOW",
            "alert_ids": ["missing-alert"],
        },
    )
    assert response.status_code == 404
    assert response.json()["detail"] == {
        "code": "alert_not_found",
        "message": "No alert exists with the requested identifier",
        "field": "alert_id",
    }
    assert client.get("/api/v1/incidents").json()["page"]["total"] == 1


def test_initial_incident_assignment_notification_is_bounded(
    client: TestClient,
    database_path: Path,
) -> None:
    with sqlite3.connect(database_path) as connection:
        analyst_id = connection.execute(
            "SELECT analyst_id FROM analysts ORDER BY created_at LIMIT 1"
        ).fetchone()[0]
        connection.executemany(
            """
            INSERT INTO analyst_notifications (
                notification_id, analyst_id, category, title, preview,
                target_type, target_id, event_key, created_at, read_at
            ) VALUES (?, ?, 'HIGH_ALERT', 'Existing alert', 'Existing preview',
                      'alert', ?, ?, ?, NULL)
            """,
            [
                (
                    f"NTF-BOUND-{index:04d}",
                    analyst_id,
                    f"alert-{index}",
                    f"existing:{index}",
                    f"2026-01-01T00:00:{index:04d}+00:00",
                )
                for index in range(500)
            ],
        )

    incident = _create_incident(client, assigned_to=analyst_id)
    with sqlite3.connect(database_path) as connection:
        count = connection.execute(
            "SELECT COUNT(*) FROM analyst_notifications WHERE analyst_id = ?",
            (analyst_id,),
        ).fetchone()[0]
        created = connection.execute(
            """
            SELECT category FROM analyst_notifications
            WHERE analyst_id = ? AND target_type = 'incident' AND target_id = ?
            """,
            (analyst_id, incident["incident_id"]),
        ).fetchone()
    assert count == 500
    assert created == ("INCIDENT_ASSIGNED",)


def test_valid_lifecycle_transitions_are_audited(client: TestClient) -> None:
    incident = _create_incident(client)
    incident_id = incident["incident_id"]

    for expected in ("TRIAGED", "INVESTIGATING", "RESOLVED", "INVESTIGATING"):
        response = client.patch(
            f"/api/v1/incidents/{incident_id}/status",
            json={"status": expected},
        )
        assert response.status_code == 200, response.text
        assert response.json()["status"] == expected

    history = response.json()["history"]
    transitions = [
        event["details"]
        for event in history
        if event["event_type"] == "STATUS_CHANGED"
    ]
    assert transitions == [
        {"from": "NEW", "to": "TRIAGED"},
        {"from": "TRIAGED", "to": "INVESTIGATING"},
        {"from": "INVESTIGATING", "to": "RESOLVED"},
        {"from": "RESOLVED", "to": "INVESTIGATING"},
    ]


def test_invalid_lifecycle_transitions_and_status_values_are_structured(
    client: TestClient,
) -> None:
    incident_id = _create_incident(client)["incident_id"]

    response = client.patch(
        f"/api/v1/incidents/{incident_id}/status",
        json={"status": "RESOLVED"},
    )
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "invalid_status_transition"
    assert response.json()["detail"]["field"] == "status"

    response = client.patch(
        f"/api/v1/incidents/{incident_id}/status",
        json={"status": "CLOSED"},
    )
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "invalid_request"
    assert response.json()["detail"]["field"] == "status"


def test_alert_linking_rejects_duplicate_and_missing_alerts(
    client: TestClient,
    database_path: Path,
    sample_alert: dict,
    auth_headers: dict[str, str],
) -> None:
    incident_id = _create_incident(client)["incident_id"]
    alert_id = _ingest_sample(client, sample_alert, auth_headers)

    response = client.post(
        f"/api/v1/incidents/{incident_id}/alerts",
        json={"alert_id": alert_id},
    )
    assert response.status_code == 201
    assert response.json()["alert_ids"] == [alert_id]

    duplicate = client.post(
        f"/api/v1/incidents/{incident_id}/alerts",
        json={"alert_id": alert_id},
    )
    assert duplicate.status_code == 409
    assert duplicate.json()["detail"]["code"] == "duplicate_alert_link"

    missing = client.post(
        f"/api/v1/incidents/{incident_id}/alerts",
        json={"alert_id": "does-not-exist"},
    )
    assert missing.status_code == 404
    assert missing.json()["detail"]["code"] == "alert_not_found"

    with sqlite3.connect(database_path) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("DELETE FROM alerts WHERE alert_id = ?", (alert_id,))


def test_notes_and_assignment_changes_are_append_only_and_audited(
    client: TestClient,
) -> None:
    incident_id = _create_incident(client)["incident_id"]

    assignment = client.patch(
        f"/api/v1/incidents/{incident_id}/assignment",
        json={"assigned_to": "analyst-3"},
    )
    assert assignment.status_code == 200
    assert assignment.json()["assigned_to"] == "analyst-3"

    note = client.post(
        f"/api/v1/incidents/{incident_id}/notes",
        json={"body": "Checked endpoint; no containment yet."},
    )
    assert note.status_code == 201
    assert note.json()["body"] == "Checked endpoint; no containment yet."
    assert note.json()["author"] == "Test Administrator (admin)"
    assert note.json()["author_id"].startswith("USR-")

    detail = client.get(f"/api/v1/incidents/{incident_id}").json()
    assert detail["notes"] == [note.json()]
    assert [event["event_type"] for event in detail["history"]] == [
        "CREATED",
        "ASSIGNMENT_CHANGED",
        "NOTE_ADDED",
    ]
    assert detail["history"][-1]["details"] == {"note_id": note.json()["note_id"]}

    unchanged = client.patch(
        f"/api/v1/incidents/{incident_id}/assignment",
        json={"assigned_to": "analyst-3"},
    )
    assert unchanged.status_code == 409
    assert unchanged.json()["detail"]["code"] == "assignment_unchanged"


def test_incident_list_uses_stable_pagination_and_filters(
    client: TestClient,
    database_path: Path,
) -> None:
    created = [
        _create_incident(
            client,
            title=f"Incident {index}",
            severity="HIGH" if index % 2 else "LOW",
            assigned_to="analyst-a" if index < 3 else "analyst-b",
        )
        for index in range(4)
    ]
    triaged_id = created[0]["incident_id"]
    response = client.patch(
        f"/api/v1/incidents/{triaged_id}/status",
        json={"status": "TRIAGED"},
    )
    assert response.status_code == 200

    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "UPDATE incidents SET created_at = ?",
            ("2026-10-06T12:00:00+00:00",),
        )

    full = client.get("/api/v1/incidents?limit=100").json()
    first = client.get("/api/v1/incidents?limit=2").json()
    second = client.get(
        "/api/v1/incidents",
        params={"limit": 2, "cursor": first["page"]["next_cursor"]},
    ).json()
    combined_ids = [item["incident_id"] for item in first["items"] + second["items"]]
    assert combined_ids == [item["incident_id"] for item in full["items"]]
    assert combined_ids == sorted(combined_ids, reverse=True)
    assert len(set(combined_ids)) == 4
    assert first["page"]["total"] == 4
    assert second["page"]["total"] == 4
    assert second["page"]["next_cursor"] is None

    filtered = client.get(
        "/api/v1/incidents",
        params=[("severity", "HIGH"), ("status", "NEW"), ("assigned_to", "ANALYST-A")],
    ).json()
    assert filtered["page"]["total"] == 1
    assert filtered["items"][0]["severity"] == "HIGH"
    assert filtered["items"][0]["status"] == "NEW"


def test_invalid_incident_cursor_is_structured(client: TestClient) -> None:
    response = client.get("/api/v1/incidents", params={"cursor": "not-a-cursor"})
    assert response.status_code == 422
    assert response.json()["detail"] == {
        "code": "invalid_cursor",
        "message": "cursor is malformed",
        "field": "cursor",
    }


def test_incident_filters_treat_sql_metacharacters_as_data(client: TestClient) -> None:
    _create_incident(client, assigned_to="analyst-a")

    response = client.get(
        "/api/v1/incidents",
        params={"assigned_to": "analyst-a' OR 1=1 --"},
    )

    assert response.status_code == 200
    assert response.json()["items"] == []
    assert response.json()["page"]["total"] == 0
    assert client.get("/api/v1/incidents").json()["page"]["total"] == 1


def test_missing_incident_and_bounded_inputs_return_structured_errors(
    client: TestClient,
) -> None:
    response = client.get("/api/v1/incidents/INC-MISSING")
    assert response.status_code == 404
    assert response.json()["detail"]["code"] == "incident_not_found"

    response = client.post(
        "/api/v1/incidents",
        json={"title": "x" * 256, "severity": "HIGH"},
    )
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "invalid_request"
    assert response.json()["detail"]["field"] == "title"

    response = client.post(
        "/api/v1/incidents",
        json={
            "title": "Duplicate initial links",
            "severity": "LOW",
            "alert_ids": ["same", "same"],
        },
    )
    assert response.status_code == 422
    assert response.json()["detail"]["field"] == "alert_ids"


def test_incident_persists_across_application_restart(database_path: Path) -> None:
    settings = Settings(
        database_url=f"sqlite:///{database_path.as_posix()}",
        wazuh_ingest_api_key="test-ingest-key",
    )
    with TestClient(create_app(settings)) as first_client:
        bootstrap_and_login(first_client)
        incident_id = _create_incident(first_client)["incident_id"]
        note = first_client.post(
            f"/api/v1/incidents/{incident_id}/notes",
            json={"body": "Persistent note"},
        )
        assert note.status_code == 201

    with TestClient(create_app(settings)) as second_client:
        response = second_client.post(
            "/api/v1/auth/login",
            headers={"Origin": "http://localhost:5173"},
            json={"username": "admin", "password": "Correct-Horse-Battery-77"},
        )
        assert response.status_code == 200
        response = second_client.get(f"/api/v1/incidents/{incident_id}")
        assert response.status_code == 200
        assert response.json()["notes"][0]["body"] == "Persistent note"
        assert [event["event_type"] for event in response.json()["history"]] == [
            "CREATED",
            "NOTE_ADDED",
        ]

    with sqlite3.connect(database_path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == len(MIGRATIONS)
