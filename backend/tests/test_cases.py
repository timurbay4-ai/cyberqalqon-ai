from __future__ import annotations

import copy
import csv
import io
import json
import sqlite3
from pathlib import Path

from fastapi.testclient import TestClient

from app.schemas.auth import AnalystCreate, AnalystRole
from app.db.cases import CaseRepository
from tests.conftest import TEST_ORIGIN, TEST_PASSWORD
from tests.test_security_events import archive_event


def _ingest_alert(client: TestClient, sample: dict, alert_id: str = "case-alert") -> str:
    payload = copy.deepcopy(sample)
    payload["id"] = alert_id
    response = client.post(
        "/api/v1/alerts/ingest",
        headers={"X-API-Key": "test-ingest-key"},
        json=payload,
    )
    assert response.status_code == 201, response.text
    return response.json()["alert"]["alert_id"]


def _ingest_event(client: TestClient, event_id: str = "case-event") -> str:
    response = client.post(
        "/api/v1/events/ingest",
        headers={"X-API-Key": "test-ingest-key"},
        json=archive_event(event_id=event_id),
    )
    assert response.status_code == 201, response.text
    return response.json()["event"]["event_id"]


def _create_case(client: TestClient, **overrides: object) -> dict:
    payload: dict[str, object] = {
        "title": "Investigate suspicious activity",
        "description": "Bounded local investigation",
        "severity": "HIGH",
        "priority": "HIGH",
    }
    payload.update(overrides)
    response = client.post("/api/v1/cases", json=payload)
    assert response.status_code == 201, response.text
    return response.json()


def _login(client: TestClient, username: str, password: str = TEST_PASSWORD) -> None:
    response = client.post(
        "/api/v1/auth/login",
        headers={"Origin": TEST_ORIGIN},
        json={"username": username, "password": password},
    )
    assert response.status_code == 200, response.text
    client.headers.update({"Origin": TEST_ORIGIN, "X-CSRF-Token": response.json()["csrf_token"]})


def test_cases_are_explicit_durable_searchable_and_versioned(
    client: TestClient, sample_alert: dict
) -> None:
    alert_id = _ingest_alert(client, sample_alert)
    assert client.get("/api/v1/cases").json()["total"] == 0

    created = _create_case(
        client,
        source_type="ALERT",
        source_id=alert_id,
        title="  Alert-driven case  ",
    )
    assert created["case_id"].startswith("CASE-")
    assert created["title"] == "Alert-driven case"
    assert created["status"] == "OPEN"
    assert created["alert_ids"] == [alert_id]
    assert created["version"] == 1
    assert created["sla"]["policy"] == "LOCAL_CASE_SLA_V1"

    listed = client.get(
        "/api/v1/cases",
        params={"search": created["case_id"], "priority": "HIGH", "sort": "priority", "limit": 1},
    )
    assert listed.status_code == 200, listed.text
    assert listed.json()["total"] == 1
    assert listed.json()["items"][0]["case_id"] == created["case_id"]

    updated = client.patch(
        f"/api/v1/cases/{created['case_id']}",
        json={"description": "Updated description", "expected_version": 1},
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["version"] == 2

    stale = client.patch(
        f"/api/v1/cases/{created['case_id']}",
        json={"description": "Lost update", "expected_version": 1},
    )
    assert stale.status_code == 409
    assert stale.json()["detail"]["code"] == "case_conflict"


def test_case_lifecycle_requires_response_resolution_and_closure_reason(client: TestClient) -> None:
    case = _create_case(client)
    case_id = case["case_id"]
    invalid = client.post(
        f"/api/v1/cases/{case_id}/status",
        json={"status": "RESOLVED", "resolution": "Done", "expected_version": 1},
    )
    assert invalid.status_code == 409

    triage = client.post(
        f"/api/v1/cases/{case_id}/status",
        json={"status": "TRIAGING", "expected_version": 1},
    )
    assert triage.status_code == 200, triage.text
    assert triage.json()["sla"]["first_response_at"] is not None
    investigate = client.post(
        f"/api/v1/cases/{case_id}/status",
        json={"status": "INVESTIGATING", "expected_version": 2},
    )
    assert investigate.status_code == 200
    missing_resolution = client.post(
        f"/api/v1/cases/{case_id}/status",
        json={"status": "RESOLVED", "expected_version": 3},
    )
    assert missing_resolution.status_code == 409
    resolved = client.post(
        f"/api/v1/cases/{case_id}/status",
        json={"status": "RESOLVED", "resolution": "Benign administrative action", "expected_version": 3},
    )
    assert resolved.status_code == 200, resolved.text
    missing_closure = client.post(
        f"/api/v1/cases/{case_id}/status",
        json={"status": "CLOSED", "expected_version": 4},
    )
    assert missing_closure.status_code == 409
    closed = client.post(
        f"/api/v1/cases/{case_id}/status",
        json={"status": "CLOSED", "closure_reason": "Investigation complete", "expected_version": 4},
    )
    assert closed.status_code == 200, closed.text
    assert closed.json()["closed_at"] is not None
    assert [item["activity_type"] for item in closed.json()["activity"]].count("STATUS_CHANGED") == 4


def test_assignment_handoff_comments_notifications_and_rbac(client: TestClient) -> None:
    admin_id = client.get("/api/v1/auth/analysts").json()[0]["analyst_id"]
    analyst = client.app.state.auth_repository.create_analyst(
        AnalystCreate(
            username="case-analyst", display_name="Case Analyst",
            password=TEST_PASSWORD, role=AnalystRole.ANALYST,
        )
    )
    case = _create_case(client, owner_id=admin_id)
    handed = client.post(
        f"/api/v1/cases/{case['case_id']}/assignment",
        json={"owner_id": analyst.analyst_id, "handoff_note": "Please continue the documented review.", "expected_version": 1},
    )
    assert handed.status_code == 200, handed.text
    assert handed.json()["owner"]["analyst_id"] == analyst.analyst_id
    assert handed.json()["comments"][0]["comment_type"] == "HANDOFF"

    client.cookies.clear()
    _login(client, "case-analyst")
    notifications = client.get("/api/v1/notifications").json()["items"]
    assert any(item["category"] == "CASE_HANDOFF" and item["target_id"] == case["case_id"] for item in notifications)
    commented = client.post(
        f"/api/v1/cases/{case['case_id']}/comments",
        json={"body": "Reviewed current evidence.", "expected_version": 2},
    )
    assert commented.status_code == 201

    client.app.state.auth_repository.create_analyst(
        AnalystCreate(
            username="case-viewer", display_name="Case Viewer",
            password=TEST_PASSWORD, role=AnalystRole.VIEWER,
        )
    )
    client.cookies.clear()
    _login(client, "case-viewer")
    assert client.get(f"/api/v1/cases/{case['case_id']}").status_code == 200
    denied = client.post(
        f"/api/v1/cases/{case['case_id']}/comments",
        json={"body": "Denied", "expected_version": 3},
    )
    assert denied.status_code == 403
    assert client.post(f"/api/v1/cases/{case['case_id']}/reports/json").status_code == 403


def test_evidence_manifest_detects_change_and_keeps_custody_history(
    client: TestClient, sample_alert: dict, database_path: Path
) -> None:
    alert_id = _ingest_alert(client, sample_alert, "evidence-alert")
    event_id = _ingest_event(client, "evidence-event")
    case = _create_case(client, source_type="ALERT", source_id=alert_id)
    acquired = client.post(
        f"/api/v1/cases/{case['case_id']}/evidence",
        json={"reference_type": "EVENT", "reference_id": event_id, "annotation": "Initial reference", "expected_version": 1},
    )
    assert acquired.status_code == 201, acquired.text
    evidence = acquired.json()["evidence"][0]
    assert evidence["digest_algorithm"] == "SHA-256"
    assert len(evidence["digest"]) == 64
    assert evidence["integrity_status"] == "VERIFIED"
    assert evidence["custody"][0]["event_type"] == "ACQUIRED"

    verified = client.post(
        f"/api/v1/cases/{case['case_id']}/evidence/{evidence['evidence_ref_id']}/verify",
        json={"expected_version": 1},
    )
    assert verified.status_code == 200, verified.text
    assert verified.json()["evidence"][0]["integrity_status"] == "VERIFIED"

    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "UPDATE security_events SET raw_event_json = ? WHERE event_id = ?",
            (json.dumps({"changed": True}), event_id),
        )
    mismatch = client.post(
        f"/api/v1/cases/{case['case_id']}/evidence/{evidence['evidence_ref_id']}/verify",
        json={"expected_version": 2},
    )
    assert mismatch.status_code == 200, mismatch.text
    current = mismatch.json()["evidence"][0]
    assert current["integrity_status"] == "MISMATCH"
    assert [item["event_type"] for item in current["custody"]] == ["ACQUIRED", "VERIFIED", "MISMATCH"]


def test_safe_playbook_is_sequential_evidence_gated_and_approval_gated(
    client: TestClient, sample_alert: dict
) -> None:
    alert_id = _ingest_alert(client, sample_alert, "playbook-alert")
    case = _create_case(client, source_type="ALERT", source_id=alert_id)
    templates = client.get("/api/v1/cases/playbooks/templates")
    assert templates.status_code == 200
    assert {item["key"] for item in templates.json()} == {
        "login-investigation", "network-investigation", "fim-investigation",
        "ioc-investigation", "powershell-investigation",
    }
    started = client.post(
        f"/api/v1/cases/{case['case_id']}/playbooks",
        json={"template_key": "login-investigation", "expected_version": 1},
    )
    assert started.status_code == 201, started.text
    playbook = started.json()["playbooks"][0]
    first, evidence_step, third, approval = playbook["steps"]
    out_of_order = client.patch(
        f"/api/v1/cases/{case['case_id']}/playbooks/{playbook['playbook_id']}/steps/{third['step_id']}",
        json={"status": "COMPLETED", "completion_note": "Too early", "expected_version": 1},
    )
    assert out_of_order.status_code == 409
    first_done = client.patch(
        f"/api/v1/cases/{case['case_id']}/playbooks/{playbook['playbook_id']}/steps/{first['step_id']}",
        json={"status": "COMPLETED", "completion_note": "Reviewed stored telemetry", "expected_version": 1},
    )
    assert first_done.status_code == 200
    missing_evidence = client.patch(
        f"/api/v1/cases/{case['case_id']}/playbooks/{playbook['playbook_id']}/steps/{evidence_step['step_id']}",
        json={"status": "COMPLETED", "completion_note": "Preserved", "expected_version": 1},
    )
    assert missing_evidence.status_code == 409
    acquired = client.post(
        f"/api/v1/cases/{case['case_id']}/evidence",
        json={"reference_type": "ALERT", "reference_id": alert_id, "expected_version": 2},
    )
    evidence_id = acquired.json()["evidence"][0]["evidence_ref_id"]
    evidence_done = client.patch(
        f"/api/v1/cases/{case['case_id']}/playbooks/{playbook['playbook_id']}/steps/{evidence_step['step_id']}",
        json={"status": "COMPLETED", "evidence_ref_id": evidence_id, "completion_note": "Reference attached", "expected_version": 1},
    )
    assert evidence_done.status_code == 200, evidence_done.text
    third_done = client.patch(
        f"/api/v1/cases/{case['case_id']}/playbooks/{playbook['playbook_id']}/steps/{third['step_id']}",
        json={"status": "COMPLETED", "completion_note": "Account context documented", "expected_version": 1},
    )
    assert third_done.status_code == 200
    approved = client.patch(
        f"/api/v1/cases/{case['case_id']}/playbooks/{playbook['playbook_id']}/steps/{approval['step_id']}",
        json={"status": "COMPLETED", "completion_note": "Disposition approved", "expected_version": 1},
    )
    assert approved.status_code == 200, approved.text
    assert approved.json()["playbooks"][0]["status"] == "COMPLETED"


def test_case_reports_are_redacted_formula_safe_bounded_and_audited(client: TestClient) -> None:
    case = _create_case(
        client,
        title="=2+2 suspicious title",
        description="token=do-not-export secret=also-hide",
    )
    case_id = case["case_id"]
    for format_name, media_type in (
        ("json", "application/json"),
        ("csv", "text/csv"),
        ("pdf", "application/pdf"),
    ):
        response = client.post(f"/api/v1/cases/{case_id}/reports/{format_name}")
        assert response.status_code == 200, response.text
        assert response.headers["content-type"].startswith(media_type)
        assert response.headers["cache-control"] == "no-store"
        assert "attachment" in response.headers["content-disposition"]
        assert b"do-not-export" not in response.content
        if format_name == "pdf":
            assert response.content.startswith(b"%PDF-")
        if format_name == "csv":
            rows = list(csv.reader(io.StringIO(response.content.decode("utf-8-sig"))))
            assert rows[1][4].startswith("'")
    detail = client.get(f"/api/v1/cases/{case_id}").json()
    assert [item["format"] for item in detail["report_history"]] == ["PDF", "CSV", "JSON"]
    audit = client.get("/api/v1/audit-events", params={"target_type": "case"}).json()["items"]
    assert sum(item["action"] == "CASE_REPORT_GENERATED" for item in audit) == 3


def test_case_analytics_definitions_and_input_boundaries(client: TestClient) -> None:
    _create_case(client, severity="CRITICAL", priority="CRITICAL")
    analytics = client.get("/api/v1/cases/analytics", params={"days": 30})
    assert analytics.status_code == 200, analytics.text
    assert analytics.json()["open_cases"] == 1
    assert "mtta_minutes" in analytics.json()["definitions"]
    assert client.get("/api/v1/cases/analytics", params={"days": 0}).status_code == 422
    assert client.post(
        "/api/v1/cases",
        json={"title": "Bad source", "severity": "HIGH", "priority": "HIGH", "source_type": "ALERT"},
    ).status_code == 422


def test_sla_evaluation_creates_deduplicated_owner_notifications(
    client: TestClient, database_path: Path
) -> None:
    owner_id = client.get("/api/v1/auth/analysts").json()[0]["analyst_id"]
    case = _create_case(client, owner_id=owner_id, priority="CRITICAL")
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "UPDATE soc_cases SET response_due_at = ?, resolution_due_at = ? WHERE case_id = ?",
            ("2020-01-01T00:00:00+00:00", "2020-01-01T01:00:00+00:00", case["case_id"]),
        )
    first = client.post("/api/v1/cases/sla/evaluate")
    assert first.status_code == 200, first.text
    assert first.json()["evaluated_cases"] == 1
    assert first.json()["notifications_created"] == 2
    second = client.post("/api/v1/cases/sla/evaluate")
    assert second.status_code == 200
    assert second.json()["notifications_created"] == 0
    notifications = client.get("/api/v1/notifications").json()["items"]
    assert sum(item["category"] == "CASE_SLA" for item in notifications) == 2


def test_case_security_boundaries_and_restart_persistence(
    client: TestClient, database_path: Path
) -> None:
    case = _create_case(
        client,
        title="<script>alert('inert')</script>",
        description="../../etc/passwd is untrusted analyst text",
    )
    assert case["title"] == "<script>alert('inert')</script>"
    persisted = CaseRepository(database_path).get(case["case_id"])
    assert persisted.title == case["title"]

    csrf = client.headers.pop("X-CSRF-Token")
    denied = client.post(
        f"/api/v1/cases/{case['case_id']}/comments",
        json={"body": "No CSRF", "expected_version": 1},
    )
    assert denied.status_code == 403
    assert denied.json()["detail"]["code"] == "invalid_csrf_token"
    client.headers["X-CSRF-Token"] = csrf

    assert client.post(
        f"/api/v1/cases/{case['case_id']}/comments",
        json={"body": "x" * 4097, "expected_version": 1},
    ).status_code == 422
    traversal = client.post(
        f"/api/v1/cases/{case['case_id']}/evidence",
        json={"reference_type": "EVENT", "reference_id": "../../etc/passwd", "expected_version": 1},
    )
    assert traversal.status_code == 404
