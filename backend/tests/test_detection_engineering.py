from __future__ import annotations

import copy
import sqlite3
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from app.schemas.auth import AnalystCreate, AnalystRole
from tests.conftest import TEST_ORIGIN, TEST_PASSWORD


def _login(client: TestClient, username: str) -> None:
    response = client.post(
        "/api/v1/auth/login",
        headers={"Origin": TEST_ORIGIN},
        json={"username": username, "password": TEST_PASSWORD},
    )
    assert response.status_code == 200, response.text
    client.headers.update({
        "Origin": TEST_ORIGIN,
        "X-CSRF-Token": response.json()["csrf_token"],
    })


def _event(timestamp: datetime, event_id: str = "hunt-event-1") -> dict:
    return {
        "timestamp": timestamp.isoformat(),
        "id": event_id,
        "agent": {"id": "001", "name": "hunt-host"},
        "rule": {"id": "100111", "level": 10, "description": "TCP scan"},
        "decoder": {"name": "json"},
        "location": "CQ-NETSCAN",
        "data": {
            "srcip": "192.0.2.25", "dstip": "127.0.0.1", "dstport": "443",
            "domain": "Example.COM.",
            "sha256": "a" * 64,
        },
        "full_log": "CQ-NETSCAN src=192.0.2.25 dst=127.0.0.1 dstport=443",
    }


def _draft_payload() -> dict:
    return {
        "name": "Local scan candidate",
        "description": "Find normalized network scan evidence.",
        "severity": 10,
        "source_type": "network",
        "mitre_ids": ["T1046"],
        "conditions": [
            {"field": "source_type", "operator": "EQUALS", "value": "network"},
            {"field": "source_ip", "operator": "EQUALS", "value": "192.0.2.25"},
        ],
        "documentation": "Local draft only; manual Wazuh review is required.",
        "change_summary": "Initial bounded draft",
    }


def test_rule_inventory_coverage_and_external_metadata_are_truthful(
    client: TestClient, sample_alert: dict
) -> None:
    alert = copy.deepcopy(sample_alert)
    alert["id"] = "external-rule-inventory"
    alert["timestamp"] = datetime.now(timezone.utc).isoformat()
    alert["rule"]["id"] = "999999"
    alert["rule"]["description"] = "External observed rule"
    alert["rule"]["mitre"] = {"id": ["T1110"], "technique": ["Brute Force"], "tactic": ["Credential Access"]}
    ingested = client.post(
        "/api/v1/alerts/ingest", headers={"X-API-Key": "test-ingest-key"}, json=alert
    )
    assert ingested.status_code == 201, ingested.text

    rules = client.get("/api/v1/detection-engineering/rules")
    assert rules.status_code == 200
    external = next(item for item in rules.json() if item["rule_id"] == "999999")
    assert external["enabled_state"] == "UNKNOWN"
    assert external["enabled_evidence"] == "OBSERVED_ALERT_ONLY"
    assert external["rule_version"] is None
    assert external["version_authority"] == "UNAVAILABLE"
    assert external["alert_count"] == 1

    coverage = client.get("/api/v1/detection-engineering/coverage")
    assert coverage.status_code == 200
    technique = next(item for item in coverage.json()["techniques"] if item["technique_id"] == "T1110")
    assert technique["coverage_state"] == "TRIGGERED"
    assert technique["triggered_detection_count"] == 1
    assert technique["tested_detection_count"] == 0


def test_draft_lifecycle_is_versioned_audited_and_side_effect_free(
    client: TestClient, database_path
) -> None:
    now = datetime.now(timezone.utc)
    event = client.post(
        "/api/v1/events/ingest",
        headers={"X-API-Key": "test-ingest-key"},
        json=_event(now),
    )
    assert event.status_code == 201, event.text
    with sqlite3.connect(database_path) as connection:
        before = tuple(connection.execute(
            "SELECT (SELECT COUNT(*) FROM alerts), (SELECT COUNT(*) FROM incidents), "
            "(SELECT COUNT(*) FROM analyst_notifications)"
        ).fetchone())

    created = client.post("/api/v1/detection-engineering/drafts", json=_draft_payload())
    assert created.status_code == 201, created.text
    draft = created.json()
    assert draft["status"] == "DRAFT"
    assert draft["version"] == 1

    premature = client.post(
        f"/api/v1/detection-engineering/drafts/{draft['draft_id']}/dry-run",
        json={"relative_minutes": 1440, "expected_version": 1, "max_events": 1000},
    )
    assert premature.status_code == 409
    assert premature.json()["detail"]["code"] == "invalid_rule_lifecycle"

    validated = client.post(
        f"/api/v1/detection-engineering/drafts/{draft['draft_id']}/validate",
        json={"expected_version": 1},
    )
    assert validated.status_code == 200, validated.text
    assert validated.json()["draft"]["version"] == 2

    dry_run = client.post(
        f"/api/v1/detection-engineering/drafts/{draft['draft_id']}/dry-run",
        json={"relative_minutes": 1440, "expected_version": 2, "max_events": 1000},
    )
    assert dry_run.status_code == 200, dry_run.text
    result = dry_run.json()
    assert result["match_count"] == 1
    assert result["matched_event_ids"] == [event.json()["event"]["event_id"]]
    assert result["side_effects"] is False
    assert result["draft"]["version"] == 3

    confirmed = client.post(
        f"/api/v1/detection-engineering/drafts/{draft['draft_id']}/confirm-manual-deployment",
        json={
            "expected_version": 3,
            "confirmation": "I_UNDERSTAND_MANUAL_DEPLOYMENT_REQUIRED",
            "reason": "Reviewed for a controlled manual change",
        },
    )
    assert confirmed.status_code == 200, confirmed.text
    assert confirmed.json()["live_wazuh_modified"] is False
    assert confirmed.json()["draft"]["status"] == "READY_FOR_MANUAL_DEPLOYMENT"

    versions = client.get(
        f"/api/v1/detection-engineering/drafts/{draft['draft_id']}/versions"
    )
    assert versions.status_code == 200
    assert [item["version_number"] for item in versions.json()] == [4, 3, 2, 1]

    rollback = client.post(
        f"/api/v1/detection-engineering/drafts/{draft['draft_id']}/rollback",
        json={"source_version": 1, "expected_version": 4, "change_summary": "Restore initial definition"},
    )
    assert rollback.status_code == 200, rollback.text
    assert rollback.json()["status"] == "DRAFT"
    assert rollback.json()["version"] == 5

    with sqlite3.connect(database_path) as connection:
        after = tuple(connection.execute(
            "SELECT (SELECT COUNT(*) FROM alerts), (SELECT COUNT(*) FROM incidents), "
            "(SELECT COUNT(*) FROM analyst_notifications)"
        ).fetchone())
        actions = {row[0] for row in connection.execute(
            "SELECT action FROM security_audit_events WHERE target_id = ?",
            (draft["draft_id"],),
        )}
    assert after == before
    assert {
        "DETECTION_DRAFT_CREATED", "DETECTION_DRAFT_VALIDATED",
        "DETECTION_DRAFT_DRY_RUN", "DETECTION_MANUAL_DEPLOYMENT_CONFIRMED",
        "DETECTION_DRAFT_ROLLED_BACK",
    } <= actions


def test_hunts_are_bounded_exported_and_isolated_by_analyst(client: TestClient) -> None:
    now = datetime.now(timezone.utc)
    created = client.post(
        "/api/v1/events/ingest",
        headers={"X-API-Key": "test-ingest-key"}, json=_event(now, "hunt-query-event"),
    )
    event_id = created.json()["event"]["event_id"]
    hunted = client.get(
        "/api/v1/threat-hunts",
        params={"relative_minutes": 1440, "ip": "192.0.2.25", "rule_id": "100111"},
    )
    assert hunted.status_code == 200, hunted.text
    assert hunted.json()["items"][0]["event_id"] == event_id
    invalid = client.get("/api/v1/threat-hunts", params={"ip": "' OR 1=1 --"})
    assert invalid.status_code == 422

    saved = client.post(
        "/api/v1/threat-hunts/saved",
        json={"name": "Scan source", "query": {"relative_minutes": 1440, "ip": "192.0.2.25"}},
    )
    assert saved.status_code == 201, saved.text
    assert len(client.get("/api/v1/threat-hunts/saved").json()) == 1
    exported = client.get("/api/v1/threat-hunts/export.csv", params={"ip": "192.0.2.25"})
    assert exported.status_code == 200
    assert event_id in exported.text
    assert exported.headers["x-content-type-options"] == "nosniff"

    client.app.state.auth_repository.create_analyst(AnalystCreate(
        username="hunt-viewer", display_name="Hunt Viewer",
        password=TEST_PASSWORD, role=AnalystRole.VIEWER,
    ))
    client.cookies.clear()
    _login(client, "hunt-viewer")
    assert client.get("/api/v1/threat-hunts/saved").json() == []
    denied = client.post(
        "/api/v1/threat-hunts/saved",
        json={"name": "Denied", "query": {"relative_minutes": 1440, "rule_id": "100111"}},
    )
    assert denied.status_code == 403


def test_ioc_validation_deduplication_matching_and_rbac(client: TestClient) -> None:
    now = datetime.now(timezone.utc)
    event = client.post(
        "/api/v1/events/ingest",
        headers={"X-API-Key": "test-ingest-key"}, json=_event(now, "ioc-match-event"),
    ).json()["event"]
    created = client.post("/api/v1/iocs", json={
        "indicator_type": "IPV4", "value": "192.0.2.25",
        "source": "Manual SOC review", "confidence": 80,
        "description": "Authorized local test indicator",
    })
    assert created.status_code == 201, created.text
    indicator = created.json()
    assert indicator["value"] == "192.0.2.25"

    duplicate = client.post("/api/v1/iocs", json={
        "indicator_type": "IPV4", "value": "192.0.2.25",
        "source": "Duplicate", "confidence": 20,
    })
    assert duplicate.status_code == 409
    assert client.post("/api/v1/iocs", json={
        "indicator_type": "DOMAIN", "value": "not-a-fqdn",
        "source": "Manual", "confidence": 50,
    }).status_code == 422
    assert client.post("/api/v1/iocs", json={
        "indicator_type": "IPV4", "value": "1.2.3.4' OR 1=1 --",
        "source": "Manual", "confidence": 50,
    }).status_code == 422

    imported = client.post("/api/v1/iocs/import", json={"indicators": [
        {"indicator_type": "IPV4", "value": "192.0.2.25", "source": "Manual", "confidence": 80},
        {"indicator_type": "DOMAIN", "value": "Example.COM.", "source": "Manual", "confidence": 60},
        {"indicator_type": "FILE_HASH", "value": "A" * 64, "source": "Manual", "confidence": 70},
    ]})
    assert imported.status_code == 200, imported.text
    assert imported.json()["created"] == 2
    assert imported.json()["duplicates"] == 1
    assert imported.json()["indicators"][0]["value"] == "example.com"

    matches = client.get("/api/v1/iocs/matches", params={"days": 1})
    assert matches.status_code == 200, matches.text
    assert matches.json()["total_matches"] == 3
    assert {item["event_id"] for item in matches.json()["matches"]} == {event["event_id"]}
    assert {item["matched_field"] for item in matches.json()["matches"]} == {
        "source_ip", "structured_json:$.data.domain", "structured_json:$.data.sha256",
    }
    exported = client.get("/api/v1/iocs/export.json")
    assert exported.status_code == 200
    assert exported.headers["cache-control"] == "no-store"
    assert {item["value"] for item in exported.json()} == {
        "192.0.2.25", "example.com", "a" * 64,
    }

    stale = client.put(f"/api/v1/iocs/{indicator['indicator_id']}", json={
        "indicator_type": "IPV4", "value": "192.0.2.25", "source": "Manual",
        "confidence": 90, "description": "Updated", "expected_version": 2,
        "is_active": True,
    })
    assert stale.status_code == 409

    client.app.state.auth_repository.create_analyst(AnalystCreate(
        username="ioc-viewer", display_name="IOC Viewer",
        password=TEST_PASSWORD, role=AnalystRole.VIEWER,
    ))
    client.cookies.clear()
    _login(client, "ioc-viewer")
    assert client.get("/api/v1/iocs").status_code == 200
    denied = client.post("/api/v1/iocs", json={
        "indicator_type": "IPV4", "value": "198.51.100.1",
        "source": "Denied", "confidence": 10,
    })
    assert denied.status_code == 403


def test_false_positive_analytics_use_terminal_dispositions_only(
    client: TestClient, sample_alert: dict
) -> None:
    now = datetime.now(timezone.utc)
    for index in range(5):
        alert = copy.deepcopy(sample_alert)
        alert["id"] = f"fp-analytics-{index}"
        alert["timestamp"] = now.isoformat()
        alert["rule"]["id"] = "424242"
        response = client.post(
            "/api/v1/alerts/ingest", headers={"X-API-Key": "test-ingest-key"}, json=alert
        )
        alert_id = response.json()["alert"]["alert_id"]
        disposition = client.patch(
            f"/api/v1/alert-workflows/{alert_id}/status",
            json={"status": "FALSE_POSITIVE", "expected_version": 1},
        )
        assert disposition.status_code == 200, disposition.text

    analytics = client.get("/api/v1/detection-engineering/analytics", params={"days": 1})
    assert analytics.status_code == 200, analytics.text
    metric = next(item for item in analytics.json()["false_positive_rules"] if item["rule_id"] == "424242")
    assert metric["dispositioned_alerts"] == 5
    assert metric["false_positive_count"] == 5
    assert metric["false_positive_rate"] == 1.0
    assert metric["tuning_candidate"] is True
    assert "424242" in analytics.json()["suggested_tuning_candidates"]
    disposition = next(item for item in analytics.json()["analyst_dispositions"] if "admin" in item["analyst"])
    assert disposition["false_positive_count"] == 5
    assert disposition["total_count"] == 5
