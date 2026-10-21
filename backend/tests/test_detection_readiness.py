from __future__ import annotations

import copy
import sqlite3
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from app.core.config import Settings
from app.db.migrations import apply_migrations
from app.main import create_app
from app.schemas.auth import AnalystCreate, AnalystRole
from tests.conftest import TEST_ORIGIN, TEST_PASSWORD, bootstrap_and_login
from tests.test_advanced_detection import _ingest, _logon, _windows


def _configuration_payload(current: dict, **overrides: object) -> dict:
    keys = {
        "threshold_count", "time_window_seconds", "severity",
        "supported_event_sources", "required_normalized_fields", "entity_grouping",
        "safe_exclusions", "evaluation_limits", "state_expiration_seconds",
        "state_schema_version",
    }
    result = {key: copy.deepcopy(current[key]) for key in keys}
    result.update(overrides)
    result["expected_version"] = current["version"]
    result["change_reason"] = "M14 bounded tuning candidate"
    return result


def _five_failures(base: datetime, *, user: str = "alice", host: str = "WIN-M14") -> list[dict]:
    events = [
        _windows(
            "4625", base + timedelta(seconds=index * 30), f"m14-{user}-{index}",
            _logon(user, "192.0.2.44"),
        )
        for index in range(5)
    ]
    for event in events:
        event["data"]["win"]["system"]["computer"] = host
    return events


def test_m14_defaults_are_durable_but_runtime_activation_is_hard_disabled(
    client: TestClient, database_path,
) -> None:
    response = client.get("/api/v1/detection-readiness/rules")
    assert response.status_code == 200, response.text
    rules = response.json()
    assert [item["rule_id"] for item in rules] == [f"DET-{index:03d}" for index in range(1, 10)]
    assert all(item["configuration_state"] == "TESTED" for item in rules)
    assert all(item["validation_state"] == "VALID" for item in rules)
    assert all(item["runtime_activation_state"] == "DISABLED_BY_POLICY" for item in rules)
    with sqlite3.connect(database_path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 18
        assert connection.execute(
            "SELECT COUNT(*) FROM advanced_detection_config_versions"
        ).fetchone()[0] == 9
        assert connection.execute(
            "SELECT COUNT(*) FROM advanced_detection_rule_state "
            "WHERE runtime_activation_state <> 'DISABLED_BY_POLICY'"
        ).fetchone()[0] == 0


def test_configuration_versioning_validation_diff_restore_and_stale_update(
    client: TestClient,
) -> None:
    history = client.get("/api/v1/detection-readiness/rules/DET-001/configurations")
    assert history.status_code == 200
    baseline = history.json()[0]
    created = client.post(
        "/api/v1/detection-readiness/rules/DET-001/configurations",
        json=_configuration_payload(baseline, threshold_count=6),
    )
    assert created.status_code == 201, created.text
    candidate = created.json()
    assert candidate["version"] == 2
    assert candidate["lifecycle_state"] == "DRAFT"

    stale = client.post(
        "/api/v1/detection-readiness/rules/DET-001/configurations",
        json=_configuration_payload(baseline, threshold_count=7),
    )
    assert stale.status_code == 409
    assert stale.json()["detail"]["code"] == "stale_version"

    validated = client.post(
        "/api/v1/detection-readiness/rules/DET-001/configurations/2/validate"
    )
    assert validated.status_code == 200, validated.text
    assert validated.json()["valid"] is True
    assert validated.json()["lifecycle"]["configuration_state"] == "VALIDATED"

    diff = client.get(
        "/api/v1/detection-readiness/rules/DET-001/configurations/diff",
        params={"from_version": 1, "to_version": 2},
    )
    assert diff.status_code == 200, diff.text
    assert {item["field"] for item in diff.json()["differences"]} == {"threshold_count"}
    assert diff.json()["executable_content_present"] is False

    restored = client.post(
        "/api/v1/detection-readiness/rules/DET-001/configurations/restore",
        json={
            "source_version": 1,
            "expected_version": 2,
            "change_reason": "Restore tested default as a new audited version",
        },
    )
    assert restored.status_code == 200, restored.text
    assert restored.json()["version"] == 3
    assert restored.json()["threshold_count"] == baseline["threshold_count"]


def test_shadow_run_and_tuning_are_bounded_and_have_no_production_side_effects(
    client: TestClient, database_path,
) -> None:
    _ingest(client, *_five_failures(datetime.now(timezone.utc) - timedelta(minutes=10)))
    with sqlite3.connect(database_path) as connection:
        before = {
            "alerts": connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0],
            "incidents": connection.execute("SELECT COUNT(*) FROM incidents").fetchone()[0],
            "cases": connection.execute("SELECT COUNT(*) FROM soc_cases").fetchone()[0],
        }

    tuning = client.post(
        "/api/v1/detection-readiness/rules/DET-001/tuning",
        json={
            "relative_minutes": 1440,
            "candidates": [
                {"threshold_count": 5, "time_window_seconds": 300},
                {"threshold_count": 10, "time_window_seconds": 300},
            ],
            "max_events": 1000,
            "max_findings": 100,
            "max_execution_ms": 3000,
        },
    )
    assert tuning.status_code == 200, tuning.text
    assert [item["finding_count"] for item in tuning.json()["results"]] == [1, 0]
    assert tuning.json()["side_effects"] is False

    shadow = client.post(
        "/api/v1/detection-readiness/rules/DET-001/shadow-runs",
        json={
            "relative_minutes": 1440,
            "max_events": 1000,
            "max_findings": 100,
            "max_execution_ms": 3000,
        },
    )
    assert shadow.status_code == 200, shadow.text
    body = shadow.json()
    assert body["run"]["status"] == "COMPLETED"
    assert body["run"]["side_effects"] is False
    assert body["run"]["match_count"] == 1
    assert body["findings"][0]["namespace"] == "SHADOW"
    assert body["findings"][0]["production_alert_id"] is None

    persisted = client.get(f"/api/v1/detection-readiness/shadow-runs/{body['run']['run_id']}")
    assert persisted.status_code == 200
    assert persisted.json()["findings"][0]["finding"]["deduplication_key"] == (
        body["findings"][0]["finding"]["deduplication_key"]
    )
    workbench = client.post(
        "/api/v1/investigations/workbench",
        json={
            "target_type": "SHADOW_FINDING",
            "target_id": body["findings"][0]["shadow_finding_id"],
            "relative_minutes": 1440,
            "related_limit": 25,
            "timeline_limit": 100,
            "max_execution_ms": 3000,
        },
    )
    assert workbench.status_code == 200, workbench.text
    assert workbench.json()["detection_context"]["source_kind"] == "SHADOW"
    assert workbench.json()["detection_context"]["shadow_run_id"] == body["run"]["run_id"]
    with sqlite3.connect(database_path) as connection:
        after = {
            "alerts": connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0],
            "incidents": connection.execute("SELECT COUNT(*) FROM incidents").fetchone()[0],
            "cases": connection.execute("SELECT COUNT(*) FROM soc_cases").fetchone()[0],
        }
        assert connection.execute(
            "SELECT COUNT(*) FROM advanced_detection_shadow_findings"
        ).fetchone()[0] == 1
    assert after == before


def test_correlation_state_restart_replay_duplicate_and_interruption_rollback(
    client: TestClient, database_path,
) -> None:
    base = datetime.now(timezone.utc) - timedelta(minutes=10)
    events = _five_failures(base)
    events.extend(_five_failures(base + timedelta(seconds=5), user="bob", host="WIN-OTHER"))
    _ingest(client, *reversed(events))
    payload = {
        "relative_minutes": 1440,
        "max_events": 1000,
        "max_findings": 100,
        "max_execution_ms": 3000,
    }
    first = client.post(
        "/api/v1/detection-readiness/rules/DET-001/correlation-replay", json=payload
    )
    assert first.status_code == 200, first.text
    first_body = first.json()
    assert first_body["newly_processed_event_count"] == 10
    assert first_body["finding_count"] == 2
    assert first_body["state_record_count"] == 2

    second = client.post(
        "/api/v1/detection-readiness/rules/DET-001/correlation-replay", json=payload
    )
    assert second.status_code == 200, second.text
    assert second.json()["newly_processed_event_count"] == 0
    assert second.json()["duplicate_event_count"] >= 10
    assert second.json()["recovered_after_restart"] is True

    with sqlite3.connect(database_path) as connection:
        before = (
            connection.execute("SELECT COUNT(*) FROM advanced_detection_correlation_state").fetchone()[0],
            connection.execute("SELECT COUNT(*) FROM advanced_detection_processed_events").fetchone()[0],
        )
    interrupted = client.post(
        "/api/v1/detection-readiness/rules/DET-001/correlation-replay",
        json={**payload, "simulate_interruption": True},
    )
    assert interrupted.status_code == 200, interrupted.text
    assert interrupted.json()["interrupted_transaction_rolled_back"] is True
    with sqlite3.connect(database_path) as connection:
        after = (
            connection.execute("SELECT COUNT(*) FROM advanced_detection_correlation_state").fetchone()[0],
            connection.execute("SELECT COUNT(*) FROM advanced_detection_processed_events").fetchone()[0],
        )
    assert after == before


def test_active_transition_is_impossible_and_viewer_cannot_mutate_configuration(
    client: TestClient,
) -> None:
    lifecycle = client.get("/api/v1/detection-readiness/rules/DET-001/lifecycle").json()
    blocked = client.post(
        "/api/v1/detection-readiness/rules/DET-001/lifecycle",
        json={
            "expected_state_version": lifecycle["state_version"],
            "target_state": "ACTIVE",
            "reason": "This must be refused by the M14 policy boundary",
        },
    )
    assert blocked.status_code == 409
    assert "hard-blocked" in blocked.json()["detail"]["message"]

    client.app.state.auth_repository.create_analyst(AnalystCreate(
        username="viewer", display_name="Read Only", password=TEST_PASSWORD,
        role=AnalystRole.VIEWER,
    ))
    login = client.post(
        "/api/v1/auth/login",
        headers={"Origin": TEST_ORIGIN},
        json={"username": "viewer", "password": TEST_PASSWORD},
    )
    assert login.status_code == 200
    client.headers.update({
        "Origin": TEST_ORIGIN,
        "X-CSRF-Token": login.json()["csrf_token"],
    })
    baseline = client.get(
        "/api/v1/detection-readiness/rules/DET-001/configurations"
    ).json()[0]
    denied = client.post(
        "/api/v1/detection-readiness/rules/DET-001/configurations",
        json=_configuration_payload(baseline, threshold_count=6),
    )
    assert denied.status_code == 403


def test_future_windows_and_state_schema_mismatch_fail_closed(
    client: TestClient, database_path,
) -> None:
    now = datetime.now(timezone.utc)
    future = client.post(
        "/api/v1/detection-readiness/rules/DET-001/shadow-runs",
        json={
            "relative_minutes": None,
            "start_time": (now + timedelta(hours=1)).isoformat(),
            "end_time": (now + timedelta(hours=2)).isoformat(),
            "max_events": 100,
            "max_findings": 10,
            "max_execution_ms": 1000,
        },
    )
    assert future.status_code == 409, future.text
    assert future.json()["detail"]["code"] == "evaluation_failed_closed"

    _ingest(client, *_five_failures(now - timedelta(minutes=10)))
    replay_payload = {
        "relative_minutes": 1440,
        "max_events": 1000,
        "max_findings": 100,
        "max_execution_ms": 3000,
    }
    assert client.post(
        "/api/v1/detection-readiness/rules/DET-001/correlation-replay",
        json=replay_payload,
    ).status_code == 200
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "UPDATE advanced_detection_correlation_state SET state_version = 2 "
            "WHERE rule_id = 'DET-001'"
        )
    mismatch = client.post(
        "/api/v1/detection-readiness/rules/DET-001/correlation-replay",
        json=replay_payload,
    )
    assert mismatch.status_code == 409, mismatch.text
    assert "version mismatch" in mismatch.json()["detail"]["message"]


def test_malicious_or_oversized_configuration_is_rejected_before_persistence(
    client: TestClient, database_path,
) -> None:
    baseline = client.get(
        "/api/v1/detection-readiness/rules/DET-001/configurations"
    ).json()[0]
    malicious = _configuration_payload(
        baseline,
        supported_event_sources=["windows_event; DROP TABLE alerts;--"],
        safe_exclusions=[{
            "field": "username",
            "operator": "EQUALS",
            "value": "x" * 257,
        }],
    )
    rejected = client.post(
        "/api/v1/detection-readiness/rules/DET-001/configurations",
        json=malicious,
    )
    assert rejected.status_code == 422, rejected.text
    with sqlite3.connect(database_path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM advanced_detection_config_versions "
            "WHERE rule_id = 'DET-001'"
        ).fetchone()[0] == 1
        assert connection.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='alerts'"
        ).fetchone()[0] == 1


def test_telemetry_readiness_requires_actual_rule_specific_evidence(
    client: TestClient,
) -> None:
    empty = client.get("/api/v1/detection-readiness/rules/DET-001/telemetry")
    assert empty.status_code == 200
    assert empty.json()["status"] == "UNAVAILABLE"
    assert "eligible_source_events" in empty.json()["missing_prerequisites"]

    _ingest(
        client,
        *_five_failures(datetime.now(timezone.utc) - timedelta(minutes=10)),
    )
    brute_force = client.get("/api/v1/detection-readiness/rules/DET-001/telemetry")
    assert brute_force.status_code == 200
    assert brute_force.json()["status"] == "READY"
    assert brute_force.json()["normalization_compatible"] is True

    failure_success = client.get("/api/v1/detection-readiness/rules/DET-002/telemetry")
    assert failure_success.status_code == 200
    assert failure_success.json()["status"] == "PARTIAL"
    assert "event_code:4624" in failure_success.json()["missing_prerequisites"]


def test_database_busy_mutation_returns_bounded_fail_closed_error(
    client: TestClient, database_path, monkeypatch,
) -> None:
    baseline = client.get(
        "/api/v1/detection-readiness/rules/DET-001/configurations"
    ).json()[0]
    repository = client.app.state.detection_readiness_repository

    def fast_fail_connection() -> sqlite3.Connection:
        connection = sqlite3.connect(database_path, timeout=0.01)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10")
        return connection

    monkeypatch.setattr(repository, "_connect", fast_fail_connection)
    locker = sqlite3.connect(database_path, timeout=1)
    try:
        locker.execute("BEGIN IMMEDIATE")
        busy = client.post(
            "/api/v1/detection-readiness/rules/DET-001/configurations",
            json=_configuration_payload(baseline, threshold_count=6),
        )
    finally:
        locker.rollback()
        locker.close()
    assert busy.status_code == 503, busy.text
    assert busy.json()["detail"]["code"] == "database_busy"


def test_schema18_requires_explicit_opt_in_and_schema17_restart_stays_ready(
    database_path,
) -> None:
    with sqlite3.connect(database_path) as connection:
        apply_migrations(connection, target_version=17)
    settings = Settings(
        database_url=f"sqlite:///{database_path.as_posix()}",
        wazuh_ingest_api_key="test-ingest-key",
        allow_m14_schema_migration=False,
    )
    with TestClient(create_app(settings)) as gated_client:
        assert gated_client.get("/health").status_code == 200
        assert gated_client.get("/readiness").status_code == 200
        bootstrap_and_login(gated_client)
        blocked = gated_client.get("/api/v1/detection-readiness/rules")
        assert blocked.status_code == 503, blocked.text
        assert blocked.json()["detail"]["code"] == "schema_approval_required"
    with sqlite3.connect(database_path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 17
        assert connection.execute(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = 18"
        ).fetchone()[0] == 0
