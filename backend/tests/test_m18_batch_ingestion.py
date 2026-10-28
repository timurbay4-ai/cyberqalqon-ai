from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.db.events import (
    BatchItemConflictError,
    BatchProcessingTimeoutError,
    EventRepository,
    RetentionCapacityError,
)
from app.main import create_app
from app.services.event_normalizer import normalize_wazuh_event


def event(index: int, *, timestamp: datetime | None = None) -> dict:
    observed = timestamp or datetime.now(timezone.utc)
    return {
        "timestamp": observed.isoformat(),
        "id": f"m18-event-{index}",
        "agent": {"id": "001", "name": "M18-DISPOSABLE"},
        "rule": {
            "id": "100111",
            "level": 10,
            "description": "M18 disposable batch fixture",
        },
        "decoder": {"name": "sshd"},
        "location": "/var/log/auth.log",
        "full_log": f"M18 fixture {index}",
    }


@pytest.fixture
def batch_client(database_path: Path) -> Iterator[TestClient]:
    settings = Settings(
        database_url=f"sqlite:///{database_path.as_posix()}",
        wazuh_ingest_api_key="test-ingest-key",
        event_batch_ingest_enabled=True,
        event_batch_max_events=100,
        event_batch_max_bytes=2_097_152,
        allow_m14_schema_migration=False,
    )
    with TestClient(create_app(settings)) as test_client:
        yield test_client


def envelope(*events: dict, batch_id: str = "m18-test-batch") -> dict:
    return {
        "protocol_version": "m18-batch-v1",
        "batch_id": batch_id,
        "events": list(events),
    }


def test_batch_endpoint_is_disabled_by_default(
    unauthenticated_client: TestClient,
    auth_headers: dict[str, str],
) -> None:
    response = unauthenticated_client.post(
        "/api/v1/events/ingest-batch",
        headers=auth_headers,
        json=envelope(event(1)),
    )
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "batch_ingestion_disabled"


def test_batch_endpoint_requires_machine_authentication(batch_client: TestClient) -> None:
    assert batch_client.post(
        "/api/v1/events/ingest-batch", json=envelope(event(1))
    ).status_code == 401
    assert batch_client.post(
        "/api/v1/events/ingest-batch",
        headers={"X-API-Key": "wrong"},
        json=envelope(event(1)),
    ).status_code == 401


def test_atomic_batch_insert_duplicate_subset_and_full_replay(
    batch_client: TestClient,
    auth_headers: dict[str, str],
    database_path: Path,
) -> None:
    first_event = event(1)
    first_payload = envelope(first_event, batch_id="m18-prime")
    assert batch_client.post(
        "/api/v1/events/ingest-batch", headers=auth_headers, json=first_payload
    ).status_code == 201

    mixed = envelope(first_event, event(2), event(3), batch_id="m18-mixed")
    response = batch_client.post(
        "/api/v1/events/ingest-batch", headers=auth_headers, json=mixed
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["status"] == "COMMITTED"
    assert body["atomic"] is True
    assert body["inserted"] == 2
    assert body["duplicates"] == 1
    assert [item["outcome"] for item in body["results"]] == [
        "DUPLICATE", "INSERTED", "INSERTED"
    ]
    assert body["timing_ms"]["commit_ms"] >= 0

    replay = batch_client.post(
        "/api/v1/events/ingest-batch", headers=auth_headers, json=mixed
    )
    assert replay.status_code == 200, replay.text
    assert replay.json()["inserted"] == 0
    assert replay.json()["duplicates"] == 3
    with sqlite3.connect(database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0] == 3
        assert connection.execute("PRAGMA quick_check").fetchone()[0] == "ok"
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_invalid_middle_event_rejects_whole_batch_without_writes(
    batch_client: TestClient,
    auth_headers: dict[str, str],
    database_path: Path,
) -> None:
    invalid = event(2)
    invalid["timestamp"] = "not-a-timestamp"
    response = batch_client.post(
        "/api/v1/events/ingest-batch",
        headers=auth_headers,
        json=envelope(event(1), invalid, event(3)),
    )
    assert response.status_code == 422
    assert [item["outcome"] for item in response.json()["detail"]["results"]] == [
        "NOT_PROCESSED", "PERMANENTLY_INVALID", "NOT_PROCESSED"
    ]
    with sqlite3.connect(database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0] == 0


def test_outside_retention_item_is_identified_and_batch_is_atomic(
    batch_client: TestClient,
    auth_headers: dict[str, str],
    database_path: Path,
) -> None:
    old = event(2, timestamp=datetime.now(timezone.utc) - timedelta(days=31))
    response = batch_client.post(
        "/api/v1/events/ingest-batch",
        headers=auth_headers,
        json=envelope(event(1), old),
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert detail["results"][1]["outcome"] == "PERMANENTLY_INVALID"
    assert detail["results"][1]["field"] == "timestamp"
    with sqlite3.connect(database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0] == 0


def test_repository_conflict_rolls_back_prior_batch_items(database_path: Path) -> None:
    repository = EventRepository(database_path, retention_days=30, max_records=100)
    # Initialize schema through the regular app fixture contract.
    settings = Settings(
        database_url=f"sqlite:///{database_path.as_posix()}",
        wazuh_ingest_api_key="test-ingest-key",
        allow_m14_schema_migration=False,
    )
    with TestClient(create_app(settings)):
        original = normalize_wazuh_event(event(1))
        repository.ingest(original)
        first = normalize_wazuh_event(event(2))
        conflicting = normalize_wazuh_event(event(3)).model_copy(
            update={"event_id": original.event_id}
        )
        with pytest.raises(BatchItemConflictError) as error:
            repository.ingest_batch([first, conflicting])
        assert error.value.index == 1
    with sqlite3.connect(database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0] == 1


def test_precommit_deadline_rolls_back_without_acknowledgement(
    batch_client: TestClient,
    database_path: Path,
) -> None:
    repository = batch_client.app.state.event_repository
    with pytest.raises(BatchProcessingTimeoutError):
        repository.ingest_batch(
            [normalize_wazuh_event(event(1))],
            # This is below the floating-point ULP at the monotonic-clock
            # magnitude, so the computed deadline equals the start time and
            # the pre-commit guard deterministically expires without sleeping.
            max_processing_seconds=5e-324,
        )
    with sqlite3.connect(database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0] == 0


def test_failure_before_commit_rolls_back_every_insert(
    batch_client: TestClient,
    database_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = batch_client.app.state.event_repository

    def crash_before_commit(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("simulated crash before commit")

    monkeypatch.setattr(repository, "_enforce_retention", crash_before_commit)
    with pytest.raises(RuntimeError, match="simulated crash"):
        repository.ingest_batch(
            [normalize_wazuh_event(event(1)), normalize_wazuh_event(event(2))]
        )
    with sqlite3.connect(database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0] == 0


def test_sqlite_busy_is_reported_as_retryable_without_cursor_claim(
    batch_client: TestClient,
    auth_headers: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def busy(*_args: object, **_kwargs: object) -> object:
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(batch_client.app.state.event_repository, "ingest_batch", busy)
    response = batch_client.post(
        "/api/v1/events/ingest-batch",
        headers=auth_headers,
        json=envelope(event(1), event(2)),
    )
    assert response.status_code == 503
    assert {item["outcome"] for item in response.json()["detail"]["results"]} == {
        "RETRYABLE_FAILURE"
    }


def test_batch_bounds_partial_json_and_sql_text_are_safe(
    batch_client: TestClient,
    auth_headers: dict[str, str],
) -> None:
    partial = batch_client.post(
        "/api/v1/events/ingest-batch",
        headers={**auth_headers, "Content-Type": "application/json"},
        content=b'{"protocol_version":"m18-batch-v1","events":',
    )
    assert partial.status_code == 400

    oversized = event(2)
    oversized["full_log"] = "x" * 300_000
    too_large = batch_client.post(
        "/api/v1/events/ingest-batch",
        headers=auth_headers,
        json=envelope(event(1), oversized),
    )
    assert too_large.status_code == 413
    assert too_large.json()["detail"]["results"][1]["outcome"] == "PERMANENTLY_INVALID"

    sql_text = event(3)
    sql_text["full_log"] = "'); DROP TABLE security_events; --"
    accepted = batch_client.post(
        "/api/v1/events/ingest-batch",
        headers=auth_headers,
        json=envelope(sql_text, batch_id="m18-sql-text"),
    )
    assert accepted.status_code == 201


def test_batch_envelope_and_total_body_are_strictly_bounded(
    batch_client: TestClient,
    auth_headers: dict[str, str],
) -> None:
    too_many = batch_client.post(
        "/api/v1/events/ingest-batch",
        headers=auth_headers,
        json=envelope(*(event(index) for index in range(101))),
    )
    assert too_many.status_code == 413
    assert too_many.json()["detail"]["code"] == "batch_event_limit_exceeded"

    extra = envelope(event(1))
    extra["unexpected"] = "rejected"
    assert batch_client.post(
        "/api/v1/events/ingest-batch", headers=auth_headers, json=extra
    ).status_code == 422

    wrong_protocol = envelope(event(2))
    wrong_protocol["protocol_version"] = "m18-batch-v0"
    assert batch_client.post(
        "/api/v1/events/ingest-batch", headers=auth_headers, json=wrong_protocol
    ).status_code == 422

    body_too_large = batch_client.post(
        "/api/v1/events/ingest-batch",
        headers={**auth_headers, "Content-Type": "application/json"},
        content=b"{" + (b"x" * 2_097_152) + b"}",
    )
    assert body_too_large.status_code == 413
    assert body_too_large.json()["detail"]["code"] == "payload_too_large"


def test_batch_retention_preserves_alert_evidence_and_reports_pressure(
    batch_client: TestClient,
    auth_headers: dict[str, str],
    sample_alert: dict,
    database_path: Path,
) -> None:
    alert = dict(sample_alert)
    alert["timestamp"] = (datetime.now(timezone.utc) - timedelta(minutes=2)).isoformat()
    created = batch_client.post(
        "/api/v1/alerts/ingest", headers=auth_headers, json=alert
    )
    assert created.status_code == 201, created.text
    alert_id = created.json()["alert"]["alert_id"]
    with sqlite3.connect(database_path) as connection:
        protected_event_id = str(
            connection.execute(
                "SELECT event_id FROM security_events WHERE related_alert_id = ?",
                (alert_id,),
            ).fetchone()[0]
        )
        audit_before = connection.execute(
            "SELECT details_json FROM security_audit_events WHERE action='SECURITY_EVENT_RETENTION' ORDER BY occurred_at DESC LIMIT 1"
        ).fetchone()

    repository = EventRepository(database_path, retention_days=30, max_records=1)
    with pytest.raises(RetentionCapacityError):
        repository.ingest_batch(
            [normalize_wazuh_event(event(10)), normalize_wazuh_event(event(11))]
        )
    with sqlite3.connect(database_path) as connection:
        event_ids = {
            str(row[0])
            for row in connection.execute("SELECT event_id FROM security_events")
        }
        audit = connection.execute(
            "SELECT details_json FROM security_audit_events "
            "WHERE action='SECURITY_EVENT_RETENTION' ORDER BY occurred_at DESC LIMIT 1"
        ).fetchone()
    assert event_ids == {protected_event_id}
    assert audit == audit_before
    batch_client.app.state.event_repository.max_records = 1
    rejected = batch_client.post('/api/v1/events/ingest-batch', headers=auth_headers,
                                 json=envelope(event(10), event(11)))
    assert rejected.status_code == 503
    assert rejected.json()['detail']['code'] == 'retention_capacity_exhausted'
    assert batch_client.app.state.ingestion_metrics.snapshot()['inserted'] == 0


def test_operations_report_uses_bounded_in_memory_batch_metrics(
    batch_client: TestClient,
    auth_headers: dict[str, str],
) -> None:
    # Operations is analyst-authenticated; inspect the collector directly to avoid
    # introducing an unrelated browser/session dependency in the machine API test.
    assert batch_client.post(
        "/api/v1/events/ingest-batch",
        headers=auth_headers,
        json=envelope(event(1), event(2)),
    ).status_code == 201
    snapshot = batch_client.app.state.ingestion_metrics.snapshot()
    assert snapshot["batch_requests"] == 1
    assert snapshot["events"] == 2
    assert snapshot["inserted"] == 2
    assert snapshot["inserts_per_second"] > 0
    assert snapshot["duplicates_per_second"] == 0
    assert snapshot["events_per_request"] == 2
    assert snapshot["historical_unique_insertions"] is None
    assert snapshot["historical_duplicate_acknowledgements"] is None
