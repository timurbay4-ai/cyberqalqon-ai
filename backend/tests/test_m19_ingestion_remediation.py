from __future__ import annotations

import sqlite3
import time
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.db.events import (
    BatchProcessingTimeoutError,
    EventRepository,
    RetentionProfile,
)
from app.main import create_app
from app.services.event_normalizer import normalize_wazuh_event


def _event(index: int, *, timestamp: datetime | None = None) -> dict[str, object]:
    observed = timestamp or datetime.now(timezone.utc)
    return {
        "timestamp": observed.isoformat(),
        "id": f"m19-event-{index}",
        "agent": {"id": "001", "name": "M19-DISPOSABLE"},
        "rule": {"id": "100111", "level": 10, "description": "M19 fixture"},
        "decoder": {"name": "sshd"},
        "location": "/var/log/auth.log",
        "full_log": f"M19 fixture {index}",
    }


@pytest.fixture
def m19_client(database_path: Path) -> Iterator[TestClient]:
    settings = Settings(
        database_url=f"sqlite:///{database_path.as_posix()}",
        wazuh_ingest_api_key="test-ingest-key",
        event_batch_ingest_enabled=True,
        event_batch_max_events=100,
        allow_m14_schema_migration=False,
    )
    with TestClient(create_app(settings)) as client:
        yield client


def test_batch_response_exposes_bounded_stage_profile(
    m19_client: TestClient,
    auth_headers: dict[str, str],
) -> None:
    response = m19_client.post(
        "/api/v1/events/ingest-batch",
        headers=auth_headers,
        json={
            "protocol_version": "m18-batch-v1",
            "batch_id": "m19-timing",
            "events": [_event(1), _event(2)],
        },
    )
    assert response.status_code == 201, response.text
    timing = response.json()["timing_ms"]
    expected_numeric = {
        "request_reception_ms",
        "authentication_ms",
        "request_parse_ms",
        "schema_validation_ms",
        "normalization_ms",
        "database_ms",
        "transaction_ms",
        "connection_ms",
        "lock_wait_ms",
        "deduplication_ms",
        "alert_lookup_ms",
        "insertion_ms",
        "retention_ms",
        "retention_state_ms",
        "retention_age_delete_ms",
        "retention_count_ms",
        "retention_candidate_ms",
        "protected_check_ms",
        "retention_delete_ms",
        "protected_count_ms",
        "retention_metadata_ms",
        "retention_audit_ms",
        "commit_ms",
        "sql_statement_count",
        "retention_rows_considered",
        "retention_rows_deleted",
        "protected_row_skips",
        "total_ms",
    }
    assert expected_numeric.issubset(timing)
    assert all(timing[key] >= 0 for key in expected_numeric)
    assert timing["sql_statement_count"] > 0
    assert isinstance(timing["full_age_sweep"], bool)


def test_capacity_fast_path_never_runs_global_protected_count(
    m19_client: TestClient,
    database_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = EventRepository(database_path, retention_days=30, max_records=2)
    now = datetime.now(timezone.utc)
    first = repository.ingest(normalize_wazuh_event(_event(1, timestamp=now)), now=now)
    second = repository.ingest(
        normalize_wazuh_event(_event(2, timestamp=now + timedelta(milliseconds=1))),
        now=now + timedelta(milliseconds=1),
    )

    def forbidden_global_count(_connection: sqlite3.Connection) -> int:
        raise AssertionError("normal retention must not run the global protected count")

    monkeypatch.setattr(repository, "_count_protected_records", forbidden_global_count)
    result = repository.ingest_batch(
        [
            normalize_wazuh_event(
                _event(3, timestamp=now + timedelta(milliseconds=2))
            )
        ],
        now=now + timedelta(milliseconds=2),
    )
    assert result.inserted == 1
    assert result.retention_rows_deleted == 1
    assert result.protected_count_ms == 0
    with sqlite3.connect(database_path) as connection:
        rows = connection.execute(
            "SELECT event_id FROM security_events ORDER BY occurred_at, event_id"
        ).fetchall()
        assert [str(row[0]) for row in rows] == [
            second.event.event_id,
            result.items[0].event_id,
        ]
        assert first.event.event_id not in {str(row[0]) for row in rows}


def test_retention_timeout_rolls_back_and_reports_safe_stage_timing(
    m19_client: TestClient,
    database_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = m19_client.app.state.event_repository

    def slow_retention(*_args: object, **_kwargs: object) -> RetentionProfile:
        # Keep a margin above the 100 ms assertion because some Windows timer
        # sources quantize short sleeps by one scheduler tick (about 15.6 ms).
        time.sleep(0.15)
        return RetentionProfile(state_ms=100.0)

    monkeypatch.setattr(repository, "_enforce_retention", slow_retention)
    with pytest.raises(BatchProcessingTimeoutError) as captured:
        repository.ingest_batch(
            [normalize_wazuh_event(_event(10))],
            max_processing_seconds=0.05,
        )
    assert captured.value.stage == "retention"
    assert captured.value.timing["retention_ms"] >= 100
    assert captured.value.timing["sql_statement_count"] > 0
    assert all(
        isinstance(value, (int, float, bool))
        for value in captured.value.timing.values()
    )
    with sqlite3.connect(database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0] == 0


def test_busy_writer_is_retryable_and_does_not_partially_insert(
    m19_client: TestClient,
    database_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = m19_client.app.state.event_repository
    original_connect = repository._connect

    def short_wait_connect() -> sqlite3.Connection:
        connection = original_connect()
        connection.execute("PRAGMA busy_timeout=25")
        return connection

    monkeypatch.setattr(repository, "_connect", short_wait_connect)
    locker = sqlite3.connect(database_path, timeout=1)
    try:
        locker.execute("BEGIN IMMEDIATE")
        with pytest.raises(sqlite3.OperationalError, match="locked"):
            repository.ingest_batch([normalize_wazuh_event(_event(20))])
    finally:
        locker.rollback()
        locker.close()
    with sqlite3.connect(database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0] == 0


def test_commit_then_retry_is_idempotent_and_integrity_is_preserved(
    m19_client: TestClient,
    database_path: Path,
) -> None:
    repository = m19_client.app.state.event_repository
    events = [normalize_wazuh_event(_event(30)), normalize_wazuh_event(_event(31))]
    committed = repository.ingest_batch(events)
    retried = repository.ingest_batch(events)
    assert (committed.inserted, committed.duplicates) == (2, 0)
    assert (retried.inserted, retried.duplicates) == (0, 2)
    with sqlite3.connect(database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0] == 2
        assert connection.execute("PRAGMA quick_check").fetchone()[0] == "ok"
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
