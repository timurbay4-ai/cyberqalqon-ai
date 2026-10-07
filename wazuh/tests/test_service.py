from __future__ import annotations

import sqlite3
from dataclasses import replace
from threading import Event

import pytest

from cyberqalqon_sender.config import SenderConfig
from cyberqalqon_sender.models import (
    AlertPayload,
    DeliveryClassification,
    DeliveryResult,
    FailureCategory,
)
from cyberqalqon_sender.service import SenderService, backoff_delay
from cyberqalqon_sender.spool import SQLiteSpool

from conftest import FakeClock, SequenceClient, make_service


def _result(
    classification: DeliveryClassification,
    category: FailureCategory | None = None,
    *,
    status: int | None = None,
    retry_after: float | None = None,
) -> DeliveryResult:
    return DeliveryResult(
        classification,
        category,
        "test result",
        status,
        retry_after,
    )


def test_first_transient_failure_is_durably_scheduled_then_recovers(
    config: SenderConfig, spool: SQLiteSpool, alert_payload: AlertPayload
) -> None:
    clock = FakeClock()
    client = SequenceClient(
        [
            _result(DeliveryClassification.TRANSIENT_FAILURE, FailureCategory.NETWORK),
            _result(DeliveryClassification.DELIVERED, status=201),
        ]
    )
    service = make_service(config, spool, client, clock)

    first = service.submit(alert_payload)
    assert first.classification == DeliveryClassification.TRANSIENT_FAILURE
    assert first.attempt_count == 1
    assert first.next_retry_at == clock.value + 2
    assert spool.status().queue_depth == 1
    assert service.process_next_due() is None

    clock.advance(2)
    recovered = service.process_next_due()
    assert recovered is not None
    assert recovered.classification == DeliveryClassification.DELIVERED
    assert recovered.attempt_count == 2
    assert spool.status().queue_depth == 0
    assert spool.status().retry_count == 1


@pytest.mark.parametrize(
    ("attempt", "random_value", "expected"),
    [
        (1, 0.5, 2.0),
        (2, 0.5, 4.0),
        (3, 0.5, 8.0),
        (20, 0.5, 10.0),
        (1, 0.0, 1.6),
        (1, 1.0, 2.4),
    ],
)
def test_exponential_backoff_cap_and_jitter(
    attempt: int, random_value: float, expected: float
) -> None:
    assert backoff_delay(
        attempt,
        base_seconds=2,
        maximum_seconds=10,
        jitter_ratio=0.2,
        random_value=random_value,
    ) == pytest.approx(expected)


def test_retry_after_is_respected_within_cap() -> None:
    assert backoff_delay(
        1,
        base_seconds=2,
        maximum_seconds=60,
        jitter_ratio=0.2,
        random_value=0.5,
        retry_after_seconds=45,
    ) == 45
    assert backoff_delay(
        1,
        base_seconds=2,
        maximum_seconds=60,
        jitter_ratio=0.2,
        random_value=0.5,
        retry_after_seconds=600,
    ) == 60


def test_retry_exhaustion_moves_item_to_dead_letter(
    config: SenderConfig, spool: SQLiteSpool, alert_payload: AlertPayload
) -> None:
    config = replace(config, max_attempts=2)
    clock = FakeClock()
    client = SequenceClient(
        [
            _result(DeliveryClassification.TRANSIENT_FAILURE, FailureCategory.SERVER, status=503),
            _result(DeliveryClassification.TRANSIENT_FAILURE, FailureCategory.SERVER, status=503),
        ]
    )
    service = make_service(config, spool, client, clock)

    first = service.submit(alert_payload)
    assert first.next_retry_at is not None
    clock.value = first.next_retry_at
    second = service.process_next_due()

    assert second is not None
    assert second.dead_letter_id is not None
    assert second.next_retry_at is None
    assert spool.status().queue_depth == 0
    record = spool.get_dead_letter(second.dead_letter_id)
    assert record is not None
    assert record["failure_category"] == FailureCategory.RETRY_EXHAUSTED.value
    assert record["attempt_count"] == 2


@pytest.mark.parametrize(
    ("classification", "category", "status"),
    [
        (DeliveryClassification.PERMANENT_FAILURE, FailureCategory.VALIDATION, 422),
        (DeliveryClassification.CONFLICT, FailureCategory.CONFLICT, 409),
    ],
)
def test_terminal_failure_never_retries_and_remains_visible(
    config: SenderConfig,
    spool: SQLiteSpool,
    alert_payload: AlertPayload,
    classification: DeliveryClassification,
    category: FailureCategory,
    status: int,
) -> None:
    clock = FakeClock()
    client = SequenceClient([_result(classification, category, status=status)])
    service = make_service(config, spool, client, clock)
    outcome = service.submit(alert_payload)

    assert outcome.classification == classification
    assert outcome.dead_letter_id is not None
    assert service.process_next_due() is None
    dead = spool.get_dead_letter(outcome.dead_letter_id)
    assert dead is not None and dead["http_status"] == status


def test_malformed_persisted_record_does_not_crash_queue(
    config: SenderConfig, spool: SQLiteSpool, alert_payload: AlertPayload
) -> None:
    queue_id = spool.enqueue(alert_payload, now=100.0)
    connection = sqlite3.connect(config.database_path)
    connection.execute(
        "UPDATE queue_items SET payload_json = ? WHERE id = ?", ("not-json", queue_id)
    )
    connection.commit()
    connection.close()
    client = SequenceClient([])
    service = make_service(config, spool, client, FakeClock(100.0))

    outcome = service.process_queue_id(queue_id)
    assert outcome is not None
    assert outcome.classification == DeliveryClassification.PERMANENT_FAILURE
    assert outcome.dead_letter_id is not None
    dead = spool.get_dead_letter(outcome.dead_letter_id)
    assert dead is not None
    assert dead["failure_category"] == FailureCategory.MALFORMED_PERSISTED_RECORD.value
    assert client.payloads == []


def test_uncertain_crash_retries_after_lease_and_duplicate_completes(
    config: SenderConfig, spool: SQLiteSpool, alert_payload: AlertPayload
) -> None:
    clock = FakeClock(100.0)
    queue_id = spool.enqueue(alert_payload, now=clock.value)
    abandoned = spool.claim_by_id(
        queue_id,
        now=clock.value,
        lease_seconds=config.lease_seconds,
        max_attempts=config.max_attempts,
    )
    assert abandoned is not None and abandoned.attempt_count == 1

    client = SequenceClient([_result(DeliveryClassification.DUPLICATE, status=200)])
    service = make_service(config, spool, client, clock)
    clock.advance(config.lease_seconds)
    outcome = service.process_next_due()

    assert outcome is not None
    assert outcome.classification == DeliveryClassification.DUPLICATE
    assert outcome.attempt_count == 2
    assert spool.status().queue_depth == 0


def test_same_alert_can_be_sent_repeatedly_and_duplicate_completes(
    config: SenderConfig, spool: SQLiteSpool, alert_payload: AlertPayload
) -> None:
    client = SequenceClient(
        [
            _result(DeliveryClassification.DELIVERED, status=201),
            _result(DeliveryClassification.DUPLICATE, status=200),
        ]
    )
    service = make_service(config, spool, client, FakeClock())
    assert service.submit(alert_payload).classification == DeliveryClassification.DELIVERED
    assert service.submit(alert_payload).classification == DeliveryClassification.DUPLICATE
    status = spool.status()
    assert status.delivered_count == 1
    assert status.duplicate_count == 1
    assert status.queue_depth == 0


def test_dead_letter_replay_success_preserves_original_trail(
    config: SenderConfig, spool: SQLiteSpool, alert_payload: AlertPayload
) -> None:
    client = SequenceClient(
        [
            _result(DeliveryClassification.PERMANENT_FAILURE, FailureCategory.VALIDATION, status=422),
            _result(DeliveryClassification.DELIVERED, status=201),
        ]
    )
    service = make_service(config, spool, client, FakeClock())
    failed = service.submit(alert_payload)
    assert failed.dead_letter_id is not None

    replay = service.replay_dead_letter(failed.dead_letter_id)
    assert replay is not None and replay.classification == DeliveryClassification.DELIVERED
    original = spool.get_dead_letter(failed.dead_letter_id)
    assert original is not None
    assert original["replay_count"] == 1
    assert original["last_replay_result"] == DeliveryClassification.DELIVERED.value
    assert spool.status().dead_letter_count == 1


def test_dead_letter_replay_failure_preserves_both_records(
    config: SenderConfig, spool: SQLiteSpool, alert_payload: AlertPayload
) -> None:
    failure = _result(
        DeliveryClassification.PERMANENT_FAILURE,
        FailureCategory.VALIDATION,
        status=422,
    )
    service = make_service(config, spool, SequenceClient([failure, failure]), FakeClock())
    first = service.submit(alert_payload)
    assert first.dead_letter_id is not None
    replay = service.replay_dead_letter(first.dead_letter_id)

    assert replay is not None and replay.dead_letter_id is not None
    assert replay.dead_letter_id != first.dead_letter_id
    assert spool.status().dead_letter_count == 2
    original = spool.get_dead_letter(first.dead_letter_id)
    assert original is not None
    assert original["last_replay_result"] == DeliveryClassification.PERMANENT_FAILURE.value


def test_unexpected_transport_exception_is_queued_for_retry(
    config: SenderConfig, spool: SQLiteSpool, alert_payload: AlertPayload
) -> None:
    class ExplodingClient:
        def deliver(self, _payload: bytes) -> DeliveryResult:
            raise RuntimeError("transport implementation bug")

    service = SenderService(
        config,
        spool,
        ExplodingClient(),
        clock=FakeClock(),
        monotonic=lambda: 0.0,
        random_source=lambda: 0.5,
    )
    outcome = service.submit(alert_payload)
    assert outcome.classification == DeliveryClassification.TRANSIENT_FAILURE
    assert outcome.next_retry_at is not None
    assert spool.status().queue_depth == 1


def test_worker_waits_when_idle_instead_of_busy_spinning(
    config: SenderConfig, spool: SQLiteSpool
) -> None:
    stop = Event()
    waits: list[float] = []

    def wait(seconds: float) -> bool:
        waits.append(seconds)
        stop.set()
        return True

    service = make_service(config, spool, SequenceClient([]), FakeClock())
    service.run_worker(stop, wait=wait)
    assert waits == [config.worker_poll_seconds]


def test_drain_honors_explicit_batch_limit(
    config: SenderConfig, spool: SQLiteSpool, alert_payload: AlertPayload
) -> None:
    for index in range(3):
        changed = alert_payload.canonical_json.replace("wazuh-001", f"wazuh-{index}")
        from cyberqalqon_sender.payloads import parse_payload_bytes

        spool.enqueue(parse_payload_bytes(changed.encode(), maximum_bytes=4096), now=100.0)
    service = make_service(
        config,
        spool,
        SequenceClient([_result(DeliveryClassification.DELIVERED, status=201)] * 3),
        FakeClock(100.0),
    )
    summary = service.drain(limit=2)
    assert summary.processed == 2
    assert spool.status().queue_depth == 1
