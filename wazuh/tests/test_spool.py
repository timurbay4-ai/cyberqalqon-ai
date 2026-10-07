from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from cyberqalqon_sender.models import (
    AlertPayload,
    DeliveryClassification,
    FailureCategory,
)
from cyberqalqon_sender.payloads import parse_payload_bytes
from cyberqalqon_sender.spool import (
    QueueCapacityError,
    ReplayRefusedError,
    SQLiteSpool,
    SpoolLimits,
)


def _spool(
    path: Path,
    *,
    queue_items: int = 10,
    queue_bytes: int = 100_000,
    dead_items: int = 10,
    dead_bytes: int = 100_000,
) -> SQLiteSpool:
    value = SQLiteSpool(
        path,
        SpoolLimits(
            queue_max_items=queue_items,
            queue_max_bytes=queue_bytes,
            dead_letter_max_items=dead_items,
            dead_letter_max_bytes=dead_bytes,
            busy_timeout_seconds=1,
        ),
    )
    value.initialize()
    return value


def _dead_letter(
    spool: SQLiteSpool,
    payload: AlertPayload,
    *,
    category: FailureCategory = FailureCategory.VALIDATION,
    now: float = 100.0,
) -> int | None:
    queue_id = spool.enqueue(payload, now=now)
    item = spool.claim_by_id(queue_id, now=now, lease_seconds=30, max_attempts=3)
    assert item is not None
    dead_id, blocked = spool.finish_terminal(
        item,
        classification=DeliveryClassification.PERMANENT_FAILURE,
        category=category,
        safe_message="terminal test failure",
        http_status=422,
        now=now + 1,
    )
    assert not blocked
    return dead_id


def test_enqueue_persists_payload_and_constant_time_accounting(
    spool: SQLiteSpool, alert_payload: AlertPayload
) -> None:
    queue_id = spool.enqueue(alert_payload, now=100.0)
    record = spool.queue_record(queue_id)
    status = spool.status()

    assert record is not None
    assert record["payload_json"] == alert_payload.canonical_json
    assert record["payload_sha256"] == alert_payload.payload_sha256
    assert status.queue_depth == 1
    assert status.queue_bytes == alert_payload.payload_bytes


def test_due_selection_is_deterministic(tmp_path: Path, alert_payload: AlertPayload) -> None:
    spool = _spool(tmp_path / "ordering.db")
    first = spool.enqueue(alert_payload, now=100.0)
    second_payload = parse_payload_bytes(
        alert_payload.canonical_json.replace("wazuh-001", "wazuh-002").encode(),
        maximum_bytes=4096,
    )
    second = spool.enqueue(second_payload, now=100.0)

    claimed_first = spool.claim_due(now=100.0, lease_seconds=30, max_attempts=3)
    assert claimed_first is not None and claimed_first.id == first
    spool.finish_success(claimed_first, DeliveryClassification.DELIVERED, now=101.0)
    claimed_second = spool.claim_due(now=101.0, lease_seconds=30, max_attempts=3)
    assert claimed_second is not None and claimed_second.id == second


def test_multibyte_payload_is_accounted_in_utf8_bytes(tmp_path: Path) -> None:
    payload = parse_payload_bytes(
        '{"id":"unicode","message":"O‘zbekcha 中文 🔐"}'.encode("utf-8"),
        maximum_bytes=4096,
    )
    spool = _spool(tmp_path / "utf8.db", queue_bytes=payload.payload_bytes)
    spool.enqueue(payload, now=100.0)
    assert spool.status().queue_bytes == len(payload.canonical_json.encode("utf-8"))


def test_count_limit_rejects_new_evidence_and_preserves_existing(
    tmp_path: Path, alert_payload: AlertPayload
) -> None:
    spool = _spool(tmp_path / "count.db", queue_items=1)
    first = spool.enqueue(alert_payload, now=100.0)

    with pytest.raises(QueueCapacityError, match="capacity exhausted"):
        spool.enqueue(alert_payload, now=101.0)

    assert spool.queue_record(first) is not None
    status = spool.status()
    assert status.queue_depth == 1
    assert status.queue_rejected_count == 1


def test_byte_limit_is_exact_and_never_discards_oldest(
    tmp_path: Path, alert_payload: AlertPayload
) -> None:
    spool = _spool(tmp_path / "bytes.db", queue_bytes=alert_payload.payload_bytes)
    first = spool.enqueue(alert_payload, now=100.0)
    with pytest.raises(QueueCapacityError):
        spool.enqueue(alert_payload, now=101.0)
    assert spool.queue_record(first) is not None


def test_enqueue_transaction_rolls_back_counter_on_insert_failure(
    tmp_path: Path, alert_payload: AlertPayload
) -> None:
    path = tmp_path / "rollback.db"
    spool = _spool(path)
    connection = sqlite3.connect(path)
    connection.execute(
        """
        CREATE TRIGGER reject_queue_insert
        BEFORE INSERT ON queue_items
        BEGIN SELECT RAISE(ABORT, 'injected failure'); END
        """
    )
    connection.commit()
    connection.close()

    with pytest.raises(sqlite3.IntegrityError, match="injected failure"):
        spool.enqueue(alert_payload, now=100.0)
    assert spool.status().queue_depth == 0
    assert spool.status().queue_bytes == 0


def test_queue_survives_process_restart(tmp_path: Path, alert_payload: AlertPayload) -> None:
    path = tmp_path / "restart.db"
    first_process = _spool(path)
    queue_id = first_process.enqueue(alert_payload, now=100.0)

    second_process = _spool(path)
    assert second_process.queue_record(queue_id) is not None
    claimed = second_process.claim_due(now=100.0, lease_seconds=30, max_attempts=3)
    assert claimed is not None and claimed.id == queue_id


def test_expired_lease_recovers_and_counts_uncertain_attempt(
    tmp_path: Path, alert_payload: AlertPayload
) -> None:
    spool = _spool(tmp_path / "lease.db")
    queue_id = spool.enqueue(alert_payload, now=100.0)
    first = spool.claim_by_id(queue_id, now=100.0, lease_seconds=10, max_attempts=3)
    assert first is not None and first.attempt_count == 1
    assert spool.claim_due(now=109.9, lease_seconds=10, max_attempts=3) is None

    recovered = spool.claim_due(now=110.0, lease_seconds=10, max_attempts=3)
    assert recovered is not None
    assert recovered.id == queue_id
    assert recovered.attempt_count == 2
    assert recovered.deliver_allowed


def test_expired_lease_does_not_exceed_max_attempts(
    tmp_path: Path, alert_payload: AlertPayload
) -> None:
    spool = _spool(tmp_path / "lease-max.db")
    queue_id = spool.enqueue(alert_payload, now=100.0)
    first = spool.claim_by_id(queue_id, now=100.0, lease_seconds=10, max_attempts=1)
    assert first is not None and first.deliver_allowed and first.attempt_count == 1

    recovered = spool.claim_due(now=110.0, lease_seconds=10, max_attempts=1)
    assert recovered is not None
    assert recovered.attempt_count == 1
    assert not recovered.deliver_allowed


def test_success_updates_counters_and_removes_queue_item(
    tmp_path: Path, alert_payload: AlertPayload
) -> None:
    spool = _spool(tmp_path / "success.db")
    queue_id = spool.enqueue(alert_payload, now=100.0)
    item = spool.claim_by_id(queue_id, now=100.0, lease_seconds=30, max_attempts=3)
    assert item is not None
    spool.finish_success(item, DeliveryClassification.DUPLICATE, now=101.0)

    status = spool.status()
    assert status.queue_depth == 0
    assert status.duplicate_count == 1
    assert status.last_success_at == 101.0


def test_permanent_failure_creates_dead_letter_without_default_payload_output(
    tmp_path: Path, alert_payload: AlertPayload
) -> None:
    spool = _spool(tmp_path / "dead.db")
    dead_id = _dead_letter(spool, alert_payload)
    assert dead_id is not None
    record = spool.get_dead_letter(dead_id)

    assert record is not None
    assert "payload_json" not in record
    assert record["failure_category"] == FailureCategory.VALIDATION.value
    assert spool.get_dead_letter(dead_id, include_payload=True)["payload_json"] == alert_payload.canonical_json  # type: ignore[index]
    assert spool.status().dead_letter_count == 1


def test_dead_letter_bound_keeps_terminal_evidence_in_blocked_queue(
    tmp_path: Path, alert_payload: AlertPayload
) -> None:
    spool = _spool(tmp_path / "dead-bound.db", dead_items=1)
    _dead_letter(spool, alert_payload, now=100.0)

    queue_id = spool.enqueue(alert_payload, now=200.0)
    item = spool.claim_by_id(queue_id, now=200.0, lease_seconds=30, max_attempts=3)
    assert item is not None
    dead_id, blocked = spool.finish_terminal(
        item,
        classification=DeliveryClassification.CONFLICT,
        category=FailureCategory.CONFLICT,
        safe_message="same id with different event",
        http_status=409,
        now=201.0,
    )

    assert dead_id is None and blocked
    record = spool.queue_record(queue_id)
    assert record is not None and record["state"] == "TERMINAL_BLOCKED"
    status = spool.status()
    assert status.dead_letter_count == 1
    assert status.terminal_blocked_count == 1
    assert status.dead_letter_blocked_count == 1

    expanded = _spool(
        tmp_path / "dead-bound.db",
        dead_items=2,
        dead_bytes=100_000,
    )
    reconciled = expanded.reconcile_terminal_blocked(now=300.0)
    assert reconciled == {"moved": 1, "remaining": 0}
    assert expanded.status().queue_depth == 0
    assert expanded.status().dead_letter_count == 2


def test_authentication_dead_letter_replay_requires_force(
    tmp_path: Path, alert_payload: AlertPayload
) -> None:
    spool = _spool(tmp_path / "replay-auth.db")
    dead_id = _dead_letter(
        spool, alert_payload, category=FailureCategory.AUTHENTICATION
    )
    assert dead_id is not None

    with pytest.raises(ReplayRefusedError, match="--force"):
        spool.replay_dead_letter(dead_id, now=200.0)
    queue_id = spool.replay_dead_letter(dead_id, now=201.0, force=True)

    assert spool.queue_record(queue_id) is not None
    record = spool.get_dead_letter(dead_id)
    assert record is not None
    assert record["replay_count"] == 1
    assert record["last_replay_queue_id"] == queue_id
    assert record["last_replay_result"] == "QUEUED"


def test_due_lookup_indexes_exist(tmp_path: Path) -> None:
    path = tmp_path / "indexes.db"
    _spool(path)
    connection = sqlite3.connect(path)
    indexes = {
        row[1] for row in connection.execute("PRAGMA index_list('queue_items')").fetchall()
    }
    connection.close()
    assert {"queue_due_idx", "queue_oldest_idx", "queue_lease_idx"}.issubset(indexes)
