from __future__ import annotations

import json
import logging
from dataclasses import replace
from pathlib import Path

import pytest
import httpx

from cyberqalqon_sender.event_shipper import (
    ArchiveCursorStateError,
    AdaptiveBatchController,
    ArchiveEventShipper,
    BatchDeliveryResult,
    EventDeliveryClient,
    EventShipperConfig,
    select_archive_event,
)
from cyberqalqon_sender.backlog import BacklogAuditError, scan_archive_backlog
from cyberqalqon_sender.config import SenderConfig


class SequenceDelivery:
    def __init__(self, results: list[str]) -> None:
        self.results = results
        self.payloads: list[bytes] = []

    def deliver(self, payload: bytes) -> str:
        self.payloads.append(payload)
        return self.results.pop(0)

    def close(self) -> None:
        return None


class SequenceBatchDelivery:
    def __init__(self, results: list[BatchDeliveryResult]) -> None:
        self.results = results
        self.calls: list[tuple[str, list[dict[str, object]]]] = []
        self.last_latency_ms: float | None = 12.5

    def deliver_batch(
        self,
        payloads: list[dict[str, object]],
        *,
        batch_id: str,
    ) -> BatchDeliveryResult:
        self.calls.append((batch_id, payloads))
        return self.results.pop(0)

    def close(self) -> None:
        return None


def _config(tmp_path: Path) -> EventShipperConfig:
    return EventShipperConfig(
        archive_path=tmp_path / "archives.json",
        state_path=tmp_path / "state" / "cursor.json",
        endpoint="http://127.0.0.1:8000/api/v1/events/ingest",
        api_key="unit-test-ingestion-key-0001",
        poll_seconds=1,
        batch_size=20,
        bootstrap_bytes=1024 * 1024,
        max_line_bytes=4096,
        connect_timeout_seconds=1,
        request_timeout_seconds=2,
        ca_bundle=None,
    )


@pytest.mark.parametrize(
    "payload",
    [
        {"rule": {"id": "100111"}},
        {"location": "/var/log/nginx/access.log"},
        {"location": "syscheck"},
        {"full_log": "CQ-NETSCAN src=127.0.0.1"},
        {"decoder": {"name": "sshd"}},
        {"data": {"win": {"system": {"eventID": "4625"}}}},
        {"data": {"win": {"system": {"eventID": "4688"}}}},
        {"data": {"win": {"system": {"eventID": "4103"}}}},
        {"data": {"win": {"system": {"eventID": "5007"}}}},
    ],
)
def test_security_source_allowlist(payload: dict[str, object]) -> None:
    assert select_archive_event(payload)


def test_generic_archive_noise_is_not_mirrored() -> None:
    assert not select_archive_event(
        {
            "location": "journald",
            "decoder": {"name": "systemd"},
            "full_log": "routine service heartbeat",
        }
    )


def test_adaptive_batch_controller_is_bounded_and_conservative() -> None:
    controller = AdaptiveBatchController(
        minimum=10,
        maximum=100,
        low_latency_ms=100,
        high_latency_ms=500,
        current=10,
    )
    assert controller.observe(request_latencies_ms=[50, 60], blocked=False) == 11
    assert controller.observe(request_latencies_ms=[700], blocked=False) == 10
    controller.current = 100
    assert controller.observe(request_latencies_ms=[50], blocked=False) == 100
    assert controller.observe(request_latencies_ms=[], blocked=True) == 50
    controller.current = 10
    assert controller.observe(request_latencies_ms=[], blocked=True) == 10


def test_batch_adaptive_configuration_cannot_exceed_network_bound(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("CYBERQALQON_EVENT_BATCH_SIZE", "100")
    monkeypatch.setenv("CYBERQALQON_EVENT_BATCH_PROTOCOL_ENABLED", "true")
    monkeypatch.setenv("CYBERQALQON_EVENT_NETWORK_BATCH_SIZE", "25")
    monkeypatch.setenv("CYBERQALQON_EVENT_ADAPTIVE_ENABLED", "true")
    monkeypatch.setenv("CYBERQALQON_EVENT_ADAPTIVE_MIN_BATCH", "10")
    monkeypatch.setenv("CYBERQALQON_EVENT_ADAPTIVE_MAX_BATCH", "50")
    monkeypatch.setenv("CYBERQALQON_URL", "http://127.0.0.1:8000")
    monkeypatch.setenv(
        "CYBERQALQON_INGEST_API_KEY", "unit-test-ingestion-key-0001"
    )
    monkeypatch.setenv("CYBERQALQON_ALLOW_INSECURE_HTTP", "true")
    monkeypatch.setenv("CYBERQALQON_EVENT_ARCHIVE", str(tmp_path / "archives.json"))
    monkeypatch.setenv("CYBERQALQON_EVENT_STATE", str(tmp_path / "cursor.json"))
    with pytest.raises(ValueError, match="network batch size"):
        EventShipperConfig.from_sender(SenderConfig.from_env())


def test_v091_benign_application_acceptance_event_is_narrowly_allowlisted() -> None:
    assert select_archive_event(
        {
            "data": {
                "win": {
                    "system": {
                        "channel": "Application",
                        "providerName": "CyberQalqon-V091",
                        "eventID": "100",
                    }
                }
            }
        }
    )
    assert not select_archive_event(
        {
            "data": {
                "win": {
                    "system": {
                        "channel": "Application",
                        "providerName": "Unrelated-Application",
                        "eventID": "100",
                    }
                }
            }
        }
    )
    assert not select_archive_event(
        {
            "data": {
                "win": {
                    "system": {
                        "channel": "Security",
                        "providerName": "CyberQalqon-V091",
                        "eventID": "100",
                    }
                }
            }
        }
    )


def test_cursor_is_durable_and_retry_does_not_advance(tmp_path: Path) -> None:
    config = _config(tmp_path)
    rows = [
        {"id": "noise", "location": "journald"},
        {"id": "selected", "rule": {"id": "100111", "level": 10}},
    ]
    config.archive_path.write_bytes(
        b"".join(json.dumps(row).encode() + b"\n" for row in rows)
    )
    shipper = ArchiveEventShipper(config, logger=logging.getLogger("shipper-test"))
    shipper.delivery.close()
    delivery = SequenceDelivery(["accepted"])
    shipper.delivery = delivery  # type: ignore[assignment]

    result = shipper.run_batch()
    assert result["processed"] == 2
    assert len(delivery.payloads) == 1
    first_state = json.loads(config.state_path.read_text(encoding="utf-8"))
    assert first_state["accepted"] == 1
    assert first_state["skipped"] == 1
    assert first_state["filtered_events"] == 1
    assert first_state["version"] == 3
    assert first_state["offset"] == config.archive_path.stat().st_size

    assert shipper.run_batch()["processed"] == 0
    assert len(delivery.payloads) == 1

    with config.archive_path.open("ab") as handle:
        handle.write(json.dumps({"id": "retry", "rule": {"id": "5710"}}).encode() + b"\n")
    retry_start = first_state["offset"]
    delivery.results.extend(["retry", "accepted"])
    blocked = shipper.run_batch()
    assert blocked["retry_blocked"] is True
    assert blocked["offset"] == retry_start
    assert json.loads(config.state_path.read_text(encoding="utf-8"))["retry_attempts"] == 1
    recovered = shipper.run_batch()
    assert recovered["retry_blocked"] is False
    assert recovered["processed"] == 1
    recovered_state = json.loads(config.state_path.read_text(encoding="utf-8"))
    assert recovered_state["accepted"] == 2
    assert recovered_state["consecutive_retries"] == 0
    assert recovered_state["recovery_transitions"] == 1
    assert recovered_state["last_recovery_at"] is not None


def test_duplicate_ack_is_observable_and_advances_once(tmp_path: Path) -> None:
    config = _config(tmp_path)
    row = {"id": "duplicate", "rule": {"id": "100111", "level": 10}}
    config.archive_path.write_bytes(json.dumps(row).encode() + b"\n")
    shipper = ArchiveEventShipper(config, logger=logging.getLogger("shipper-test"))
    shipper.delivery.close()
    delivery = SequenceDelivery(["duplicate"])
    shipper.delivery = delivery  # type: ignore[assignment]

    result = shipper.run_batch()
    state = json.loads(config.state_path.read_text(encoding="utf-8"))
    assert result["processed"] == 1
    assert state["duplicate_attempts"] == 1
    assert state["accepted"] == 0
    assert state["last_success_at"] is not None
    assert state["offset"] == config.archive_path.stat().st_size


@pytest.mark.parametrize(
    ("status", "body", "expected"),
    [
        (201, {"status": "created", "duplicate": False}, "accepted"),
        (200, {"status": "duplicate", "duplicate": True}, "duplicate"),
        (201, {"status": "duplicate", "duplicate": True}, "protocol_error"),
        (200, {"status": "created", "duplicate": False}, "protocol_error"),
        (201, {"status": "created"}, "protocol_error"),
        (422, {"status": "rejected"}, "rejected"),
        (503, {"status": "unavailable"}, "retry"),
    ],
)
def test_delivery_contract_is_explicit(
    tmp_path: Path, status: int, body: dict[str, object], expected: str,
) -> None:
    client = EventDeliveryClient(_config(tmp_path))
    client.client.close()
    client.client = httpx.Client(
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(status, json=body)
        )
    )
    try:
        assert client.deliver(b"{}") == expected
    finally:
        client.close()


@pytest.mark.parametrize(
    ("status", "body", "expected", "outcomes"),
    [
        (
            201,
            {
                "protocol_version": "m18-batch-v1",
                "batch_id": "m18-contract",
                "status": "COMMITTED",
                "atomic": True,
                "inserted": 1,
                "duplicates": 1,
                "results": [
                    {"index": 0, "outcome": "INSERTED"},
                    {"index": 1, "outcome": "DUPLICATE"},
                ],
            },
            "accepted",
            ("accepted", "duplicate"),
        ),
        (
            200,
            {
                "protocol_version": "m18-batch-v1",
                "batch_id": "m18-contract",
                "status": "COMMITTED",
                "atomic": True,
                "inserted": 0,
                "duplicates": 2,
                "results": [
                    {"index": 0, "outcome": "DUPLICATE"},
                    {"index": 1, "outcome": "DUPLICATE"},
                ],
            },
            "accepted",
            ("duplicate", "duplicate"),
        ),
        (503, {"detail": {"code": "busy"}}, "retry", ()),
        (422, {"detail": {"code": "invalid"}}, "rejected", ()),
        (
            201,
            {
                "protocol_version": "m18-batch-v1",
                "batch_id": "wrong",
                "status": "COMMITTED",
                "atomic": True,
                "inserted": 2,
                "duplicates": 0,
                "results": [
                    {"index": 0, "outcome": "INSERTED"},
                    {"index": 1, "outcome": "INSERTED"},
                ],
            },
            "protocol_error",
            (),
        ),
    ],
)
def test_batch_delivery_contract_is_explicit(
    tmp_path: Path,
    status: int,
    body: dict[str, object],
    expected: str,
    outcomes: tuple[str, ...],
) -> None:
    client = EventDeliveryClient(_config(tmp_path))
    client.client.close()
    client.client = httpx.Client(
        transport=httpx.MockTransport(lambda _request: httpx.Response(status, json=body))
    )
    try:
        result = client.deliver_batch(
            [{"rule": {"id": "1"}}, {"rule": {"id": "2"}}],
            batch_id="m18-contract",
        )
        assert result.status == expected
        assert result.outcomes == outcomes
    finally:
        client.close()


def test_network_batch_advances_only_after_atomic_ack(tmp_path: Path) -> None:
    config = replace(
        _config(tmp_path),
        batch_protocol_enabled=True,
        network_batch_size=10,
    )
    rows = [
        {"id": "noise", "location": "journald"},
        {"id": "new", "rule": {"id": "100111", "level": 10}},
        {"id": "duplicate", "rule": {"id": "5710", "level": 5}},
    ]
    config.archive_path.write_bytes(
        b"".join(json.dumps(row).encode() + b"\n" for row in rows)
    )
    shipper = ArchiveEventShipper(config, logger=logging.getLogger("batch-shipper-test"))
    shipper.delivery.close()
    delivery = SequenceBatchDelivery(
        [BatchDeliveryResult("accepted", ("accepted", "duplicate"))]
    )
    shipper.delivery = delivery  # type: ignore[assignment]

    result = shipper.run_batch()
    state = json.loads(config.state_path.read_text(encoding="utf-8"))
    assert result["processed"] == 3
    assert result["offset"] == config.archive_path.stat().st_size
    assert state["accepted"] == 1
    assert state["duplicate_attempts"] == 1
    assert state["filtered_events"] == 1
    assert state["batch_http_requests"] == 1
    assert state["batch_events_acknowledged"] == 2
    assert state["last_batch_size"] == 2
    assert state["ingress_protocol"] == "m18-batch-v1"
    assert len(delivery.calls) == 1


def test_network_batch_retry_preserves_cursor_and_batch_identity(tmp_path: Path) -> None:
    config = replace(
        _config(tmp_path),
        batch_protocol_enabled=True,
        network_batch_size=10,
    )
    config.archive_path.write_bytes(
        b'{"id":"selected","rule":{"id":"100111","level":10}}\n'
    )
    shipper = ArchiveEventShipper(config, logger=logging.getLogger("batch-retry-test"))
    shipper.delivery.close()
    delivery = SequenceBatchDelivery(
        [
            BatchDeliveryResult("retry"),
            BatchDeliveryResult("accepted", ("duplicate",)),
        ]
    )
    shipper.delivery = delivery  # type: ignore[assignment]

    blocked = shipper.run_batch()
    blocked_state = json.loads(config.state_path.read_text(encoding="utf-8"))
    assert blocked["retry_blocked"] is True
    assert blocked_state["offset"] == 0
    assert blocked_state["batch_events_acknowledged"] == 0

    recovered = shipper.run_batch()
    recovered_state = json.loads(config.state_path.read_text(encoding="utf-8"))
    assert recovered["retry_blocked"] is False
    assert recovered_state["offset"] == config.archive_path.stat().st_size
    assert recovered_state["duplicate_attempts"] == 1
    assert recovered_state["retry_attempts"] == 1
    assert recovered_state["recovery_transitions"] == 1
    assert delivery.calls[0][0] == delivery.calls[1][0]


def test_network_batch_protocol_error_never_advances_past_gap(tmp_path: Path) -> None:
    config = replace(
        _config(tmp_path),
        batch_protocol_enabled=True,
        network_batch_size=10,
    )
    config.archive_path.write_bytes(
        b'{"id":"selected","rule":{"id":"100111"}}\n'
        b'{"id":"noise","location":"journald"}\n'
    )
    shipper = ArchiveEventShipper(config, logger=logging.getLogger("batch-gap-test"))
    shipper.delivery.close()
    shipper.delivery = SequenceBatchDelivery(
        [BatchDeliveryResult("protocol_error")]
    )  # type: ignore[assignment]

    result = shipper.run_batch()
    state = json.loads(config.state_path.read_text(encoding="utf-8"))
    assert result["retry_blocked"] is True
    assert state["offset"] == 0
    assert state["filtered_events"] == 0
    assert state["protocol_errors"] == 1


def test_incorrect_success_response_does_not_advance_cursor(tmp_path: Path) -> None:
    config = _config(tmp_path)
    config.archive_path.write_bytes(b'{"rule":{"id":"100111"}}\n')
    shipper = ArchiveEventShipper(config, logger=logging.getLogger("shipper-test"))
    shipper.delivery.close()
    shipper.delivery = SequenceDelivery(["protocol_error"])  # type: ignore[assignment]

    result = shipper.run_batch()
    state = json.loads(config.state_path.read_text(encoding="utf-8"))

    assert result["retry_blocked"] is True
    assert result["offset"] == 0
    assert state["protocol_errors"] == 1
    assert state["retry_attempts"] == 1


def test_permanent_delivery_rejection_blocks_without_advancing(tmp_path: Path) -> None:
    config = _config(tmp_path)
    config.archive_path.write_bytes(b'{"rule":{"id":"100111"}}\n')
    shipper = ArchiveEventShipper(config, logger=logging.getLogger("shipper-test"))
    shipper.delivery.close()
    shipper.delivery = SequenceDelivery(["rejected"])  # type: ignore[assignment]

    result = shipper.run_batch()
    state = json.loads(config.state_path.read_text(encoding="utf-8"))

    assert result["terminal_blocked"] is True
    assert result["offset"] == 0
    assert state["terminal_blocked"] is True
    assert state["delivery_rejected"] == 1


def test_legacy_state_requires_explicit_upgrade(tmp_path: Path) -> None:
    config = _config(tmp_path)
    config.archive_path.write_text("{}\n", encoding="utf-8")
    stat = config.archive_path.stat()
    config.state_path.parent.mkdir(parents=True)
    config.state_path.write_text(
        json.dumps(
            {
                "version": 2,
                "device": stat.st_dev,
                "inode": stat.st_ino,
                "offset": 0,
                "accepted": 4,
            }
        ),
        encoding="utf-8",
    )
    shipper = ArchiveEventShipper(config, logger=logging.getLogger("shipper-test"))
    try:
        with pytest.raises(ArchiveCursorStateError, match="operator-approved"):
            shipper.run_batch()
    finally:
        shipper.close()


def test_malformed_and_oversized_lines_are_skipped_without_delivery(tmp_path: Path) -> None:
    config = replace(_config(tmp_path), max_line_bytes=32)
    config.archive_path.write_bytes(b"not-json\n" + b"x" * 64 + b"\n")
    shipper = ArchiveEventShipper(config, logger=logging.getLogger("shipper-test"))
    shipper.delivery.close()
    delivery = SequenceDelivery([])
    shipper.delivery = delivery  # type: ignore[assignment]

    result = shipper.run_batch()
    state = json.loads(config.state_path.read_text(encoding="utf-8"))
    assert result["processed"] == 2
    assert state["rejected"] == 2
    assert state["malformed_json"] == 1
    assert state["oversized_lines"] == 1
    assert state["delivery_rejected"] == 0
    assert delivery.payloads == []


def test_partial_tail_waits_without_advancing_or_rejecting(tmp_path: Path) -> None:
    config = _config(tmp_path)
    partial = json.dumps({"id": "partial", "rule": {"id": "100111"}}).encode()
    config.archive_path.write_bytes(partial)
    shipper = ArchiveEventShipper(config, logger=logging.getLogger("shipper-test"))
    shipper.delivery.close()
    delivery = SequenceDelivery(["accepted"])
    shipper.delivery = delivery  # type: ignore[assignment]

    first = shipper.run_batch()
    state = json.loads(config.state_path.read_text(encoding="utf-8"))
    assert first["processed"] == 0
    assert state["offset"] == 0
    assert state["rejected"] == 0
    assert delivery.payloads == []

    with config.archive_path.open("ab") as handle:
        handle.write(b"\n")
    second = shipper.run_batch()
    assert second["processed"] == 1
    assert len(delivery.payloads) == 1


def test_partial_batch_restart_resumes_from_last_acknowledged_record(tmp_path: Path) -> None:
    config = replace(_config(tmp_path), batch_size=2)
    rows = [
        {"id": f"selected-{index}", "rule": {"id": "100111"}}
        for index in range(3)
    ]
    config.archive_path.write_bytes(
        b"".join(json.dumps(row).encode() + b"\n" for row in rows)
    )
    first_shipper = ArchiveEventShipper(config, logger=logging.getLogger("shipper-test"))
    first_shipper.delivery.close()
    first_delivery = SequenceDelivery(["accepted", "accepted"])
    first_shipper.delivery = first_delivery  # type: ignore[assignment]

    assert first_shipper.run_batch()["processed"] == 2
    first_shipper.close()

    resumed_shipper = ArchiveEventShipper(config, logger=logging.getLogger("shipper-test"))
    resumed_shipper.delivery.close()
    resumed_delivery = SequenceDelivery(["accepted"])
    resumed_shipper.delivery = resumed_delivery  # type: ignore[assignment]
    assert resumed_shipper.run_batch()["processed"] == 1
    state = json.loads(config.state_path.read_text(encoding="utf-8"))
    delivered_ids = [
        json.loads(payload)["id"]
        for payload in first_delivery.payloads + resumed_delivery.payloads
    ]
    assert delivered_ids == ["selected-0", "selected-1", "selected-2"]
    assert state["accepted"] == 3
    assert state["offset"] == config.archive_path.stat().st_size


@pytest.mark.parametrize("failure", ["rotation", "truncation"])
def test_existing_cursor_fails_closed_on_archive_identity_or_size_change(
    tmp_path: Path, failure: str,
) -> None:
    config = _config(tmp_path)
    config.archive_path.write_bytes(
        json.dumps({"id": "selected", "rule": {"id": "100111"}}).encode() + b"\n"
    )
    shipper = ArchiveEventShipper(config, logger=logging.getLogger("shipper-test"))
    shipper.delivery.close()
    shipper.delivery = SequenceDelivery(["accepted"])  # type: ignore[assignment]
    shipper.run_batch()
    before = config.state_path.read_bytes()

    if failure == "rotation":
        config.archive_path.replace(tmp_path / "archives.json.1")
        config.archive_path.write_text("{}\n", encoding="utf-8")
    else:
        config.archive_path.write_bytes(b"")

    with pytest.raises(ArchiveCursorStateError):
        shipper.run_batch()
    assert config.state_path.read_bytes() == before


def test_backlog_audit_counts_records_without_advancing_cursor(tmp_path: Path) -> None:
    config = replace(_config(tmp_path), max_line_bytes=4096)
    consumed = json.dumps({"location": "journald", "id": "consumed"}).encode() + b"\n"
    selected = json.dumps({"rule": {"id": "100111"}, "id": "selected"}).encode() + b"\n"
    filtered = json.dumps({"location": "journald", "id": "filtered"}).encode() + b"\n"
    malformed = b"not-json\n"
    config.archive_path.write_bytes(consumed + selected + filtered + malformed)
    stat = config.archive_path.stat()
    config.state_path.parent.mkdir(parents=True)
    state = {
        "version": 2,
        "device": stat.st_dev,
        "inode": stat.st_ino,
        "offset": len(consumed),
        "updated_at": 123.5,
    }
    config.state_path.write_text(json.dumps(state), encoding="utf-8")
    before = config.state_path.read_bytes()

    result = scan_archive_backlog(
        config.archive_path,
        config.state_path,
        max_line_bytes=config.max_line_bytes,
        selector=select_archive_event,
    )

    assert result.byte_lag == len(selected + filtered + malformed)
    assert result.unread_records == 3
    assert result.eligible_records == 1
    assert result.filtered_records == 1
    assert result.malformed_records == 1
    assert result.oversized_records == 0
    assert result.cursor_updated_at_epoch == 123.5
    assert config.state_path.read_bytes() == before


def test_backlog_audit_fails_closed_on_archive_rotation(tmp_path: Path) -> None:
    config = _config(tmp_path)
    config.archive_path.write_text("{}\n", encoding="utf-8")
    stat = config.archive_path.stat()
    config.state_path.parent.mkdir(parents=True)
    config.state_path.write_text(
        json.dumps({"version": 2, "device": stat.st_dev, "inode": stat.st_ino + 1, "offset": 0}),
        encoding="utf-8",
    )
    with pytest.raises(BacklogAuditError, match="identity does not match"):
        scan_archive_backlog(
            config.archive_path,
            config.state_path,
            max_line_bytes=config.max_line_bytes,
            selector=select_archive_event,
        )
