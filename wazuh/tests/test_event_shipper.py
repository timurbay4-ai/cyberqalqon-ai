from __future__ import annotations

import json
import logging
from dataclasses import replace
from pathlib import Path

import pytest

from cyberqalqon_sender.event_shipper import (
    ArchiveEventShipper,
    EventShipperConfig,
    select_archive_event,
)


class SequenceDelivery:
    def __init__(self, results: list[str]) -> None:
        self.results = results
        self.payloads: list[bytes] = []

    def deliver(self, payload: bytes) -> str:
        self.payloads.append(payload)
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
    assert first_state["version"] == 2
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
    assert json.loads(config.state_path.read_text(encoding="utf-8"))["accepted"] == 2


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
