from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

import pytest

from cyberqalqon_sender.config import SenderConfig
from cyberqalqon_sender.models import AlertPayload, DeliveryResult
from cyberqalqon_sender.payloads import parse_payload_bytes
from cyberqalqon_sender.service import SenderService
from cyberqalqon_sender.spool import SQLiteSpool, SpoolLimits


class FakeClock:
    def __init__(self, value: float = 1_800_000_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class SequenceClient:
    def __init__(self, results: Iterable[DeliveryResult]) -> None:
        self.results = list(results)
        self.payloads: list[bytes] = []

    def deliver(self, payload: bytes) -> DeliveryResult:
        self.payloads.append(payload)
        if not self.results:
            raise AssertionError("unexpected delivery attempt")
        return self.results.pop(0)


@pytest.fixture
def sender_env(tmp_path: Path) -> dict[str, str]:
    return {
        "CYBERQALQON_URL": "http://127.0.0.1:8000",
        "CYBERQALQON_ALLOW_INSECURE_HTTP": "true",
        "CYBERQALQON_INGEST_API_KEY": "unit-test-ingestion-key-0001",
        "CYBERQALQON_SENDER_DB": str((tmp_path / "sender.db").resolve()),
        "CYBERQALQON_MAX_PAYLOAD_BYTES": "4096",
        "CYBERQALQON_QUEUE_MAX_BYTES": "16384",
        "CYBERQALQON_DEAD_LETTER_MAX_BYTES": "16384",
    }


@pytest.fixture
def config(sender_env: dict[str, str]) -> SenderConfig:
    return SenderConfig.from_env(sender_env)


@pytest.fixture
def spool(config: SenderConfig) -> SQLiteSpool:
    value = SQLiteSpool(
        config.database_path,
        SpoolLimits(
            queue_max_items=config.queue_max_items,
            queue_max_bytes=config.queue_max_bytes,
            dead_letter_max_items=config.dead_letter_max_items,
            dead_letter_max_bytes=config.dead_letter_max_bytes,
            busy_timeout_seconds=config.sqlite_busy_timeout_seconds,
        ),
    )
    value.initialize()
    return value


@pytest.fixture
def alert_payload() -> AlertPayload:
    raw = b'''{
      "id": "wazuh-001",
      "timestamp": "2026-10-07T12:00:00Z",
      "agent": {"id": "001", "name": "host-01"},
      "rule": {"id": "5710", "level": 10, "description": "Authentication failure"}
    }'''
    return parse_payload_bytes(raw, maximum_bytes=4096)


def make_service(
    config: SenderConfig,
    spool: SQLiteSpool,
    client: SequenceClient,
    clock: FakeClock,
    *,
    random_value: float = 0.5,
) -> SenderService:
    return SenderService(
        config,
        spool,
        client,
        clock=clock,
        monotonic=lambda: clock.value,
        random_source=lambda: random_value,
    )
