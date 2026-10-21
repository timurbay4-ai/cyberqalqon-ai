from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone


def _archive_event() -> dict:
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "id": "m20-health-reliability-1",
        "agent": {"id": "001", "name": "m20-disposable"},
        "rule": {
            "id": "100120",
            "level": 8,
            "description": "M20 isolated health responsiveness fixture",
            "groups": ["m20"],
        },
        "decoder": {"name": "json"},
        "location": "m20-disposable",
        "data": {"srcip": "127.0.0.1"},
    }


def test_liveness_is_not_queued_behind_synchronous_ingestion(
    client, auth_headers, monkeypatch
) -> None:
    repository = client.app.state.event_repository
    real_ingest = repository.ingest
    entered = threading.Event()
    release = threading.Event()

    def slow_ingest(event):
        entered.set()
        assert release.wait(timeout=3)
        return real_ingest(event)

    monkeypatch.setattr(repository, "ingest", slow_ingest)
    with ThreadPoolExecutor(max_workers=2) as executor:
        ingestion = executor.submit(
            client.post,
            "/api/v1/events/ingest",
            headers=auth_headers,
            json=_archive_event(),
        )
        assert entered.wait(timeout=2)
        started = time.monotonic()
        health = client.get("/health")
        health_ms = (time.monotonic() - started) * 1000
        release.set()
        ingest_response = ingestion.result(timeout=3)

    assert health.status_code == 200
    assert health.json() == {"status": "ok", "service": "cyberqalqon-backend"}
    assert health_ms < 500
    assert ingest_response.status_code == 201


def test_liveness_is_not_queued_behind_storage_readiness(client, monkeypatch) -> None:
    repository = client.app.state.alert_repository
    entered = threading.Event()
    release = threading.Event()

    def slow_readiness() -> bool:
        entered.set()
        assert release.wait(timeout=3)
        return True

    monkeypatch.setattr(repository, "is_ready", slow_readiness)
    with ThreadPoolExecutor(max_workers=2) as executor:
        readiness = executor.submit(client.get, "/readiness")
        assert entered.wait(timeout=2)
        started = time.monotonic()
        health = client.get("/health")
        health_ms = (time.monotonic() - started) * 1000
        release.set()
        readiness_response = readiness.result(timeout=3)

    assert health.status_code == 200
    assert health_ms < 500
    assert readiness_response.status_code == 200
