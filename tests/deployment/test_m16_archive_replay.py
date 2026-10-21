from __future__ import annotations

import gzip
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "wazuh"))

from app.core.config import Settings  # noqa: E402
from app.main import create_app  # noqa: E402
from cyberqalqon_sender.archive_recovery import (  # noqa: E402
    ArchiveGenerationManifest,
    HistoricalArchiveReplayer,
)
from cyberqalqon_sender.event_shipper import select_archive_event  # noqa: E402


class ApiDelivery:
    def __init__(self, client: TestClient) -> None:
        self.client = client
        self.statuses: list[int] = []

    def deliver(self, payload: bytes) -> str:
        response = self.client.post(
            "/api/v1/events/ingest",
            headers={
                "X-API-Key": "m16-disposable-ingest-key",
                "Content-Type": "application/json",
            },
            content=payload,
        )
        self.statuses.append(response.status_code)
        if response.status_code == 201:
            return "accepted"
        if response.status_code == 200 and response.json().get("duplicate") is True:
            return "duplicate"
        if response.status_code in {400, 409, 413, 415, 422}:
            return "rejected"
        return "retry"


def test_gzip_historical_replay_is_idempotent_against_disposable_schema17(
    tmp_path: Path,
) -> None:
    database = tmp_path / "disposable.db"
    settings = Settings(
        database_url=f"sqlite:///{database.as_posix()}",
        wazuh_ingest_api_key="m16-disposable-ingest-key",
        allow_m14_schema_migration=False,
        ai_enabled=False,
    )
    event = {
        "id": "M16-DISPOSABLE-REPLAY-1",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agent": {"id": "001", "name": "m16-disposable"},
        "rule": {"id": "100111", "level": 10, "description": "Disposable replay"},
        "location": "/var/log/m16-disposable.log",
        "full_log": "Synthetic disposable replay evidence",
    }
    encoded = json.dumps(event, separators=(",", ":")).encode("utf-8") + b"\n"
    archive = tmp_path / "immutable.json.gz"
    with gzip.open(archive, "wb") as handle:
        handle.write(encoded)
        handle.write(encoded)
        handle.write(b'{"location":"journald","id":"filtered"}\n')
        handle.write(b"malformed\n")

    manifest = ArchiveGenerationManifest(tmp_path / "manifest.json")
    generation = manifest.register(archive)
    with TestClient(create_app(settings)) as client:
        delivery = ApiDelivery(client)
        replayer = HistoricalArchiveReplayer(
            generation,
            tmp_path / "replay-state",
            max_line_bytes=4096,
            selector=select_archive_event,
            delivery=delivery,
        )
        state = replayer.run_batch(
            operator_approved=True,
            limit=10,
            records_per_second=1000,
        )
        assert state.status == "COMPLETE"
        assert state.accepted == 1
        assert state.duplicates == 1
        assert state.filtered == 1
        assert state.malformed == 1
        assert delivery.statuses == [201, 200]
        assert replayer.run_batch(operator_approved=True).as_dict() == state.as_dict()

    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 17
        assert connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0] == 1
        assert connection.execute("PRAGMA quick_check").fetchone()[0] == "ok"
