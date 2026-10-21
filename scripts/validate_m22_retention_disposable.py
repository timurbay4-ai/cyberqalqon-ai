"""Validate schema-17 retention at 100k records in a disposable database only."""

from __future__ import annotations

import argparse
from contextlib import closing
import gc
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import statistics
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.db.events import EventRepository  # noqa: E402
from app.db.migrations import apply_migrations  # noqa: E402
from app.services.event_normalizer import normalize_wazuh_event  # noqa: E402


def _rss_bytes() -> int | None:
    try:
        import psutil

        return int(psutil.Process().memory_info().rss)
    except (ImportError, OSError):
        return None


def _fixture_row(index: int, occurred_at: str) -> tuple[object, ...]:
    event_id = f"EVT-M22-{index:06d}"
    deduplication_id = hashlib.sha256(event_id.encode()).hexdigest()
    return (
        event_id,
        deduplication_id,
        event_id,
        occurred_at,
        occurred_at,
        "wazuh_archive",
        "m22-disposable",
        "100111",
        10,
        "M22 disposable retention fixture",
        "{}",
        "{}",
        "m22_disposable",
        2,
        "m22 disposable retention fixture",
    )


def _populate(connection: sqlite3.Connection, *, count: int, now: datetime) -> float:
    sql = """
        INSERT INTO security_events (
            event_id, deduplication_id, source_event_id, occurred_at, ingested_at,
            source_type, hostname, rule_id, severity, message, structured_json,
            raw_event_json, ingestion_source, raw_size_bytes, search_text
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    started = time.monotonic()
    connection.execute("BEGIN IMMEDIATE")
    for start in range(0, count, 1000):
        rows = [
            _fixture_row(
                index,
                (now - timedelta(seconds=count - index)).isoformat(),
            )
            for index in range(start, min(start + 1000, count))
        ]
        connection.executemany(sql, rows)
    connection.execute(
        "UPDATE security_event_store_state SET retained_records = ?, "
        "last_retention_at = ?, last_deleted_count = 0 WHERE singleton = 1",
        (count, now.isoformat()),
    )
    connection.commit()
    return time.monotonic() - started


def _protect_three(connection: sqlite3.Connection, now: datetime) -> list[str]:
    protected = [f"EVT-M22-{index:06d}" for index in range(3)]
    connection.execute("BEGIN IMMEDIATE")
    connection.execute(
        """
        INSERT INTO soc_cases (
            case_id, title, description, severity, priority, status, owner_id,
            source_type, source_id, resolution, closure_reason, created_by,
            created_by_display, created_at, updated_at, first_response_at,
            resolved_at, closed_at, response_due_at, resolution_due_at, version
        ) VALUES (
            'CASE-M22-DISPOSABLE', 'M22 retention evidence', '', 'HIGH', 'HIGH',
            'OPEN', NULL, 'MANUAL', NULL, '', '', NULL, 'M22 validator', ?, ?,
            NULL, NULL, NULL, ?, ?, 1
        )
        """,
        (
            now.isoformat(),
            now.isoformat(),
            (now + timedelta(hours=1)).isoformat(),
            (now + timedelta(hours=4)).isoformat(),
        ),
    )
    connection.executemany(
        "INSERT INTO case_events (case_id, event_id, linked_at, linked_by, linked_by_display) "
        "VALUES ('CASE-M22-DISPOSABLE', ?, ?, NULL, 'M22 validator')",
        [(event_id, now.isoformat()) for event_id in protected],
    )
    connection.commit()
    return protected


def validate(record_count: int = 100_000) -> dict[str, object]:
    if record_count != 100_000:
        raise ValueError("M22 acceptance requires exactly 100000 fixture records")
    now = datetime.now(timezone.utc)
    rss_before = _rss_bytes()
    cpu_before = time.process_time()
    with tempfile.TemporaryDirectory(prefix="cyberqalqon-m22-retention-") as temporary:
        database = Path(temporary) / "schema17-disposable.db"
        with closing(sqlite3.connect(database)) as connection:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA journal_mode = WAL")
            apply_migrations(connection, target_version=17)
            populate_seconds = _populate(connection, count=record_count, now=now)
            protected = _protect_three(connection, now)
            before_count = int(
                connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
            )
        repository = EventRepository(database, retention_days=30, max_records=100_000)
        new_payload = {
            "id": "m22-forward-acceptance",
            "timestamp": now.isoformat(),
            "rule": {"id": "100111", "level": 10, "description": "M22 acceptance"},
            "agent": {"id": "001", "name": "m22-disposable"},
            "location": "/var/ossec/logs/archives/archives.json",
        }
        started = time.monotonic()
        stored = repository.ingest(normalize_wazuh_event(new_payload), now=now)
        ingest_seconds = time.monotonic() - started
        unique_latencies_ms = [ingest_seconds * 1000]
        duplicate_latencies_ms: list[float] = []
        unique_acknowledgements = 1
        duplicate_acknowledgements = 0
        for index in range(100):
            payload = {
                **new_payload,
                "id": f"m22-forward-throughput-{index:03d}",
                "timestamp": (now + timedelta(milliseconds=index + 1)).isoformat(),
            }
            normalized = normalize_wazuh_event(payload)
            request_started = time.monotonic()
            inserted = repository.ingest(normalized, now=now)
            unique_latencies_ms.append((time.monotonic() - request_started) * 1000)
            unique_acknowledgements += int(not inserted.duplicate)
            request_started = time.monotonic()
            duplicate = repository.ingest(normalized, now=now)
            duplicate_latencies_ms.append((time.monotonic() - request_started) * 1000)
            duplicate_acknowledgements += int(duplicate.duplicate)
        with closing(sqlite3.connect(database)) as connection:
            connection.execute("PRAGMA foreign_keys = ON")
            after_count = int(
                connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
            )
            retained, deleted = connection.execute(
                "SELECT retained_records, last_deleted_count FROM security_event_store_state "
                "WHERE singleton = 1"
            ).fetchone()
            remaining_protected = {
                str(row[0])
                for row in connection.execute(
                    "SELECT event_id FROM security_events WHERE event_id IN (?, ?, ?)",
                    tuple(protected),
                )
            }
            new_present = connection.execute(
                "SELECT 1 FROM security_events WHERE event_id = ?",
                (stored.event.event_id,),
            ).fetchone() is not None
            quick_check = str(connection.execute("PRAGMA quick_check").fetchone()[0])
            foreign_key_errors = len(connection.execute("PRAGMA foreign_key_check").fetchall())
            schema_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            journal_mode = str(connection.execute("PRAGMA journal_mode").fetchone()[0])
            audit_row = connection.execute(
                "SELECT details_json FROM security_audit_events "
                "WHERE action='SECURITY_EVENT_RETENTION' ORDER BY occurred_at DESC LIMIT 1"
            ).fetchone()
            audit = json.loads(audit_row[0]) if audit_row is not None else None
            database_size = database.stat().st_size
            wal_path = Path(f"{database}-wal")
            wal_size = wal_path.stat().st_size if wal_path.exists() else 0
        rss_after = _rss_bytes()
        passed = (
            schema_version == 17
            and before_count == 100_000
            and after_count == 100_000
            and int(retained) == 100_000
            and int(deleted) == 1
            and remaining_protected == set(protected)
            and new_present
            and quick_check == "ok"
            and foreign_key_errors == 0
            and unique_acknowledgements == 101
            and duplicate_acknowledgements == 100
        )
        all_latencies = sorted(unique_latencies_ms + duplicate_latencies_ms)
        p95_index = max(0, int(len(all_latencies) * 0.95) - 1)
        load_duration_seconds = sum(all_latencies) / 1000
        result = {
            "status": "PASS" if passed else "FAIL",
            "scope": "DISPOSABLE_SCHEMA17_SYNTHETIC_100K",
            "live_database_modified": False,
            "schema_version": schema_version,
            "retention_limit": 100_000,
            "before_records": before_count,
            "after_records": after_count,
            "retained_state_records": int(retained),
            "last_deleted_count": int(deleted),
            "protected_records_expected": len(protected),
            "protected_records_preserved": len(remaining_protected),
            "new_event_preserved": new_present,
            "quick_check": quick_check,
            "foreign_key_errors": foreign_key_errors,
            "journal_mode": journal_mode,
            "populate_seconds": round(populate_seconds, 3),
            "single_ingest_retention_seconds": round(ingest_seconds, 6),
            "single_event_contract": {
                "http_201_equivalent_unique_insertions": unique_acknowledgements,
                "http_200_equivalent_duplicate_acknowledgements": duplicate_acknowledgements,
                "classification_source": "EVENT_REPOSITORY_CONTRACT",
            },
            "throughput": {
                "operations": len(all_latencies),
                "duration_seconds": round(load_duration_seconds, 6),
                "operations_per_second": round(len(all_latencies) / load_duration_seconds, 3),
                "latency_p50_ms": round(statistics.median(all_latencies), 3),
                "latency_p95_ms": round(all_latencies[p95_index], 3),
                "unique_p95_ms": round(
                    sorted(unique_latencies_ms)[
                        max(0, int(len(unique_latencies_ms) * 0.95) - 1)
                    ],
                    3,
                ),
                "duplicate_p95_ms": round(
                    sorted(duplicate_latencies_ms)[
                        max(0, int(len(duplicate_latencies_ms) * 0.95) - 1)
                    ],
                    3,
                ),
            },
            "process_cpu_seconds": round(time.process_time() - cpu_before, 3),
            "rss_delta_bytes": (
                rss_after - rss_before
                if rss_before is not None and rss_after is not None
                else None
            ),
            "database_size_bytes": database_size,
            "wal_size_bytes": wal_size,
            "retention_audit": audit,
            "contains_raw_payload": False,
        }
        # sqlite3 connections opened by the repository may participate in a
        # reference cycle on Windows. Force finalization before TemporaryDirectory
        # attempts to remove the disposable database.
        del repository, stored
        gc.collect()
        return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not args.output.is_absolute():
        raise ValueError("output path must be absolute")
    result = validate()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
