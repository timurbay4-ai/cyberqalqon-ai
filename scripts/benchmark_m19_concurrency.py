"""Bounded one-writer/concurrent-reader M19 benchmark on a disposable DB."""

from __future__ import annotations

import argparse
import gc
import json
import os
import sqlite3
import statistics
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "scripts"))

from app.db.events import EventFilters, EventRepository, _utc_iso  # noqa: E402
from app.db.migrations import apply_migrations  # noqa: E402
from app.services.event_normalizer import normalize_wazuh_event  # noqa: E402
from benchmark_m13 import _insert_until, _seed_supporting_records  # noqa: E402


def _p95(values: list[float]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return round(ordered[max(0, int((len(ordered) - 1) * 0.95))], 3)


def _event(index: int, anchor: datetime) -> dict[str, Any]:
    return {
        "timestamp": (anchor + timedelta(microseconds=index)).isoformat(),
        "id": f"m19-concurrent-{index}",
        "agent": {"id": "001", "name": "M19-DISPOSABLE"},
        "rule": {"id": "100111", "level": 10, "description": "M19 concurrency"},
        "decoder": {"name": "sshd"},
        "location": "/var/log/auth.log",
        "full_log": f"M19 concurrency fixture {index}",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--population", type=int, default=100_000)
    parser.add_argument("--batches", type=int, default=20)
    parser.add_argument("--readers", type=int, default=3)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "artifacts" / "runtime" / "m19-concurrency.json",
    )
    args = parser.parse_args()
    output = args.output.resolve()
    if ROOT not in output.parents:
        parser.error("output must remain below the repository root")
    if not 10_000 <= args.population <= 100_000:
        parser.error("population must be between 10000 and 100000")
    if not 5 <= args.batches <= 100 or not 1 <= args.readers <= 4:
        parser.error("batches/readers are outside bounded limits")

    with tempfile.TemporaryDirectory(prefix="cyberqalqon-m19-concurrency-") as directory:
        database = Path(directory) / "concurrency.db"
        anchor = datetime.now(timezone.utc) - timedelta(hours=1)
        with closing(sqlite3.connect(database, timeout=30)) as connection:
            apply_migrations(connection, target_version=17)
            _seed_supporting_records(connection, anchor)
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            _insert_until(connection, anchor, 0, args.population, 5_000)
            connection.execute(
                "UPDATE security_event_store_state SET retained_records=?, "
                "last_retention_at=? WHERE singleton=1",
                (args.population, _utc_iso(datetime.now(timezone.utc))),
            )
            connection.commit()
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")

        repository = EventRepository(
            database, retention_days=30, max_records=args.population
        )
        stop = threading.Event()
        reader_latencies: list[float] = []
        writer_latencies: list[float] = []
        errors: list[str] = []
        samples_lock = threading.Lock()
        write_events = [
            normalize_wazuh_event(_event(index, datetime.now(timezone.utc)))
            for index in range(args.batches * 10)
        ]

        def reader() -> None:
            while not stop.is_set():
                started = time.perf_counter()
                try:
                    repository.list(EventFilters(), limit=50, sort="newest")
                    elapsed = (time.perf_counter() - started) * 1000
                    with samples_lock:
                        reader_latencies.append(elapsed)
                except Exception as exc:  # recorded, never hidden
                    with samples_lock:
                        errors.append(type(exc).__name__)
                    stop.set()

        def writer() -> None:
            for index in range(args.batches):
                started = time.perf_counter()
                try:
                    repository.ingest_batch(write_events[index * 10 : (index + 1) * 10])
                    writer_latencies.append((time.perf_counter() - started) * 1000)
                except Exception as exc:  # recorded, never hidden
                    errors.append(type(exc).__name__)
                    break
            stop.set()

        cpu_started = time.process_time()
        wall_started = time.perf_counter()
        with ThreadPoolExecutor(max_workers=args.readers + 1) as executor:
            futures = [executor.submit(reader) for _ in range(args.readers)]
            futures.append(executor.submit(writer))
            for future in futures:
                future.result(timeout=180)
        wall_seconds = time.perf_counter() - wall_started
        cpu_seconds = time.process_time() - cpu_started
        wal = Path(f"{database}-wal")
        with closing(sqlite3.connect(database, timeout=30)) as connection:
            count = int(connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0])
            state_count = int(
                connection.execute(
                    "SELECT retained_records FROM security_event_store_state WHERE singleton=1"
                ).fetchone()[0]
            )
            quick_check = str(connection.execute("PRAGMA quick_check").fetchone()[0])
            foreign_keys = len(connection.execute("PRAGMA foreign_key_check").fetchall())
        report = {
            "version": 1,
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "environment": "temporary-isolated-auto-removed",
            "live_database_opened": False,
            "population": args.population,
            "writer_count": 1,
            "reader_count": args.readers,
            "batch_size": 10,
            "writer_batches": len(writer_latencies),
            "reader_queries": len(reader_latencies),
            "writer_latency_p50_ms": round(statistics.median(writer_latencies), 3),
            "writer_latency_p95_ms": _p95(writer_latencies),
            "reader_latency_p50_ms": round(statistics.median(reader_latencies), 3),
            "reader_latency_p95_ms": _p95(reader_latencies),
            "wall_seconds": round(wall_seconds, 3),
            "cpu_seconds": round(cpu_seconds, 3),
            "wal_size_bytes_before_close": wal.stat().st_size if wal.exists() else 0,
            "errors": errors,
            "retained_records": count,
            "state_retained_records": state_count,
            "quick_check": quick_check,
            "foreign_key_errors": foreign_keys,
            "pass": not errors
            and len(writer_latencies) == args.batches
            and count == args.population
            and state_count == args.population
            and quick_check == "ok"
            and foreign_keys == 0,
        }
        # sqlite3 context managers commit/rollback but do not close repository
        # connections. Drop thread/future closures and force finalizers before
        # Windows removes the disposable directory.
        del futures
        del repository
        gc.collect()
    output.parent.mkdir(parents=True, exist_ok=True)
    pending = output.with_suffix(output.suffix + ".tmp")
    pending.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(pending, output)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
