"""Disposable M18 single-event versus atomic-batch ingestion benchmark."""

from __future__ import annotations

import argparse
import gc
import json
import os
import shutil
import sqlite3
import statistics
import sys
import tempfile
import time
import tracemalloc
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "scripts"))

from fastapi.testclient import TestClient  # noqa: E402

from app.core.config import Settings  # noqa: E402
from app.db.events import _utc_iso  # noqa: E402
from app.db.migrations import apply_migrations  # noqa: E402
from app.main import create_app  # noqa: E402
from benchmark_m13 import _insert_until, _seed_supporting_records  # noqa: E402


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int((len(ordered) - 1) * percentile)))
    return round(ordered[index], 3)


def _size(path: Path) -> int:
    return path.stat().st_size if path.exists() else 0


def _event(population: int, variant: str, index: int, anchor: datetime) -> dict[str, Any]:
    return {
        "timestamp": (anchor + timedelta(microseconds=index)).isoformat(),
        "id": f"m18-{population}-{variant}-{index}",
        "agent": {"id": "001", "name": "M18-DISPOSABLE"},
        "rule": {
            "id": "100111",
            "level": 10,
            "description": "M18 disposable benchmark",
        },
        "decoder": {"name": "sshd"},
        "location": "/var/log/auth.log",
        "full_log": f"M18 disposable benchmark {population} {variant} {index}",
    }


def _run_variant(
    base: Path,
    database: Path,
    *,
    population: int,
    probe_events: int,
    batch_size: int,
) -> dict[str, Any]:
    shutil.copy2(base, database)
    variant = "single" if batch_size == 1 else f"batch-{batch_size}"
    settings = Settings(
        database_url=f"sqlite:///{database.as_posix()}",
        wazuh_ingest_api_key="m18-disposable-benchmark-key",
        allow_m14_schema_migration=False,
        event_batch_ingest_enabled=True,
        event_batch_max_events=100,
        event_batch_max_bytes=2_097_152,
        security_event_retention_days=30,
        security_event_max_records=population,
    )
    anchor = datetime.now(timezone.utc)
    events = [_event(population, variant, index, anchor) for index in range(probe_events)]
    payload_bytes = sum(
        len(json.dumps(item, separators=(",", ":")).encode("utf-8")) for item in events
    )
    request_latencies: list[float] = []
    request_parse_latencies: list[float] = []
    normalization_latencies: list[float] = []
    database_latencies: list[float] = []
    transaction_latencies: list[float] = []
    retention_latencies: list[float] = []
    commit_latencies: list[float] = []
    backend_total_latencies: list[float] = []
    statuses: list[int] = []
    requests = 0
    wal = Path(f"{database}-wal")
    wal_before = _size(wal)
    database_before = _size(database)
    cpu_started = time.process_time()
    tracemalloc.start()
    wall_started = time.perf_counter()
    application = create_app(settings)
    with TestClient(application) as client:
        headers = {"X-API-Key": "m18-disposable-benchmark-key"}
        for start in range(0, probe_events, batch_size):
            chunk = events[start : start + batch_size]
            request_started = time.perf_counter()
            if batch_size == 1:
                response = client.post(
                    "/api/v1/events/ingest", headers=headers, json=chunk[0]
                )
            else:
                response = client.post(
                    "/api/v1/events/ingest-batch",
                    headers=headers,
                    json={
                        "protocol_version": "m18-batch-v1",
                        "batch_id": f"m18-{population}-{batch_size}-{start}",
                        "events": chunk,
                    },
                )
                if response.status_code in {200, 201}:
                    timing = response.json()["timing_ms"]
                    request_parse_latencies.append(float(timing["request_parse_ms"]))
                    normalization_latencies.append(float(timing["normalization_ms"]))
                    database_latencies.append(float(timing["database_ms"]))
                    transaction_latencies.append(float(timing["transaction_ms"]))
                    retention_latencies.append(float(timing["retention_ms"]))
                    commit_latencies.append(float(timing["commit_ms"]))
                    backend_total_latencies.append(float(timing["total_ms"]))
            request_latencies.append((time.perf_counter() - request_started) * 1000)
            statuses.append(response.status_code)
            requests += 1
            if response.status_code != 201:
                raise RuntimeError(
                    f"{variant} insert returned {response.status_code}: {response.text[:240]}"
                )
        insert_wall = time.perf_counter() - wall_started

        duplicate_started = time.perf_counter()
        duplicate_statuses: list[int] = []
        for start in range(0, probe_events, batch_size):
            chunk = events[start : start + batch_size]
            if batch_size == 1:
                response = client.post(
                    "/api/v1/events/ingest", headers=headers, json=chunk[0]
                )
            else:
                response = client.post(
                    "/api/v1/events/ingest-batch",
                    headers=headers,
                    json={
                        "protocol_version": "m18-batch-v1",
                        "batch_id": f"m18-replay-{population}-{batch_size}-{start}",
                        "events": chunk,
                    },
                )
            duplicate_statuses.append(response.status_code)
            if response.status_code != 200:
                raise RuntimeError(
                    f"{variant} duplicate returned {response.status_code}: {response.text[:240]}"
                )
        duplicate_wall = time.perf_counter() - duplicate_started
    del client, application
    gc.collect()
    total_wall = time.perf_counter() - wall_started
    _current, peak_python_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    cpu_seconds = time.process_time() - cpu_started

    with closing(sqlite3.connect(database, timeout=30)) as connection:
        retained = int(connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0])
        state_retained = int(
            connection.execute(
                "SELECT retained_records FROM security_event_store_state WHERE singleton=1"
            ).fetchone()[0]
        )
        quick_check = str(connection.execute("PRAGMA quick_check").fetchone()[0])
        foreign_key_errors = len(connection.execute("PRAGMA foreign_key_check").fetchall())

    result: dict[str, Any] = {
        "variant": variant,
        "population_at_cap": population,
        "probe_events": probe_events,
        "batch_size": batch_size,
        "requests": requests,
        "http_requests_per_event": round(requests / probe_events, 6),
        "insert_wall_seconds": round(insert_wall, 6),
        "insert_events_per_second": round(probe_events / insert_wall, 3),
        "payload_mib_per_second": round((payload_bytes / 1_048_576) / insert_wall, 6),
        "request_latency_p50_ms": _percentile(request_latencies, 0.50),
        "request_latency_p95_ms": _percentile(request_latencies, 0.95),
        "duplicate_wall_seconds": round(duplicate_wall, 6),
        "duplicate_events_per_second": round(probe_events / duplicate_wall, 3),
        "cpu_seconds": round(cpu_seconds, 6),
        "total_wall_seconds": round(total_wall, 6),
        "peak_python_bytes": peak_python_bytes,
        "database_growth_bytes": _size(database) - database_before,
        "wal_growth_bytes": _size(wal) - wal_before,
        "retained_records": retained,
        "state_retained_records": state_retained,
        "quick_check": quick_check,
        "foreign_key_errors": foreign_key_errors,
        "insert_statuses": sorted(set(statuses)),
        "duplicate_statuses": sorted(set(duplicate_statuses)),
    }
    if transaction_latencies:
        result["request_parse_latency_p50_ms"] = _percentile(request_parse_latencies, 0.50)
        result["request_parse_latency_p95_ms"] = _percentile(request_parse_latencies, 0.95)
        result["normalization_latency_p50_ms"] = _percentile(normalization_latencies, 0.50)
        result["normalization_latency_p95_ms"] = _percentile(normalization_latencies, 0.95)
        result["database_latency_p50_ms"] = _percentile(database_latencies, 0.50)
        result["database_latency_p95_ms"] = _percentile(database_latencies, 0.95)
        result["transaction_latency_p50_ms"] = _percentile(transaction_latencies, 0.50)
        result["transaction_latency_p95_ms"] = _percentile(transaction_latencies, 0.95)
        result["retention_latency_p50_ms"] = _percentile(retention_latencies, 0.50)
        result["retention_latency_p95_ms"] = _percentile(retention_latencies, 0.95)
        result["commit_latency_p50_ms"] = _percentile(commit_latencies, 0.50)
        result["commit_latency_p95_ms"] = _percentile(commit_latencies, 0.95)
        result["backend_total_latency_p50_ms"] = _percentile(backend_total_latencies, 0.50)
        result["backend_total_latency_p95_ms"] = _percentile(backend_total_latencies, 0.95)
    database.unlink(missing_ok=True)
    Path(f"{database}-wal").unlink(missing_ok=True)
    Path(f"{database}-shm").unlink(missing_ok=True)
    gc.collect()
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--populations", default="10000,50000,100000")
    parser.add_argument("--probe-events", type=int, default=100)
    parser.add_argument("--batch-sizes", default="1,10,25,50,100")
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "artifacts" / "runtime" / "m18-benchmark.json",
    )
    args = parser.parse_args()
    populations = [int(value) for value in args.populations.split(",")]
    batch_sizes = [int(value) for value in args.batch_sizes.split(",")]
    if any(value not in {10_000, 50_000, 100_000} for value in populations):
        parser.error("populations must be selected from 10000,50000,100000")
    if not 10 <= args.probe_events <= 1000:
        parser.error("probe-events must be between 10 and 1000")
    if any(value not in {1, 10, 25, 50, 100} for value in batch_sizes):
        parser.error("batch sizes must be selected from 1,10,25,50,100")
    if ROOT not in args.output.resolve().parents:
        parser.error("output must remain below the repository root")

    report: dict[str, Any] = {
        "version": 1,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "environment": "temporary-isolated-auto-removed",
        "live_database_opened": False,
        "schema_version": 17,
        "feature_gate_default": False,
        "probe_events_per_variant": args.probe_events,
        "results": [],
        "limitations": [
            "Synthetic TestClient workload; it excludes the real Windows/WSL relay.",
            "peak_python_bytes excludes SQLite native allocations and OS page cache.",
            "Results are disposable engineering evidence, not live throughput claims.",
        ],
    }
    with tempfile.TemporaryDirectory(prefix="cyberqalqon-m18-benchmark-") as directory:
        temporary = Path(directory)
        for population in populations:
            base = temporary / f"base-{population}.db"
            anchor = datetime.now(timezone.utc) - timedelta(hours=1)
            with closing(sqlite3.connect(base, timeout=30)) as connection:
                apply_migrations(connection, target_version=17)
                _seed_supporting_records(connection, anchor)
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute("PRAGMA synchronous=FULL")
                _insert_until(
                    connection,
                    anchor,
                    0,
                    population,
                    min(5_000, population),
                )
                connection.execute(
                    "UPDATE security_event_store_state SET retained_records=?, "
                    "last_retention_at=? WHERE singleton=1",
                    (population, _utc_iso(datetime.now(timezone.utc))),
                )
                connection.commit()
                connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            for batch_size in batch_sizes:
                result = _run_variant(
                    base,
                    temporary / f"run-{population}-{batch_size}.db",
                    population=population,
                    probe_events=args.probe_events,
                    batch_size=batch_size,
                )
                report["results"].append(result)
                print(json.dumps(result, sort_keys=True), flush=True)
            base.unlink(missing_ok=True)

    singles = {
        item["population_at_cap"]: item
        for item in report["results"]
        if item["batch_size"] == 1
    }
    for item in report["results"]:
        baseline = singles[item["population_at_cap"]]
        item["speedup_vs_single"] = round(
            item["insert_events_per_second"] / baseline["insert_events_per_second"],
            3,
        )
    report["integrity_pass"] = all(
        item["quick_check"] == "ok"
        and item["foreign_key_errors"] == 0
        and item["retained_records"] == item["population_at_cap"]
        and item["state_retained_records"] == item["population_at_cap"]
        for item in report["results"]
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    pending = args.output.with_suffix(args.output.suffix + ".tmp")
    pending.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(pending, args.output)
    return 0 if report["integrity_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
