"""Disposable M24 Operations latency, cancellation, and concurrency benchmark.

The script only creates auto-removed schema-17 databases. It never opens the
live database, archive, checkpoint, approval manifest, or network services.
"""

from __future__ import annotations

import argparse
import gc
import hashlib
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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "scripts"))

from app.db.events import EventRepository  # noqa: E402
from app.db.operations import OperationalRepository  # noqa: E402
from app.schemas.events import NormalizedSecurityEvent  # noqa: E402
from benchmark_m19 import _build_base, _seed_protected_rows  # noqa: E402


LEGACY_QUALITY_SQL = """
SELECT COUNT(*) AS total_events,
       SUM(CASE WHEN raw_event_json IS NOT NULL AND length(raw_event_json) >= 2
                THEN 1 ELSE 0 END) AS raw_evidence_records,
       SUM(CASE WHEN hostname IS NULL OR hostname = '' THEN 1 ELSE 0 END),
       SUM(CASE WHEN username IS NULL OR username = '' THEN 1 ELSE 0 END),
       SUM(CASE WHEN rule_id IS NULL OR rule_id = '' THEN 1 ELSE 0 END)
FROM security_events
"""
LEGACY_RETENTION_SQL = """
SELECT COUNT(*), MIN(occurred_at), MAX(occurred_at), MAX(ingested_at)
FROM security_events
"""
PROPOSED_SQL = {
    "retained_records": (
        "SELECT retained_records,last_retention_at,last_deleted_count "
        "FROM security_event_store_state WHERE singleton=1"
    ),
    "oldest": (
        "SELECT occurred_at FROM security_events "
        "ORDER BY occurred_at ASC,event_id ASC LIMIT 1"
    ),
    "newest": (
        "SELECT occurred_at FROM security_events "
        "ORDER BY occurred_at DESC,event_id DESC LIMIT 1"
    ),
    "last_ingested": (
        "SELECT ingested_at FROM security_events ORDER BY ingested_at DESC LIMIT 1"
    ),
}


def _percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int((len(ordered) - 1) * fraction + 0.5)))
    return round(ordered[index], 3)


def _latencies(values: list[float]) -> dict[str, float | int]:
    return {
        "samples": len(values),
        "p50_ms": round(statistics.median(values), 3),
        "p95_ms": _percentile(values, 0.95),
        "max_ms": round(max(values), 3),
    }


def _rss_bytes() -> int | None:
    try:
        import psutil

        return int(psutil.Process().memory_info().rss)
    except (ImportError, OSError):
        if os.name != "nt":
            return None
        try:
            import ctypes
            from ctypes import wintypes

            class ProcessMemoryCounters(ctypes.Structure):
                _fields_ = [
                    ("cb", wintypes.DWORD),
                    ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                ]

            counters = ProcessMemoryCounters()
            counters.cb = ctypes.sizeof(counters)
            kernel32 = ctypes.windll.kernel32
            psapi = ctypes.windll.psapi
            kernel32.GetCurrentProcess.restype = wintypes.HANDLE
            psapi.GetProcessMemoryInfo.argtypes = [
                wintypes.HANDLE,
                ctypes.POINTER(ProcessMemoryCounters),
                wintypes.DWORD,
            ]
            psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
            handle = kernel32.GetCurrentProcess()
            ok = psapi.GetProcessMemoryInfo(
                handle, ctypes.byref(counters), counters.cb
            )
            return int(counters.WorkingSetSize) if ok else None
        except (AttributeError, OSError, ValueError):
            return None


def _make_payload_large(database: Path, payload_bytes: int) -> None:
    padding = "x" * max(1, payload_bytes - 64)
    raw = json.dumps({"m24": "large-json", "padding": padding}, separators=(",", ":"))
    structured = json.dumps(
        {"event": {"action": "m24-benchmark"}, "padding": padding},
        separators=(",", ":"),
    )
    with closing(sqlite3.connect(database, timeout=30)) as connection:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute(
            "UPDATE security_events SET raw_event_json=?, structured_json=?, raw_size_bytes=?",
            (raw, structured, len(raw.encode("utf-8"))),
        )
        connection.commit()
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")


def _query_plans(database: Path) -> dict[str, list[str]]:
    queries = {
        "legacy_quality": LEGACY_QUALITY_SQL,
        "legacy_retention": LEGACY_RETENTION_SQL,
        **PROPOSED_SQL,
    }
    with closing(
        sqlite3.connect(f"file:{database.as_posix()}?mode=ro", uri=True, timeout=1)
    ) as connection:
        return {
            name: [str(row[3]) for row in connection.execute("EXPLAIN QUERY PLAN " + sql)]
            for name, sql in queries.items()
        }


def _legacy_scan(database: Path, *, deadline_seconds: float = 5.0) -> dict[str, Any]:
    started = time.perf_counter()
    cpu_started = time.process_time()
    deadline = time.monotonic() + deadline_seconds
    cancelled = False
    with closing(
        sqlite3.connect(f"file:{database.as_posix()}?mode=ro", uri=True, timeout=1)
    ) as connection:
        connection.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1_000)
        try:
            connection.execute(LEGACY_QUALITY_SQL).fetchone()
            connection.execute(LEGACY_RETENTION_SQL).fetchone()
        except sqlite3.OperationalError as error:
            if "interrupted" not in str(error).lower():
                raise
            cancelled = True
        finally:
            connection.set_progress_handler(None, 0)
    return {
        "completed": not cancelled,
        "cancelled_at_deadline": cancelled,
        "deadline_seconds": deadline_seconds,
        "wall_ms": round((time.perf_counter() - started) * 1000, 3),
        "cpu_ms": round((time.process_time() - cpu_started) * 1000, 3),
    }


def _cancellation_probe(database: Path, *, cancel_after_seconds: float = 0.02) -> dict[str, Any]:
    started = time.perf_counter()
    cancel_at = time.monotonic() + cancel_after_seconds
    interrupted = False
    with closing(
        sqlite3.connect(f"file:{database.as_posix()}?mode=ro", uri=True, timeout=1)
    ) as connection:
        connection.set_progress_handler(lambda: int(time.monotonic() >= cancel_at), 500)
        try:
            connection.execute(LEGACY_QUALITY_SQL).fetchone()
        except sqlite3.OperationalError as error:
            if "interrupted" not in str(error).lower():
                raise
            interrupted = True
        finally:
            connection.set_progress_handler(None, 0)
    elapsed_ms = (time.perf_counter() - started) * 1000
    return {
        "requested_after_ms": round(cancel_after_seconds * 1000, 3),
        "observed_interrupt_ms": round(elapsed_ms, 3),
        "interrupted": interrupted,
        "bounded_under_250_ms": interrupted and elapsed_ms < 250,
    }


def _operations_latency(database: Path, *, rounds: int) -> dict[str, Any]:
    repository = OperationalRepository(database)
    fresh: list[float] = []
    fresh_cpu: list[float] = []
    cached: list[float] = []
    cached_cpu: list[float] = []
    for index in range(rounds):
        repository._invalidate_overview_cache()
        started = time.perf_counter()
        cpu_started = time.process_time()
        first = repository.overview(limit=40 + index)
        fresh_cpu.append((time.process_time() - cpu_started) * 1000)
        fresh.append((time.perf_counter() - started) * 1000)
        started = time.perf_counter()
        cpu_started = time.process_time()
        second = repository.overview(limit=40 + index)
        cached_cpu.append((time.process_time() - cpu_started) * 1000)
        cached.append((time.perf_counter() - started) * 1000)
        assert first.measurement.state == "FRESH"
        assert second.measurement.state == "CACHED"
        assert first.data_quality.raw_evidence_records is None
    return {
        "application_cache_cold": _latencies(fresh),
        "application_cache_cold_cpu": _latencies(fresh_cpu),
        "application_cache_warm": _latencies(cached),
        "application_cache_warm_cpu": _latencies(cached_cpu),
        "target_p95_under_2000_ms": _percentile(fresh, 0.95) < 2_000,
    }


def _singleflight_probe(database: Path, *, clients: int = 8) -> dict[str, Any]:
    repository = OperationalRepository(database)
    original = repository._compute_overview
    entered = threading.Event()
    release = threading.Event()
    lock = threading.Lock()
    compute_calls = 0

    def delayed(**kwargs):
        nonlocal compute_calls
        with lock:
            compute_calls += 1
        entered.set()
        release.wait(timeout=2)
        return original(**kwargs)

    repository._compute_overview = delayed  # type: ignore[method-assign]
    with ThreadPoolExecutor(max_workers=clients) as executor:
        futures = [executor.submit(repository.overview, limit=77) for _ in range(clients)]
        if not entered.wait(timeout=1):
            raise RuntimeError("single-flight owner did not start")
        time.sleep(0.05)
        release.set()
        results = [future.result(timeout=3) for future in futures]
    return {
        "clients": clients,
        "compute_calls": compute_calls,
        "coalesced_requests": repository._overview_singleflight_joins,
        "states": sorted({item.measurement.state for item in results}),
        "cache_hits": repository._overview_cache_hits,
        "cache_misses": repository._overview_cache_misses,
        "cache_hit_ratio": round(
            repository._overview_cache_hits
            / max(1, repository._overview_cache_hits + repository._overview_cache_misses),
            3,
        ),
        "pass": compute_calls == 1 and repository._overview_singleflight_joins == clients - 1,
    }


def _event(index: int, payload_bytes: int) -> NormalizedSecurityEvent:
    now = datetime.now(timezone.utc)
    event_id = f"EVT-M24-WRITER-{index:08d}"
    raw = {"m24": "writer", "padding": "w" * max(1, payload_bytes - 64)}
    return NormalizedSecurityEvent(
        event_id=event_id,
        deduplication_id=hashlib.sha256(event_id.encode("ascii")).hexdigest(),
        timestamp=now,
        source_type="windows_event",
        hostname="M24-DISPOSABLE",
        agent_id="m24",
        agent_name="m24-disposable",
        rule_id="M24",
        severity=5,
        message="Disposable M24 concurrent writer event",
        ingestion_source="m24_disposable",
        structured_payload={"event": {"action": "m24-writer"}},
        raw_payload=raw,
        raw_size_bytes=len(json.dumps(raw).encode("utf-8")),
    )


def _concurrent_read_write(
    database: Path, *, population: int, payload_bytes: int
) -> dict[str, Any]:
    writer = EventRepository(database, retention_days=30, max_records=population)
    start = threading.Event()
    reader_latencies: list[float] = []
    writer_latencies: list[float] = []
    lock = threading.Lock()

    def read_worker(worker: int) -> None:
        repository = OperationalRepository(
            database,
            overview_cache_ttl_seconds=0,
            overview_stale_ttl_seconds=0,
        )
        start.wait(timeout=2)
        local: list[float] = []
        for offset in range(12):
            began = time.perf_counter()
            repository.overview(limit=20 + ((worker + offset) % 5))
            local.append((time.perf_counter() - began) * 1000)
        with lock:
            reader_latencies.extend(local)

    def write_worker() -> None:
        start.wait(timeout=2)
        for index in range(8):
            began = time.perf_counter()
            writer.ingest(_event(index, payload_bytes))
            writer_latencies.append((time.perf_counter() - began) * 1000)

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(read_worker, index) for index in range(4)]
        futures.append(executor.submit(write_worker))
        start.set()
        for future in futures:
            future.result(timeout=60)

    with closing(sqlite3.connect(database, timeout=5)) as connection:
        retained = int(connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0])
        durable_retained = int(
            connection.execute(
                "SELECT retained_records FROM security_event_store_state WHERE singleton=1"
            ).fetchone()[0]
        )
        quick_check = str(connection.execute("PRAGMA quick_check").fetchone()[0])
        foreign_keys = len(connection.execute("PRAGMA foreign_key_check").fetchall())
    return {
        "readers": 4,
        "single_event_writes": 8,
        "reader_latency": _latencies(reader_latencies),
        "writer_latency": _latencies(writer_latencies),
        "retained_records": retained,
        "durable_retained_records": durable_retained,
        "quick_check": quick_check,
        "foreign_key_errors": foreign_keys,
        "event_loss": retained != population,
        "pass": retained == durable_retained == population and quick_check == "ok" and foreign_keys == 0,
    }


def _run_population(root: Path, population: int, payload_bytes: int, rounds: int) -> dict[str, Any]:
    database = root / f"m24-{population}.db"
    _build_base(database, population)
    _make_payload_large(database, payload_bytes)
    if population == 100_000:
        with closing(sqlite3.connect(database, timeout=30)) as connection:
            _seed_protected_rows(connection, 1_000, datetime.now(timezone.utc))
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    rss_before = _rss_bytes()
    rss_peak = [rss_before or 0]
    stop_sampling = threading.Event()

    def sample_memory() -> None:
        # Working-set sampling is observability only. Keep it deliberately low
        # frequency so instrumentation cannot distort SQLite CPU measurements.
        while not stop_sampling.wait(0.25):
            current = _rss_bytes()
            if current is not None:
                rss_peak[0] = max(rss_peak[0], current)

    sampler = threading.Thread(target=sample_memory, daemon=True)
    sampler.start()
    cpu_before = time.process_time()
    try:
        result = {
            "population": population,
            "database_bytes": database.stat().st_size,
            "json_payload_bytes_per_large_column": payload_bytes,
            "protected_evidence_rows": 1_000 if population == 100_000 else 0,
            "query_plans": _query_plans(database),
            "legacy_request_path": _legacy_scan(database),
            "cancellation": _cancellation_probe(database),
            "optimized_request_path": _operations_latency(database, rounds=rounds),
            "singleflight": _singleflight_probe(database),
            "concurrent_read_write": _concurrent_read_write(
                database, population=population, payload_bytes=payload_bytes
            ),
        }
    finally:
        stop_sampling.set()
        sampler.join(timeout=1)
    result["cpu_seconds"] = round(time.process_time() - cpu_before, 3)
    rss_after = _rss_bytes()
    result["rss_delta_bytes"] = (
        rss_after - rss_before
        if rss_before is not None and rss_after is not None
        else None
    )
    result["rss_peak_bytes"] = rss_peak[0] or None
    result["wal_bytes"] = Path(f"{database}-wal").stat().st_size if Path(f"{database}-wal").exists() else 0
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rounds", type=int, default=10)
    parser.add_argument("--payload-bytes", type=int, default=4096)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "artifacts" / "runtime" / "m24-operations-performance.json",
    )
    args = parser.parse_args()
    if not 5 <= args.rounds <= 30:
        parser.error("rounds must be between 5 and 30")
    if not 1024 <= args.payload_bytes <= 16_384:
        parser.error("payload bytes must be between 1024 and 16384")
    output = args.output.resolve()
    if ROOT not in output.parents:
        parser.error("output must remain below the repository root")

    with tempfile.TemporaryDirectory(prefix="cyberqalqon-m24-") as directory:
        root = Path(directory)
        results = [
            _run_population(root, population, args.payload_bytes, args.rounds)
            for population in (10_000, 50_000, 100_000)
        ]
        gc.collect()
    report = {
        "version": 1,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "environment": "DISPOSABLE_TEMPORARY_AUTO_REMOVED",
        "live_database_opened": False,
        "live_endpoint_called": False,
        "schema_version": 17,
        "single_event_ingestion_only": True,
        "results": results,
        "pass": all(
            item["optimized_request_path"]["target_p95_under_2000_ms"]
            and item["cancellation"]["bounded_under_250_ms"]
            and item["singleflight"]["pass"]
            and item["concurrent_read_write"]["pass"]
            for item in results
        ),
        "limitations": [
            "Application-cache cold does not flush the operating-system page cache.",
            "Disposable timings are not live production rollout acceptance.",
            "The legacy path has a five-second progress-handler ceiling per population.",
            "Concurrent writes use the production single-event repository and retention path; batch ingestion is disabled.",
        ],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    pending = output.with_suffix(output.suffix + ".tmp")
    pending.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(pending, output)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
