#!/usr/bin/env python3
"""Run CQQL benchmarks only against a temporary disposable schema-17 database.

The script never reads the configured/live CyberQalqon database.  It creates a
fresh temporary directory, applies the repository's real schema-17 migrations,
loads deterministic synthetic rows, and removes the directory on exit.
"""

from __future__ import annotations

import argparse
import ctypes
import gc
import hashlib
import json
import math
import os
import secrets
import sqlite3
import statistics
import sys
import tempfile
import threading
import time
import tracemalloc
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.db.alerts import AlertRepository  # noqa: E402
from app.db.cqql import CQQLSearchRepository, CQQLQueryTimeoutError  # noqa: E402
from app.db.cqql import CQQLQueryCancelledError  # noqa: E402
from app.api.routes.cqql import _render_csv  # noqa: E402
from app.core.config import Settings  # noqa: E402
from app.main import create_app  # noqa: E402
from app.schemas.auth import AnalystCreate, AnalystRole  # noqa: E402
from app.services.cqql import compile_cqql  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


INSERT_COLUMNS = (
    "event_id", "deduplication_id", "source_event_id", "event_code",
    "occurred_at", "ingested_at", "source_type", "hostname", "agent_id",
    "agent_name", "source_ip", "destination_ip", "source_port",
    "destination_port", "username", "event_category", "event_action",
    "outcome", "rule_id", "severity", "message", "structured_json",
    "raw_event_json", "ingestion_source", "related_alert_id", "raw_size_bytes",
    "search_text", "manager_identity", "event_provider", "event_channel",
    "process_name", "process_id", "parent_process_name", "parent_process_id",
    "normalization_schema", "operating_system", "process_path", "command_line",
    "parent_process_path", "mitre_ids_json", "mitre_tactics_json",
    "mitre_techniques_json",
)
INSERT_SQL = (
    f"INSERT INTO security_events ({','.join(INSERT_COLUMNS)}) VALUES "
    f"({','.join('?' for _ in INSERT_COLUMNS)})"
)


def synthetic_row(index: int, base: datetime) -> tuple[object, ...]:
    occurred = base - timedelta(seconds=index % 604_800)
    event_code = ("4625", "4624", "4688", "4104")[index % 4]
    hostname = f"SYNTH-HOST-{index % 100:03d}"
    source_ip = f"192.0.2.{(index % 250) + 1}"
    severity = index % 17
    event_id = f"EVT-M25-{index:012d}"
    deduplication = hashlib.sha256(event_id.encode("ascii")).hexdigest()
    mitre = ["T1110"] if event_code == "4625" else (["T1059.001"] if event_code == "4104" else [])
    message = f"Synthetic M25 event {event_code} from {hostname} {source_ip}"
    search_text = f"{event_id} {event_code} {hostname} {source_ip} synthetic authentication event"
    return (
        event_id, deduplication, f"source-{index}", event_code,
        occurred.isoformat(), (occurred + timedelta(milliseconds=25)).isoformat(),
        "windows_event", hostname, f"{index % 32:03d}", hostname,
        source_ip, "198.51.100.20", 49_152 + index % 1_000, 443,
        f"user-{index % 200:03d}", "windows_security", "logon",
        "failure" if event_code == "4625" else "success", "60122", severity,
        message, "{}", "{}", "m25-disposable-benchmark", None, 128,
        search_text.casefold(), "synthetic-manager",
        "Microsoft-Windows-Security-Auditing", "Security", "logon.exe",
        str(index % 65_535), "services.exe", "512", "wazuh-event-v3",
        "windows", "C:\\Synthetic\\logon.exe", "logon.exe --synthetic",
        "C:\\Windows\\services.exe", json.dumps(mitre),
        json.dumps(["Credential Access"] if mitre else []),
        json.dumps(["Brute Force"] if mitre else []),
    )


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * fraction) - 1)]


def process_memory() -> dict[str, int | None]:
    """Return current/peak RSS on Windows without adding a benchmark dependency."""

    if os.name != "nt":
        return {"rss_bytes": None, "peak_rss_bytes": None}

    class MemoryCounters(ctypes.Structure):
        _fields_ = [
            ("cb", ctypes.c_ulong), ("PageFaultCount", ctypes.c_ulong),
            ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t),
        ]

    counters = MemoryCounters()
    counters.cb = ctypes.sizeof(counters)
    get_current_process = ctypes.windll.kernel32.GetCurrentProcess
    get_current_process.argtypes = []
    get_current_process.restype = ctypes.c_void_p
    get_process_memory_info = ctypes.windll.psapi.GetProcessMemoryInfo
    get_process_memory_info.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(MemoryCounters),
        ctypes.c_ulong,
    ]
    get_process_memory_info.restype = ctypes.c_int
    process = get_current_process()
    if not get_process_memory_info(process, ctypes.byref(counters), counters.cb):
        return {"rss_bytes": None, "peak_rss_bytes": None}
    return {
        "rss_bytes": int(counters.WorkingSetSize),
        "peak_rss_bytes": int(counters.PeakWorkingSetSize),
    }


def timed_search(
    repository: CQQLSearchRepository,
    query: str,
    start: datetime,
    end: datetime,
) -> float:
    compiled = compile_cqql(query)
    started = time.perf_counter()
    repository.search(
        compiled,
        start_time=start,
        end_time=end,
        sort="newest",
        limit=100,
        cursor=None,
    )
    return (time.perf_counter() - started) * 1_000


def query_plan(path: Path, query: str, start: datetime, end: datetime) -> list[str]:
    compiled = compile_cqql(query)
    source = "security_events e"
    if compiled.planner_strategy in {"TIME_ORDERED_OR", "TIME_ORDERED_BOOLEAN"}:
        source += " INDEXED BY idx_security_events_occurred_id"
    with closing(sqlite3.connect(path)) as connection:
        rows = connection.execute(
            f"EXPLAIN QUERY PLAN SELECT e.event_id FROM {source} "
            f"WHERE e.occurred_at BETWEEN ? AND ? AND {compiled.sql} "
            "ORDER BY e.occurred_at DESC, e.event_id DESC LIMIT 100",
            (start.isoformat(), end.isoformat(), *compiled.parameters),
        ).fetchall()
    return [str(row[3]) for row in rows]


def pagination_probe(
    repository: CQQLSearchRepository,
    start: datetime,
    end: datetime,
) -> dict[str, object]:
    compiled = compile_cqql("event.severity >= 0")
    cursor: str | None = None
    event_ids: list[str] = []
    started = time.perf_counter()
    pages = 0
    for _ in range(10):
        page = repository.search(
            compiled, start_time=start, end_time=end,
            sort="newest", limit=100, cursor=cursor,
        )
        pages += 1
        event_ids.extend(item.event_id for item in page.items)
        cursor = page.next_cursor
        if cursor is None:
            break
    return {
        "pages": pages,
        "rows": len(event_ids),
        "unique_rows": len(set(event_ids)),
        "duplicates": len(event_ids) - len(set(event_ids)),
        "wall_ms": round((time.perf_counter() - started) * 1_000, 3),
    }


def analytics_probe(
    repository: CQQLSearchRepository,
    start: datetime,
    end: datetime,
) -> dict[str, object]:
    started = time.perf_counter()
    try:
        result = repository.analytics(
            compile_cqql("event.severity >= 0"),
            start_time=start,
            end_time=end,
            group_by=["source.ip"],
            top_n=10,
            interval="day",
        )
    except CQQLQueryTimeoutError:
        return {
            "status": "TIMEOUT",
            "deadline_ms": 1_500,
            "wall_ms": round((time.perf_counter() - started) * 1_000, 3),
        }
    return {
        "status": "COMPLETE",
        "wall_ms": round((time.perf_counter() - started) * 1_000, 3),
        "repository_execution_ms": result.execution_ms,
        "matching_events": result.matching_events,
        "group_buckets": len(result.groups[0].buckets),
        "time_buckets": len(result.time_series),
        "truncated": result.groups[0].truncated,
    }


def cancellation_probe(path: Path) -> dict[str, object]:
    started = time.perf_counter()
    interrupted = False
    with closing(sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)) as connection:
        connection.execute("PRAGMA query_only=ON")
        deadline = started + 0.05
        connection.set_progress_handler(
            lambda: 1 if time.perf_counter() >= deadline else 0,
            1_000,
        )
        try:
            connection.execute(
                "WITH RECURSIVE cqql_cancel_probe(value) AS ("
                "VALUES(0) UNION ALL SELECT value + 1 FROM cqql_cancel_probe "
                "WHERE value < 100000000) SELECT SUM(value) FROM cqql_cancel_probe"
            ).fetchone()
        except sqlite3.OperationalError as exc:
            if "interrupted" not in str(exc).casefold():
                raise
            interrupted = True
        finally:
            connection.set_progress_handler(None, 0)
    if not interrupted:
        raise RuntimeError("SQLite progress-handler cancellation probe did not interrupt")
    return {
        "configured_deadline_ms": 50,
        "interrupted": interrupted,
        "observed_ms": round((time.perf_counter() - started) * 1_000, 3),
    }


def repository_cancellation_probe(
    repository: CQQLSearchRepository, start: datetime, end: datetime
) -> dict[str, object]:
    cancellation = threading.Event()
    compiled = compile_cqql('text CONTAINS "synthetic authentication"')

    def execute() -> str:
        try:
            repository.search(
                compiled, start_time=start, end_time=end,
                sort="newest", limit=100, cursor=None,
                cancel_event=cancellation,
            )
        except CQQLQueryCancelledError:
            return "CANCELLED"
        return "COMPLETED_BEFORE_CANCEL"

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(execute)
        time.sleep(0.025)
        cancel_started = time.perf_counter()
        cancellation.set()
        status = future.result(timeout=2)
    return {
        "status": status,
        "cancel_after_ms": 25,
        "cancellation_latency_ms": round((time.perf_counter() - cancel_started) * 1_000, 3),
    }


def export_probe(
    repository: CQQLSearchRepository, start: datetime, end: datetime
) -> dict[str, object]:
    started = time.perf_counter()
    try:
        result = repository.export(
            compile_cqql("event.severity >= 0"), start_time=start, end_time=end,
            sort="newest", limit=1_000,
        )
    except CQQLQueryTimeoutError:
        return {"status": "TIMEOUT", "wall_ms": round((time.perf_counter() - started) * 1_000, 3)}
    content, rows, byte_truncated = _render_csv(
        list(result.items),
        ["timestamp", "event_id", "event_code", "severity", "source_type", "hostname", "source_ip", "rule_id"],
    )
    return {
        "status": "COMPLETE",
        "wall_ms": round((time.perf_counter() - started) * 1_000, 3),
        "repository_execution_ms": result.execution_ms,
        "rows": rows,
        "bytes": len(content),
        "truncated": result.truncated or byte_truncated,
    }


def api_probe(path: Path, start: datetime, end: datetime, iterations: int) -> dict[str, object]:
    password = "M25-" + secrets.token_urlsafe(24)
    settings = Settings(
        database_url=f"sqlite:///{path.as_posix()}",
        wazuh_ingest_api_key="M25-" + secrets.token_urlsafe(32),
        allow_m14_schema_migration=False,
    )
    wall_samples: list[float] = []
    server_samples: list[float] = []
    with TestClient(create_app(settings)) as client:
        client.app.state.auth_repository.bootstrap_first_admin(
            AnalystCreate(
                username="m25-benchmark",
                display_name="M25 Disposable Benchmark",
                password=password,
                role=AnalystRole.ADMIN,
            )
        )
        login = client.post(
            "/api/v1/auth/login",
            headers={"Origin": "http://localhost:5173"},
            json={"username": "m25-benchmark", "password": password},
        )
        if login.status_code != 200:
            raise RuntimeError("Disposable API benchmark login failed")
        client.headers.update(
            {
                "Origin": "http://localhost:5173",
                "X-CSRF-Token": login.json()["csrf_token"],
            }
        )
        payload = {
            "query": 'source.ip = "192.0.2.10" AND event.severity >= 8',
            "start_time": start.isoformat(),
            "end_time": end.isoformat(),
            "sort": "newest",
            "limit": 100,
        }
        statuses: list[int] = []
        for _ in range(iterations):
            started = time.perf_counter()
            response = client.post("/api/v1/siem/search", json=payload)
            wall_samples.append((time.perf_counter() - started) * 1_000)
            statuses.append(response.status_code)
            if response.status_code != 200:
                raise RuntimeError("Disposable API benchmark CQQL request failed")
            server_samples.append(float(response.json()["metadata"]["execution_ms"]))
    return {
        "iterations": iterations,
        "statuses": statuses,
        "wall_p50_ms": round(statistics.median(wall_samples), 3),
        "wall_p95_ms": round(percentile(wall_samples, 0.95), 3),
        "server_execution_p50_ms": round(statistics.median(server_samples), 3),
        "server_execution_p95_ms": round(percentile(server_samples, 0.95), 3),
    }


def writer_probe(path: Path, base: datetime, first_index: int) -> dict[str, object]:
    barrier = threading.Barrier(5)

    def writer() -> list[float]:
        timings: list[float] = []
        barrier.wait()
        with closing(sqlite3.connect(path, timeout=5)) as connection:
            connection.execute("PRAGMA busy_timeout=5000")
            for offset in range(20):
                started = time.perf_counter()
                connection.execute(INSERT_SQL, synthetic_row(first_index + offset, base))
                connection.commit()
                timings.append((time.perf_counter() - started) * 1_000)
        return timings

    repository = CQQLSearchRepository(path)
    query = 'source.ip = "192.0.2.10" AND event.severity >= 8'
    start = base - timedelta(days=7)
    end = base + timedelta(minutes=1)

    def reader() -> int:
        barrier.wait()
        timeouts = 0
        for _ in range(20):
            try:
                timed_search(repository, query, start, end)
            except CQQLQueryTimeoutError:
                timeouts += 1
        return timeouts

    with ThreadPoolExecutor(max_workers=5) as executor:
        readers = [executor.submit(reader) for _ in range(4)]
        writer_future = executor.submit(writer)
        timings = writer_future.result()
        reader_timeouts = sum(future.result() for future in readers)
    return {"timings": timings, "reader_timeouts": reader_timeouts}


def run(sizes: list[int], iterations: int) -> dict[str, Any]:
    queries = {
        "indexed_source_ip": 'source.ip = "192.0.2.10"',
        "two_field_and": 'host.name = "SYNTH-HOST-010" AND event.severity >= 8',
        "bounded_or": 'event.code = "4625" OR event.code = "4688"',
        "nested_or_and": '(event.code = "4625" OR event.code = "4688") AND event.severity >= 8',
        "not_expression": 'NOT event.outcome = "success"',
        "numeric_comparison": "event.severity >= 10",
        "full_text": 'text CONTAINS "synthetic authentication"',
        "keyword_heavy_fts": 'text CONTAINS "synthetic authentication event windows security source host"',
        "mitre_membership": 'mitre.id = "T1110"',
        "maximum_boolean_clauses": " OR ".join(
            f'event.code = "{("4625", "4624", "4688", "4104")[index % 4]}"'
            for index in range(32)
        ),
    }
    report: dict[str, Any] = {
        "benchmark": "CyberQalqon M26 CQQL disposable benchmark",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "schema": 17,
        "synthetic_only": True,
        "iterations": iterations,
        "populations": [],
    }
    with tempfile.TemporaryDirectory(prefix="cyberqalqon-m25-cqql-") as temporary:
        path = Path(temporary) / "cqql-benchmark.db"
        AlertRepository(
            f"sqlite:///{path.as_posix()}", migration_target_version=17
        ).initialize()
        repository = CQQLSearchRepository(path)
        base = datetime(2026, 10, 21, 8, 0, tzinfo=timezone.utc)
        inserted = 0
        tracemalloc.start()
        cpu_started = time.process_time()
        for size in sizes:
            population_started = time.perf_counter()
            with closing(sqlite3.connect(path, timeout=30)) as connection:
                connection.execute("PRAGMA busy_timeout=30000")
                for batch_start in range(inserted, size, 1_000):
                    upper = min(size, batch_start + 1_000)
                    connection.executemany(
                        INSERT_SQL,
                        (synthetic_row(index, base) for index in range(batch_start, upper)),
                    )
                    connection.commit()
            population_ms = (time.perf_counter() - population_started) * 1_000
            inserted = size
            start = base - timedelta(days=7)
            end = base + timedelta(minutes=1)
            query_results: dict[str, Any] = {}
            for name, query in queries.items():
                compile_samples: list[float] = []
                for _ in range(50):
                    compile_started = time.perf_counter()
                    compile_cqql(query)
                    compile_samples.append((time.perf_counter() - compile_started) * 1_000)
                cold: float | None = None
                cold_status = "COMPLETE"
                try:
                    cold = timed_search(repository, query, start, end)
                except CQQLQueryTimeoutError:
                    cold_status = "TIMEOUT"
                warm: list[float] = []
                warm_timeouts = 0
                for _ in range(iterations):
                    try:
                        warm.append(timed_search(repository, query, start, end))
                    except CQQLQueryTimeoutError:
                        warm_timeouts += 1
                query_results[name] = {
                    "cold_status": cold_status,
                    "cold_ms": round(cold, 3) if cold is not None else None,
                    "warm_completed": len(warm),
                    "warm_timeouts": warm_timeouts,
                    "warm_p50_ms": round(statistics.median(warm), 3) if warm else None,
                    "warm_p95_ms": round(percentile(warm, 0.95), 3) if warm else None,
                    "warm_max_ms": round(max(warm), 3) if warm else None,
                    "compile_p50_ms": round(statistics.median(compile_samples), 4),
                    "plan": query_plan(path, query, start, end),
                    "cost_class": compile_cqql(query).cost_class,
                    "planner_strategy": compile_cqql(query).planner_strategy,
                }
            concurrent_started = time.perf_counter()
            concurrent: list[float] = []
            concurrent_timeouts = 0

            def concurrent_reader(_: int) -> float | None:
                try:
                    return timed_search(repository, queries["two_field_and"], start, end)
                except CQQLQueryTimeoutError:
                    return None

            with ThreadPoolExecutor(max_workers=4) as executor:
                outcomes = list(executor.map(concurrent_reader, range(4)))
                concurrent = [value for value in outcomes if value is not None]
                concurrent_timeouts = len(outcomes) - len(concurrent)
            concurrent_wall_ms = (time.perf_counter() - concurrent_started) * 1_000
            with closing(sqlite3.connect(path)) as connection:
                quick_check = str(connection.execute("PRAGMA quick_check").fetchone()[0])
                foreign_key_violations = len(connection.execute("PRAGMA foreign_key_check").fetchall())
            current_memory, peak_memory = tracemalloc.get_traced_memory()
            operating_memory = process_memory()
            report["populations"].append(
                {
                    "events": size,
                    "population_ms": round(population_ms, 3),
                    "database_bytes": path.stat().st_size,
                    "wal_bytes": path.with_name(path.name + "-wal").stat().st_size
                    if path.with_name(path.name + "-wal").exists()
                    else 0,
                    "python_tracemalloc_current_bytes": current_memory,
                    "python_tracemalloc_peak_bytes": peak_memory,
                    **operating_memory,
                    "process_cpu_seconds": round(time.process_time() - cpu_started, 3),
                    "quick_check": quick_check,
                    "foreign_key_violations": foreign_key_violations,
                    "queries": query_results,
                    "concurrent_four_searches": {
                        "wall_ms": round(concurrent_wall_ms, 3),
                        "completed": len(concurrent),
                        "timeouts": concurrent_timeouts,
                        "individual_p95_ms": round(percentile(concurrent, 0.95), 3) if concurrent else None,
                    },
                    "pagination_traversal": pagination_probe(repository, start, end),
                    "bounded_analytics": analytics_probe(repository, start, end),
                    "bounded_csv_export": export_probe(repository, start, end),
                }
            )
        report["api_latency_at_largest_population"] = api_probe(
            path, start, end, iterations
        )
        report["progress_handler_cancellation_at_largest_population"] = cancellation_probe(path)
        report["repository_fts_cancellation_at_largest_population"] = repository_cancellation_probe(
            repository, start, end
        )
        writer = writer_probe(path, base, inserted + 10_000)
        report["search_during_single_event_writes"] = {
            "writes": len(writer["timings"]),
            "writer_p50_ms": round(statistics.median(writer["timings"]), 3),
            "writer_p95_ms": round(percentile(writer["timings"], 0.95), 3),
            "reader_timeouts": writer["reader_timeouts"],
        }
        tracemalloc.stop()
        # TestClient/AnyIO keeps cyclic references briefly on Windows. Collect
        # them before TemporaryDirectory attempts to unlink the SQLite file.
        gc.collect()
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sizes", nargs="+", type=int, default=[10_000, 50_000, 100_000])
    parser.add_argument("--iterations", type=int, default=7)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    if any(size < 1 or size > 100_000 for size in arguments.sizes):
        parser.error("sizes must be between 1 and 100000")
    sizes = sorted(set(arguments.sizes))
    report = run(sizes, arguments.iterations)
    rendered = json.dumps(report, indent=2, sort_keys=True)
    if arguments.output:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
