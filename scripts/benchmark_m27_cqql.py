#!/usr/bin/env python3
"""Reproducible M27 CQQL planner/FTS benchmark on disposable schema 17 only."""

from __future__ import annotations

import argparse
import gc
import hashlib
import json
import sqlite3
import statistics
import sys
import tempfile
import threading
import time
import tracemalloc
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "scripts"))

import benchmark_cqql as m26  # noqa: E402
from app.db.alerts import AlertRepository  # noqa: E402
from app.db.cqql import (  # noqa: E402
    CQQLQueryBusyError,
    CQQLQueryTimeoutError,
    CQQLSearchRepository,
)
from app.services.cqql import compile_cqql  # noqa: E402


QUERY_MATRIX = {
    "indexed_equality": 'source.ip = "192.0.2.10"',
    "indexed_conjunction": 'host.name = "SYNTH-HOST-010" AND event.severity >= 8',
    "simple_or": 'event.code = "4625" OR event.code = "4688"',
    "nested_or_and": '(event.code = "4625" OR event.code = "4688") AND event.severity >= 8',
    "nested_two_or_groups": (
        '(event.code = "4625" OR event.code = "4688") AND '
        '(event.outcome = "success" OR event.outcome = "failure")'
    ),
    "deep_legal_boolean": (
        '((event.code = "4625" AND event.severity >= 8) OR '
        '(event.code = "4688" AND event.severity >= 10)) AND '
        '(event.outcome = "success" OR event.outcome = "failure")'
    ),
    "not_expression": 'NOT (event.code = "4624" OR event.code = "4104")',
    "numeric_comparison": "event.severity >= 10",
    "sparse_fts": 'text CONTAINS "EVT-M25-000000000042"',
    "dense_fts": 'text CONTAINS "synthetic"',
    "no_match_fts": 'text CONTAINS "m27nomatchsentinel"',
    "mixed_boolean_fts": 'text CONTAINS "synthetic" AND event.severity >= 16',
}


def percentile(values: list[float], fraction: float) -> float | None:
    return m26.percentile(values, fraction) if values else None


def execute(
    repository: CQQLSearchRepository,
    query: str,
    start: datetime,
    end: datetime,
) -> tuple[str, float, list[str]]:
    started = time.perf_counter()
    try:
        result = repository.search(
            compile_cqql(query),
            start_time=start,
            end_time=end,
            sort="newest",
            limit=100,
            cursor=None,
        )
    except CQQLQueryTimeoutError:
        return "TIMEOUT", (time.perf_counter() - started) * 1_000, []
    return (
        "COMPLETE",
        (time.perf_counter() - started) * 1_000,
        [item.event_id for item in result.items],
    )


def reference_ids(path: Path, query: str, start: datetime, end: datetime) -> list[str]:
    compiled = replace(compile_cqql(query), planner_strategy="DEFAULT")
    with closing(sqlite3.connect(path)) as connection:
        rows = connection.execute(
            "SELECT e.event_id FROM security_events e "
            f"WHERE e.occurred_at BETWEEN ? AND ? AND {compiled.sql} "
            "ORDER BY e.occurred_at DESC, e.event_id DESC LIMIT 100",
            (start.isoformat(), end.isoformat(), *compiled.parameters),
        ).fetchall()
    return [str(row[0]) for row in rows]


def fts_candidate_count(path: Path, query: str) -> int | None:
    compiled = compile_cqql(query)
    if not compiled.uses_fts:
        return None
    fts_parameter = next(
        (parameter for parameter in compiled.parameters if isinstance(parameter, str) and '"' in parameter),
        None,
    )
    if fts_parameter is None:
        return None
    with closing(sqlite3.connect(path)) as connection:
        return int(
            connection.execute(
                "SELECT COUNT(*) FROM security_events_fts WHERE security_events_fts MATCH ?",
                (fts_parameter,),
            ).fetchone()[0]
        )


def concurrency_probe(
    repository: CQQLSearchRepository,
    start: datetime,
    end: datetime,
) -> dict[str, object]:
    barrier = threading.Barrier(8)

    def competing_request(index: int) -> dict[str, object]:
        barrier.wait()
        query = QUERY_MATRIX["dense_fts"] if index < 6 else QUERY_MATRIX["indexed_equality"]
        started = time.perf_counter()
        try:
            status, _, _ = execute(repository, query, start, end)
        except CQQLQueryBusyError:
            status = "BUSY"
        return {"status": status, "wall_ms": round((time.perf_counter() - started) * 1_000, 3)}

    with ThreadPoolExecutor(max_workers=8) as executor:
        outcomes = list(executor.map(competing_request, range(8)))
    recovery_status, recovery_ms, _ = execute(
        repository, QUERY_MATRIX["indexed_equality"], start, end
    )
    return {
        "requests": outcomes,
        "complete": sum(item["status"] == "COMPLETE" for item in outcomes),
        "busy": sum(item["status"] == "BUSY" for item in outcomes),
        "timeouts": sum(item["status"] == "TIMEOUT" for item in outcomes),
        "post_pressure_recovery": recovery_status,
        "post_pressure_recovery_ms": round(recovery_ms, 3),
    }


def run(sizes: list[int], iterations: int) -> dict[str, Any]:
    report: dict[str, Any] = {
        "benchmark": "CyberQalqon M27 disposable CQQL planner and selectivity benchmark",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "schema": 17,
        "synthetic_only": True,
        "query_deadline_ms": 1_500,
        "max_concurrent_queries": 4,
        "cold_definition": "new repository/connection without query warm-up; OS cache is not flushed",
        "iterations": iterations,
        "populations": [],
    }
    with tempfile.TemporaryDirectory(prefix="cyberqalqon-m27-cqql-") as temporary:
        path = Path(temporary) / "m27-benchmark.db"
        AlertRepository(
            f"sqlite:///{path.as_posix()}", migration_target_version=17
        ).initialize()
        base = datetime(2026, 10, 22, 8, 0, tzinfo=timezone.utc)
        start = base - timedelta(days=7)
        end = base + timedelta(minutes=1)
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
                        m26.INSERT_SQL,
                        (m26.synthetic_row(index, base) for index in range(batch_start, upper)),
                    )
                    connection.commit()
            inserted = size
            repository = CQQLSearchRepository(path)
            queries: dict[str, Any] = {}
            for name, query in QUERY_MATRIX.items():
                compiled = compile_cqql(query)
                cold_samples: list[float] = []
                cold_statuses: list[str] = []
                for _ in range(3):
                    status, elapsed, _ = execute(CQQLSearchRepository(path), query, start, end)
                    cold_statuses.append(status)
                    cold_samples.append(elapsed)
                warm_samples: list[float] = []
                timeouts = 0
                errors = 0
                last_ids: list[str] = []
                for _ in range(iterations):
                    try:
                        status, elapsed, last_ids = execute(repository, query, start, end)
                    except Exception:
                        errors += 1
                        continue
                    if status == "TIMEOUT":
                        timeouts += 1
                    else:
                        warm_samples.append(elapsed)
                reference = reference_ids(path, query, start, end)
                queries[name] = {
                    "cold_complete": cold_statuses.count("COMPLETE"),
                    "cold_timeouts": cold_statuses.count("TIMEOUT"),
                    "cold_p50_ms": round(statistics.median(cold_samples), 3),
                    "cold_p95_ms": round(percentile(cold_samples, 0.95), 3),
                    "warm_complete": len(warm_samples),
                    "warm_timeouts": timeouts,
                    "errors": errors,
                    "warm_p50_ms": round(statistics.median(warm_samples), 3) if warm_samples else None,
                    "warm_p95_ms": round(percentile(warm_samples, 0.95), 3) if warm_samples else None,
                    "warm_max_ms": round(max(warm_samples), 3) if warm_samples else None,
                    "result_equivalent": bool(warm_samples) and last_ids == reference,
                    "reference_result_count": len(reference),
                    "result_fingerprint": hashlib.sha256("\n".join(reference).encode()).hexdigest(),
                    "fts_candidate_count": fts_candidate_count(path, query),
                    "cost_class": compiled.cost_class,
                    "plan_class": compiled.plan_class,
                    "planner_strategy": compiled.planner_strategy,
                    "diagnostic_reasons": list(compiled.diagnostic_reasons),
                    "plan": m26.query_plan(path, query, start, end),
                }
            with closing(sqlite3.connect(path)) as connection:
                quick_check = str(connection.execute("PRAGMA quick_check").fetchone()[0])
                foreign_keys = len(connection.execute("PRAGMA foreign_key_check").fetchall())
                page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
                page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
            current_memory, peak_memory = tracemalloc.get_traced_memory()
            report["populations"].append(
                {
                    "events": size,
                    "population_ms": round((time.perf_counter() - population_started) * 1_000, 3),
                    "database_bytes": path.stat().st_size,
                    "logical_page_bytes": page_count * page_size,
                    "wal_bytes": path.with_name(path.name + "-wal").stat().st_size
                    if path.with_name(path.name + "-wal").exists() else 0,
                    "python_tracemalloc_current_bytes": current_memory,
                    "python_tracemalloc_peak_bytes": peak_memory,
                    **m26.process_memory(),
                    "process_cpu_seconds": round(time.process_time() - cpu_started, 3),
                    "quick_check": quick_check,
                    "foreign_key_violations": foreign_keys,
                    "queries": queries,
                    "pagination": m26.pagination_probe(repository, start, end),
                    "analytics": m26.analytics_probe(repository, start, end),
                    "csv_export": m26.export_probe(repository, start, end),
                    "concurrency": concurrency_probe(repository, start, end),
                }
            )
        writer = m26.writer_probe(path, base, inserted + 10_000)
        report["single_event_writer_at_largest_population"] = {
            "writes": len(writer["timings"]),
            "writer_p50_ms": round(statistics.median(writer["timings"]), 3),
            "writer_p95_ms": round(percentile(writer["timings"], 0.95), 3),
            "reader_timeouts": writer["reader_timeouts"],
        }
        tracemalloc.stop()
        gc.collect()
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sizes", nargs="+", type=int, default=[10_000, 50_000, 100_000])
    parser.add_argument("--iterations", type=int, default=5)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    if arguments.iterations < 1 or arguments.iterations > 20:
        parser.error("iterations must be between 1 and 20")
    if any(size < 1 or size > 100_000 for size in arguments.sizes):
        parser.error("sizes must be between 1 and 100000")
    report = run(sorted(set(arguments.sizes)), arguments.iterations)
    rendered = json.dumps(report, indent=2, sort_keys=True)
    if arguments.output:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
