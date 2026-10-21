"""Bounded disposable SQLite near-capacity benchmark for M13.

The live database is never opened. One temporary schema-17 database grows through
the requested checkpoints and is removed automatically when the process exits.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import statistics
import sys
import tempfile
import time
import tracemalloc
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.db.detection_engineering import DetectionEngineeringRepository  # noqa: E402
from app.db.investigation_workbench import InvestigationWorkbenchRepository  # noqa: E402
from app.db.migrations import apply_migrations  # noqa: E402
from app.schemas.investigation_workbench import WorkbenchRequest  # noqa: E402


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int((len(ordered) - 1) * percentile + 0.5)))
    return ordered[index]


def _measure(operation: Callable[[], object], runs: int) -> dict[str, object]:
    operation()
    latencies: list[float] = []
    cpu_times: list[float] = []
    for _ in range(runs):
        wall_started = time.perf_counter()
        cpu_started = time.process_time()
        operation()
        cpu_times.append((time.process_time() - cpu_started) * 1000)
        latencies.append((time.perf_counter() - wall_started) * 1000)
    return {
        "runs": runs,
        "wall_ms": {
            "median": round(statistics.median(latencies), 3),
            "p95": round(_percentile(latencies, 0.95), 3),
            "max": round(max(latencies), 3),
        },
        "cpu_ms": {
            "median": round(statistics.median(cpu_times), 3),
            "p95": round(_percentile(cpu_times, 0.95), 3),
            "max": round(max(cpu_times), 3),
        },
    }


def _row(index: int, anchor: datetime) -> tuple[object, ...]:
    event_id = f"EVT-M13-BENCH-{index:08d}"
    occurred_at = anchor + timedelta(milliseconds=index * 2)
    source_ip = f"192.0.2.{index % 250 + 1}"
    username = f"user-{index % 1000:04d}"
    process = ("powershell.exe", "cmd.exe", "rundll32.exe", "python.exe", "nginx")[index % 5]
    action = ("logon-failed", "process-start", "file-created", "network-connect")[index % 4]
    outcome = "failure" if index % 4 == 0 else "success"
    source_type = "windows_event" if index % 5 else "web"
    structured = json.dumps(
        {
            "event": {"action": action, "outcome": outcome},
            "process": {"name": process, "pid": str(index % 4000)},
            "dns": {"query_name": f"host-{index % 100}.example.test"},
        },
        separators=(",", ":"),
    )
    return (
        event_id,
        hashlib.sha256(event_id.encode("ascii")).hexdigest(),
        occurred_at.isoformat(),
        occurred_at.isoformat(),
        source_type,
        f"HOST-{index % 200:03d}",
        f"{index % 20 + 1:03d}",
        f"HOST-{index % 200:03d}",
        source_ip,
        f"198.51.100.{index % 100 + 1}",
        username,
        "authentication" if index % 2 == 0 else "process",
        action,
        outcome,
        str(60122 + index % 9),
        5 + index % 8,
        f"Synthetic {action} benchmark event for {username}",
        structured,
        "{}",
        "m13_benchmark",
        len(structured),
        f"synthetic {action} {source_ip} {username} {process}",
        "benchmark-manager",
        "Microsoft-Windows-Security-Auditing",
        "Security",
        process,
        str(index % 4000),
        "services.exe",
        str(index % 500),
        "wazuh-event-v2",
        "[]",
        "[]",
        "[]",
    )


INSERT_EVENT = """
INSERT INTO security_events (
    event_id, deduplication_id, occurred_at, ingested_at, source_type,
    hostname, agent_id, agent_name, source_ip, destination_ip, username,
    event_category, event_action, outcome, rule_id, severity, message,
    structured_json, raw_event_json, ingestion_source, raw_size_bytes,
    search_text, manager_identity, event_provider, event_channel,
    process_name, process_id, parent_process_name, parent_process_id,
    normalization_schema, mitre_ids_json, mitre_tactics_json,
    mitre_techniques_json
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
          ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


def _seed_supporting_records(connection: sqlite3.Connection, now: datetime) -> None:
    timestamp = now.isoformat()
    connection.execute(
        "INSERT INTO alerts (alert_id,fingerprint,occurred_at,agent_id,rule_id,rule_level,"
        "normalized_json,raw_event_json,ingested_at,agent_name,has_mitre,mitre_ids_text,search_text) "
        "VALUES ('ALERT-M13-BENCH',?,?,'001','60122',10,'{}','{}',?,'HOST-001',0,'|','benchmark')",
        ("a" * 64, timestamp, timestamp),
    )
    connection.execute(
        "INSERT INTO incidents (incident_id,title,description,severity,status,assigned_to,created_at,updated_at) "
        "VALUES ('INC-M13-BENCH','Benchmark incident','Disposable only','HIGH','INVESTIGATING',NULL,?,?)",
        (timestamp, timestamp),
    )
    connection.execute(
        "INSERT INTO incident_history (event_id,incident_id,event_type,actor,occurred_at,details_json) "
        "VALUES ('HIST-M13-BENCH','INC-M13-BENCH','CREATED','benchmark',?,'{}')",
        (timestamp,),
    )
    connection.execute(
        "INSERT INTO ioc_indicators (indicator_id,indicator_type,normalized_value,source,confidence,"
        "description,is_active,version,created_at,updated_at) "
        "VALUES ('IOC-M13-BENCH','IPV4','192.0.2.1','M13 benchmark',80,'Disposable only',1,1,?,?)",
        (timestamp, timestamp),
    )
    connection.commit()


def _insert_until(
    connection: sqlite3.Connection, anchor: datetime, start: int, stop: int, batch_size: int
) -> dict[str, object]:
    wall_started = time.perf_counter()
    cpu_started = time.process_time()
    batch_latencies: list[float] = []
    for batch_start in range(start, stop, batch_size):
        batch_end = min(stop, batch_start + batch_size)
        batch = [_row(index, anchor) for index in range(batch_start, batch_end)]
        started = time.perf_counter()
        connection.executemany(INSERT_EVENT, batch)
        connection.commit()
        batch_latencies.append((time.perf_counter() - started) * 1000)
    elapsed = time.perf_counter() - wall_started
    return {
        "inserted": stop - start,
        "wall_seconds": round(elapsed, 3),
        "cpu_seconds": round(time.process_time() - cpu_started, 3),
        "rows_per_second": round((stop - start) / elapsed, 1),
        "batch_wall_ms": {
            "median": round(statistics.median(batch_latencies), 3),
            "p95": round(_percentile(batch_latencies, 0.95), 3),
            "max": round(max(batch_latencies), 3),
        },
    }


def _checkpoint(database: Path, count: int, anchor: datetime, runs: int) -> dict[str, object]:
    primary_id = f"EVT-M13-BENCH-{count // 2:08d}"
    repository = InvestigationWorkbenchRepository(database)
    workbench_request = WorkbenchRequest(
        target_type="EVENT",
        target_id=primary_id,
        relative_minutes=1440,
        related_limit=50,
        timeline_limit=150,
        max_execution_ms=5000,
    )

    def sql(query: str, parameters: tuple[object, ...] = ()) -> list[sqlite3.Row]:
        with closing(sqlite3.connect(database)) as connection:
            connection.row_factory = sqlite3.Row
            return connection.execute(query, parameters).fetchall()

    operations: dict[str, Callable[[], object]] = {
        "event_query": lambda: sql(
            "SELECT event_id FROM security_events WHERE source_type=? "
            "ORDER BY occurred_at DESC,event_id DESC LIMIT 100",
            ("windows_event",),
        ),
        "full_text_search": lambda: sql(
            "SELECT event_id FROM security_events_fts WHERE security_events_fts MATCH ? LIMIT 100",
            ('"logon-failed"',),
        ),
        "related_event_lookup": lambda: sql(
            "SELECT event_id FROM security_events WHERE source_ip=? "
            "ORDER BY occurred_at DESC,event_id DESC LIMIT 100",
            ("192.0.2.1",),
        ),
        "ip_pivot": lambda: sql(
            "SELECT event_id FROM security_events WHERE source_ip=? "
            "ORDER BY occurred_at DESC,event_id DESC LIMIT 100",
            ("192.0.2.25",),
        ),
        "account_pivot": lambda: sql(
            "SELECT event_id FROM security_events WHERE username=? COLLATE NOCASE "
            "ORDER BY occurred_at DESC,event_id DESC LIMIT 100",
            ("user-0025",),
        ),
        "process_pivot": lambda: sql(
            "SELECT event_id FROM security_events WHERE process_name=? COLLATE NOCASE "
            "ORDER BY occurred_at DESC,event_id DESC LIMIT 100",
            ("powershell.exe",),
        ),
        "alert_detail": lambda: sql(
            "SELECT normalized_json,raw_event_json FROM alerts WHERE alert_id=?",
            ("ALERT-M13-BENCH",),
        ),
        "timeline_aggregation": lambda: sql(
            "SELECT event_id,event_type,occurred_at FROM incident_history WHERE incident_id=? "
            "ORDER BY occurred_at DESC,event_id DESC LIMIT 100",
            ("INC-M13-BENCH",),
        ),
        "workbench_query": lambda: repository.build(
            workbench_request,
            start=anchor - timedelta(hours=1),
            end=anchor + timedelta(hours=2),
        ),
        "ioc_matching": lambda: DetectionEngineeringRepository(database).ioc_matches(
            days=7, limit=500
        ),
    }
    measurements = {name: _measure(operation, runs) for name, operation in operations.items()}

    def concurrent_workbench_read(_: int) -> float:
        started = time.perf_counter()
        operations["workbench_query"]()
        return (time.perf_counter() - started) * 1000

    concurrent_started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=4) as executor:
        concurrent = list(executor.map(concurrent_workbench_read, range(8)))
    concurrent_wall_ms = (time.perf_counter() - concurrent_started) * 1000
    with closing(sqlite3.connect(database)) as connection:
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        integrity = connection.execute("PRAGMA quick_check").fetchone()[0]
        foreign_keys = len(connection.execute("PRAGMA foreign_key_check").fetchall())
    return {
        "events": count,
        "database_bytes": database.stat().st_size,
        "quick_check": integrity,
        "foreign_key_errors": foreign_keys,
        "measurements": measurements,
        "concurrency": {
            "workers": 4,
            "reads": 8,
            "wall_ms": round(concurrent_wall_ms, 3),
            "slowest_read_ms": round(max(float(value) for value in concurrent), 3),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkpoints", type=int, nargs="+", default=[50_000, 100_000, 250_000])
    parser.add_argument("--runs", type=int, default=7)
    parser.add_argument("--batch-size", type=int, default=5_000)
    args = parser.parse_args()
    checkpoints = sorted(set(args.checkpoints))
    if not checkpoints or checkpoints[0] < 10_000 or checkpoints[-1] > 1_000_000:
        parser.error("checkpoints must be between 10000 and 1000000")
    if not 3 <= args.runs <= 50 or not 500 <= args.batch_size <= 10_000:
        parser.error("runs must be 3..50 and batch-size must be 500..10000")

    with tempfile.TemporaryDirectory(prefix="cyberqalqon-m13-benchmark-") as directory:
        database = Path(directory) / "m13.db"
        anchor = datetime.now(timezone.utc) - timedelta(hours=1)
        with closing(sqlite3.connect(database)) as connection:
            apply_migrations(connection)
            _seed_supporting_records(connection, anchor)
            current = 0
            results: list[dict[str, object]] = []
            tracemalloc.start()
            for checkpoint in checkpoints:
                ingestion = _insert_until(
                    connection, anchor, current, checkpoint, args.batch_size
                )
                current = checkpoint
                result = _checkpoint(database, checkpoint, anchor, args.runs)
                result["ingestion"] = ingestion
                results.append(result)
                print(json.dumps({"checkpoint": result}, sort_keys=True), flush=True)
            _, peak_bytes = tracemalloc.get_traced_memory()
            tracemalloc.stop()
        print(
            json.dumps(
                {
                    "database": "temporary-isolated",
                    "schema_version": 17,
                    "checkpoints": results,
                    "python_tracemalloc_peak_bytes": peak_bytes,
                    "process_id": os.getpid(),
                    "synthetic_measurement": True,
                },
                sort_keys=True,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
