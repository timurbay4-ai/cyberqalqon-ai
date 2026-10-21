"""Repeatable isolated M12 read-path latency and memory benchmark.

The script never opens the configured/live database. It creates a temporary schema,
loads synthetic normalized rows, and removes the database when the process exits.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import statistics
import sys
import tempfile
import time
import tracemalloc
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.db.investigation_workbench import InvestigationWorkbenchRepository  # noqa: E402
from app.db.migrations import apply_migrations  # noqa: E402
from app.schemas.investigation_workbench import WorkbenchRequest  # noqa: E402


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * percentile))))
    return ordered[index]


def _load(database_path: Path, count: int) -> tuple[str, datetime]:
    anchor = datetime.now(timezone.utc) - timedelta(hours=1)
    rows = []
    for index in range(count):
        event_id = f"EVT-M12-BENCH-{index:08d}"
        deduplication_id = hashlib.sha256(event_id.encode("ascii")).hexdigest()
        occurred_at = anchor + timedelta(milliseconds=index * 10)
        source_ip = f"192.0.2.{index % 50 + 1}"
        rows.append((
            event_id, deduplication_id, occurred_at.isoformat(), occurred_at.isoformat(),
            "windows_event", f"WIN-{index % 20:02d}", "002", f"WIN-{index % 20:02d}",
            source_ip, "198.51.100.10", f"user-{index % 100:03d}", "authentication",
            "logon-failed", "failure", "60122", 5, "Synthetic failed logon benchmark event",
            "{}", "{}", "benchmark", 2, f"failed logon {source_ip}",
            "lab-manager", "Microsoft-Windows-Security-Auditing", "Security",
            "powershell.exe", str(index % 500), "explorer.exe", "1", "wazuh-event-v2",
            "[]", "[]", "[]",
        ))
    with sqlite3.connect(database_path) as connection:
        connection.row_factory = sqlite3.Row
        apply_migrations(connection)
        connection.executemany(
            """
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
            """,
            rows,
        )
        connection.commit()
    return rows[count // 2][0], anchor


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", type=int, default=10_000)
    parser.add_argument("--runs", type=int, default=30)
    args = parser.parse_args()
    if not 100 <= args.events <= 100_000 or not 5 <= args.runs <= 200:
        parser.error("events must be 100..100000 and runs must be 5..200")

    with tempfile.TemporaryDirectory(prefix="cyberqalqon-m12-benchmark-") as directory:
        database_path = Path(directory) / "m12.db"
        event_id, anchor = _load(database_path, args.events)
        repository = InvestigationWorkbenchRepository(database_path)
        request = WorkbenchRequest(
            target_type="EVENT", target_id=event_id, relative_minutes=1440,
            related_limit=50, timeline_limit=150, max_execution_ms=5000,
        )

        def run_once() -> float:
            started = time.perf_counter()
            result = repository.build(
                request, start=anchor - timedelta(hours=1), end=anchor + timedelta(hours=4)
            )
            if result.primary_event.event_id != event_id or len(result.related_events) > 50:
                raise RuntimeError("bounded benchmark result was invalid")
            return (time.perf_counter() - started) * 1000

        run_once()
        tracemalloc.start()
        latencies = [run_once() for _ in range(args.runs)]
        _, peak_bytes = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        concurrent_started = time.perf_counter()
        with ThreadPoolExecutor(max_workers=4) as executor:
            concurrent = list(executor.map(lambda _: run_once(), range(8)))
        concurrent_wall_ms = (time.perf_counter() - concurrent_started) * 1000
        print(json.dumps({
            "database": "temporary-isolated",
            "schema_version": 17,
            "events": args.events,
            "sequential_runs": args.runs,
            "latency_ms": {
                "min": round(min(latencies), 3),
                "median": round(statistics.median(latencies), 3),
                "p95": round(_percentile(latencies, 0.95), 3),
                "max": round(max(latencies), 3),
            },
            "tracemalloc_peak_bytes": peak_bytes,
            "concurrency": {
                "workers": 4,
                "reads": len(concurrent),
                "wall_ms": round(concurrent_wall_ms, 3),
                "slowest_read_ms": round(max(concurrent), 3),
            },
            "limits": {"related_events": 50, "timeline_items": 150, "budget_ms": 5000},
        }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
