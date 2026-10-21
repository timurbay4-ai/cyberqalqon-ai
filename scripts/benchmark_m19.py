"""Run sequential M19 near-capacity benchmarks on auto-removed schema-17 DBs.

No live database, shipper state, network rule, or service is opened or changed.
Each variant receives its own copy so retention results cannot contaminate the
next measurement.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import tempfile
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "scripts"))

from app.db.events import _utc_iso  # noqa: E402
from app.db.migrations import apply_migrations  # noqa: E402
from benchmark_m13 import _insert_until, _seed_supporting_records  # noqa: E402
from benchmark_m18 import _run_variant  # noqa: E402


PROBES = {1: 100, 10: 200, 25: 500}


def _seed_protected_rows(connection: sqlite3.Connection, count: int, now: datetime) -> None:
    timestamp = now.isoformat()
    rows = [
        (
            f"PIN-M19-{index:08d}",
            "INC-M13-BENCH",
            "EVENT",
            f"EVT-M13-BENCH-{index:08d}",
            "M19 disposable protected evidence",
            timestamp,
            "M19 benchmark",
            timestamp,
            timestamp,
        )
        for index in range(count)
    ]
    connection.executemany(
        "INSERT INTO incident_evidence_pins ("
        "evidence_pin_id,incident_id,evidence_type,evidence_id,annotation,"
        "source_timestamp,pinned_by_display,pinned_at,updated_at"
        ") VALUES (?,?,?,?,?,?,?,?,?)",
        rows,
    )
    connection.commit()


def _build_base(path: Path, population: int) -> None:
    anchor = datetime.now(timezone.utc) - timedelta(hours=1)
    with closing(sqlite3.connect(path, timeout=30)) as connection:
        apply_migrations(connection, target_version=17)
        _seed_supporting_records(connection, anchor)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        _insert_until(connection, anchor, 0, population, min(5_000, population))
        connection.execute(
            "UPDATE security_event_store_state SET retained_records=?, "
            "last_retention_at=? WHERE singleton=1",
            (population, _utc_iso(datetime.now(timezone.utc))),
        )
        connection.commit()
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "artifacts" / "runtime" / "m19-benchmark.json",
    )
    args = parser.parse_args()
    output = args.output.resolve()
    if ROOT not in output.parents:
        parser.error("output must remain below the repository root")

    report: dict[str, Any] = {
        "version": 1,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "environment": "temporary-isolated-auto-removed",
        "live_database_opened": False,
        "schema_version": 17,
        "synchronous": "FULL",
        "feature_gate_default": False,
        "results": [],
        "limitations": [
            "Synthetic TestClient measurements are not live production acceptance.",
            "Python traced memory excludes SQLite native allocations and OS cache.",
            "Protected scenario uses 1,000 oldest incident evidence pins.",
            "HTTP acknowledgement is TestClient-local and excludes the Windows/WSL relay.",
        ],
    }
    with tempfile.TemporaryDirectory(prefix="cyberqalqon-m19-benchmark-") as directory:
        temporary = Path(directory)
        for population in (50_000, 90_000, 99_000, 100_000):
            base = temporary / f"base-{population}.db"
            _build_base(base, population)
            sizes = (1, 10, 25) if population in {50_000, 90_000, 100_000} else (10,)
            for batch_size in sizes:
                result = _run_variant(
                    base,
                    temporary / f"run-{population}-{batch_size}.db",
                    population=population,
                    probe_events=PROBES[batch_size],
                    batch_size=batch_size,
                )
                result["scenario"] = "normal_at_capacity"
                report["results"].append(result)
                print(json.dumps(result, sort_keys=True), flush=True)

            if population == 100_000:
                with closing(sqlite3.connect(base, timeout=30)) as connection:
                    _seed_protected_rows(connection, 1_000, datetime.now(timezone.utc))
                    connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                for batch_size in (10, 25):
                    result = _run_variant(
                        base,
                        temporary / f"run-protected-{batch_size}.db",
                        population=population,
                        probe_events=PROBES[batch_size],
                        batch_size=batch_size,
                    )
                    result["scenario"] = "oldest_1000_protected"
                    report["results"].append(result)
                    print(json.dumps(result, sort_keys=True), flush=True)
            base.unlink(missing_ok=True)

    normal_singles = {
        item["population_at_cap"]: item
        for item in report["results"]
        if item["scenario"] == "normal_at_capacity" and item["batch_size"] == 1
    }
    for item in report["results"]:
        baseline = normal_singles.get(item["population_at_cap"])
        item["speedup_vs_normal_single"] = (
            round(
                item["insert_events_per_second"] / baseline["insert_events_per_second"],
                3,
            )
            if baseline
            else None
        )
    report["integrity_pass"] = all(
        item["quick_check"] == "ok"
        and item["foreign_key_errors"] == 0
        and item["retained_records"] == item["population_at_cap"]
        and item["state_retained_records"] == item["population_at_cap"]
        for item in report["results"]
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    pending = output.with_suffix(output.suffix + ".tmp")
    pending.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    pending.replace(output)
    print(json.dumps({"output": str(output), "integrity_pass": report["integrity_pass"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
