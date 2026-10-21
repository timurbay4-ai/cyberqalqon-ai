"""Bounded M23 microbenchmarks on disposable schema-17 and archive fixtures.

This script never opens the live database, checkpoint, approval, or Wazuh archive.
It isolates the two source changes introduced by M23: bounded cached Operations
queries and coalesced checkpoint persistence for locally classified records.
"""

from __future__ import annotations

import argparse
import gc
import json
import os
import statistics
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "wazuh"))
sys.path.insert(0, str(ROOT / "scripts"))

from app.db.operations import OperationalRepository  # noqa: E402
from benchmark_m19 import _build_base  # noqa: E402
from cyberqalqon_sender.durable_state import durable_atomic_json  # noqa: E402
from cyberqalqon_sender.forward_ingestion import (  # noqa: E402
    ForwardIngestionWorker,
    initialize_forward_generation,
    load_forward_state,
    validate_forward_checkpoint,
)


def _percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    return round(ordered[max(0, int((len(ordered) - 1) * fraction))], 3)


def _timed(call: Callable[[], Any]) -> tuple[Any, float]:
    started = time.perf_counter()
    value = call()
    return value, (time.perf_counter() - started) * 1000


def _rss_bytes() -> int | None:
    try:
        import psutil

        return int(psutil.Process().memory_info().rss)
    except (ImportError, OSError):
        return None


def _operations_benchmark(database: Path, *, rounds: int) -> dict[str, Any]:
    repository = OperationalRepository(database, overview_cache_ttl_seconds=2.0)
    fresh: list[float] = []
    cached: list[float] = []
    for _ in range(rounds):
        repository._invalidate_overview_cache()
        overview, elapsed = _timed(lambda: repository.overview(limit=50))
        assert overview.measurement.state == "FRESH"
        fresh.append(elapsed)
        cached_overview, elapsed = _timed(lambda: repository.overview(limit=50))
        assert cached_overview.measurement.state == "CACHED"
        cached.append(elapsed)
    return {
        "rounds": rounds,
        "fresh_latency_p50_ms": round(statistics.median(fresh), 3),
        "fresh_latency_p95_ms": _percentile(fresh, 0.95),
        "cached_latency_p50_ms": round(statistics.median(cached), 3),
        "cached_latency_p95_ms": _percentile(cached, 0.95),
        "cache_speedup_p50": round(
            statistics.median(fresh) / max(statistics.median(cached), 0.000001), 3
        ),
        "execution_model": "BOUNDED_THREADPOOL_AT_API_BOUNDARY",
        "cache_ttl_seconds": 2.0,
    }


class _UnexpectedDelivery:
    def deliver(self, _payload: bytes) -> str:
        raise AssertionError("filtered fixtures must never reach delivery")


def _checkpoint_benchmark(directory: Path, *, records: int) -> dict[str, Any]:
    directory.mkdir(parents=True, exist_ok=True)
    source = (directory / "filtered-archive.json").resolve()
    rows = [
        json.dumps(
            {"id": f"filtered-{index}", "rule": {"id": "1", "level": 1}},
            separators=(",", ":"),
        ).encode()
        + b"\n"
        for index in range(records)
    ]
    source.write_bytes(b"".join(rows))
    legacy = (directory / "legacy.json").resolve()
    legacy.write_text(
        json.dumps({"version": 3, "device": 1, "inode": 2, "offset": 93438552}),
        encoding="utf-8",
    )
    state = initialize_forward_generation(
        source,
        (directory / "forward").resolve(),
        namespace="m23-benchmark",
        start_offset=0,
        legacy_state_path=legacy,
    )
    writes = 0

    def counted_writer(path: Path, value: dict[str, Any]) -> None:
        nonlocal writes
        writes += 1
        durable_atomic_json(path, value)

    worker = ForwardIngestionWorker(
        state,
        selector=lambda _event: False,
        delivery=_UnexpectedDelivery(),
        max_line_bytes=4096,
        state_writer=counted_writer,
    )
    final_state, coalesced_ms = _timed(lambda: worker.run_batch(limit=records))
    validation = validate_forward_checkpoint(state, deep=True, max_line_bytes=4096)

    baseline_state = load_forward_state(state)
    baseline_path = (directory / "legacy-per-record-state.json").resolve()
    baseline_value = baseline_state.as_dict()
    _value, per_record_ms = _timed(
        lambda: [durable_atomic_json(baseline_path, baseline_value) for _ in range(records)]
    )
    return {
        "records": records,
        "legacy_per_record_checkpoint_writes": records,
        "legacy_per_record_persistence_ms": round(per_record_ms, 3),
        "coalesced_checkpoint_writes": writes,
        "coalesced_filter_and_persistence_ms": round(coalesced_ms, 3),
        "checkpoint_write_reduction_percent": round((1 - writes / records) * 100, 3),
        "records_accounted": final_state.records,
        "filtered_accounted": final_state.filtered,
        "cursor_at_source_end": final_state.offset == source.stat().st_size,
        "deep_checkpoint_validation": validation["status"],
        "processed_chain_verified": validation["chain_verified"],
        "acknowledged_event_checkpoint_policy": "IMMEDIATE_UNCHANGED",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--population", type=int, default=100_000)
    parser.add_argument("--rounds", type=int, default=10)
    parser.add_argument("--filtered-records", type=int, default=500)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "artifacts" / "runtime" / "m23-performance.json",
    )
    args = parser.parse_args()
    if args.population not in {50_000, 90_000, 100_000}:
        parser.error("population must be 50000, 90000, or 100000")
    if not 3 <= args.rounds <= 30 or not 50 <= args.filtered_records <= 1000:
        parser.error("rounds or filtered-records is outside the bounded range")
    output = args.output.resolve()
    if ROOT not in output.parents:
        parser.error("output must remain below the repository root")

    cpu_before = time.process_time()
    rss_before = _rss_bytes()
    with tempfile.TemporaryDirectory(prefix="cyberqalqon-m23-") as temporary:
        root = Path(temporary)
        database = root / "operations.db"
        _build_base(database, args.population)
        operations = _operations_benchmark(database, rounds=args.rounds)
        checkpoint = _checkpoint_benchmark(
            root / "checkpoint", records=args.filtered_records
        )
        # sqlite3 connection context managers commit/rollback but do not close;
        # collect repository-local connections before Windows removes the fixture.
        gc.collect()
    gc.collect()
    rss_after = _rss_bytes()
    report = {
        "version": 1,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "environment": "DISPOSABLE_TEMPORARY_AUTO_REMOVED",
        "live_database_opened": False,
        "live_checkpoint_opened": False,
        "schema_version": 17,
        "population": args.population,
        "operations": operations,
        "checkpoint": checkpoint,
        "cpu_seconds": round(time.process_time() - cpu_before, 3),
        "rss_delta_bytes": (
            rss_after - rss_before
            if rss_before is not None and rss_after is not None
            else None
        ),
        "pass": (
            checkpoint["coalesced_checkpoint_writes"] == 1
            and checkpoint["records_accounted"] == args.filtered_records
            and checkpoint["filtered_accounted"] == args.filtered_records
            and checkpoint["cursor_at_source_end"]
            and checkpoint["deep_checkpoint_validation"] == "VALID"
            and operations["cache_speedup_p50"] > 1
        ),
        "limitations": [
            "Checkpoint baseline isolates durable atomic-write cost; it is not a production throughput claim.",
            "Operations measurements are in-process disposable SQLite timings.",
            "API threadpool isolation is regression-tested separately.",
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
