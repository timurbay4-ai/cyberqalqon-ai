"""Disposable schema-17 capacity and retention-pressure benchmark for M16."""

from __future__ import annotations

import argparse
import gc
import json
import os
import shutil
import sqlite3
import tempfile
import time
import tracemalloc
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

from benchmark_m13 import _checkpoint, _insert_until, _seed_supporting_records


ROOT = Path(__file__).resolve().parents[1]

import sys

sys.path.insert(0, str(ROOT / "backend"))

from app.db.migrations import apply_migrations  # noqa: E402
from app.db.events import EventRepository  # noqa: E402
from app.services.event_normalizer import normalize_wazuh_event  # noqa: E402


def _file_size(path: Path) -> int:
    return path.stat().st_size if path.exists() else 0


def _retention_probe(database: Path, maximum: int) -> dict[str, object]:
    wal = Path(f"{database}-wal")
    before_wal = _file_size(wal)
    now = datetime.now(timezone.utc)
    payload = {
        "id": f"m16-retention-{maximum}",
        "timestamp": now.isoformat(),
        "agent": {"id": "001", "name": "M16-BENCH"},
        "rule": {"id": "100111", "level": 10, "description": "M16 retention probe"},
        "location": "/var/log/m16-benchmark.log",
        "full_log": "Synthetic M16 retention pressure probe",
    }
    started = time.perf_counter()
    cpu_started = time.process_time()
    # The capacity fixture uses direct bulk SQL for measurement speed. Synchronize
    # the repository-owned counter before exercising the real ingest path; live
    # ingestion updates this counter transactionally for every inserted event.
    with closing(sqlite3.connect(database, timeout=30)) as connection:
        actual_before = int(
            connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
        )
        connection.execute(
            "UPDATE security_event_store_state SET retained_records = ? WHERE singleton = 1",
            (actual_before,),
        )
        connection.commit()
    repository = EventRepository(database, retention_days=30, max_records=maximum)
    stored = repository.ingest(normalize_wazuh_event(payload), now=now)
    with closing(sqlite3.connect(database, timeout=30)) as connection:
        retained = int(
            connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
        )
        state = connection.execute(
            "SELECT last_deleted_count, retained_records FROM security_event_store_state "
            "WHERE singleton = 1"
        ).fetchone()
        audit = connection.execute(
            "SELECT details_json FROM security_audit_events "
            "WHERE action = 'SECURITY_EVENT_RETENTION' "
            "ORDER BY occurred_at DESC, audit_id DESC LIMIT 1"
        ).fetchone()
        checkpoint = connection.execute("PRAGMA wal_checkpoint(PASSIVE)").fetchone()
    audit_details = json.loads(audit[0]) if audit else {}
    return {
        "inserted": 1,
        "inserted_event_id": stored.event.event_id,
        "deleted": max(0, int(state[0] if state else 0)),
        "retained": retained,
        "state_retained": int(state[1] if state else 0),
        "maximum": maximum,
        "wall_ms": round((time.perf_counter() - started) * 1000, 3),
        "cpu_ms": round((time.process_time() - cpu_started) * 1000, 3),
        "wal_bytes_before": before_wal,
        "wal_bytes_after": _file_size(wal),
        "wal_checkpoint_busy": int(checkpoint[0]),
        "wal_checkpoint_log_frames": int(checkpoint[1]),
        "wal_checkpointed_frames": int(checkpoint[2]),
        "count_preserved": retained == maximum,
        "audited_decision": audit_details.get("decision"),
        "audited_deleted_by_limit": audit_details.get("deleted_by_limit"),
        "audited_protected_records": audit_details.get("protected_records"),
        "audited_over_limit_records": audit_details.get("over_limit_records"),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--checkpoints",
        type=int,
        nargs="+",
        default=[50_000, 100_000, 150_000, 250_000, 500_000],
    )
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--batch-size", type=int, default=5_000)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "artifacts" / "runtime" / "m16-capacity-benchmark.json",
    )
    args = parser.parse_args()
    checkpoints = sorted(set(args.checkpoints))
    if not checkpoints or checkpoints[0] < 10_000 or checkpoints[-1] > 500_000:
        parser.error("checkpoints must be between 10000 and 500000")
    if not 3 <= args.runs <= 20 or not 500 <= args.batch_size <= 10_000:
        parser.error("runs must be 3..20 and batch-size must be 500..10000")
    output = args.output.resolve()
    if ROOT not in output.parents:
        parser.error("output must remain below the repository root")

    disk_before = shutil.disk_usage(ROOT)
    with tempfile.TemporaryDirectory(prefix="cyberqalqon-m16-capacity-") as directory:
        database = Path(directory) / "m16.db"
        anchor = datetime.now(timezone.utc) - timedelta(hours=1)
        with closing(sqlite3.connect(database)) as connection:
            apply_migrations(connection, target_version=17)
            _seed_supporting_records(connection, anchor)
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = NORMAL")
            current = 0
            results: list[dict[str, object]] = []
            tracemalloc.start()
            for checkpoint_count in checkpoints:
                ingestion = _insert_until(
                    connection,
                    anchor,
                    current,
                    checkpoint_count,
                    args.batch_size,
                )
                current = checkpoint_count
                query = _checkpoint(database, checkpoint_count, anchor, args.runs)
                retention = _retention_probe(database, checkpoint_count)
                size = database.stat().st_size
                result = {
                    **query,
                    "ingestion": ingestion,
                    "retention_probe": retention,
                    "storage": {
                        "database_bytes": size,
                        "wal_bytes": _file_size(Path(f"{database}-wal")),
                        "shm_bytes": _file_size(Path(f"{database}-shm")),
                        "database_bytes_per_event": round(size / checkpoint_count, 3),
                    },
                }
                results.append(result)
                print(
                    json.dumps(
                        {
                            "checkpoint": checkpoint_count,
                            "quick_check": result["quick_check"],
                            "retention_wall_ms": retention["wall_ms"],
                            "database_bytes": size,
                        },
                        sort_keys=True,
                    ),
                    flush=True,
                )
            _, peak_bytes = tracemalloc.get_traced_memory()
            tracemalloc.stop()
        # Some repository methods use sqlite connection context managers whose finalizers
        # close after local references are released. Force that deterministic boundary on
        # Windows before TemporaryDirectory removes the disposable database.
        gc.collect()
        disk_after = shutil.disk_usage(ROOT)
        report = {
            "version": 1,
            "database": "temporary-isolated-auto-removed",
            "live_database_opened": False,
            "schema_version": 17,
            "synthetic_measurement": True,
            "checkpoints": results,
            "python_tracemalloc_peak_bytes": peak_bytes,
            "disk_free_bytes_before": disk_before.free,
            "disk_free_bytes_after_benchmark_before_cleanup": disk_after.free,
            "process_id": os.getpid(),
            "captured_at": datetime.now(timezone.utc).isoformat(),
        }
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary = output.with_suffix(output.suffix + ".tmp")
        temporary.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
        os.replace(temporary, output)
        print(json.dumps({"result": str(output), "checkpoints": checkpoints}, sort_keys=True))
        healthy = all(
            item["quick_check"] == "ok"
            and item["foreign_key_errors"] == 0
            and item["retention_probe"]["count_preserved"]
            for item in results
        )
    return 0 if healthy else 1


if __name__ == "__main__":
    raise SystemExit(main())
