"""Bounded disposable A/B benchmark for the M17 retention fast path."""

from __future__ import annotations

import argparse
import gc
import json
import os
import shutil
import sqlite3
import statistics
import tempfile
import time
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

import sys

sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "scripts"))

from app.db.events import EventRepository, _utc_iso  # noqa: E402
from app.db.migrations import apply_migrations  # noqa: E402
from app.services.event_normalizer import normalize_wazuh_event  # noqa: E402
from benchmark_m13 import _insert_until, _seed_supporting_records  # noqa: E402


class LegacyRetentionRepository(EventRepository):
    """Pre-M17 retention behavior retained only for an isolated A/B measurement."""

    def _enforce_retention(
        self,
        connection: sqlite3.Connection,
        now: datetime,
        *,
        preserve_event_id: str | None = None,
    ) -> None:
        row = connection.execute(
            "SELECT last_retention_at, retained_records FROM security_event_store_state "
            "WHERE singleton = 1"
        ).fetchone()
        last = datetime.fromisoformat(row[0]) if row and row[0] else None
        retained_before = int(row[1]) if row else 0
        if last is not None and now - last < timedelta(minutes=5) and retained_before <= self.max_records:
            return
        cutoff = _utc_iso(now - timedelta(days=self.retention_days))
        protected = self._protected_event_filter("security_events")
        deleted_by_age = connection.execute(
            f"DELETE FROM security_events WHERE occurred_at < ? AND NOT {protected}",
            (cutoff,),
        ).rowcount
        count = int(connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0])
        overflow = count - self.max_records
        if overflow > 0:
            preserve_clause = "AND e.event_id <> ?" if preserve_event_id is not None else ""
            parameters: tuple[object, ...] = (
                (preserve_event_id, overflow) if preserve_event_id is not None else (overflow,)
            )
            deleted_by_limit = connection.execute(
                "DELETE FROM security_events WHERE event_id IN ("
                "SELECT e.event_id FROM security_events e "
                f"WHERE NOT {self._protected_event_filter('e')} {preserve_clause} "
                "ORDER BY e.occurred_at ASC, e.event_id ASC LIMIT ?)",
                parameters,
            ).rowcount
        else:
            deleted_by_limit = 0
        retained = int(connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0])
        protected_records = int(
            connection.execute(
                "SELECT COUNT(*) FROM security_events e JOIN ("
                "SELECT event_id AS protected_event_id FROM case_events UNION "
                "SELECT evidence_id FROM incident_evidence_pins WHERE evidence_type='EVENT' UNION "
                "SELECT reference_id FROM case_evidence_refs WHERE reference_type='EVENT' UNION "
                "SELECT e2.event_id FROM security_events e2 JOIN alerts a ON a.alert_id="
                "COALESCE(e2.related_alert_id,e2.source_event_id)) protected "
                "ON protected.protected_event_id=e.event_id"
            ).fetchone()[0]
        )
        connection.execute(
            "UPDATE security_event_store_state SET last_retention_at=?,last_deleted_count=?,"
            "retained_records=? WHERE singleton=1",
            (_utc_iso(now), max(0, deleted_by_age) + max(0, deleted_by_limit), retained),
        )
        self._audit_retention(
            connection,
            now,
            deleted_by_age=deleted_by_age,
            deleted_by_limit=deleted_by_limit,
            protected_records=protected_records,
            retained_records=retained,
        )


def _file_size(path: Path) -> int:
    return path.stat().st_size if path.exists() else 0


def _run(repository: EventRepository, database: Path, *, runs: int, label: str) -> dict[str, object]:
    latencies: list[float] = []
    cpu_started = time.process_time()
    wal = Path(f"{database}-wal")
    wal_before = _file_size(wal)
    anchor = datetime.now(timezone.utc)
    for index in range(runs):
        payload = {
            "id": f"m17-{label}-{index}",
            "timestamp": (anchor + timedelta(milliseconds=index)).isoformat(),
            "agent": {"id": "001", "name": "M17-BENCH"},
            "rule": {"id": "100111", "level": 10, "description": "M17 benchmark"},
            "location": "/var/log/m17-benchmark.log",
            "full_log": "Synthetic disposable M17 retention benchmark",
        }
        started = time.perf_counter()
        repository.ingest(normalize_wazuh_event(payload), now=anchor)
        latencies.append((time.perf_counter() - started) * 1000)
    with closing(sqlite3.connect(database, timeout=30)) as connection:
        retained = int(connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0])
        state_retained = int(
            connection.execute(
                "SELECT retained_records FROM security_event_store_state WHERE singleton=1"
            ).fetchone()[0]
        )
        quick_check = str(connection.execute("PRAGMA quick_check").fetchone()[0])
        foreign_keys = len(connection.execute("PRAGMA foreign_key_check").fetchall())
    return {
        "runs": runs,
        "median_ms": round(statistics.median(latencies), 3),
        "maximum_ms": round(max(latencies), 3),
        "minimum_ms": round(min(latencies), 3),
        "wall_ms": round(sum(latencies), 3),
        "cpu_ms": round((time.process_time() - cpu_started) * 1000, 3),
        "wal_growth_bytes": _file_size(wal) - wal_before,
        "retained_records": retained,
        "state_retained_records": state_retained,
        "quick_check": quick_check,
        "foreign_key_errors": foreign_keys,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", type=int, default=20_000)
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "artifacts" / "runtime" / "m17-retention-ab.json",
    )
    args = parser.parse_args()
    if not 5_000 <= args.events <= 50_000 or not 3 <= args.runs <= 20:
        parser.error("events must be 5000..50000 and runs must be 3..20")
    if ROOT not in args.output.resolve().parents:
        parser.error("output must remain below the repository root")

    disk_before = shutil.disk_usage(ROOT).free
    with tempfile.TemporaryDirectory(prefix="cyberqalqon-m17-retention-") as directory:
        temp = Path(directory)
        base = temp / "base.db"
        anchor = datetime.now(timezone.utc) - timedelta(hours=1)
        with closing(sqlite3.connect(base, timeout=30)) as connection:
            apply_migrations(connection, target_version=17)
            _seed_supporting_records(connection, anchor)
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=NORMAL")
            _insert_until(connection, anchor, 0, args.events, min(5000, args.events))
            connection.execute(
                "UPDATE security_event_store_state SET retained_records=?,last_retention_at=? "
                "WHERE singleton=1",
                (args.events, _utc_iso(datetime.now(timezone.utc))),
            )
            connection.commit()
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        legacy_db = temp / "legacy.db"
        optimized_db = temp / "optimized.db"
        shutil.copy2(base, legacy_db)
        shutil.copy2(base, optimized_db)
        legacy_repository = LegacyRetentionRepository(
            legacy_db, retention_days=30, max_records=args.events
        )
        legacy = _run(
            legacy_repository,
            legacy_db,
            runs=args.runs,
            label="legacy",
        )
        optimized_repository = EventRepository(
            optimized_db, retention_days=30, max_records=args.events
        )
        optimized = _run(
            optimized_repository,
            optimized_db,
            runs=args.runs,
            label="optimized",
        )
        speedup = (
            float(legacy["median_ms"]) / float(optimized["median_ms"])
            if float(optimized["median_ms"]) > 0 else None
        )
        report = {
            "version": 1,
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "database": "temporary-isolated-auto-removed",
            "live_database_opened": False,
            "schema_version": 17,
            "events_at_cap": args.events,
            "legacy": legacy,
            "optimized": optimized,
            "median_speedup": round(speedup, 3) if speedup is not None else None,
            "disk_free_bytes_before": disk_before,
            "disk_free_bytes_after_before_cleanup": shutil.disk_usage(ROOT).free,
            "limitations": [
                "Synthetic fixture; it does not measure Windows-to-WSL HTTP latency.",
                "The 100000-event pre-change reference remains the M16 bounded capacity benchmark.",
            ],
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        temporary = args.output.with_suffix(args.output.suffix + ".tmp")
        temporary.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
        os.replace(temporary, args.output)
        print(json.dumps(report, sort_keys=True))
        healthy = all(
            result["quick_check"] == "ok"
            and result["foreign_key_errors"] == 0
            and result["retained_records"] == args.events
            and result["state_retained_records"] == args.events
            for result in (legacy, optimized)
        )
        del legacy_repository, optimized_repository
        gc.collect()
    return 0 if healthy else 1


if __name__ == "__main__":
    raise SystemExit(main())
