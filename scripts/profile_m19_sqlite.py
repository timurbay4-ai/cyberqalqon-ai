"""Profile M19 retention/query costs against a read-only backup and disposable copy.

The source database is never opened writable. A temporary copy is used for the
bounded transaction probes and removed automatically.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import statistics
import sys
import tempfile
import time
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.db.events import EventRepository, _utc_iso  # noqa: E402
from app.services.event_normalizer import normalize_wazuh_event  # noqa: E402


PROTECTED_FILTER = (
    "(EXISTS (SELECT 1 FROM case_events ce WHERE ce.event_id = e.event_id) "
    "OR EXISTS (SELECT 1 FROM incident_evidence_pins iep "
    "WHERE iep.evidence_type = 'EVENT' AND iep.evidence_id = e.event_id) "
    "OR EXISTS (SELECT 1 FROM case_evidence_refs cer "
    "WHERE cer.reference_type = 'EVENT' AND cer.reference_id = e.event_id) "
    "OR EXISTS (SELECT 1 FROM alerts a WHERE a.alert_id = "
    "COALESCE(e.related_alert_id, e.source_event_id)))"
)

PROTECTED_COUNT_SQL = """
    SELECT COUNT(*)
    FROM (
        SELECT ce.event_id AS protected_event_id FROM case_events ce
        UNION
        SELECT e.event_id FROM incident_evidence_pins iep
        JOIN security_events e ON e.event_id = iep.evidence_id
        WHERE iep.evidence_type = 'EVENT'
        UNION
        SELECT e.event_id FROM case_evidence_refs cer
        JOIN security_events e ON e.event_id = cer.reference_id
        WHERE cer.reference_type = 'EVENT'
        UNION
        SELECT e2.event_id FROM security_events e2
        JOIN alerts a ON a.alert_id = COALESCE(e2.related_alert_id, e2.source_event_id)
    ) protected
"""


def _percentile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    position = max(0, min(len(ordered) - 1, int((len(ordered) - 1) * percentile)))
    return round(ordered[position], 3)


def _timed(call: Callable[[], Any]) -> tuple[Any, float]:
    started = time.perf_counter()
    result = call()
    return result, round((time.perf_counter() - started) * 1000, 3)


def _event(index: int, anchor: datetime) -> dict[str, Any]:
    padding = "x" * 2048
    return {
        "timestamp": (anchor + timedelta(microseconds=index)).isoformat(),
        "id": f"m19-disposable-{index}",
        "agent": {"id": "001", "name": "M19-DISPOSABLE"},
        "rule": {"id": "100111", "level": 10, "description": "M19 profile"},
        "decoder": {"name": "sshd"},
        "location": "/var/log/auth.log",
        "full_log": f"M19 disposable transaction profile {index} {padding}",
    }


def _read_only_profile(source: Path) -> dict[str, Any]:
    uri = f"file:{source.as_posix()}?mode=ro"
    with closing(sqlite3.connect(uri, uri=True, timeout=30)) as connection:
        connection.execute("PRAGMA query_only=ON")
        queries: dict[str, tuple[str, tuple[Any, ...]]] = {
            "count_all": ("SELECT COUNT(*) FROM security_events", ()),
            "protected_count": (PROTECTED_COUNT_SQL, ()),
            "retention_candidates_10": (
                "SELECT e.event_id, e.occurred_at, e.related_alert_id, e.source_event_id "
                "FROM security_events e "
                "ORDER BY e.occurred_at ASC, e.event_id ASC LIMIT ?",
                (10,),
            ),
            "retention_candidates_25": (
                "SELECT e.event_id, e.occurred_at, e.related_alert_id, e.source_event_id "
                "FROM security_events e "
                "ORDER BY e.occurred_at ASC, e.event_id ASC LIMIT ?",
                (25,),
            ),
        }
        results: dict[str, Any] = {}
        for name, (sql, parameters) in queries.items():
            rows, elapsed_ms = _timed(
                lambda sql=sql, parameters=parameters: connection.execute(
                    sql, parameters
                ).fetchall()
            )
            plan = [
                str(row[3])
                for row in connection.execute(
                    "EXPLAIN QUERY PLAN " + sql, parameters
                ).fetchall()
            ]
            results[name] = {
                "elapsed_ms": elapsed_ms,
                "result_rows": len(rows),
                "scalar": rows[0][0] if len(rows) == 1 and len(rows[0]) == 1 else None,
                "query_plan": plan,
            }
        results["index_count"] = int(
            connection.execute(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='index' "
                "AND tbl_name='security_events'"
            ).fetchone()[0]
        )
        results["trigger_count"] = int(
            connection.execute(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' "
                "AND tbl_name='security_events'"
            ).fetchone()[0]
        )
        results["journal_mode"] = str(connection.execute("PRAGMA journal_mode").fetchone()[0])
        results["synchronous"] = int(connection.execute("PRAGMA synchronous").fetchone()[0])
        results["schema_version"] = int(connection.execute("PRAGMA user_version").fetchone()[0])
        return results


def _transaction_profile(source: Path, samples: int) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="cyberqalqon-m19-profile-") as directory:
        database = Path(directory) / "profile.db"
        shutil.copy2(source, database)
        with closing(sqlite3.connect(database, timeout=30)) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute(
                "UPDATE security_event_store_state SET retained_records=("
                "SELECT COUNT(*) FROM security_events), last_retention_at=? "
                "WHERE singleton=1",
                (_utc_iso(datetime.now(timezone.utc)),),
            )
            connection.commit()
            maximum = int(
                connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
            )

        repository = EventRepository(
            database,
            retention_days=30,
            max_records=maximum,
        )
        anchor = datetime.now(timezone.utc)
        durations: list[float] = []
        retention: list[float] = []
        commits: list[float] = []
        lock_waits: list[float] = []
        candidates: list[float] = []
        protection_checks: list[float] = []
        deletes: list[float] = []
        statement_counts: list[int] = []
        inserts = 0
        duplicates = 0
        for sample in range(samples):
            events = [
                normalize_wazuh_event(_event(sample * 10 + index, anchor))
                for index in range(10)
            ]
            result, elapsed_ms = _timed(
                lambda events=events: repository.ingest_batch(
                    events, max_processing_seconds=60.0
                )
            )
            durations.append(elapsed_ms)
            retention.append(result.retention_ms)
            commits.append(result.commit_ms)
            lock_waits.append(result.lock_wait_ms)
            candidates.append(result.retention_candidate_ms)
            protection_checks.append(result.protected_check_ms)
            deletes.append(result.retention_delete_ms)
            statement_counts.append(result.sql_statement_count)
            inserts += result.inserted
            duplicates += result.duplicates

        # Force one five-minute reconciliation pass on the disposable copy.
        with closing(sqlite3.connect(database, timeout=30)) as connection:
            connection.execute(
                "UPDATE security_event_store_state SET last_retention_at=? WHERE singleton=1",
                (_utc_iso(datetime.now(timezone.utc) - timedelta(minutes=6)),),
            )
            connection.commit()
        sweep_events = [
            normalize_wazuh_event(_event(100_000 + index, anchor)) for index in range(10)
        ]
        sweep_result, sweep_elapsed_ms = _timed(
            lambda: repository.ingest_batch(
                sweep_events, max_processing_seconds=60.0
            )
        )

        with closing(sqlite3.connect(database, timeout=30)) as connection:
            event_count = int(
                connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
            )
            state_count = int(
                connection.execute(
                    "SELECT retained_records FROM security_event_store_state WHERE singleton=1"
                ).fetchone()[0]
            )
            foreign_keys = len(connection.execute("PRAGMA foreign_key_check").fetchall())
        return {
            "samples": samples,
            "batch_size": 10,
            "transaction_elapsed_p50_ms": _percentile(durations, 0.50),
            "transaction_elapsed_p95_ms": _percentile(durations, 0.95),
            "transaction_elapsed_max_ms": round(max(durations), 3),
            "reported_retention_p50_ms": _percentile(retention, 0.50),
            "reported_retention_p95_ms": _percentile(retention, 0.95),
            "reported_commit_p95_ms": _percentile(commits, 0.95),
            "lock_wait_p95_ms": _percentile(lock_waits, 0.95),
            "retention_candidate_p95_ms": _percentile(candidates, 0.95),
            "protected_check_p95_ms": _percentile(protection_checks, 0.95),
            "retention_delete_p95_ms": _percentile(deletes, 0.95),
            "sql_statement_count_max": max(statement_counts),
            "inserted": inserts,
            "duplicates": duplicates,
            "full_sweep_elapsed_ms": sweep_elapsed_ms,
            "full_sweep_retention_ms": sweep_result.retention_ms,
            "event_count": event_count,
            "state_count": state_count,
            "foreign_key_errors": foreign_keys,
            "database_size_bytes": database.stat().st_size,
            "wal_size_bytes": Path(f"{database}-wal").stat().st_size
            if Path(f"{database}-wal").exists()
            else 0,
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=5)
    args = parser.parse_args()
    source = args.database.resolve()
    output = args.output.resolve()
    if not source.is_file():
        parser.error("database must name an existing backup")
    if ROOT not in output.parents:
        parser.error("output must remain below the repository root")
    if not 1 <= args.samples <= 20:
        parser.error("samples must be between 1 and 20")

    report = {
        "version": 1,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "source_database": str(source),
        "source_opened_writable": False,
        "live_database_opened": False,
        "read_only": _read_only_profile(source),
        "disposable_transactions": _transaction_profile(source, args.samples),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    pending = output.with_suffix(output.suffix + ".tmp")
    pending.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(pending, output)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
