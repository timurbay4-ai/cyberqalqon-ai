#!/usr/bin/env python3
"""Evaluate an event-rowid FTS5 prototype on disposable schema-17 data only.

This is deliberately not an application migration.  It builds a temporary
database, proves upgrade/downgrade and evidence preservation, compares query
shapes, measures the additional write path, writes a JSON report, and deletes
the database.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
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
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "scripts"))

from app.db.alerts import AlertRepository  # noqa: E402
from benchmark_cqql import INSERT_SQL, synthetic_row  # noqa: E402


DEADLINE_SECONDS = 1.5


def _percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * fraction) - 1)]


def _evidence_digest(connection: sqlite3.Connection) -> str:
    digest = hashlib.sha256()
    for row in connection.execute(
        "SELECT event_id, raw_event_json FROM security_events ORDER BY event_id"
    ):
        digest.update(str(row[0]).encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(row[1]).encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def _upgrade(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        BEGIN IMMEDIATE;
        CREATE VIRTUAL TABLE security_events_fts_rowid_v2 USING fts5(
            search_text,
            content='security_events',
            content_rowid='rowid',
            tokenize='unicode61'
        );
        INSERT INTO security_events_fts_rowid_v2(security_events_fts_rowid_v2)
        VALUES('rebuild');
        CREATE TRIGGER m26_fts_rowid_insert AFTER INSERT ON security_events BEGIN
            INSERT INTO security_events_fts_rowid_v2(rowid, search_text)
            VALUES(new.rowid, new.search_text);
        END;
        CREATE TRIGGER m26_fts_rowid_delete AFTER DELETE ON security_events BEGIN
            INSERT INTO security_events_fts_rowid_v2(
                security_events_fts_rowid_v2, rowid, search_text
            ) VALUES('delete', old.rowid, old.search_text);
        END;
        CREATE TRIGGER m26_fts_rowid_update AFTER UPDATE OF search_text ON security_events BEGIN
            INSERT INTO security_events_fts_rowid_v2(
                security_events_fts_rowid_v2, rowid, search_text
            ) VALUES('delete', old.rowid, old.search_text);
            INSERT INTO security_events_fts_rowid_v2(rowid, search_text)
            VALUES(new.rowid, new.search_text);
        END;
        COMMIT;
        """
    )


def _downgrade(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        BEGIN IMMEDIATE;
        DROP TRIGGER m26_fts_rowid_insert;
        DROP TRIGGER m26_fts_rowid_delete;
        DROP TRIGGER m26_fts_rowid_update;
        DROP TABLE security_events_fts_rowid_v2;
        COMMIT;
        """
    )


def _execute_bounded(
    connection: sqlite3.Connection,
    sql: str,
    parameters: tuple[object, ...],
) -> tuple[str, float | None, list[str]]:
    deadline = time.perf_counter() + DEADLINE_SECONDS
    connection.set_progress_handler(
        lambda: 1 if time.perf_counter() >= deadline else 0,
        1_000,
    )
    started = time.perf_counter()
    try:
        rows = [str(row[0]) for row in connection.execute(sql, parameters).fetchall()]
        return "COMPLETE", (time.perf_counter() - started) * 1_000, rows
    except sqlite3.OperationalError as exc:
        if "interrupted" not in str(exc).casefold():
            raise
        return "TIMEOUT", None, []
    finally:
        connection.set_progress_handler(None, 0)


def _benchmark_query(
    connection: sqlite3.Connection,
    sql: str,
    parameters: tuple[object, ...],
    iterations: int,
) -> dict[str, Any]:
    plan = [
        str(row[3])
        for row in connection.execute("EXPLAIN QUERY PLAN " + sql, parameters)
    ]
    samples: list[float] = []
    statuses: list[str] = []
    reference: list[str] | None = None
    identity_stable = True
    for _ in range(iterations):
        status, elapsed, rows = _execute_bounded(connection, sql, parameters)
        statuses.append(status)
        if elapsed is not None:
            samples.append(elapsed)
            if reference is None:
                reference = rows
            elif rows != reference:
                identity_stable = False
    return {
        "statuses": statuses,
        "completed": len(samples),
        "timeouts": statuses.count("TIMEOUT"),
        "p50_ms": round(statistics.median(samples), 3) if samples else None,
        "p95_ms": round(_percentile(samples, 0.95), 3) if samples else None,
        "max_ms": round(max(samples), 3) if samples else None,
        "result_ids": reference or [],
        "stable_ordering": identity_stable,
        "plan": plan,
    }


def _write_probe(path: Path, base: datetime, first_index: int, writes: int) -> dict[str, Any]:
    timings: list[float] = []
    with closing(sqlite3.connect(path, timeout=30)) as connection:
        connection.execute("PRAGMA wal_autocheckpoint=0")
        for index in range(first_index, first_index + writes):
            started = time.perf_counter()
            connection.execute(INSERT_SQL, synthetic_row(index, base))
            connection.commit()
            timings.append((time.perf_counter() - started) * 1_000)
        wal = path.with_name(path.name + "-wal")
        wal_bytes = wal.stat().st_size if wal.exists() else 0
        quick_check = str(connection.execute("PRAGMA quick_check").fetchone()[0])
        foreign_keys = len(connection.execute("PRAGMA foreign_key_check").fetchall())
        digest = _evidence_digest(connection)
    return {
        "writes": writes,
        "p50_ms": round(statistics.median(timings), 3),
        "p95_ms": round(_percentile(timings, 0.95), 3),
        "max_ms": round(max(timings), 3),
        "wal_bytes_before_close": wal_bytes,
        "database_bytes": path.stat().st_size,
        "quick_check": quick_check,
        "foreign_key_violations": foreign_keys,
        "evidence_sha256": digest,
    }


def run(events: int, iterations: int, writes: int) -> dict[str, Any]:
    base = datetime(2026, 10, 21, 8, 0, tzinfo=timezone.utc)
    start = (base - timedelta(days=7)).isoformat()
    end = (base + timedelta(minutes=1)).isoformat()
    broad_match = '"synthetic" "authentication"'
    sparse_match = '"999999999999"'
    baseline_sql = (
        "SELECT e.event_id FROM security_events e "
        "WHERE e.occurred_at BETWEEN ? AND ? AND e.event_id IN ("
        "SELECT event_id FROM security_events_fts WHERE security_events_fts MATCH ?) "
        "ORDER BY e.occurred_at DESC, e.event_id DESC LIMIT 100"
    )
    direct_v2_sql = (
        "SELECT e.event_id FROM security_events_fts_rowid_v2 f "
        "JOIN security_events e ON e.rowid=f.rowid "
        "WHERE e.occurred_at BETWEEN ? AND ? AND security_events_fts_rowid_v2 MATCH ? "
        "ORDER BY e.occurred_at DESC, e.event_id DESC LIMIT 100"
    )
    time_ordered_v2_sql = (
        "SELECT e.event_id FROM security_events e INDEXED BY idx_security_events_occurred_id "
        "WHERE e.occurred_at BETWEEN ? AND ? AND EXISTS ("
        "SELECT 1 FROM security_events_fts_rowid_v2 f "
        "WHERE f.rowid=e.rowid AND security_events_fts_rowid_v2 MATCH ?) "
        "ORDER BY e.occurred_at DESC, e.event_id DESC LIMIT 100"
    )

    with tempfile.TemporaryDirectory(prefix="cyberqalqon-m26-fts-") as raw:
        candidate_path = Path(raw) / "candidate.db"
        baseline_path = Path(raw) / "baseline.db"
        AlertRepository(
            f"sqlite:///{candidate_path.as_posix()}", migration_target_version=17
        ).initialize()
        with closing(sqlite3.connect(candidate_path, timeout=30)) as connection:
            for batch_start in range(0, events, 1_000):
                upper = min(events, batch_start + 1_000)
                connection.executemany(
                    INSERT_SQL,
                    (synthetic_row(index, base) for index in range(batch_start, upper)),
                )
                connection.commit()
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            schema_before = int(connection.execute("PRAGMA user_version").fetchone()[0])
            count_before = int(connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0])
            digest_before = _evidence_digest(connection)
            quick_before = str(connection.execute("PRAGMA quick_check").fetchone()[0])
        shutil.copy2(candidate_path, baseline_path)
        size_before = candidate_path.stat().st_size

        with closing(sqlite3.connect(candidate_path, timeout=30)) as connection:
            upgrade_started = time.perf_counter()
            _upgrade(connection)
            upgrade_ms = (time.perf_counter() - upgrade_started) * 1_000
            connection.execute(
                "INSERT INTO security_events_fts_rowid_v2("
                "security_events_fts_rowid_v2, rank) VALUES('integrity-check', 1)"
            )
            connection.commit()
            digest_after_upgrade = _evidence_digest(connection)
            broad_parameters = (start, end, broad_match)
            sparse_parameters = (start, end, sparse_match)
            queries = {
                "baseline_broad": _benchmark_query(
                    connection, baseline_sql, broad_parameters, iterations
                ),
                "rowid_direct_broad": _benchmark_query(
                    connection, direct_v2_sql, broad_parameters, iterations
                ),
                "rowid_time_ordered_broad": _benchmark_query(
                    connection, time_ordered_v2_sql, broad_parameters, iterations
                ),
                "baseline_sparse": _benchmark_query(
                    connection, baseline_sql, sparse_parameters, iterations
                ),
                "rowid_direct_sparse": _benchmark_query(
                    connection, direct_v2_sql, sparse_parameters, iterations
                ),
                "rowid_time_ordered_sparse": _benchmark_query(
                    connection, time_ordered_v2_sql, sparse_parameters, iterations
                ),
            }
            broad_equivalent = (
                queries["baseline_broad"]["result_ids"]
                == queries["rowid_direct_broad"]["result_ids"]
                == queries["rowid_time_ordered_broad"]["result_ids"]
            )
            sparse_equivalent = (
                queries["baseline_sparse"]["result_ids"]
                == queries["rowid_direct_sparse"]["result_ids"]
                == queries["rowid_time_ordered_sparse"]["result_ids"]
            )
            for result in queries.values():
                result_ids = result.pop("result_ids")
                result["result_count"] = len(result_ids)
                result["result_ids_sha256"] = hashlib.sha256(
                    "\n".join(result_ids).encode("utf-8")
                ).hexdigest()
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        size_after_upgrade = candidate_path.stat().st_size

        baseline_write = _write_probe(baseline_path, base, events, writes)
        candidate_write = _write_probe(candidate_path, base, events, writes)

        with closing(sqlite3.connect(candidate_path, timeout=30)) as connection:
            downgrade_started = time.perf_counter()
            _downgrade(connection)
            downgrade_ms = (time.perf_counter() - downgrade_started) * 1_000
            schema_after = int(connection.execute("PRAGMA user_version").fetchone()[0])
            count_after = int(connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0])
            digest_after_downgrade = _evidence_digest(connection)
            quick_after = str(connection.execute("PRAGMA quick_check").fetchone()[0])
            foreign_keys_after = len(connection.execute("PRAGMA foreign_key_check").fetchall())
            prototype_objects_after = int(
                connection.execute(
                    "SELECT COUNT(*) FROM sqlite_master WHERE name LIKE 'm26_fts_rowid_%' "
                    "OR name='security_events_fts_rowid_v2'"
                ).fetchone()[0]
            )

        report: dict[str, Any] = {
            "benchmark": "CyberQalqon M26 disposable FTS5 rowid prototype",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scope": "DISPOSABLE_ONLY",
            "live_database_opened": False,
            "events_before_write_probe": events,
            "write_probe_events": writes,
            "iterations": iterations,
            "deadline_ms": int(DEADLINE_SECONDS * 1_000),
            "schema_before": schema_before,
            "schema_after_downgrade": schema_after,
            "event_count_before": count_before,
            "event_count_after": count_after,
            "evidence_sha256_before": digest_before,
            "evidence_sha256_after_upgrade": digest_after_upgrade,
            "evidence_sha256_after_writes_baseline": baseline_write["evidence_sha256"],
            "evidence_sha256_after_writes_candidate": candidate_write["evidence_sha256"],
            "evidence_sha256_after_downgrade": digest_after_downgrade,
            "quick_check_before": quick_before,
            "quick_check_after": quick_after,
            "foreign_key_violations_after": foreign_keys_after,
            "prototype_objects_after_downgrade": prototype_objects_after,
            "upgrade_ms": round(upgrade_ms, 3),
            "downgrade_ms": round(downgrade_ms, 3),
            "database_bytes_before": size_before,
            "database_bytes_after_upgrade": size_after_upgrade,
            "database_growth_bytes": size_after_upgrade - size_before,
            "queries": queries,
            "broad_result_equivalent": broad_equivalent,
            "sparse_result_equivalent": sparse_equivalent,
            "baseline_write": baseline_write,
            "candidate_write": candidate_write,
        }
        report["pass"] = all(
            (
                schema_before == schema_after == 17,
                count_before == events,
                count_after == events + writes,
                digest_before == digest_after_upgrade,
                baseline_write["evidence_sha256"] == candidate_write["evidence_sha256"],
                candidate_write["evidence_sha256"] == digest_after_downgrade,
                quick_before == quick_after == "ok",
                foreign_keys_after == 0,
                prototype_objects_after == 0,
                broad_equivalent,
                sparse_equivalent,
            )
        )
        return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", type=int, default=50_000)
    parser.add_argument("--iterations", type=int, default=5)
    parser.add_argument("--writes", type=int, default=50)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    if not 1_000 <= arguments.events <= 100_000:
        parser.error("events must be between 1000 and 100000")
    if not 1 <= arguments.iterations <= 20:
        parser.error("iterations must be between 1 and 20")
    if not 1 <= arguments.writes <= 1_000:
        parser.error("writes must be between 1 and 1000")
    report = run(arguments.events, arguments.iterations, arguments.writes)
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    pending = arguments.output.with_suffix(arguments.output.suffix + ".tmp")
    pending.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(pending, arguments.output)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
