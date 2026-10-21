#!/usr/bin/env python3
"""Benchmark an FTS rowid reverse-map candidate on a disposable schema-17 copy."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import statistics
import tempfile
import time
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


def _event(index: int) -> dict[str, Any]:
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "id": f"m20-fts-candidate-{index}",
        "agent": {"id": "001", "name": "M20-DISPOSABLE"},
        "rule": {
            "id": "100111",
            "level": 10,
            "description": "M20 disposable FTS candidate",
        },
        "decoder": {"name": "json"},
        "location": "m20-disposable",
        "full_log": f"M20 disposable FTS candidate {index}",
    }


def _candidate_sql() -> str:
    return """
        CREATE TABLE security_events_fts_row_map (
            event_id TEXT PRIMARY KEY,
            fts_rowid INTEGER NOT NULL UNIQUE
        ) WITHOUT ROWID;
        INSERT INTO security_events_fts_row_map(event_id, fts_rowid)
        SELECT event_id, rowid FROM security_events_fts;

        DROP TRIGGER security_events_fts_insert;
        DROP TRIGGER security_events_fts_delete;
        DROP TRIGGER security_events_fts_update;

        CREATE TRIGGER security_events_fts_insert
        AFTER INSERT ON security_events BEGIN
            INSERT INTO security_events_fts(event_id, search_text)
            VALUES (new.event_id, new.search_text);
            INSERT INTO security_events_fts_row_map(event_id, fts_rowid)
            VALUES (new.event_id, last_insert_rowid());
        END;

        CREATE TRIGGER security_events_fts_delete
        AFTER DELETE ON security_events BEGIN
            DELETE FROM security_events_fts
            WHERE rowid = (
                SELECT fts_rowid FROM security_events_fts_row_map
                WHERE event_id = old.event_id
            );
            DELETE FROM security_events_fts_row_map WHERE event_id = old.event_id;
        END;

        CREATE TRIGGER security_events_fts_update
        AFTER UPDATE OF search_text ON security_events BEGIN
            DELETE FROM security_events_fts
            WHERE rowid = (
                SELECT fts_rowid FROM security_events_fts_row_map
                WHERE event_id = old.event_id
            );
            DELETE FROM security_events_fts_row_map WHERE event_id = old.event_id;
            INSERT INTO security_events_fts(event_id, search_text)
            VALUES (new.event_id, new.search_text);
            INSERT INTO security_events_fts_row_map(event_id, fts_rowid)
            VALUES (new.event_id, last_insert_rowid());
        END;
    """


def _p95(values: list[float]) -> float:
    ordered = sorted(values)
    return ordered[max(0, int(len(ordered) * 0.95 + 0.999999) - 1)]


def run(source: Path, output: Path, samples: int) -> dict[str, Any]:
    from app.db.events import EventRepository
    from app.services.event_normalizer import normalize_wazuh_event

    if not source.is_file():
        raise FileNotFoundError(source)
    with tempfile.TemporaryDirectory(prefix="cyberqalqon-m20-fts-") as raw:
        database = Path(raw) / "candidate.db"
        shutil.copy2(source, database)
        size_before = database.stat().st_size
        with closing(sqlite3.connect(database, timeout=30)) as connection:
            connection.execute("PRAGMA foreign_keys=ON")
            schema = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if schema != 17:
                raise RuntimeError(f"candidate requires schema 17, observed {schema}")
            original_triggers = {
                str(name): str(sql)
                for name, sql in connection.execute(
                    "SELECT name, sql FROM sqlite_master WHERE type='trigger' "
                    "AND name IN ('security_events_fts_insert', "
                    "'security_events_fts_delete', 'security_events_fts_update')"
                )
            }
            started = time.perf_counter()
            connection.executescript("BEGIN IMMEDIATE;" + _candidate_sql() + "COMMIT;")
            migration_seconds = time.perf_counter() - started
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            event_count = int(
                connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
            )
            map_count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM security_events_fts_row_map"
                ).fetchone()[0]
            )
            missing_map = int(
                connection.execute(
                    "SELECT COUNT(*) FROM security_events e "
                    "LEFT JOIN security_events_fts_row_map m ON m.event_id=e.event_id "
                    "WHERE m.event_id IS NULL"
                ).fetchone()[0]
            )
            invalid_map = int(
                connection.execute(
                    "SELECT COUNT(*) FROM security_events_fts_row_map m "
                    "LEFT JOIN security_events_fts f ON f.rowid=m.fts_rowid "
                    "WHERE f.rowid IS NULL OR f.event_id<>m.event_id"
                ).fetchone()[0]
            )
        size_after_migration = database.stat().st_size

        repository = EventRepository(database, retention_days=30, max_records=100_000)
        transaction_ms: list[float] = []
        retention_ms: list[float] = []
        retention_delete_ms: list[float] = []
        commit_ms: list[float] = []
        for sample in range(samples):
            result = repository.ingest_batch(
                [
                    normalize_wazuh_event(_event(sample * 10 + index))
                    for index in range(10)
                ]
            )
            transaction_ms.append(result.transaction_ms)
            retention_ms.append(result.retention_ms)
            retention_delete_ms.append(result.retention_delete_ms)
            commit_ms.append(result.commit_ms)

        with closing(sqlite3.connect(database, timeout=30)) as connection:
            connection.execute("PRAGMA foreign_keys=ON")
            quick_check_before_rollback = str(
                connection.execute("PRAGMA quick_check").fetchone()[0]
            )
            foreign_keys_before_rollback = len(
                connection.execute("PRAGMA foreign_key_check").fetchall()
            )
            duplicate_ids = int(
                connection.execute(
                    "SELECT COUNT(*) FROM (SELECT event_id FROM security_events "
                    "GROUP BY event_id HAVING COUNT(*)>1)"
                ).fetchone()[0]
            )
            started = time.perf_counter()
            connection.execute("BEGIN IMMEDIATE")
            for name in (
                "security_events_fts_insert",
                "security_events_fts_delete",
                "security_events_fts_update",
            ):
                connection.execute(f"DROP TRIGGER {name}")
            for sql in original_triggers.values():
                connection.execute(sql)
            connection.execute("DROP TABLE security_events_fts_row_map")
            connection.commit()
            rollback_seconds = time.perf_counter() - started
            quick_check_after_rollback = str(
                connection.execute("PRAGMA quick_check").fetchone()[0]
            )
            foreign_keys_after_rollback = len(
                connection.execute("PRAGMA foreign_key_check").fetchall()
            )
            restored_triggers = int(
                connection.execute(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' "
                    "AND name IN ('security_events_fts_insert', "
                    "'security_events_fts_delete', 'security_events_fts_update')"
                ).fetchone()[0]
            )

        report = {
            "version": 1,
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "scope": "DISPOSABLE_ONLY",
            "live_schema_modified": False,
            "source_database": str(source),
            "source_opened_writable": False,
            "schema_version": 17,
            "candidate": "fts_rowid_reverse_map",
            "migration_seconds": round(migration_seconds, 3),
            "database_size_before": size_before,
            "database_size_after_migration": size_after_migration,
            "database_growth_bytes": size_after_migration - size_before,
            "event_count_at_migration": event_count,
            "map_count": map_count,
            "missing_map_rows": missing_map,
            "invalid_map_rows": invalid_map,
            "samples": samples,
            "batch_size": 10,
            "transaction_p50_ms": round(statistics.median(transaction_ms), 3),
            "transaction_p95_ms": round(_p95(transaction_ms), 3),
            "retention_p50_ms": round(statistics.median(retention_ms), 3),
            "retention_p95_ms": round(_p95(retention_ms), 3),
            "retention_delete_p50_ms": round(
                statistics.median(retention_delete_ms), 3
            ),
            "retention_delete_p95_ms": round(_p95(retention_delete_ms), 3),
            "commit_p95_ms": round(_p95(commit_ms), 3),
            "quick_check_before_rollback": quick_check_before_rollback,
            "foreign_key_errors_before_rollback": foreign_keys_before_rollback,
            "duplicate_event_id_groups": duplicate_ids,
            "rollback_seconds": round(rollback_seconds, 3),
            "restored_original_triggers": restored_triggers,
            "quick_check_after_rollback": quick_check_after_rollback,
            "foreign_key_errors_after_rollback": foreign_keys_after_rollback,
        }
        report["pass"] = all(
            (
                event_count == map_count,
                missing_map == 0,
                invalid_map == 0,
                quick_check_before_rollback == "ok",
                foreign_keys_before_rollback == 0,
                duplicate_ids == 0,
                restored_triggers == 3,
                quick_check_after_rollback == "ok",
                foreign_keys_after_rollback == 0,
            )
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    pending = output.with_suffix(output.suffix + ".tmp")
    pending.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(pending, output)
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=5)
    args = parser.parse_args()
    report = run(args.database.resolve(), args.output.resolve(), args.samples)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
