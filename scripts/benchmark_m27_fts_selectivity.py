#!/usr/bin/env python3
"""Compare FTS selectivity/recency strategies on a disposable rowid prototype."""

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

import benchmark_m26_fts_candidate as prototype  # noqa: E402
from app.db.alerts import AlertRepository  # noqa: E402
from benchmark_cqql import INSERT_SQL, synthetic_row  # noqa: E402


def run(events: int, iterations: int) -> dict[str, Any]:
    base = datetime(2026, 10, 22, 8, 0, tzinfo=timezone.utc)
    start = (base - timedelta(days=7)).isoformat()
    end = (base + timedelta(minutes=1)).isoformat()
    queries = {
        "dense_common": '"synthetic"',
        "sparse_recent": '"m27rarecent"',
        "sparse_historical": '"m27rarehistorical"',
        "selective_multiple_tokens": '"synthetic" "m27rarecent"',
        "no_match": '"m27nomatch"',
    }
    sql = {
        "schema17_candidate_first": (
            "SELECT e.event_id FROM security_events e WHERE e.occurred_at BETWEEN ? AND ? "
            "AND e.event_id IN (SELECT event_id FROM security_events_fts "
            "WHERE security_events_fts MATCH ?) "
            "ORDER BY e.occurred_at DESC, e.event_id DESC LIMIT 100"
        ),
        "rowid_direct": (
            "SELECT e.event_id FROM security_events_fts_rowid_v2 f "
            "JOIN security_events e ON e.rowid=f.rowid "
            "WHERE e.occurred_at BETWEEN ? AND ? AND security_events_fts_rowid_v2 MATCH ? "
            "ORDER BY e.occurred_at DESC, e.event_id DESC LIMIT 100"
        ),
        "rowid_time_first": (
            "SELECT e.event_id FROM security_events e INDEXED BY idx_security_events_occurred_id "
            "WHERE e.occurred_at BETWEEN ? AND ? AND EXISTS ("
            "SELECT 1 FROM security_events_fts_rowid_v2 f WHERE f.rowid=e.rowid "
            "AND security_events_fts_rowid_v2 MATCH ?) "
            "ORDER BY e.occurred_at DESC, e.event_id DESC LIMIT 100"
        ),
    }
    report: dict[str, Any] = {
        "benchmark": "CyberQalqon M27 disposable FTS selectivity and recency matrix",
        "scope": "DISPOSABLE_ONLY",
        "live_database_opened": False,
        "schema": 17,
        "experimental_rowid_schema_activated_live": False,
        "events": events,
        "iterations": iterations,
        "deadline_ms": 1_500,
        "queries": {},
    }
    with tempfile.TemporaryDirectory(prefix="cyberqalqon-m27-fts-") as raw:
        path = Path(raw) / "selectivity.db"
        AlertRepository(f"sqlite:///{path.as_posix()}", migration_target_version=17).initialize()
        with closing(sqlite3.connect(path, timeout=30)) as connection:
            for batch_start in range(0, events, 1_000):
                connection.executemany(
                    INSERT_SQL,
                    (
                        synthetic_row(index, base)
                        for index in range(batch_start, min(events, batch_start + 1_000))
                    ),
                )
                connection.commit()
            connection.execute(
                "UPDATE security_events SET search_text=search_text || ' m27rarecent' "
                "WHERE event_id=?",
                ("EVT-M25-000000000000",),
            )
            connection.execute(
                "UPDATE security_events SET search_text=search_text || ' m27rarehistorical' "
                "WHERE event_id=?",
                (f"EVT-M25-{events - 1:012d}",),
            )
            connection.commit()
            prototype._upgrade(connection)  # noqa: SLF001 - disposable prototype reuse
            for name, match in queries.items():
                candidate_count = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM security_events_fts "
                        "WHERE security_events_fts MATCH ?",
                        (match,),
                    ).fetchone()[0]
                )
                strategies = {
                    strategy: prototype._benchmark_query(  # noqa: SLF001
                        connection, statement, (start, end, match), iterations
                    )
                    for strategy, statement in sql.items()
                }
                reference = strategies["schema17_candidate_first"]["result_ids"]
                for result in strategies.values():
                    result_ids = result.pop("result_ids")
                    result["result_count"] = len(result_ids)
                    result["equivalent_when_complete"] = (
                        result_ids == reference if result["completed"] else None
                    )
                report["queries"][name] = {
                    "candidate_count": candidate_count,
                    "strategies": strategies,
                }
            integrity_before_drop = str(connection.execute("PRAGMA quick_check").fetchone()[0])
            prototype._downgrade(connection)  # noqa: SLF001
            integrity_after_drop = str(connection.execute("PRAGMA quick_check").fetchone()[0])
            foreign_keys = len(connection.execute("PRAGMA foreign_key_check").fetchall())
            schema = int(connection.execute("PRAGMA user_version").fetchone()[0])
        report.update(
            {
                "quick_check_with_prototype": integrity_before_drop,
                "quick_check_after_prototype_drop": integrity_after_drop,
                "foreign_key_violations": foreign_keys,
                "schema_after": schema,
            }
        )
        report["pass"] = all(
            (
                integrity_before_drop == "ok",
                integrity_after_drop == "ok",
                foreign_keys == 0,
                schema == 17,
                all(
                    result["equivalent_when_complete"] is not False
                    for query in report["queries"].values()
                    for result in query["strategies"].values()
                ),
            )
        )
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", type=int, default=50_000)
    parser.add_argument("--iterations", type=int, default=5)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    if not 10_000 <= arguments.events <= 100_000:
        parser.error("events must be between 10000 and 100000")
    if not 1 <= arguments.iterations <= 20:
        parser.error("iterations must be between 1 and 20")
    report = run(arguments.events, arguments.iterations)
    rendered = json.dumps(report, indent=2, sort_keys=True)
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
