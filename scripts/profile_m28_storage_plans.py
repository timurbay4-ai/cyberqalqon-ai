#!/usr/bin/env python3
"""Explain M28 mixed-source performance blockers on a disposable database."""

from __future__ import annotations

import argparse
import copy
import json
import sqlite3
import sys
import tempfile
import time
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "scripts"))

from app.db.alerts import AlertRepository  # noqa: E402
from app.db.events import EventRepository  # noqa: E402
from app.services.event_normalizer import normalize_wazuh_event  # noqa: E402
import m28_synthetic  # noqa: E402


def run() -> dict:
    base = datetime.now(timezone.utc)
    templates = m28_synthetic.cases(base)
    with tempfile.TemporaryDirectory(prefix="cyberqalqon-m28-plans-") as temporary:
        path = Path(temporary) / "plans.db"
        AlertRepository(f"sqlite:///{path.as_posix()}", migration_target_version=17).initialize()
        repository = EventRepository(path, retention_days=30, max_records=100_000)
        with closing(repository._connect()) as connection:
            for index in range(1000):
                raw = copy.deepcopy(templates[index % len(templates)][1])
                raw["id"] = f"SYNTHETIC-M28-PLAN-{index}"
                event = normalize_wazuh_event(raw)
                repository._insert_event_row(connection, event, occurred_at=event.timestamp,
                    ingested_at=base, related_alert_id=None)
            connection.commit()
            parameters = ((base-timedelta(days=1)).isoformat(), (base+timedelta(minutes=1)).isoformat(), "Microsoft-Windows-Sysmon")
            predicate = "WHERE e.occurred_at BETWEEN ? AND ? AND e.event_provider = ? COLLATE NOCASE ORDER BY e.occurred_at DESC, e.event_id DESC LIMIT 100"
            statements = {
                "provider_default": "SELECT e.event_id FROM security_events e " + predicate,
                "provider_time_ordered_experimental": "SELECT e.event_id FROM security_events e INDEXED BY idx_security_events_occurred_id " + predicate,
            }
            observed = {}
            rows_by_shape = {}
            for name, sql in statements.items():
                plan = [str(row[3]) for row in connection.execute("EXPLAIN QUERY PLAN " + sql, parameters)]
                timings = []
                for _ in range(5):
                    started = time.perf_counter()
                    rows_by_shape[name] = [row[0] for row in connection.execute(sql, parameters)]
                    timings.append(round((time.perf_counter()-started)*1000, 3))
                observed[name] = {"plan": plan, "timings_ms": timings}
            index_rows = connection.execute("PRAGMA index_xinfo(idx_security_events_windows_provider)").fetchall()
            index_columns = [{"column": row[2], "collation": row[4], "descending": bool(row[3])} for row in index_rows if row[5]]
            analytics_plan = [str(row[3]) for row in connection.execute(
                "EXPLAIN QUERY PLAN SELECT e.event_category, COUNT(*) FROM security_events e "
                "WHERE e.occurred_at BETWEEN ? AND ? AND e.severity>=0 GROUP BY e.event_category "
                "ORDER BY COUNT(*) DESC LIMIT 10", parameters[:2])]
            fts_delete_plan = [str(row[3]) for row in connection.execute(
                "EXPLAIN QUERY PLAN DELETE FROM security_events_fts WHERE event_id=?", ("synthetic",))]
            fts_delete_trigger = str(connection.execute(
                "SELECT sql FROM sqlite_master WHERE name='security_events_fts_delete'").fetchone()[0])
            quick = connection.execute("PRAGMA quick_check").fetchone()[0]
        return {"scope": "DISPOSABLE_ONLY", "synthetic_rows": 1000, "schema": 17,
            "live_database_opened": False, "provider_index_columns": index_columns,
            "provider_shapes": observed, "provider_results_equivalent": rows_by_shape["provider_default"] == rows_by_shape["provider_time_ordered_experimental"],
            "analytics_plan": analytics_plan, "fts_retention_delete_plan": fts_delete_plan,
            "fts_delete_trigger": fts_delete_trigger, "quick_check": quick,
            "experimental_strategy_enabled": False}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = run()
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True)+"\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["provider_results_equivalent"] and result["quick_check"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
