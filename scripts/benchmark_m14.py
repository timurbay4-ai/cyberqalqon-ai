"""Laptop-light M14 benchmark using one automatically removed SQLite database."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import statistics
import sys
import tempfile
import time
import tracemalloc
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.db.detection_readiness import DetectionReadinessRepository  # noqa: E402
from app.db.migrations import apply_migrations  # noqa: E402
from app.schemas.auth import AnalystPrincipal, AnalystRole, Permission  # noqa: E402
from app.schemas.detection_readiness import (  # noqa: E402
    CorrelationReplayRequest,
    DetectionTuningRequest,
    ShadowRunRequest,
    TuningCandidate,
)
from app.services.advanced_detection import AdvancedDetectionEngine, RULES  # noqa: E402


def _measure(operation: Callable[[], object], runs: int) -> dict[str, float | int]:
    operation()
    wall: list[float] = []
    cpu: list[float] = []
    for _ in range(runs):
        wall_started = time.perf_counter()
        cpu_started = time.process_time()
        operation()
        cpu.append((time.process_time() - cpu_started) * 1000)
        wall.append((time.perf_counter() - wall_started) * 1000)
    ordered = sorted(wall)
    return {
        "runs": runs,
        "wall_median_ms": round(statistics.median(wall), 3),
        "wall_p95_ms": round(ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))], 3),
        "wall_max_ms": round(max(wall), 3),
        "cpu_median_ms": round(statistics.median(cpu), 3),
    }


def _insert_events(database: Path, count: int, anchor: datetime) -> None:
    sql = """
        INSERT INTO security_events (
            event_id, deduplication_id, event_code, occurred_at, ingested_at,
            source_type, hostname, source_ip, username, event_category,
            event_action, outcome, message, structured_json, raw_event_json,
            ingestion_source, raw_size_bytes, search_text, operating_system,
            normalization_schema
        ) VALUES (?, ?, '4625', ?, ?, 'windows_event', ?, ?, ?,
                  'windows_security', 'logon-failed', 'failure', ?, '{}', ?,
                  'm14_benchmark', ?, ?, 'windows', 'wazuh-event-v2')
    """
    rows: list[tuple[object, ...]] = []
    for index in range(count):
        group = index // 5
        event_id = f"EVT-M14-BENCH-{index:08d}"
        occurred = anchor + timedelta(milliseconds=index * 5)
        host = f"WIN-{group % 200:03d}"
        user = f"user-{group % 1000:04d}"
        source_ip = f"192.0.2.{group % 250 + 1}"
        message = f"Synthetic failed logon benchmark event {index}"
        raw = json.dumps({
            "data": {"win": {"eventdata": {
                "targetUserName": user,
                "ipAddress": source_ip,
                "logonType": "3",
                "status": "0xC000006D",
            }}},
        }, separators=(",", ":"))
        search = f"4625 {host} {user} {source_ip}"
        rows.append((
            event_id, hashlib.sha256(event_id.encode()).hexdigest(),
            occurred.isoformat(), occurred.isoformat(), host, source_ip, user,
            message, raw, len(raw), search,
        ))
    with closing(sqlite3.connect(database)) as connection, connection:
        for start in range(0, len(rows), 1000):
            connection.executemany(sql, rows[start:start + 1000])
            connection.commit()


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="cyberqalqon-m14-") as directory:
        database = Path(directory) / "m14.db"
        with closing(sqlite3.connect(database)) as connection, connection:
            apply_migrations(connection)
        anchor = datetime.now(timezone.utc) - timedelta(hours=1)
        _insert_events(database, 10_000, anchor)
        size_after_events = database.stat().st_size

        engine = AdvancedDetectionEngine(database)
        repository = DetectionReadinessRepository(database, engine)
        repository.ensure_defaults()
        now = datetime.now(timezone.utc).isoformat()
        with closing(sqlite3.connect(database)) as connection, connection:
            connection.execute(
                "INSERT INTO analysts (analyst_id,username,username_normalized,display_name,"
                "role,password_hash,is_active,created_at,updated_at) "
                "VALUES ('ANALYST-M14-BENCH','m14-bench','m14-bench','M14 Benchmark',"
                "'ADMIN','benchmark-not-a-login-secret',1,?,?)",
                (now, now),
            )
        principal = AnalystPrincipal(
            analyst_id="ANALYST-M14-BENCH",
            username="m14-bench",
            display_name="M14 Benchmark",
            role=AnalystRole.ADMIN,
            permissions=[Permission.SOC_READ, Permission.ALERT_WRITE, Permission.ANALYST_MANAGE],
        )
        start = anchor - timedelta(minutes=1)
        end = datetime.now(timezone.utc)
        loaded = engine.load_events(start, end, 5000)

        single = _measure(
            lambda: engine.evaluate_events(
                "DET-001", loaded, evaluation_end=end, max_findings=100
            ),
            10,
        )
        nine = _measure(
            lambda: [
                engine.evaluate_events(
                    spec.rule_id, loaded, evaluation_end=end, max_findings=100
                )
                for spec in RULES
            ],
            5,
        )
        inventory = _measure(repository.lifecycle_inventory, 20)
        sqlite_query = _measure(
            lambda: engine.load_events(start, end, 1000),
            20,
        )
        tuning_payload = DetectionTuningRequest(
            relative_minutes=1440,
            candidates=[
                TuningCandidate(threshold_count=5, time_window_seconds=300),
                TuningCandidate(threshold_count=10, time_window_seconds=300),
            ],
            max_events=5000,
            max_findings=200,
            max_execution_ms=5000,
        )
        tuning = _measure(
            lambda: repository.tuning_comparison("DET-001", tuning_payload),
            5,
        )

        tracemalloc.start()
        shadow_payload = ShadowRunRequest(
            relative_minutes=1440,
            max_events=5000,
            max_findings=200,
            max_execution_ms=5000,
        )
        shadow = _measure(
            lambda: repository.run_shadow("DET-001", shadow_payload, principal),
            3,
        )
        _, peak_bytes = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        replay_payload = CorrelationReplayRequest(
            relative_minutes=1440,
            max_events=5000,
            max_findings=200,
            max_execution_ms=5000,
        )
        persistence_started = time.perf_counter()
        first_replay = repository.replay_correlation_state("DET-001", replay_payload)
        persistence_ms = (time.perf_counter() - persistence_started) * 1000
        recovery_started = time.perf_counter()
        second_replay = repository.replay_correlation_state("DET-001", replay_payload)
        recovery_ms = (time.perf_counter() - recovery_started) * 1000

        concurrent_started = time.perf_counter()
        with ThreadPoolExecutor(max_workers=4) as pool:
            concurrent_results = list(pool.map(
                lambda _: repository.lifecycle_inventory(), range(12)
            ))
        concurrent_ms = (time.perf_counter() - concurrent_started) * 1000

        with closing(sqlite3.connect(database)) as connection, connection:
            quick_check = connection.execute("PRAGMA quick_check").fetchone()[0]
            foreign_keys = len(connection.execute("PRAGMA foreign_key_check").fetchall())
            production_counts = {
                table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in ("alerts", "incidents", "soc_cases")
            }
        result = {
            "dataset_events": 10_000,
            "bounded_evaluation_events": len(loaded),
            "single_rule": single,
            "nine_rules": nine,
            "shadow_run": shadow,
            "tuning_comparison": tuning,
            "rule_inventory": inventory,
            "sqlite_bounded_query": sqlite_query,
            "state_persistence_ms": round(persistence_ms, 3),
            "state_recovery_ms": round(recovery_ms, 3),
            "first_replay_new_events": first_replay.newly_processed_event_count,
            "second_replay_new_events": second_replay.newly_processed_event_count,
            "second_replay_duplicates": second_replay.duplicate_event_count,
            "concurrent_inventory": {
                "workers": 4,
                "queries": len(concurrent_results),
                "wall_ms": round(concurrent_ms, 3),
            },
            "python_peak_tracked_bytes_shadow": peak_bytes,
            "database_bytes_after_events": size_after_events,
            "database_bytes_after_m14_runs": database.stat().st_size,
            "quick_check": quick_check,
            "foreign_key_errors": foreign_keys,
            "production_side_effect_counts": production_counts,
        }
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if (
            quick_check == "ok"
            and foreign_keys == 0
            and production_counts == {"alerts": 0, "incidents": 0, "soc_cases": 0}
            and second_replay.newly_processed_event_count == 0
        ) else 1


if __name__ == "__main__":
    raise SystemExit(main())
