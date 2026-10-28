#!/usr/bin/env python3
"""M28 mixed-source normalization and schema-17 benchmark; disposable DB only."""

from __future__ import annotations

import argparse
import copy
import gc
import hashlib
import json
import secrets
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


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "scripts"))

import m28_synthetic  # noqa: E402
from benchmark_cqql import percentile, process_memory  # noqa: E402
from app.core.config import Settings  # noqa: E402
from app.db.alerts import AlertRepository  # noqa: E402
from app.db.events import EventRepository  # noqa: E402
from app.db.cqql import CQQLSearchRepository, CQQLQueryTimeoutError, CQQLQueryBusyError  # noqa: E402
from app.main import create_app  # noqa: E402
from app.schemas.auth import AnalystCreate, AnalystRole  # noqa: E402
from app.services.cqql import compile_cqql  # noqa: E402
from app.services.event_normalizer import normalize_wazuh_event, _normalize_legacy_wazuh_event, EventNormalizationError  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


def stats(samples: list[float]) -> dict:
    return {"samples": len(samples), "p50_ms": round(statistics.median(samples), 4),
            "p95_ms": round(percentile(samples, .95), 4), "max_ms": round(max(samples), 4)}


def run(sizes: list[int], *, normalization_only: bool = False) -> dict:
    base = datetime.now(timezone.utc).replace(microsecond=0)
    templates = m28_synthetic.cases(base)
    samples: dict[str, list[float]] = {}
    legacy_samples = []
    sizes_bytes = []
    tracemalloc.start()
    normalization_started = time.perf_counter()
    for iteration in range(50):
        for name, raw, _ in templates:
            started = time.perf_counter()
            normalized = normalize_wazuh_event(raw)
            elapsed = (time.perf_counter() - started) * 1000
            family = normalized.structured_payload["_cuse"]["source_family"]
            samples.setdefault(family, []).append(elapsed)
            started = time.perf_counter()
            _normalize_legacy_wazuh_event(raw)
            legacy_samples.append((time.perf_counter() - started) * 1000)
            if iteration == 0:
                sizes_bytes.append(len(json.dumps(raw).encode()))
    normalization_seconds = time.perf_counter() - normalization_started
    _, allocation_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    invalid = m28_synthetic.windows(0, base)
    invalid["timestamp"] = "invalid"
    started = time.perf_counter()
    rejected = 0
    for _ in range(100):
        try:
            normalize_wazuh_event(invalid)
        except EventNormalizationError:
            rejected += 1
    rejection_ms = (time.perf_counter() - started) * 1000
    report = {
        "label": "SYNTHETIC_M28_DISPOSABLE_BENCHMARK", "generated_at": base.isoformat(),
        "scope": "DISPOSABLE_ONLY", "live_database_opened": False,
        "schema": 17, "query_deadline_seconds": 1.5, "query_concurrency": 4,
        "normalization_by_family": {family: stats(values) for family, values in samples.items()},
        "legacy_same_population": stats(legacy_samples),
        "mixed_normalization": stats([value for values in samples.values() for value in values]),
        "normalization_events_per_second": round(sum(map(len, samples.values())) / (sum(map(sum, samples.values())) / 1000), 3),
        "normalization_sample_wall_seconds": round(normalization_seconds, 3),
        "normalization_tracemalloc_peak_bytes": allocation_peak,
        "payload_bytes_min": min(sizes_bytes), "payload_bytes_max": max(sizes_bytes),
        "invalid_source_rejected": rejected, "invalid_source_100_rejections_ms": round(rejection_ms, 3),
        "populations": [],
    }
    if normalization_only:
        report["pass"] = rejected == 100
        return report
    with tempfile.TemporaryDirectory(prefix="cyberqalqon-m28-mixed-") as temporary:
        path = Path(temporary) / "mixed.db"
        AlertRepository(f"sqlite:///{path.as_posix()}", migration_target_version=17).initialize()
        event_repository = EventRepository(path, retention_days=30, max_records=100_000)
        inserted = 0
        cpu_started = time.process_time()

        def raw_event(index: int) -> dict:
            raw = copy.deepcopy(templates[index % len(templates)][1])
            raw["id"] = f"SYNTHETIC-M28-POPULATION-{index:012d}"
            return raw

        settings = Settings(database_url=f"sqlite:///{path.as_posix()}",
                            wazuh_ingest_api_key="M28-" + secrets.token_urlsafe(32),
                            allow_m14_schema_migration=False)
        password = "M28-" + secrets.token_urlsafe(24)
        with TestClient(create_app(settings)) as client:
            retention_samples: list[float] = []
            active_repository = client.app.state.event_repository
            enforce_retention = active_repository._enforce_retention
            def measured_retention(*args, **kwargs):
                started = time.perf_counter()
                try:
                    return enforce_retention(*args, **kwargs)
                finally:
                    retention_samples.append((time.perf_counter()-started)*1000)
            active_repository._enforce_retention = measured_retention
            client.app.state.auth_repository.bootstrap_first_admin(AnalystCreate(
                username="m28-disposable", display_name="M28 Synthetic Benchmark",
                password=password, role=AnalystRole.ADMIN))
            login = client.post("/api/v1/auth/login", headers={"Origin": "http://localhost:5173"},
                                json={"username": "m28-disposable", "password": password})
            if login.status_code != 200:
                raise RuntimeError("disposable login failed")
            client.headers.update({"Origin": "http://localhost:5173", "X-CSRF-Token": login.json()["csrf_token"]})
            for size in sizes:
                started = time.perf_counter()
                # Population uses the actual normalizer and insert helper inside
                # transactions; API latency below uses single-event commits.
                with closing(event_repository._connect()) as connection:
                    for batch_start in range(inserted, size, 500):
                        for index in range(batch_start, min(size, batch_start + 500)):
                            event = normalize_wazuh_event(raw_event(index))
                            event_repository._insert_event_row(connection, event,
                                occurred_at=event.timestamp, ingested_at=base, related_alert_id=None)
                        connection.commit()
                    connection.execute("UPDATE security_event_store_state SET retained_records=(SELECT COUNT(*) FROM security_events) WHERE singleton=1")
                    connection.commit()
                population_ms = (time.perf_counter() - started) * 1000
                inserted = size
                new_samples = []
                duplicates = []
                retention_samples.clear()
                for offset in range(12):
                    raw = raw_event(size * 10 + offset)
                    for expected_status, timings in ((201, new_samples), (200, duplicates)):
                        started = time.perf_counter()
                        response = client.post("/api/v1/events/ingest", headers={"X-API-Key": settings.wazuh_ingest_api_key}, json=raw)
                        timings.append((time.perf_counter() - started) * 1000)
                        if response.status_code != expected_status:
                            raise RuntimeError(f"single-event contract mismatch: HTTP {response.status_code}")
                search = {}
                for name, query in {
                    "windows_failure": 'event.code = "4625"',
                    "sysmon_provider": 'event.provider = "Microsoft-Windows-Sysmon"',
                    "source_pivot": 'source.ip = "192.0.2.28"',
                    "nested": '(event.code = "4625" OR event.code = "4688") AND event.severity >= 7',
                }.items():
                    timings = []
                    timeouts = 0
                    for _ in range(5):
                        started = time.perf_counter()
                        try:
                            CQQLSearchRepository(path).search(compile_cqql(query), start_time=base-timedelta(days=1),
                                end_time=base+timedelta(minutes=1), sort="newest", limit=100, cursor=None)
                        except CQQLQueryTimeoutError:
                            timeouts += 1
                        else:
                            timings.append((time.perf_counter()-started)*1000)
                    search[name] = {**(stats(timings) if timings else {}), "timeouts": timeouts}
                started = time.perf_counter()
                analytics = client.post("/api/v1/siem/search/analytics", json={
                    "query": 'event.severity >= 0', "start_time": (base-timedelta(days=1)).isoformat(),
                    "end_time": (base+timedelta(minutes=1)).isoformat(), "group_by": ["event.category"], "interval": "day"})
                analytics_ms = (time.perf_counter()-started)*1000
                with closing(sqlite3.connect(path)) as connection:
                    count = int(connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0])
                    quick = str(connection.execute("PRAGMA quick_check").fetchone()[0])
                    fk = len(connection.execute("PRAGMA foreign_key_check").fetchall())
                    schema = int(connection.execute("PRAGMA user_version").fetchone()[0])
                    cuse_count = int(connection.execute("SELECT COUNT(*) FROM security_events WHERE json_extract(structured_json, '$._cuse.version')='cuse-v1'").fetchone()[0])
                    evidence_mismatches = 0
                    for event_id, dedup, raw_json in connection.execute("SELECT event_id, deduplication_id, raw_event_json FROM security_events"):
                        digest = hashlib.sha256(raw_json.encode()).hexdigest()
                        evidence_mismatches += int(digest != dedup or event_id != f"EVT-{digest[:24].upper()}")
                    wal = path.with_name(path.name + "-wal")
                    wal_bytes = wal.stat().st_size if wal.exists() else 0
                report["populations"].append({"events_seeded": size, "event_count_after_api_samples": count,
                    "cuse_records": cuse_count, "schema": schema, "population_ms": round(population_ms, 3),
                    "single_event_http_ingest": stats(new_samples), "duplicate_http_ack": stats(duplicates),
                    "retention": stats(retention_samples), "synthetic_evidence_mismatches": evidence_mismatches,
                    "search": search, "analytics_http_status": analytics.status_code,
                    "analytics_wall_ms": round(analytics_ms, 3), "quick_check": quick,
                    "foreign_key_violations": fk, "database_bytes": path.stat().st_size,
                    "wal_bytes": wal_bytes, "process_cpu_seconds": round(time.process_time()-cpu_started, 3), **process_memory()})
                print(f"verified disposable population={size}, count={count}, quick_check={quick}", flush=True)
            import threading
            barrier = threading.Barrier(5)
            def reader(index: int) -> dict:
                barrier.wait()
                completed = timeouts = busy = 0
                for _ in range(5):
                    try:
                        CQQLSearchRepository(path).search(compile_cqql('event.provider = "Microsoft-Windows-Sysmon"'),
                            start_time=base-timedelta(days=1), end_time=base+timedelta(minutes=1),
                            sort="newest", limit=100, cursor=None)
                        completed += 1
                    except CQQLQueryTimeoutError:
                        timeouts += 1
                    except CQQLQueryBusyError:
                        busy += 1
                return {"completed": completed, "timeouts": timeouts, "busy": busy}
            def writer() -> list[float]:
                barrier.wait()
                timings = []
                for index in range(8):
                    event = normalize_wazuh_event(raw_event(5_000_000 + index))
                    started = time.perf_counter()
                    active_repository.ingest(event)
                    timings.append((time.perf_counter()-started)*1000)
                return timings
            with ThreadPoolExecutor(max_workers=5) as executor:
                readers = [executor.submit(reader, index) for index in range(4)]
                writer_future = executor.submit(writer)
                writer_timings = writer_future.result()
                read_results = [future.result() for future in readers]
            report["concurrent_writer_readers"] = {"single_event_writer": stats(writer_timings), "readers": read_results}
        report["integrity_pass"] = all(p["quick_check"] == "ok" and p["foreign_key_violations"] == 0 and p["schema"] == 17 and p["event_count_after_api_samples"] <= 100_000
            and p["synthetic_evidence_mismatches"] == 0 and p["cuse_records"] == p["event_count_after_api_samples"] for p in report["populations"])
        report["performance_status"] = "PASS" if all(
            population["analytics_http_status"] == 200 and
            all(query["timeouts"] == 0 for query in population["search"].values())
            for population in report["populations"]
        ) and all(reader["timeouts"] == 0 for reader in report["concurrent_writer_readers"]["readers"]) else "BLOCKED"
        report["pass"] = report["integrity_pass"] and report["performance_status"] == "PASS"
        # sqlite transaction context managers commit but cyclic references from
        # TestClient can postpone handle finalization on Windows.
        gc.collect()
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sizes", nargs="+", type=int, default=[10_000, 50_000, 100_000])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--normalization-only", action="store_true")
    args = parser.parse_args()
    if any(size < 1 or size > 100_000 for size in args.sizes):
        parser.error("sizes must be between 1 and 100000")
    report = run(sorted(set(args.sizes)), normalization_only=args.normalization_only)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
