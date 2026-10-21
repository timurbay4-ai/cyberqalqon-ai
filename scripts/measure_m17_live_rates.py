"""Bounded, read-only M17 live ingestion rate sampler.

The sampler reads the durable shipper state and active archive through WSL,
reads aggregate SQLite retention counters in read-only mode, and measures health
latency. It never changes a cursor, archive, database row, service, or network
configuration.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import time
from typing import Any
from urllib.request import urlopen


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATABASE = ROOT / "backend" / "data" / "cyberqalqon-local-lab.db"
DEFAULT_OUTPUT = ROOT / "artifacts" / "runtime" / "m17-live-rate-sample.json"

WSL_SNAPSHOT = r"""
import json, os, time, urllib.request
state_path = "/var/lib/cyberqalqon-sender/event-shipper-state.json"
archive_path = "/var/ossec/logs/archives/archives.json"
state = json.load(open(state_path, encoding="utf-8"))
archive = os.stat(archive_path)
started = time.perf_counter()
try:
    with urllib.request.urlopen("http://127.0.0.1:18000/health", timeout=5) as response:
        relay_status = int(response.status)
except Exception:
    relay_status = None
relay_latency_ms = (time.perf_counter() - started) * 1000.0
print(json.dumps({
    "captured_at_epoch": time.time(),
    "state_version": int(state.get("version", 0)),
    "archive_size_bytes": int(archive.st_size),
    "archive_device": int(archive.st_dev),
    "archive_inode": int(archive.st_ino),
    "cursor_bytes": int(state["offset"]),
    "cursor_device": int(state["device"]),
    "cursor_inode": int(state["inode"]),
    "accepted": int(state.get("accepted", 0)),
    "filtered": int(state.get("filtered_events", state.get("skipped", 0))),
    "malformed": int(state.get("malformed_json", 0)),
    "oversized": int(state.get("oversized_lines", 0)),
    "delivery_rejected": int(state.get("delivery_rejected", state.get("rejected", 0))),
    "retry_attempts": int(state.get("retry_attempts", 0)),
    "updated_at_epoch": float(state.get("updated_at", 0)),
    "relay_health_status": relay_status,
    "relay_health_latency_ms": round(relay_latency_ms, 3),
}, sort_keys=True))
"""


def _wsl_snapshot(distro: str) -> dict[str, Any]:
    result = subprocess.run(
        ["wsl.exe", "-d", distro, "-u", "root", "--", "python3", "-c", WSL_SNAPSHOT],
        cwd=ROOT,
        capture_output=True,
        check=False,
        text=True,
        timeout=15,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "WSL shipper snapshot failed")
    return json.loads(result.stdout)


def _database_snapshot(path: Path) -> dict[str, Any]:
    wal = Path(f"{path}-wal")
    with sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True, timeout=10) as connection:
        details = [
            json.loads(row[0])
            for row in connection.execute(
                "SELECT details_json FROM security_audit_events "
                "WHERE action='SECURITY_EVENT_RETENTION'"
            ).fetchall()
        ]
        count, last_ingested = connection.execute(
            "SELECT COUNT(*), MAX(ingested_at) FROM security_events"
        ).fetchone()
        protected = int(
            connection.execute(
                """
                SELECT COUNT(*) FROM security_events e JOIN (
                    SELECT event_id AS protected_event_id FROM case_events
                    UNION SELECT evidence_id FROM incident_evidence_pins
                          WHERE evidence_type='EVENT'
                    UNION SELECT reference_id FROM case_evidence_refs
                          WHERE reference_type='EVENT'
                    UNION SELECT e2.event_id FROM security_events e2
                          JOIN alerts a ON a.alert_id=
                              COALESCE(e2.related_alert_id,e2.source_event_id)
                ) p ON p.protected_event_id=e.event_id
                """
            ).fetchone()[0]
        )
    return {
        "event_count": int(count),
        "protected_event_count": protected,
        "last_ingested_at": last_ingested,
        "retention_audit_rows": len(details),
        "retention_deleted_by_limit": sum(
            int(item.get("deleted_by_limit", 0)) for item in details
        ),
        "retention_deleted_by_age": sum(
            int(item.get("deleted_by_age", 0)) for item in details
        ),
        "database_bytes": path.stat().st_size,
        "wal_bytes": wal.stat().st_size if wal.exists() else 0,
    }


def _http_latency(url: str) -> dict[str, Any]:
    started = time.perf_counter()
    status: int | None = None
    try:
        with urlopen(url, timeout=5) as response:  # noqa: S310 - fixed loopback URL.
            status = int(response.status)
    except OSError:
        status = None
    return {
        "status": status,
        "latency_ms": round((time.perf_counter() - started) * 1000.0, 3),
    }


def _rate(delta: int, duration: float) -> float:
    return round(delta / duration, 3)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=int, default=30)
    parser.add_argument("--distro", default="Ubuntu-24.04")
    parser.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    if not 10 <= args.seconds <= 120:
        parser.error("--seconds must be between 10 and 120")
    database = args.database.resolve()
    output = args.output.resolve()
    if ROOT not in output.parents:
        parser.error("--output must remain below the repository root")
    if not database.is_file():
        parser.error("database file does not exist")

    start_shipper = _wsl_snapshot(args.distro)
    start_database = _database_snapshot(database)
    start_backend = _http_latency("http://127.0.0.1:8000/health")
    started = time.monotonic()
    time.sleep(args.seconds)
    duration = time.monotonic() - started
    end_shipper = _wsl_snapshot(args.distro)
    end_database = _database_snapshot(database)
    end_backend = _http_latency("http://127.0.0.1:8000/health")

    keys = (
        "archive_size_bytes",
        "cursor_bytes",
        "accepted",
        "filtered",
        "malformed",
        "oversized",
        "delivery_rejected",
        "retry_attempts",
    )
    deltas = {
        key: int(end_shipper[key]) - int(start_shipper[key]) for key in keys
    }
    start_lag = int(start_shipper["archive_size_bytes"]) - int(start_shipper["cursor_bytes"])
    end_lag = int(end_shipper["archive_size_bytes"]) - int(end_shipper["cursor_bytes"])
    deltas["archive_lag_bytes"] = end_lag - start_lag
    deltas["retention_deleted_by_limit"] = (
        int(end_database["retention_deleted_by_limit"])
        - int(start_database["retention_deleted_by_limit"])
    )
    deltas["wal_bytes"] = int(end_database["wal_bytes"]) - int(start_database["wal_bytes"])
    net_lag_rate = _rate(deltas["archive_lag_bytes"], duration)
    drain_seconds = (
        round(end_lag / -net_lag_rate, 3) if net_lag_rate < 0 and end_lag > 0 else None
    )
    report = {
        "version": 1,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": round(duration, 3),
        "start": {
            "shipper": start_shipper,
            "database": start_database,
            "backend_health": start_backend,
        },
        "end": {
            "shipper": end_shipper,
            "database": end_database,
            "backend_health": end_backend,
        },
        "deltas": deltas,
        "rates_per_second": {
            "archive_growth_bytes": _rate(deltas["archive_size_bytes"], duration),
            "cursor_progress_bytes": _rate(deltas["cursor_bytes"], duration),
            "net_archive_lag_bytes": net_lag_rate,
            "successful_acknowledgements": _rate(deltas["accepted"], duration),
            "filtered_records": _rate(deltas["filtered"], duration),
            "retention_insert_proxy": _rate(
                deltas["retention_deleted_by_limit"], duration
            ),
        },
        "backlog_trend": (
            "DRAINING" if net_lag_rate < 0 else "GROWING" if net_lag_rate > 0 else "STABLE"
        ),
        "estimated_drain_seconds": drain_seconds,
        "accounting_notes": {
            "state_version": int(end_shipper["state_version"]),
            "historic_duplicate_count": None,
            "accepted_counter_semantics": "V2_MIXED_INSERT_AND_DUPLICATE_ACKNOWLEDGEMENT",
            "retention_insert_proxy": (
                "At the exact cap with zero protected events, deleted_by_limit tracks "
                "unique insert pressure during this sample; it is not a durable v3 counter."
            ),
        },
        "host": {
            "disk_free_bytes": os.statvfs(ROOT).f_bavail * os.statvfs(ROOT).f_frsize
            if hasattr(os, "statvfs")
            else None
        },
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(temporary, output)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
