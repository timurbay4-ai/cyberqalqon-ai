#!/usr/bin/env python3
"""Run the M20 backend rollout rehearsal against disposable state only."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import sqlite3
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = REPOSITORY_ROOT / "backend"
PYTHON = BACKEND_ROOT / ".venv" / "Scripts" / "python.exe"
DISPOSABLE_KEY = "m20-disposable-ingest-key"


def _free_loopback_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _request(
    base_url: str,
    path: str,
    *,
    payload: dict[str, Any] | None = None,
    timeout: float = 8.0,
) -> tuple[int, dict[str, Any], float]:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"Accept": "application/json"}
    if body is not None:
        headers.update(
            {
                "Content-Type": "application/json",
                "X-API-Key": DISPOSABLE_KEY,
            }
        )
    request = urllib.request.Request(base_url + path, data=body, headers=headers)
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
            return (
                int(response.status),
                json.loads(raw) if raw else {},
                (time.monotonic() - started) * 1000,
            )
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        return (
            int(exc.code),
            json.loads(raw) if raw else {},
            (time.monotonic() - started) * 1000,
        )


def _event(index: int) -> dict[str, Any]:
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "id": f"m20-rehearsal-{index}",
        "agent": {"id": "001", "name": "M20-DISPOSABLE"},
        "rule": {
            "id": "100111",
            "level": 10,
            "description": "M20 disposable rollout rehearsal",
            "groups": ["m20", "disposable"],
        },
        "decoder": {"name": "json"},
        "location": "m20-disposable",
        "full_log": f"M20 disposable event {index}",
    }


def _environment(database: Path, *, batch_enabled: bool) -> dict[str, str]:
    environment = os.environ.copy()
    environment.update(
        {
            "APP_ENV": "local",
            "APP_DEBUG": "false",
            "DATABASE_URL": f"sqlite:///{database.as_posix()}",
            "WAZUH_INGEST_API_KEY": DISPOSABLE_KEY,
            "WAZUH_INGEST_API_KEY_FILE": "",
            "ALLOW_M14_SCHEMA_MIGRATION": "false",
            "EVENT_BATCH_INGEST_ENABLED": "true" if batch_enabled else "false",
            "EVENT_BATCH_MAX_EVENTS": "10",
            "EVENT_BATCH_PROCESSING_TIMEOUT_SECONDS": "15",
            "SECURITY_EVENT_RETENTION_DAYS": "30",
            "SECURITY_EVENT_MAX_RECORDS": "100",
            "AI_ENABLED": "false",
        }
    )
    return environment


def _start_backend(
    database: Path,
    port: int,
    directory: Path,
    *,
    batch_enabled: bool,
) -> tuple[subprocess.Popen[bytes], str]:
    command = [
        str(PYTHON),
        "-m",
        "uvicorn",
        "app.main:app",
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
    ]
    process = subprocess.Popen(
        command,
        cwd=BACKEND_ROOT,
        env=_environment(database, batch_enabled=batch_enabled),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    base_url = f"http://127.0.0.1:{port}"
    for _ in range(120):
        if process.poll() is not None:
            raise RuntimeError(f"isolated backend exited with code {process.returncode}")
        try:
            if _request(base_url, "/health", timeout=0.5)[0] == 200:
                return process, base_url
        except (OSError, TimeoutError, urllib.error.URLError):
            pass
        time.sleep(0.1)
    process.terminate()
    process.wait(timeout=5)
    raise RuntimeError("isolated backend did not become healthy")


def _stop_backend(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def _sha256_tree(path: Path) -> str:
    digest = hashlib.sha256()
    for item in sorted(p for p in path.rglob("*.py") if "__pycache__" not in p.parts):
        digest.update(item.relative_to(path).as_posix().encode("utf-8"))
        digest.update(item.read_bytes())
    return digest.hexdigest()


def run(output: Path) -> dict[str, Any]:
    if not PYTHON.is_file():
        raise RuntimeError(f"backend Python is unavailable: {PYTHON}")
    result: dict[str, Any] = {
        "status": "FAIL",
        "scope": "DISPOSABLE_ONLY",
        "source_sha256": _sha256_tree(BACKEND_ROOT / "app"),
        "live_state_touched": False,
        "browser_uat": "DEFERRED_BY_USER",
    }
    with tempfile.TemporaryDirectory(prefix="cyberqalqon-m20-rehearsal-") as raw:
        directory = Path(raw)
        database = directory / "m20-rehearsal.db"
        port = _free_loopback_port()
        process: subprocess.Popen[bytes] | None = None
        try:
            process, base_url = _start_backend(
                database, port, directory, batch_enabled=False
            )
            result["startup_command"] = (
                "backend/.venv/Scripts/python.exe -m uvicorn app.main:app "
                f"--host 127.0.0.1 --port {port}"
            )
            result["initial_health"] = _request(base_url, "/health")[:2]
            result["initial_readiness"] = _request(base_url, "/readiness")[:2]

            alert = json.loads(
                (REPOSITORY_ROOT / "wazuh" / "samples" / "authentication-failure.json")
                .read_text(encoding="utf-8")
            )
            alert["timestamp"] = datetime.now(timezone.utc).isoformat()
            alert["id"] = "m20-protected-alert"
            alert_status, alert_body, _ = _request(
                base_url, "/api/v1/alerts/ingest", payload=alert
            )
            if alert_status != 201:
                raise RuntimeError(f"protected alert seed failed: HTTP {alert_status}")
            protected_alert_id = str(alert_body["alert"]["alert_id"])

            for index in range(1, 100):
                status_code, _, _ = _request(
                    base_url, "/api/v1/events/ingest", payload=_event(index)
                )
                if status_code != 201:
                    raise RuntimeError(f"single seed {index} failed: HTTP {status_code}")

            duplicate_fixture = _event(100)
            new_status, _, new_ms = _request(
                base_url, "/api/v1/events/ingest", payload=duplicate_fixture
            )
            duplicate_status, _, duplicate_ms = _request(
                base_url, "/api/v1/events/ingest", payload=duplicate_fixture
            )
            result["single_event"] = {
                "new_status": new_status,
                "duplicate_status": duplicate_status,
                "new_latency_ms": round(new_ms, 3),
                "duplicate_latency_ms": round(duplicate_ms, 3),
            }

            locker = sqlite3.connect(database, timeout=1)
            locked_response: dict[str, Any] = {}
            try:
                locker.execute("BEGIN IMMEDIATE")

                def blocked_write() -> None:
                    status_code, _, latency = _request(
                        base_url,
                        "/api/v1/events/ingest",
                        payload=_event(101),
                        timeout=8,
                    )
                    locked_response.update(status=status_code, latency_ms=latency)

                writer = threading.Thread(target=blocked_write, daemon=True)
                writer.start()
                time.sleep(0.2)
                health_latencies = [
                    _request(base_url, "/health", timeout=1)[2] for _ in range(5)
                ]
                locker.rollback()
                writer.join(timeout=8)
                if writer.is_alive():
                    raise RuntimeError("blocked disposable writer did not recover")
            finally:
                try:
                    locker.rollback()
                except sqlite3.Error:
                    pass
                locker.close()
            result["health_during_locked_writer"] = {
                "samples_ms": [round(value, 3) for value in health_latencies],
                "max_ms": round(max(health_latencies), 3),
                "writer_status": locked_response.get("status"),
                "writer_latency_ms": round(float(locked_response.get("latency_ms", 0)), 3),
            }

            _stop_backend(process)
            process = None
            process, base_url = _start_backend(
                database, port, directory, batch_enabled=False
            )
            restart_duplicate = _request(
                base_url, "/api/v1/events/ingest", payload=duplicate_fixture
            )[0]
            result["restart_duplicate_status"] = restart_duplicate

            _stop_backend(process)
            process = None
            process, base_url = _start_backend(
                database, port, directory, batch_enabled=True
            )
            batch_status, batch_body, batch_ms = _request(
                base_url,
                "/api/v1/events/ingest-batch",
                payload={
                    "protocol_version": "m18-batch-v1",
                    "batch_id": "m20-disposable-batch-10",
                    "events": [_event(200 + index) for index in range(10)],
                },
                timeout=20,
            )
            result["isolated_batch_10"] = {
                "status": batch_status,
                "inserted": batch_body.get("inserted"),
                "duplicates": batch_body.get("duplicates"),
                "latency_ms": round(batch_ms, 3),
            }

            _stop_backend(process)
            process = None
            process, base_url = _start_backend(
                database, port, directory, batch_enabled=False
            )
            rollback_batch_status = _request(
                base_url,
                "/api/v1/events/ingest-batch",
                payload={
                    "protocol_version": "m18-batch-v1",
                    "batch_id": "m20-disabled-after-rollback",
                    "events": [_event(999)],
                },
            )[0]
            rollback_single_status = _request(
                base_url, "/api/v1/events/ingest", payload=_event(300)
            )[0]
            result["configuration_rollback"] = {
                "batch_status": rollback_batch_status,
                "single_status": rollback_single_status,
            }

            with closing(sqlite3.connect(database)) as connection:
                quick_check = str(connection.execute("PRAGMA quick_check").fetchone()[0])
                foreign_keys = len(connection.execute("PRAGMA foreign_key_check").fetchall())
                schema = int(connection.execute("PRAGMA user_version").fetchone()[0])
                event_count = int(
                    connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
                )
                protected_count = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM security_events WHERE related_alert_id = ?",
                        (protected_alert_id,),
                    ).fetchone()[0]
                )
                duplicate_event_ids = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM (SELECT event_id FROM security_events "
                        "GROUP BY event_id HAVING COUNT(*) > 1)"
                    ).fetchone()[0]
                )
            result["sqlite"] = {
                "schema": schema,
                "quick_check": quick_check,
                "foreign_key_errors": foreign_keys,
                "event_count": event_count,
                "protected_alert_events": protected_count,
                "duplicate_event_id_groups": duplicate_event_ids,
            }
            passed = all(
                (
                    new_status == 201,
                    duplicate_status == 200,
                    locked_response.get("status") == 201,
                    restart_duplicate == 200,
                    batch_status == 201,
                    rollback_batch_status == 503,
                    rollback_single_status == 201,
                    quick_check == "ok",
                    foreign_keys == 0,
                    schema == 17,
                    protected_count >= 1,
                    duplicate_event_ids == 0,
                    max(health_latencies) < 500,
                )
            )
            result["status"] = "PASS" if passed else "FAIL"
        finally:
            if process is not None:
                _stop_backend(process)

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=REPOSITORY_ROOT / "artifacts" / "runtime" / "m20-backend-rollout-rehearsal.json",
    )
    args = parser.parse_args()
    result = run(args.output.resolve())
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
