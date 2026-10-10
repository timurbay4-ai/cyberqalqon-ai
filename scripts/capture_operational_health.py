"""Capture a bounded, read-only local lab health snapshot and record transitions.

The collector does not run as a daemon and does not change Wazuh, Windows
services, firewall rules, or enrollment. It records only sanitized metrics.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import subprocess
import sys
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = REPOSITORY_ROOT / "backend"
DEFAULT_DATABASE = BACKEND_ROOT / "data" / "cyberqalqon-local-lab.db"
DEFAULT_OUTPUT = REPOSITORY_ROOT / "artifacts" / "runtime" / "operational-health.json"
sys.path.insert(0, str(BACKEND_ROOT))

from app.core.config import Settings  # noqa: E402
from app.db.operations import OperationalRepository  # noqa: E402
from app.schemas.operations import ComponentObservation, OperationalSnapshot  # noqa: E402
from app.services.wazuh_api import WazuhApiClient  # noqa: E402


def _run(arguments: list[str], *, timeout: int = 10) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        arguments,
        cwd=REPOSITORY_ROOT,
        capture_output=True,
        check=False,
        text=True,
        timeout=timeout,
    )


def _wsl(distro: str, command: str) -> subprocess.CompletedProcess[str]:
    return _run(["wsl.exe", "-d", distro, "-u", "root", "--", "bash", "-lc", command])


def _component(
    key: str,
    kind: str,
    state: str,
    authority: str,
    summary: str,
    observed_at: datetime,
    *,
    metrics: dict[str, Any] | None = None,
    last_error: str | None = None,
) -> ComponentObservation:
    return ComponentObservation(
        component_key=key,
        component_kind=kind,
        state=state,
        authority=authority,
        summary=summary,
        metrics=metrics or {},
        last_error=last_error,
        observed_at=observed_at,
    )


def manager_observation(distro: str, now: datetime) -> ComponentObservation:
    result = _wsl(
        distro,
        "printf '%s\\n' \"$(systemctl is-active wazuh-manager 2>/dev/null || true)\" "
        "\"$(hostname)\" \"$(/var/ossec/bin/wazuh-control info 2>/dev/null "
        "| sed -n 's/^WAZUH_VERSION=\"\\(.*\\)\"/\\1/p' | head -n1)\"",
    )
    lines = [line.strip() for line in result.stdout.splitlines()]
    active = result.returncode == 0 and bool(lines) and lines[0] == "active"
    identity = lines[1][:255] if len(lines) > 1 and lines[1] else None
    version = lines[2][:64] if len(lines) > 2 and lines[2] else None
    return _component(
        "wazuh-manager-runtime",
        "manager",
        "HEALTHY" if active else "UNAVAILABLE",
        "OS_SERVICE_MANAGER",
        "Wazuh Manager service is active." if active else "Wazuh Manager service is not active.",
        now,
        metrics={"service_active": active, "identity": identity, "version": version},
        last_error=None if active else "systemd did not report wazuh-manager active",
    )


def api_observation(settings: Settings, now: datetime) -> ComponentObservation:
    inventory = WazuhApiClient(settings).fetch_inventory()
    metrics: dict[str, Any] = {
        "agent_count": len(inventory.agents) if inventory.available else None,
        "manager_identity": inventory.manager_identity,
    }
    return _component(
        "wazuh-manager-api",
        "wazuh_api",
        "HEALTHY" if inventory.available else "UNAVAILABLE",
        "WAZUH_API",
        inventory.reason,
        now,
        metrics=metrics,
        last_error=None if inventory.available else inventory.reason,
    )


def sender_observation(distro: str, now: datetime) -> ComponentObservation:
    service = _wsl(distro, "systemctl is-active cyberqalqon-sender.service")
    service_active = service.returncode == 0 and service.stdout.strip() == "active"
    result = _wsl(
        distro,
        "set -a; . /etc/cyberqalqon/sender.env; set +a; "
        "/opt/cyberqalqon-sender/.venv/bin/cyberqalqon-sender status --json",
    )
    try:
        status = json.loads(result.stdout)
        queue = status["queue"]
        dead = status["dead_letter"]
        counters = status["counters"]
        queue_depth = max(0, int(queue.get("depth", 0)))
        dead_count = max(0, int(dead.get("count", 0)))
        terminal = max(0, int(queue.get("terminal_blocked", 0)))
        oldest_raw = queue.get("oldest_pending_age_seconds")
        oldest_age = float(oldest_raw) if oldest_raw is not None else None
        degraded = (
            dead_count > 0
            or terminal > 0
            or queue_depth >= 100
            or (oldest_age is not None and oldest_age >= 60)
        )
        state = "UNAVAILABLE" if not service_active else ("DEGRADED" if degraded else "HEALTHY")
        metrics = {
            "service_active": service_active,
            "queue_depth": queue_depth,
            "pending": max(0, int(queue.get("pending", 0))),
            "in_flight": max(0, int(queue.get("in_flight", 0))),
            "terminal_blocked": terminal,
            "oldest_pending_age_seconds": oldest_age,
            "queue_warning_threshold": 100,
            "oldest_pending_warning_seconds": 60,
            "dead_letter_count": dead_count,
            "retry_count": max(0, int(counters.get("retries", 0))),
            "delivered": max(0, int(counters.get("delivered", 0))),
            "last_success_at": status.get("last_success_at"),
            "last_failure_at": status.get("last_failure_at"),
        }
        return _component(
            "wazuh-alert-sender",
            "sender",
            state,
            "DURABLE_SENDER_STATE",
            "Sender service is active and its durable queue is empty."
            if state == "HEALTHY"
            else "Sender service or durable queue requires attention.",
            now,
            metrics=metrics,
            last_error=status.get("last_safe_error") if state != "HEALTHY" else None,
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return _component(
            "wazuh-alert-sender",
            "sender",
            "UNAVAILABLE",
            "DURABLE_SENDER_STATE",
            "Durable sender status could not be read.",
            now,
            last_error="bounded sender status command failed",
        )


def shipper_observation(distro: str, now: datetime) -> ComponentObservation:
    command = r'''python3 - <<'PY'
import json, os, subprocess, urllib.request
state_path='/var/lib/cyberqalqon-sender/event-shipper-state.json'
archive_path='/var/ossec/logs/archives/archives.json'
try:
    state=json.load(open(state_path, encoding='utf-8'))
    stat=os.stat(archive_path)
    active=subprocess.run(['systemctl','is-active','cyberqalqon-event-shipper.service'],capture_output=True,text=True).stdout.strip()=='active'
    try:
        with urllib.request.urlopen('http://127.0.0.1:18000/health', timeout=2) as response:
            backend_reachable=response.status == 200
    except Exception:
        backend_reachable=False
    print(json.dumps({'service_active':active,'backend_reachable':backend_reachable,'archive_size':stat.st_size,'archive_mtime':stat.st_mtime,'state':state}))
except Exception as exc:
    print(json.dumps({'error_type':type(exc).__name__}))
PY'''
    result = _wsl(distro, command)
    try:
        payload = json.loads(result.stdout)
        if "error_type" in payload:
            raise ValueError("shipper state unavailable")
        state_data = payload["state"]
        archive_size = max(0, int(payload["archive_size"]))
        offset = max(0, int(state_data.get("offset", 0)))
        lag_bytes = max(0, archive_size - offset)
        service_active = bool(payload.get("service_active"))
        backend_reachable = bool(payload.get("backend_reachable"))
        retry_attempts = max(0, int(state_data.get("retry_attempts", 0)))
        blocked = service_active and not backend_reachable and lag_bytes > 0 and retry_attempts > 0
        healthy = service_active and not blocked
        metrics = {
            "service_active": service_active,
            "backend_reachable": backend_reachable,
            "archive_size_bytes": archive_size,
            "archive_cursor_bytes": offset,
            "archive_lag_bytes": lag_bytes,
            "accepted": max(0, int(state_data.get("accepted", 0))),
            "filtered_events": max(0, int(state_data.get("filtered_events", 0))),
            "malformed_json": max(0, int(state_data.get("malformed_json", 0))),
            "oversized_lines": max(0, int(state_data.get("oversized_lines", 0))),
            "delivery_rejected": max(0, int(state_data.get("delivery_rejected", 0))),
            "retry_attempts": retry_attempts,
            "state_updated_epoch": float(state_data.get("updated_at", 0)),
        }
        return _component(
            "wazuh-event-shipper",
            "event_shipper",
            "HEALTHY" if healthy else "DEGRADED",
            "DURABLE_SHIPPER_STATE",
            "Event shipper is advancing its durable archive cursor."
            if healthy
            else "Event shipper cursor is blocked behind an undelivered selected event.",
            now,
            metrics=metrics,
            last_error="delivery retry is preventing cursor advance" if blocked else None,
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return _component(
            "wazuh-event-shipper",
            "event_shipper",
            "UNAVAILABLE",
            "DURABLE_SHIPPER_STATE",
            "Durable event-shipper state could not be read.",
            now,
            last_error="bounded shipper state command failed",
        )


def windows_agent_observation(now: datetime) -> ComponentObservation:
    root = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "ossec-agent"
    service = _run(["sc.exe", "query", "WazuhSvc"])
    service_active = "RUNNING" in service.stdout
    version = _bounded_text(root / "VERSION", 64)
    config = _bounded_text(root / "ossec.conf", 1_048_576) or ""
    match = re.search(r"<address>\s*([^<]+?)\s*</address>", config, flags=re.IGNORECASE)
    manager_address = match.group(1).strip()[:255] if match else None
    key_size = (root / "client.keys").stat().st_size if (root / "client.keys").is_file() else 0
    reachable = False
    if manager_address:
        try:
            with socket.create_connection((manager_address, 1514), timeout=1.0):
                reachable = True
        except OSError:
            pass
    if not service_active:
        state, summary = "UNAVAILABLE", "Windows Wazuh agent service is not running."
    elif key_size == 0:
        state, summary = "UNAVAILABLE", "Windows agent is running but has no enrollment key."
    elif not reachable:
        state, summary = "DEGRADED", "Windows agent manager endpoint is not reachable."
    else:
        state, summary = "UNKNOWN", "Windows agent endpoint is reachable; API enrollment is unverified."
    return _component(
        "windows-wazuh-agent",
        "windows_agent",
        state,
        "OS_SERVICE_MANAGER",
        summary,
        now,
        metrics={
            "service_active": service_active,
            "version": version,
            "configured_manager": manager_address,
            "manager_port": 1514,
            "manager_reachable": reachable,
            "enrollment_key_present": key_size > 0,
        },
        last_error=None if state in {"HEALTHY", "UNKNOWN"} else summary,
    )


def database_observation(database: Path, now: datetime) -> ComponentObservation:
    try:
        with sqlite3.connect(f"file:{database.as_posix()}?mode=ro", uri=True, timeout=5) as connection:
            quick_check = str(connection.execute("PRAGMA quick_check").fetchone()[0])
            schema = int(connection.execute("PRAGMA user_version").fetchone()[0])
            events = int(connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0])
        healthy = quick_check == "ok"
        return _component(
            "cyberqalqon-database",
            "database",
            "HEALTHY" if healthy else "DEGRADED",
            "APPLICATION_DATABASE",
            "SQLite quick_check passed." if healthy else "SQLite quick_check did not pass.",
            now,
            metrics={
                "quick_check": quick_check,
                "schema_version": schema,
                "security_events": events,
                "size_bytes": database.stat().st_size,
            },
            last_error=None if healthy else "SQLite quick_check failed",
        )
    except (OSError, sqlite3.Error, TypeError, ValueError):
        return _component(
            "cyberqalqon-database",
            "database",
            "UNAVAILABLE",
            "APPLICATION_DATABASE",
            "SQLite diagnostics could not be read.",
            now,
            last_error="bounded read-only database check failed",
        )


def _bounded_text(path: Path, maximum: int) -> str | None:
    try:
        if path.stat().st_size > maximum:
            return None
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None


def capture(database: Path, manager_distro: str) -> OperationalSnapshot:
    now = datetime.now(timezone.utc)
    settings = Settings.from_env()
    return OperationalSnapshot(
        collected_at=now,
        components=[
            manager_observation(manager_distro, now),
            api_observation(settings, now),
            sender_observation(manager_distro, now),
            shipper_observation(manager_distro, now),
            windows_agent_observation(now),
            database_observation(database, now),
        ],
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--manager-distro", default="Ubuntu-24.04")
    parser.add_argument("--no-record", action="store_true")
    args = parser.parse_args()
    database = args.database.resolve()
    output = args.output.resolve()
    if not database.is_relative_to(REPOSITORY_ROOT) or not output.is_relative_to(REPOSITORY_ROOT):
        raise SystemExit("database and output paths must stay within the repository")
    snapshot = capture(database, args.manager_distro)
    payload = json.dumps(snapshot.model_dump(mode="json"), indent=2) + "\n"
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(payload, encoding="utf-8")
    os.replace(temporary, output)
    transitions = 0
    if not args.no_record:
        transitions = OperationalRepository(database).record_snapshot(snapshot)
    states = ", ".join(
        f"{item.component_key}={item.state}" for item in snapshot.components
    )
    print(f"PASS: snapshot={output}; transitions={transitions}; {states}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
