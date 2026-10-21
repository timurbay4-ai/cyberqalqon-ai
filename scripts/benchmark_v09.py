"""Bounded, read-only v0.9 latency and normalization benchmark."""

from __future__ import annotations

import argparse
import json
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, TypeVar

from capture_operational_health import sender_observation, shipper_observation

from app.core.config import Settings
from app.db.agents import AgentRepository
from app.db.operations import OperationalRepository
from app.services.event_normalizer import normalize_wazuh_event


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATABASE = REPOSITORY_ROOT / "backend" / "data" / "cyberqalqon-local-lab.db"
T = TypeVar("T")


def _samples(call: Callable[[], T], count: int) -> tuple[dict[str, float], T]:
    timings: list[float] = []
    result: T | None = None
    for _ in range(count):
        started = time.perf_counter_ns()
        result = call()
        timings.append((time.perf_counter_ns() - started) / 1_000_000)
    ordered = sorted(timings)
    p95_index = min(len(ordered) - 1, max(0, int(len(ordered) * 0.95 + 0.999) - 1))
    assert result is not None
    return {
        "samples": float(count),
        "p50_ms": round(statistics.median(ordered), 3),
        "p95_ms": round(ordered[p95_index], 3),
        "max_ms": round(max(ordered), 3),
    }, result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    parser.add_argument("--samples", type=int, default=50)
    parser.add_argument("--wsl-samples", type=int, default=7)
    parser.add_argument("--manager-distro", default="Ubuntu-24.04")
    arguments = parser.parse_args()
    if not 5 <= arguments.samples <= 500 or not 3 <= arguments.wsl_samples <= 20:
        parser.error("samples must be 5..500 and wsl-samples must be 3..20")

    database = arguments.database.resolve()
    settings = Settings.from_env()
    agents = AgentRepository(database, settings)
    operations = OperationalRepository(database)

    def list_agents():
        return agents.list_agents(
            search=None,
            os_platform=None,
            connection_status=None,
            version=None,
            manager=None,
            source_type=None,
            last_seen_minutes=None,
            sort="last_seen",
            order="desc",
            limit=50,
            offset=0,
        )

    list_agents()
    list_latency, inventory = _samples(list_agents, arguments.samples)
    agent_key = inventory.items[0].agent_key if inventory.items else None
    detail_latency = None
    if agent_key is not None:
        detail_latency, _ = _samples(lambda: agents.get_agent(agent_key), arguments.samples)
    overview_latency, _ = _samples(lambda: operations.overview(limit=50), arguments.samples)

    raw_windows_event = {
        "timestamp": "2026-10-10T12:00:00+00:00",
        "id": "v09-benchmark-4625",
        "agent": {"id": "099", "name": "v09-benchmark-windows"},
        "manager": {"name": "v09-benchmark-manager"},
        "rule": {"id": "5710", "level": 5, "description": "Benchmark fixture"},
        "data": {
            "win": {
                "system": {
                    "providerName": "Microsoft-Windows-Security-Auditing",
                    "eventID": "4625",
                    "channel": "Security",
                    "computer": "WIN-BENCHMARK",
                },
                "eventdata": {
                    "targetUserName": "foydalanuvchi-测试",
                    "processId": "1234",
                    "ipAddress": "192.0.2.44",
                },
            }
        },
    }
    normalization_count = min(5000, arguments.samples * 20)
    normalization_latency, _ = _samples(
        lambda: normalize_wazuh_event(raw_windows_event), normalization_count
    )
    normalization_latency["events_per_second"] = round(
        1000 / max(normalization_latency["p50_ms"], 0.001), 1
    )

    now = datetime.now(timezone.utc)
    sender_latency, sender = _samples(
        lambda: sender_observation(arguments.manager_distro, now, settings),
        arguments.wsl_samples,
    )
    shipper_latency, shipper = _samples(
        lambda: shipper_observation(arguments.manager_distro, now, settings),
        arguments.wsl_samples,
    )
    payload = {
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "database_bytes": database.stat().st_size,
        "inventory_items": inventory.page.total,
        "agent_inventory": list_latency,
        "agent_detail": detail_latency,
        "operational_overview": overview_latency,
        "windows_normalization": normalization_latency,
        "sender_queue_lookup": {**sender_latency, "state": sender.state},
        "shipper_lag_calculation": {**shipper_latency, "state": shipper.state},
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
