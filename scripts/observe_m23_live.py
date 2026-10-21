"""Bounded, read-only M23 forward-ingestion observation for the WSL runtime.

The sampler never starts/stops a service, writes a checkpoint, changes approval,
opens SQLite, or scans archive contents.  It reads only small state/manifest
files, source metadata, systemd counters, and scoped health endpoints.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import subprocess
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


EXPECTED_GENERATION = "e58aa9c7b9fbb04204f21d181dc1e6bdc2603d345ed120b7790c2df4fcb7da3a"
EXPECTED_SOURCE = (2096, 33582586)
EXPECTED_LEGACY_SHA256 = "ef11626503c7af1c9a1d605ca7cfaf6abb01acbe0101817c1f5df22656260dde"
STATE = Path(f"/var/lib/cyberqalqon-forward/m22-forward/{EXPECTED_GENERATION}.json")
SOURCE = Path("/var/ossec/logs/archives/archives.json")
LEGACY = Path("/var/lib/cyberqalqon-sender/event-shipper-state.json")
APPROVAL = Path("/etc/cyberqalqon/forward-approval.json")
ENDPOINTS = {
    "gateway": "http://172.19.240.1:16000/health",
    "relay": "http://127.0.0.1:18000/health",
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _http(url: str) -> tuple[int, float]:
    started = time.monotonic()
    try:
        with urllib.request.urlopen(url, timeout=3) as response:
            response.read(256)
            status = int(response.status)
    except Exception:
        status = 0
    return status, round((time.monotonic() - started) * 1000, 3)


def _service() -> dict[str, Any]:
    output = subprocess.check_output(
        [
            "systemctl",
            "show",
            "cyberqalqon-forward-ingestion.service",
            "-p", "ActiveState",
            "-p", "SubState",
            "-p", "MainPID",
            "-p", "NRestarts",
            "-p", "ExecMainStatus",
            "-p", "MemoryCurrent",
            "-p", "CPUUsageNSec",
        ],
        text=True,
    )
    values: dict[str, Any] = {}
    for line in output.splitlines():
        key, _, value = line.partition("=")
        values[key] = int(value) if value.isdigit() else value
    return values


def _percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return round(ordered[max(0, math.ceil(len(ordered) * fraction) - 1)], 3)


def _approval(now: float, state: dict[str, Any]) -> dict[str, Any]:
    if not APPROVAL.is_file():
        return {"state": "ABSENT", "sha256": None, "expires_at_epoch": None}
    encoded = APPROVAL.read_bytes()
    digest = hashlib.sha256(encoded).hexdigest()
    try:
        value = json.loads(encoded)
        metadata = APPROVAL.stat()
        issued = float(value["issued_at_epoch"])
        expires = float(value["expires_at_epoch"])
        security_scope = (
            metadata.st_uid == 0
            and metadata.st_mode & 0o022 == 0
            and value.get("version") == 1
            and value.get("decision") == "APPROVED"
            and value.get("purpose") == "M22_LIVE_FORWARD_INGESTION"
            and value.get("historical_continuity") == "UNPROVEN"
            and value.get("accepts_unproven_history") is True
            and value.get("historical_replay_approved") is False
            and value.get("legacy_checkpoint_mutation_approved") is False
            and value.get("single_event_ingestion_only") is True
            and value.get("contains_raw_payload") is False
        )
        identity_scope = (
            value.get("generation_id") == state.get("generation_id")
            and value.get("source_device") == state.get("source_device")
            and value.get("source_inode") == state.get("source_inode")
            and value.get("start_offset") == state.get("start_offset")
            and value.get("start_prefix_sha256") == state.get("start_prefix_sha256")
            and value.get("legacy_state_sha256") == state.get("legacy_state_sha256")
            and value.get("legacy_cursor") == state.get("legacy_cursor_at_registration")
        )
        window_valid = issued <= now + 300 and expires > issued and expires - issued <= 86_400
        status = (
            "INVALID"
            if not security_scope or not window_valid
            else "MISMATCH"
            if not identity_scope
            else "EXPIRED"
            if expires <= now
            else "VALID"
        )
        return {
            "state": status,
            "validation_basis": "BOUNDED_SCOPE_TIME_IDENTITY",
            "sha256": digest,
            "issued_at_epoch": issued,
            "expires_at_epoch": expires,
            "remaining_seconds": round(max(0.0, expires - now), 3),
        }
    except (KeyError, TypeError, ValueError, json.JSONDecodeError, OSError):
        return {"state": "INVALID", "sha256": digest, "expires_at_epoch": None}


def _sample(index: int) -> dict[str, Any]:
    captured = time.time()
    state = json.loads(STATE.read_text(encoding="utf-8"))
    source = SOURCE.stat()
    legacy = json.loads(LEGACY.read_text(encoding="utf-8"))
    legacy_sha = _sha256(LEGACY)
    health = {name: _http(url) for name, url in ENDPOINTS.items()}
    return {
        "sample": index,
        "captured_at_epoch": captured,
        "captured_at_utc": datetime.fromtimestamp(captured, timezone.utc).isoformat(),
        "service": _service(),
        "generation_id": state.get("generation_id"),
        "source_device": source.st_dev,
        "source_inode": source.st_ino,
        "source_size_bytes": source.st_size,
        "rotation_detected": (source.st_dev, source.st_ino) != EXPECTED_SOURCE,
        "checkpoint_sha256": _sha256(STATE),
        "checkpoint_updated_at_epoch": state.get("updated_at_epoch"),
        "cursor_bytes": int(state["offset"]),
        "lag_bytes": max(0, source.st_size - int(state["offset"])),
        "records": int(state["records"]),
        "accepted": int(state["accepted"]),
        "duplicates": int(state["duplicates"]),
        "filtered": int(state["filtered"]),
        "malformed": int(state["malformed"]),
        "retry_attempts": int(state["retry_attempts"]),
        "protocol_errors": int(state["protocol_errors"]),
        "delivery_rejected": int(state["delivery_rejected"]),
        "terminal_blocked": bool(state["terminal_blocked"]),
        "last_success_at_epoch": state.get("last_success_at_epoch"),
        "legacy_cursor": int(legacy["offset"]),
        "legacy_sha256": legacy_sha,
        "legacy_unchanged": (
            int(legacy["offset"]) == 93438552
            and legacy_sha == EXPECTED_LEGACY_SHA256
        ),
        "approval": _approval(captured, state),
        "health": {
            name: {"http_status": result[0], "latency_ms": result[1]}
            for name, result in health.items()
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--samples", type=int, default=6)
    parser.add_argument("--interval-seconds", type=float, default=10.0)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not 3 <= args.samples <= 12 or not 5 <= args.interval_seconds <= 30:
        parser.error("samples/interval are outside bounded read-only limits")
    if not args.output.is_absolute():
        parser.error("output must be absolute")

    samples: list[dict[str, Any]] = []
    for index in range(args.samples):
        if index:
            time.sleep(args.interval_seconds)
        samples.append(_sample(index + 1))

    intervals: list[dict[str, float]] = []
    for previous, current in zip(samples, samples[1:]):
        elapsed = current["captured_at_epoch"] - previous["captured_at_epoch"]
        archive_rate = (
            current["source_size_bytes"] - previous["source_size_bytes"]
        ) / elapsed
        cursor_rate = (current["cursor_bytes"] - previous["cursor_bytes"]) / elapsed
        intervals.append(
            {
                "elapsed_seconds": round(elapsed, 3),
                "archive_growth_bytes_per_second": round(archive_rate, 3),
                "cursor_progress_bytes_per_second": round(cursor_rate, 3),
                "net_lag_bytes_per_second": round(archive_rate - cursor_rate, 3),
                "accepted_per_second": round(
                    (current["accepted"] - previous["accepted"]) / elapsed, 3
                ),
                "duplicates_per_second": round(
                    (current["duplicates"] - previous["duplicates"]) / elapsed, 3
                ),
                "filtered_per_second": round(
                    (current["filtered"] - previous["filtered"]) / elapsed, 3
                ),
            }
        )
    average_net = statistics_mean(
        [item["net_lag_bytes_per_second"] for item in intervals]
    )
    sustained_drain = bool(intervals) and all(
        item["net_lag_bytes_per_second"] < 0 for item in intervals
    )
    endpoint_latency = {
        name: {
            "http_200": sum(
                sample["health"][name]["http_status"] == 200 for sample in samples
            ),
            "samples": len(samples),
            "p50_ms": _percentile(
                [sample["health"][name]["latency_ms"] for sample in samples], 0.50
            ),
            "p95_ms": _percentile(
                [sample["health"][name]["latency_ms"] for sample in samples], 0.95
            ),
        }
        for name in ENDPOINTS
    }
    first, last = samples[0], samples[-1]
    result = {
        "version": 1,
        "scope": "READ_ONLY_LIVE_OBSERVATION",
        "production_configuration_changed": False,
        "service_action_performed": False,
        "samples": samples,
        "intervals": intervals,
        "summary": {
            "duration_seconds": round(
                last["captured_at_epoch"] - first["captured_at_epoch"], 3
            ),
            "initial_cursor": first["cursor_bytes"],
            "final_cursor": last["cursor_bytes"],
            "cursor_delta": last["cursor_bytes"] - first["cursor_bytes"],
            "initial_lag_bytes": first["lag_bytes"],
            "final_lag_bytes": last["lag_bytes"],
            "accepted_delta": last["accepted"] - first["accepted"],
            "duplicates_delta": last["duplicates"] - first["duplicates"],
            "filtered_delta": last["filtered"] - first["filtered"],
            "archive_growth_bytes_per_second_average": statistics_mean(
                [item["archive_growth_bytes_per_second"] for item in intervals]
            ),
            "cursor_progress_bytes_per_second_average": statistics_mean(
                [item["cursor_progress_bytes_per_second"] for item in intervals]
            ),
            "net_lag_bytes_per_second_average": average_net,
            "backlog_trend": (
                "DRAINING" if average_net < 0 else "GROWING" if average_net > 0 else "STABLE"
            ),
            "sustained_drain_all_intervals": sustained_drain,
            "catch_up_seconds": (
                round(last["lag_bytes"] / -average_net, 3)
                if sustained_drain and average_net < 0
                else None
            ),
            "http": endpoint_latency,
        },
        "acceptance": {
            "service_active": all(
                sample["service"].get("ActiveState") == "active" for sample in samples
            ),
            "generation_exact": all(
                sample["generation_id"] == EXPECTED_GENERATION for sample in samples
            ),
            "rotation_absent": not any(sample["rotation_detected"] for sample in samples),
            "approval_valid": all(
                sample["approval"]["state"] == "VALID" for sample in samples
            ),
            "legacy_unchanged": all(sample["legacy_unchanged"] for sample in samples),
            "delivery_errors_zero": all(
                sample["retry_attempts"] == 0
                and sample["protocol_errors"] == 0
                and sample["delivery_rejected"] == 0
                and not sample["terminal_blocked"]
                for sample in samples
            ),
            "health_http_200": all(
                sample["health"][name]["http_status"] == 200
                for sample in samples
                for name in ENDPOINTS
            ),
        },
        "historical_continuity": "UNPROVEN",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    pending = args.output.with_suffix(args.output.suffix + ".tmp")
    pending.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(pending, args.output)
    print(json.dumps({"output": str(args.output), "summary": result["summary"], "acceptance": result["acceptance"]}, sort_keys=True))
    return 0 if all(result["acceptance"].values()) else 1


def statistics_mean(values: list[float]) -> float:
    return round(sum(values) / len(values), 3) if values else 0.0


if __name__ == "__main__":
    raise SystemExit(main())
