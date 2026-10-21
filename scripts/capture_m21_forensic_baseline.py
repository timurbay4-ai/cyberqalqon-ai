#!/usr/bin/env python3
"""Capture a payload-free, read-only M21 WSL archive/state baseline.

Run inside the Ubuntu WSL distribution as an account that can read the Wazuh
and sender evidence. The script refuses to overwrite an existing manifest and
does not open any source for writing.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any


ARCHIVE_DIRECTORY = Path("/var/ossec/logs/archives/2026/Oct")
ACTIVE_ARCHIVE = Path("/var/ossec/logs/archives/archives.json")
LEGACY_STATE = Path("/var/lib/cyberqalqon-sender/event-shipper-state.json")
SENDER_DATABASE = Path("/var/lib/cyberqalqon-sender/sender.db")
BACKUP_ROOTS = (
    Path("/var/lib/cyberqalqon-sender/state-backups"),
    Path("/var/lib/cyberqalqon-sender/backups"),
    Path("/var/lib/cyberqalqon-sender/deployment-backups"),
)
M20_ARTIFACTS = (
    "m20-archive-continuity-analysis.json",
    "m20-checkpoint-prefix-analysis.json",
    "m20-original-generation-prefix-binding.json",
    "m20-backend-wazuh-identity-export.tsv.gz",
    "m20-rotation-recovery-forensics.json",
)
STATE_FIELDS = (
    "version",
    "device",
    "inode",
    "offset",
    "accepted",
    "duplicate_attempts",
    "legacy_successful_acknowledgements",
    "filtered_events",
    "malformed_json",
    "oversized_lines",
    "protocol_errors",
    "delivery_rejected",
    "retry_attempts",
    "consecutive_retries",
    "terminal_blocked",
    "last_failure_category",
    "updated_at",
)


def _sha256(path: Path, *, limit: int | None = None) -> tuple[str, int]:
    digest = hashlib.sha256()
    read_bytes = 0
    with path.open("rb") as handle:
        while limit is None or read_bytes < limit:
            requested = 1024 * 1024 if limit is None else min(1024 * 1024, limit - read_bytes)
            if requested <= 0:
                break
            chunk = handle.read(requested)
            if not chunk:
                break
            digest.update(chunk)
            read_bytes += len(chunk)
    return digest.hexdigest(), read_bytes


def _identity(stat: os.stat_result) -> dict[str, Any]:
    return {
        "device": stat.st_dev,
        "inode": stat.st_ino,
        "size": stat.st_size,
        "mode": oct(stat.st_mode & 0o777),
        "uid": stat.st_uid,
        "gid": stat.st_gid,
        "birth_time_epoch": getattr(stat, "st_birthtime", None),
        "ctime_ns": stat.st_ctime_ns,
        "mtime_ns": stat.st_mtime_ns,
    }


def _file(path: Path, *, active_prefix: bool = False) -> dict[str, Any]:
    record: dict[str, Any] = {"path": str(path), "exists": path.is_file()}
    if not record["exists"]:
        record.update({"readable": False, "confidence": "UNKNOWN"})
        return record
    before = path.stat()
    captured_size = before.st_size if active_prefix else None
    digest, read_bytes = _sha256(path, limit=captured_size)
    after = path.stat()
    same_identity = (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino)
    stable = same_identity and (
        after.st_size >= before.st_size if active_prefix else _identity(before) == _identity(after)
    )
    compression = "GZIP" if path.suffix.casefold() == ".gz" else "NONE"
    record.update(
        {
            **_identity(after),
            "compression": compression,
            "readable": read_bytes == (captured_size if active_prefix else after.st_size),
            "identity_stable_during_capture": same_identity,
            "metadata_stable_during_capture": stable,
            "sha256_scope": (
                f"stored_prefix_0_{captured_size}" if active_prefix else "stored_file"
            ),
            "sha256": digest,
            "hashed_bytes": read_bytes,
            "confidence": "PROVEN_CURRENT_CONTENT" if stable else "CAPTURE_RACED_SOURCE",
        }
    )
    if compression == "GZIP":
        try:
            with gzip.open(path, "rb") as handle:
                handle.read(1)
                record["gzip_header_readable"] = True
                record["gzip_header_mtime"] = handle.mtime
        except (EOFError, OSError):
            record["gzip_header_readable"] = False
    return record


def _service(name: str) -> dict[str, str]:
    result = subprocess.run(
        [
            "systemctl",
            "show",
            name,
            "-p",
            "LoadState",
            "-p",
            "ActiveState",
            "-p",
            "SubState",
            "-p",
            "NRestarts",
            "-p",
            "MainPID",
            "--no-pager",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    values: dict[str, str] = {}
    for line in result.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key] = value
    return values


def _backup_inventory() -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for root in BACKUP_ROOTS:
        if not root.is_dir():
            continue
        for path in sorted(item for item in root.rglob("*") if item.is_file()):
            records.append(_file(path))
    return records


def capture(repo_root: Path) -> dict[str, Any]:
    archives = [
        next(iter(sorted(ARCHIVE_DIRECTORY.glob(f"ossec-archive-{day:02d}.json*"))), None)
        for day in range(15, 20)
    ]
    archive_records = [
        _file(path) if path is not None else {
            "path": str(ARCHIVE_DIRECTORY / f"ossec-archive-{day:02d}.json[.gz]"),
            "exists": False,
            "readable": False,
            "confidence": "UNKNOWN",
        }
        for day, path in zip(range(15, 20), archives, strict=True)
    ]
    state_file = _file(LEGACY_STATE)
    state_payload = json.loads(LEGACY_STATE.read_text(encoding="utf-8"))
    state_projection = {name: state_payload.get(name) for name in STATE_FIELDS}
    artifacts = [_file(repo_root / "artifacts" / "runtime" / name) for name in M20_ARTIFACTS]
    return {
        "version": 1,
        "captured_at_epoch": time.time(),
        "contains_raw_payload": False,
        "capture_mode": "READ_ONLY",
        "legacy_state": {"file": state_file, "projection": state_projection},
        "archives_day_15_through_19": archive_records,
        "active_archive": _file(ACTIVE_ARCHIVE, active_prefix=True),
        "sender_database": _file(SENDER_DATABASE),
        "checkpoint_backups": _backup_inventory(),
        "existing_forensic_manifests": artifacts,
        "services": {
            name: _service(name)
            for name in (
                "cyberqalqon-event-shipper.service",
                "cyberqalqon-sender.service",
                "cyberqalqon-backend-relay.service",
                "wazuh-manager.service",
            )
        },
        "confidence_note": (
            "SHA-256 proves the bytes observed during this capture. It does not create "
            "historical chain of custody or prove continuity across collection downtime."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    repo_root = arguments.repo_root.resolve()
    output = arguments.output.resolve()
    if output.exists():
        raise SystemExit(f"refusing to overwrite existing manifest: {output}")
    payload = capture(repo_root)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.tmp-{os.getpid()}")
    with temporary.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, output)
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
