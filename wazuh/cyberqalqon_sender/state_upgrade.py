"""Explicit, reversible-before-first-write shipper state v2 to v3 upgrade."""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .durable_state import durable_atomic_json, durable_atomic_write


class StateUpgradeError(RuntimeError):
    """Raised when a state transition cannot preserve the live cursor exactly."""


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _nonnegative(raw: dict[str, Any], name: str, default: int = 0) -> int:
    value = int(raw.get(name, default))
    if value < 0:
        raise StateUpgradeError(f"state field {name!r} must be non-negative")
    return value


def _load_object(content: bytes) -> dict[str, Any]:
    try:
        value = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StateUpgradeError("state file is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise StateUpgradeError("state file must contain one JSON object")
    return value


@dataclass(frozen=True, slots=True)
class StateUpgradePlan:
    state_path: Path
    archive_path: Path
    source_version: int
    archive_device: int
    archive_inode: int
    acknowledged_cursor: int
    archive_size: int
    source_sha256: str
    legacy_successful_acknowledgements: int
    proposed_backup_path: Path

    def as_dict(self) -> dict[str, Any]:
        return {
            "state_path": str(self.state_path),
            "archive_path": str(self.archive_path),
            "source_version": self.source_version,
            "target_version": 3,
            "archive_device": self.archive_device,
            "archive_inode": self.archive_inode,
            "acknowledged_cursor": self.acknowledged_cursor,
            "archive_size": self.archive_size,
            "source_sha256": self.source_sha256,
            "legacy_successful_acknowledgements": self.legacy_successful_acknowledgements,
            "historic_unique_insertions": None,
            "historic_duplicate_acknowledgements": None,
            "proposed_backup_path": str(self.proposed_backup_path),
        }


def plan_v2_upgrade(
    state_path: Path,
    archive_path: Path,
    backup_directory: Path,
) -> StateUpgradePlan:
    content = state_path.read_bytes()
    raw = _load_object(content)
    version = int(raw.get("version", -1))
    if version != 2:
        raise StateUpgradeError(f"expected state version 2, found {version}")
    stat = archive_path.stat()
    device = int(raw["device"])
    inode = int(raw["inode"])
    offset = _nonnegative(raw, "offset")
    if device != stat.st_dev or inode != stat.st_ino:
        raise StateUpgradeError("state archive identity does not match the active archive")
    if offset > stat.st_size:
        raise StateUpgradeError("state cursor is beyond the active archive size")
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    backup = backup_directory / f"{state_path.name}.v2-{stamp}.bak"
    return StateUpgradePlan(
        state_path=state_path,
        archive_path=archive_path,
        source_version=version,
        archive_device=device,
        archive_inode=inode,
        acknowledged_cursor=offset,
        archive_size=stat.st_size,
        source_sha256=_sha256(content),
        legacy_successful_acknowledgements=_nonnegative(raw, "accepted"),
        proposed_backup_path=backup,
    )


def convert_v2_state(raw: dict[str, Any], *, accounting_started_at: float) -> dict[str, Any]:
    if int(raw.get("version", -1)) != 2:
        raise StateUpgradeError("only version 2 state can be converted")
    converted: dict[str, Any] = {
        "version": 3,
        "device": _nonnegative(raw, "device"),
        "inode": _nonnegative(raw, "inode"),
        "offset": _nonnegative(raw, "offset"),
        # v2 accepted mixed inserted and duplicate HTTP acknowledgements. It must
        # not be reinterpreted as either exact v3 counter.
        "accepted": 0,
        "duplicate_attempts": 0,
        "legacy_successful_acknowledgements": _nonnegative(raw, "accepted"),
        "accounting_started_at": accounting_started_at,
        "skipped": _nonnegative(raw, "skipped"),
        "rejected": _nonnegative(raw, "rejected"),
        "filtered_events": _nonnegative(raw, "filtered_events", _nonnegative(raw, "skipped")),
        "malformed_json": _nonnegative(raw, "malformed_json"),
        "oversized_lines": _nonnegative(raw, "oversized_lines"),
        "delivery_rejected": _nonnegative(raw, "delivery_rejected"),
        "retry_attempts": _nonnegative(raw, "retry_attempts"),
        "protocol_errors": 0,
        "consecutive_retries": _nonnegative(raw, "consecutive_retries"),
        "recovery_transitions": _nonnegative(raw, "recovery_transitions"),
        "last_success_at": raw.get("last_success_at"),
        "last_failure_at": raw.get("last_failure_at"),
        "last_recovery_at": raw.get("last_recovery_at"),
        "delivery_window_started_at": accounting_started_at,
        "last_request_latency_ms": None,
        "current_batch_size": None,
        "terminal_blocked": False,
        "last_failure_category": None,
        "updated_at": float(raw.get("updated_at", 0)),
    }
    return converted


def apply_v2_upgrade(
    plan: StateUpgradePlan,
    *,
    operator_approved: bool,
    now: float | None = None,
) -> dict[str, Any]:
    if not operator_approved:
        raise StateUpgradeError("live state upgrade requires explicit operator approval")
    current = plan.state_path.read_bytes()
    if _sha256(current) != plan.source_sha256:
        raise StateUpgradeError("state changed after planning; create a new upgrade plan")
    refreshed = plan_v2_upgrade(
        plan.state_path,
        plan.archive_path,
        plan.proposed_backup_path.parent,
    )
    if (
        refreshed.archive_device != plan.archive_device
        or refreshed.archive_inode != plan.archive_inode
        or refreshed.acknowledged_cursor != plan.acknowledged_cursor
    ):
        raise StateUpgradeError("archive identity or cursor changed after planning")
    backup_path = plan.proposed_backup_path
    if backup_path.exists():
        raise StateUpgradeError("refusing to overwrite an existing state backup")
    durable_atomic_write(backup_path, current)
    if _sha256(backup_path.read_bytes()) != plan.source_sha256:
        raise StateUpgradeError("state backup SHA-256 verification failed")
    raw = _load_object(current)
    converted = convert_v2_state(
        raw,
        accounting_started_at=now if now is not None else time.time(),
    )
    durable_atomic_json(plan.state_path, converted)
    converted_bytes = plan.state_path.read_bytes()
    manifest = {
        "version": 1,
        "state_path": str(plan.state_path),
        "archive_path": str(plan.archive_path),
        "backup_path": str(backup_path),
        "backup_sha256": plan.source_sha256,
        "converted_sha256": _sha256(converted_bytes),
        "cursor": plan.acknowledged_cursor,
        "archive_device": plan.archive_device,
        "archive_inode": plan.archive_inode,
        "rollback_allowed_only_before_new_state_writes": True,
    }
    manifest_path = backup_path.with_suffix(backup_path.suffix + ".manifest.json")
    durable_atomic_json(manifest_path, manifest)
    return {**manifest, "manifest_path": str(manifest_path)}


def rollback_upgrade(manifest_path: Path, *, operator_approved: bool) -> dict[str, Any]:
    if not operator_approved:
        raise StateUpgradeError("state rollback requires explicit operator approval")
    manifest = _load_object(manifest_path.read_bytes())
    state_path = Path(str(manifest["state_path"]))
    backup_path = Path(str(manifest["backup_path"]))
    current = state_path.read_bytes()
    if _sha256(current) != str(manifest["converted_sha256"]):
        raise StateUpgradeError("rollback refused: v3 state has changed since conversion")
    backup = backup_path.read_bytes()
    if _sha256(backup) != str(manifest["backup_sha256"]):
        raise StateUpgradeError("rollback refused: backup SHA-256 verification failed")
    durable_atomic_write(state_path, backup)
    return {
        "status": "ROLLED_BACK",
        "state_path": str(state_path),
        "restored_sha256": _sha256(state_path.read_bytes()),
    }
