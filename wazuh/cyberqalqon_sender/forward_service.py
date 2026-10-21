"""Approval-gated runtime for one independent forward archive generation.

Importing this module has no side effects. A service can run only with a short-lived,
root-controlled approval manifest bound to the prepared checkpoint and source identity.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import signal
import stat as stat_module
import time
from dataclasses import dataclass
from pathlib import Path
from threading import Event
from typing import Any

from .config import SenderConfig
from .event_shipper import EventDeliveryClient, EventShipperConfig, select_archive_event
from .forward_ingestion import (
    ForwardCheckpointLock,
    ForwardIngestionError,
    ForwardIngestionWorker,
    load_forward_state,
    validate_forward_checkpoint,
)


APPROVAL_PURPOSE = "M22_LIVE_FORWARD_INGESTION"
MAX_APPROVAL_WINDOW_SECONDS = 86_400


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _read_stable_json(path: Path, *, label: str) -> tuple[dict[str, Any], str]:
    if not path.is_absolute() or not path.is_file():
        raise ForwardIngestionError(f"{label} must be an existing absolute file")
    before = path.stat()
    encoded = path.read_bytes()
    after = path.stat()
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise ForwardIngestionError(f"{label} changed while it was read")
    try:
        raw = json.loads(encoded.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ForwardIngestionError(f"{label} is not valid JSON") from exc
    if not isinstance(raw, dict):
        raise ForwardIngestionError(f"{label} must contain a JSON object")
    return raw, hashlib.sha256(encoded).hexdigest()


def validate_live_approval(
    approval_path: Path,
    state_path: Path,
    *,
    now: float | None = None,
    require_root_owner: bool = True,
    deep_on_evolved_state: bool = True,
) -> dict[str, Any]:
    """Verify a narrow, expiring live approval without exposing raw records."""

    approval, approval_sha = _read_stable_json(approval_path, label="approval manifest")
    stat = approval_path.stat()
    if os.name == "posix":
        if stat.st_mode & 0o022:
            raise ForwardIngestionError("approval manifest is group/world writable")
        if require_root_owner and stat.st_uid != 0:
            raise ForwardIngestionError("approval manifest must be owned by root")
        state_stat = state_path.stat()
        if state_stat.st_mode & 0o022:
            raise ForwardIngestionError("forward state is group/world writable")
        if state_stat.st_uid != os.geteuid():
            raise ForwardIngestionError("forward state must be owned by the service user")
    required = {
        "version": 1,
        "decision": "APPROVED",
        "purpose": APPROVAL_PURPOSE,
        "historical_continuity": "UNPROVEN",
        "accepts_unproven_history": True,
        "historical_replay_approved": False,
        "legacy_checkpoint_mutation_approved": False,
        "single_event_ingestion_only": True,
        "contains_raw_payload": False,
    }
    for key, expected in required.items():
        if approval.get(key) != expected:
            raise ForwardIngestionError(f"approval manifest {key} is not authorized")
    timestamp = time.time() if now is None else now
    issued = approval.get("issued_at_epoch")
    expires = approval.get("expires_at_epoch")
    if (
        isinstance(issued, bool)
        or not isinstance(issued, (int, float))
        or isinstance(expires, bool)
        or not isinstance(expires, (int, float))
        or issued > timestamp + 300
        or expires <= timestamp
        or expires - issued > MAX_APPROVAL_WINDOW_SECONDS
    ):
        raise ForwardIngestionError("approval manifest time window is invalid or expired")

    state = load_forward_state(state_path)
    exact = {
        "generation_id": state.generation_id,
        "state_path": str(state_path),
        "source_path": state.source_path,
        "source_device": state.source_device,
        "source_inode": state.source_inode,
        "start_offset": state.start_offset,
        "start_prefix_sha256": state.start_prefix_sha256,
        "legacy_state_path": state.legacy_state_path,
        "legacy_state_sha256": state.legacy_state_sha256,
        "legacy_cursor": state.legacy_cursor_at_registration,
    }
    for key, expected in exact.items():
        if approval.get(key) != expected:
            raise ForwardIngestionError(f"approval manifest does not match {key}")
    prepared_sha = approval.get("prepared_state_sha256")
    if (
        not isinstance(prepared_sha, str)
        or len(prepared_sha) != 64
        or any(character not in "0123456789abcdef" for character in prepared_sha)
    ):
        raise ForwardIngestionError("approval manifest prepared-state digest is invalid")
    current_sha = _sha256_file(state_path)
    if current_sha != prepared_sha and deep_on_evolved_state:
        # Restart after legitimate progress is safe only if the complete processed
        # chain can still be proven against the same approved generation.
        validate_forward_checkpoint(state_path, deep=True)
    else:
        validate_forward_checkpoint(state_path, deep=False)
    return {
        "status": "APPROVED",
        "approval_sha256": approval_sha,
        "approval_expires_at_epoch": float(expires),
        "generation_id": state.generation_id,
        "source_device": state.source_device,
        "source_inode": state.source_inode,
        "start_offset": state.start_offset,
        "historical_continuity": "UNPROVEN",
        "historical_replay_approved": False,
        "legacy_checkpoint_mutation_approved": False,
        "contains_raw_payload": False,
    }


def build_approval_renewal_proposal(
    approval_path: Path,
    state_path: Path,
    *,
    requested_expires_at_epoch: float,
    now: float | None = None,
    require_root_owner: bool = True,
) -> dict[str, Any]:
    """Build a non-authorizing, idempotent renewal/activation proposal.

    The current approval is treated as operator authority only while its exact
    generation/security scope and finite time window remain valid.  Expiry can
    never be converted into renewed authority by this function: an expired
    manifest yields a fresh-activation proposal that still carries
    ``PENDING_EXPLICIT_USER_APPROVAL``.
    """

    timestamp = time.time() if now is None else now
    if (
        isinstance(timestamp, bool)
        or not isinstance(timestamp, (int, float))
        or not math.isfinite(timestamp)
        or timestamp < 0
    ):
        raise ForwardIngestionError("proposal clock is invalid")
    if (
        isinstance(requested_expires_at_epoch, bool)
        or not isinstance(requested_expires_at_epoch, (int, float))
        or not math.isfinite(requested_expires_at_epoch)
        or requested_expires_at_epoch < timestamp + 60
        or requested_expires_at_epoch - timestamp > MAX_APPROVAL_WINDOW_SECONDS
    ):
        raise ForwardIngestionError(
            "requested approval expiry must be 60 to 86400 seconds in the future"
        )

    current, current_sha = _read_stable_json(
        approval_path, label="current approval manifest"
    )
    approval_stat = approval_path.stat()
    state_stat = state_path.stat()
    if os.name == "posix":
        if approval_stat.st_mode & 0o022:
            raise ForwardIngestionError("current approval manifest is group/world writable")
        if require_root_owner and approval_stat.st_uid != 0:
            raise ForwardIngestionError("current approval manifest must be owned by root")
        if state_stat.st_mode & 0o022:
            raise ForwardIngestionError("forward state is group/world writable")

    required = {
        "version": 1,
        "decision": "APPROVED",
        "purpose": APPROVAL_PURPOSE,
        "historical_continuity": "UNPROVEN",
        "accepts_unproven_history": True,
        "historical_replay_approved": False,
        "legacy_checkpoint_mutation_approved": False,
        "single_event_ingestion_only": True,
        "contains_raw_payload": False,
    }
    for key, expected in required.items():
        if current.get(key) != expected:
            raise ForwardIngestionError(
                f"current approval manifest {key} is not authorized"
            )

    issued = current.get("issued_at_epoch")
    expires = current.get("expires_at_epoch")
    if (
        isinstance(issued, bool)
        or not isinstance(issued, (int, float))
        or not math.isfinite(issued)
        or isinstance(expires, bool)
        or not isinstance(expires, (int, float))
        or not math.isfinite(expires)
        or expires <= issued
        or expires - issued > MAX_APPROVAL_WINDOW_SECONDS
    ):
        raise ForwardIngestionError("current approval time window is invalid")
    if issued > timestamp + 300:
        raise ForwardIngestionError("current approval is invalid after a clock regression")

    state = load_forward_state(state_path)
    exact = {
        "generation_id": state.generation_id,
        "state_path": str(state_path),
        "source_path": state.source_path,
        "source_device": state.source_device,
        "source_inode": state.source_inode,
        "start_offset": state.start_offset,
        "start_prefix_sha256": state.start_prefix_sha256,
        "legacy_state_path": state.legacy_state_path,
        "legacy_state_sha256": state.legacy_state_sha256,
        "legacy_cursor": state.legacy_cursor_at_registration,
    }
    for key, expected in exact.items():
        if current.get(key) != expected:
            raise ForwardIngestionError(
                f"current approval manifest does not match {key}"
            )
    prepared_sha = current.get("prepared_state_sha256")
    if (
        not isinstance(prepared_sha, str)
        or len(prepared_sha) != 64
        or any(character not in "0123456789abcdef" for character in prepared_sha)
    ):
        raise ForwardIngestionError(
            "current approval manifest prepared-state digest is invalid"
        )
    validate_forward_checkpoint(state_path, deep=True)

    common = {
        "current_approval_sha256": current_sha,
        "current_expires_at_epoch": float(expires),
        "requested_expires_at_epoch": float(requested_expires_at_epoch),
        "generation_id": state.generation_id,
        "checkpoint_sha256": _sha256_file(state_path),
        "source_device": state.source_device,
        "source_inode": state.source_inode,
        "legacy_state_sha256": state.legacy_state_sha256,
        "legacy_cursor": state.legacy_cursor_at_registration,
        "historical_continuity": "UNPROVEN",
        "historical_replay_approved": False,
        "legacy_checkpoint_mutation_approved": False,
        "contains_raw_payload": False,
    }
    if expires > timestamp and requested_expires_at_epoch <= expires:
        return {
            "status": "ALREADY_APPROVED",
            "action_required": "NONE",
            "reason_codes": ["EXISTING_APPROVAL_COVERS_REQUESTED_WINDOW"],
            "proposal": None,
            **common,
        }

    proposal_kind = "RENEWAL" if expires > timestamp else "FRESH_ACTIVATION"
    proposal = build_approval_template(
        state_path, expires_at_epoch=float(requested_expires_at_epoch)
    )
    proposal.update(
        {
            "proposal_kind": proposal_kind,
            "proposal_created_at_epoch": float(timestamp),
            "replaces_approval_sha256": current_sha,
            "previous_expires_at_epoch": float(expires),
        }
    )
    encoded = json.dumps(
        proposal, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    expired = expires <= timestamp
    return {
        "status": (
            "ACTIVATION_PROPOSAL_REQUIRED" if expired else "RENEWAL_PROPOSAL_READY"
        ),
        "action_required": "EXPLICIT_OPERATOR_APPROVAL",
        "reason_codes": [
            "EXPIRED_APPROVAL" if expired else "OPERATOR_REQUESTED_EXTENSION"
        ],
        "proposal_sha256": hashlib.sha256(encoded).hexdigest(),
        "proposal": proposal,
        **common,
    }


def build_approval_template(state_path: Path, *, expires_at_epoch: float) -> dict[str, Any]:
    """Build an unsigned template; this does not grant or imply approval."""

    state = load_forward_state(state_path)
    return {
        "version": 1,
        "decision": "PENDING_EXPLICIT_USER_APPROVAL",
        "purpose": APPROVAL_PURPOSE,
        "issued_at_epoch": None,
        "expires_at_epoch": expires_at_epoch,
        "generation_id": state.generation_id,
        "state_path": str(state_path),
        "prepared_state_sha256": _sha256_file(state_path),
        "source_path": state.source_path,
        "source_device": state.source_device,
        "source_inode": state.source_inode,
        "start_offset": state.start_offset,
        "start_prefix_sha256": state.start_prefix_sha256,
        "legacy_state_path": state.legacy_state_path,
        "legacy_state_sha256": state.legacy_state_sha256,
        "legacy_cursor": state.legacy_cursor_at_registration,
        "historical_continuity": "UNPROVEN",
        "accepts_unproven_history": False,
        "historical_replay_approved": False,
        "legacy_checkpoint_mutation_approved": False,
        "single_event_ingestion_only": True,
        "contains_raw_payload": False,
    }


def append_payload_free_audit(audit_path: Path, event: dict[str, Any]) -> None:
    if not audit_path.is_absolute():
        raise ValueError("forward audit path must be absolute")
    forbidden = {"payload", "raw", "event", "full_log", "api_key", "token", "secret"}
    if forbidden.intersection(event):
        raise ForwardIngestionError("audit event contains a forbidden payload field")
    audit_path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    encoded = (
        json.dumps(
            {"timestamp_epoch": time.time(), **event, "contains_raw_payload": False},
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")
    flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(audit_path, flags, 0o600)
    try:
        metadata = os.fstat(descriptor)
        if not stat_module.S_ISREG(metadata.st_mode):
            raise ForwardIngestionError("forward audit target is not a regular file")
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
        os.write(descriptor, encoded)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@dataclass(slots=True)
class RateLimitedDelivery:
    delivery: EventDeliveryClient
    records_per_second: float
    stop_event: Event
    _last_attempt: float | None = None

    def deliver(self, payload: bytes) -> str:
        if self._last_attempt is not None:
            delay = max(
                0.0,
                (1.0 / self.records_per_second) - (time.monotonic() - self._last_attempt),
            )
            if delay:
                time.sleep(delay)
        self._last_attempt = time.monotonic()
        return self.delivery.deliver(payload)


def run_forward_service(
    sender: SenderConfig,
    *,
    state_path: Path,
    approval_path: Path,
    audit_path: Path,
    batch_limit: int = 10,
    records_per_second: float = 5.0,
    poll_seconds: float = 5.0,
    stop_event: Event | None = None,
) -> int:
    """Run one single-event worker; caller must supply explicit live approval."""

    if not 1 <= batch_limit <= 25:
        raise ValueError("forward batch limit must be between 1 and 25")
    if not 0 < records_per_second <= 25:
        raise ValueError("forward rate must be greater than zero and at most 25 records/s")
    if not 0.1 <= poll_seconds <= 300:
        raise ValueError("forward poll interval must be between 0.1 and 300 seconds")
    event_config = EventShipperConfig.from_sender(sender)
    if event_config.batch_protocol_enabled or event_config.adaptive_enabled:
        raise ForwardIngestionError(
            "forward service requires single-event protocol and adaptive batching disabled"
        )
    approval = validate_live_approval(approval_path, state_path)
    stop = stop_event or Event()
    if stop_event is None:
        def request_stop(_signum: int, _frame: object) -> None:
            stop.set()

        signal.signal(signal.SIGINT, request_stop)
        if hasattr(signal, "SIGTERM"):
            signal.signal(signal.SIGTERM, request_stop)
    client = EventDeliveryClient(event_config)
    delivery = RateLimitedDelivery(client, records_per_second, stop)
    worker = ForwardIngestionWorker(
        state_path,
        selector=select_archive_event,
        delivery=delivery,
        max_line_bytes=event_config.max_line_bytes,
    )
    append_payload_free_audit(
        audit_path,
        {
            "action": "service_start",
            "generation_id": approval["generation_id"],
            "approval_sha256": approval["approval_sha256"],
            "batch_limit": batch_limit,
            "records_per_second": records_per_second,
        },
    )
    try:
        with ForwardCheckpointLock(state_path):
            while not stop.is_set():
                # Expiry and exact generation binding are rechecked before each batch.
                validate_live_approval(
                    approval_path,
                    state_path,
                    deep_on_evolved_state=False,
                )
                before = load_forward_state(state_path)
                after = worker.run_batch(
                    limit=batch_limit,
                    checkpoint_lock_owned=True,
                )
                append_payload_free_audit(
                    audit_path,
                    {
                        "action": "batch_complete",
                        "generation_id": after.generation_id,
                        "start_offset": before.offset,
                        "end_offset": after.offset,
                        "accepted_delta": after.accepted - before.accepted,
                        "duplicate_delta": after.duplicates - before.duplicates,
                        "filtered_delta": after.filtered - before.filtered,
                        "malformed_delta": after.malformed - before.malformed,
                        "retry_delta": after.retry_attempts - before.retry_attempts,
                        "status": after.status,
                    },
                )
                if after.terminal_blocked:
                    return 4
                exponent = min(after.consecutive_retries, 6)
                wait = min(60.0, poll_seconds * (2**exponent))
                if after.offset == before.offset or after.consecutive_retries:
                    stop.wait(wait)
    except ForwardIngestionError as exc:
        append_payload_free_audit(
            audit_path,
            {
                "action": "service_blocked",
                "generation_id": approval["generation_id"],
                "error_type": type(exc).__name__,
            },
        )
        raise
    finally:
        client.close()
        append_payload_free_audit(
            audit_path,
            {"action": "service_stop", "generation_id": approval["generation_id"]},
        )
    return 0
