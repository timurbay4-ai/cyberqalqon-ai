"""Generation-aware, operator-gated recovery for immutable Wazuh archives.

This module is deliberately separate from the live event shipper. Registering or auditing an
archive never changes the live cursor, and replay requires an explicit approval flag on every
batch. Durable replay offsets are uncompressed byte offsets, including for gzip archives.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, BinaryIO, Callable, Iterator

from .durable_state import durable_atomic_json


class ArchiveRecoveryError(RuntimeError):
    """Raised when immutable evidence or durable replay state cannot be trusted."""


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    durable_atomic_json(path, payload)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


@contextmanager
def _open_archive(path: Path, compression: str) -> Iterator[BinaryIO]:
    try:
        if compression == "GZIP":
            with gzip.open(path, "rb") as handle:
                yield handle
        else:
            with path.open("rb") as handle:
                yield handle
    except ArchiveRecoveryError:
        raise
    except (EOFError, OSError) as exc:
        raise ArchiveRecoveryError("registered archive cannot be decoded safely") from exc


@dataclass(frozen=True, slots=True)
class ArchiveGeneration:
    generation_id: str
    path: str
    compression: str
    device: int
    inode: int
    size_bytes: int
    mtime_ns: int
    sha256: str
    registered_at_epoch: float

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ArchiveGeneration":
        try:
            generation = cls(
                generation_id=str(value["generation_id"]),
                path=str(value["path"]),
                compression=str(value["compression"]),
                device=int(value["device"]),
                inode=int(value["inode"]),
                size_bytes=int(value["size_bytes"]),
                mtime_ns=int(value["mtime_ns"]),
                sha256=str(value["sha256"]),
                registered_at_epoch=float(value["registered_at_epoch"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ArchiveRecoveryError("archive generation metadata is malformed") from exc
        if generation.compression not in {"NONE", "GZIP"}:
            raise ArchiveRecoveryError("archive generation compression is unsupported")
        if len(generation.sha256) != 64 or len(generation.generation_id) != 64:
            raise ArchiveRecoveryError("archive generation digest is malformed")
        return generation


class ArchiveGenerationManifest:
    def __init__(self, path: Path) -> None:
        if not path.is_absolute():
            raise ValueError("archive generation manifest path must be absolute")
        self.path = path

    def _load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"version": 1, "generations": []}
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise ArchiveRecoveryError("archive generation manifest is unreadable") from exc
        if not isinstance(raw, dict) or raw.get("version") != 1:
            raise ArchiveRecoveryError("archive generation manifest version is unsupported")
        generations = raw.get("generations")
        if not isinstance(generations, list):
            raise ArchiveRecoveryError("archive generation manifest is malformed")
        return raw

    def register(self, archive_path: Path) -> ArchiveGeneration:
        if not archive_path.is_absolute() or not archive_path.is_file():
            raise ArchiveRecoveryError("archive path must be an existing absolute file")
        before = archive_path.stat()
        fingerprint = _sha256_file(archive_path)
        after = archive_path.stat()
        identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        if identity_before != identity_after:
            raise ArchiveRecoveryError("archive changed while its generation was registered")
        identity = "\x00".join(
            (
                "archive-generation-v1",
                str(after.st_dev),
                str(after.st_ino),
                str(after.st_size),
                str(after.st_mtime_ns),
                fingerprint,
            )
        )
        generation = ArchiveGeneration(
            generation_id=hashlib.sha256(identity.encode("utf-8")).hexdigest(),
            path=str(archive_path),
            compression="GZIP" if archive_path.suffix.casefold() == ".gz" else "NONE",
            device=after.st_dev,
            inode=after.st_ino,
            size_bytes=after.st_size,
            mtime_ns=after.st_mtime_ns,
            sha256=fingerprint,
            registered_at_epoch=time.time(),
        )
        manifest = self._load()
        existing = [
            ArchiveGeneration.from_dict(item)
            for item in manifest["generations"]
            if isinstance(item, dict)
        ]
        by_id = {item.generation_id: item for item in existing}
        if generation.generation_id in by_id:
            return by_id[generation.generation_id]
        if any(item.path == generation.path for item in existing):
            raise ArchiveRecoveryError(
                "this archive path is already registered with a different immutable identity"
            )
        manifest["generations"].append(asdict(generation))
        _atomic_json(self.path, manifest)
        return generation

    def get(self, generation_id: str) -> ArchiveGeneration:
        for item in self._load()["generations"]:
            if isinstance(item, dict) and item.get("generation_id") == generation_id:
                return ArchiveGeneration.from_dict(item)
        raise ArchiveRecoveryError("archive generation is not registered")


def _validate_generation(generation: ArchiveGeneration, *, full_digest: bool = False) -> Path:
    path = Path(generation.path)
    try:
        stat = path.stat()
    except OSError as exc:
        raise ArchiveRecoveryError("registered archive is unavailable") from exc
    observed = (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)
    expected = (
        generation.device,
        generation.inode,
        generation.size_bytes,
        generation.mtime_ns,
    )
    if observed != expected:
        raise ArchiveRecoveryError("registered archive identity changed; replay refused")
    if full_digest and _sha256_file(path) != generation.sha256:
        raise ArchiveRecoveryError("registered archive digest changed; replay refused")
    return path


def _validate_replay_checkpoint(
    generation: ArchiveGeneration,
    archive_path: Path,
    *,
    offset: int,
) -> bool:
    """Validate an uncompressed replay offset without advancing durable state.

    Returns ``True`` when the checkpoint is exactly at EOF.  A replay checkpoint is
    only safe at offset zero, or immediately after a newline.  This check also
    detects offsets beyond the uncompressed end of gzip archives; a normal file
    seek alone would otherwise permit a sparse position past EOF.
    """

    if offset < 0:
        raise ArchiveRecoveryError("historical replay checkpoint is negative")
    with _open_archive(archive_path, generation.compression) as handle:
        if offset:
            try:
                handle.seek(offset - 1)
                previous = handle.read(1)
            except (OSError, ValueError) as exc:
                raise ArchiveRecoveryError(
                    "historical replay checkpoint cannot be restored"
                ) from exc
            if not previous:
                raise ArchiveRecoveryError(
                    "historical replay checkpoint is beyond the archive"
                )
            if previous != b"\n":
                raise ArchiveRecoveryError(
                    "historical replay checkpoint is not on a record boundary"
                )
        try:
            handle.seek(offset)
            next_byte = handle.read(1)
        except (OSError, ValueError) as exc:
            raise ArchiveRecoveryError(
                "historical replay checkpoint cannot be restored"
            ) from exc
    return next_byte == b""


@dataclass(slots=True)
class HistoricalReplayState:
    generation_id: str
    offset: int = 0
    status: str = "PAUSED"
    accepted: int = 0
    duplicates: int = 0
    filtered: int = 0
    malformed: int = 0
    oversized: int = 0
    delivery_rejected: int = 0
    retry_attempts: int = 0
    protocol_errors: int = 0
    consecutive_retries: int = 0
    terminal_blocked: bool = False
    last_failure_category: str | None = None
    last_success_at_epoch: float | None = None
    last_failure_at_epoch: float | None = None
    updated_at_epoch: float = 0.0

    def as_dict(self) -> dict[str, Any]:
        return {"version": 2, **asdict(self)}


class HistoricalArchiveReplayer:
    def __init__(
        self,
        generation: ArchiveGeneration,
        state_directory: Path,
        *,
        max_line_bytes: int,
        selector: Callable[[dict[str, Any]], bool],
        delivery: Any,
    ) -> None:
        if not state_directory.is_absolute():
            raise ValueError("historical replay state directory must be absolute")
        if not 4_096 <= max_line_bytes <= 1_048_576:
            raise ValueError("max_line_bytes is outside the supported replay bound")
        self.generation = generation
        self.state_path = state_directory / f"{generation.generation_id}.json"
        self.max_line_bytes = max_line_bytes
        self.selector = selector
        self.delivery = delivery

    def _load_state(self) -> HistoricalReplayState:
        if not self.state_path.exists():
            return HistoricalReplayState(generation_id=self.generation.generation_id)
        try:
            raw = json.loads(self.state_path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict) or raw.get("version") not in {1, 2}:
                raise ArchiveRecoveryError("historical replay state version is unsupported")
            if raw.get("generation_id") != self.generation.generation_id:
                raise ArchiveRecoveryError("historical replay state generation does not match")
            state = HistoricalReplayState(
                generation_id=self.generation.generation_id,
                offset=int(raw.get("offset", 0)),
                status=str(raw.get("status", "PAUSED")),
                accepted=max(0, int(raw.get("accepted", 0))),
                duplicates=max(0, int(raw.get("duplicates", 0))),
                filtered=max(0, int(raw.get("filtered", 0))),
                malformed=max(0, int(raw.get("malformed", 0))),
                oversized=max(0, int(raw.get("oversized", 0))),
                delivery_rejected=max(0, int(raw.get("delivery_rejected", 0))),
                retry_attempts=max(0, int(raw.get("retry_attempts", 0))),
                protocol_errors=max(0, int(raw.get("protocol_errors", 0))),
                consecutive_retries=max(0, int(raw.get("consecutive_retries", 0))),
                terminal_blocked=bool(raw.get("terminal_blocked", False)),
                last_failure_category=(
                    str(raw["last_failure_category"])
                    if raw.get("last_failure_category") is not None else None
                ),
                last_success_at_epoch=(
                    float(raw["last_success_at_epoch"])
                    if raw.get("last_success_at_epoch") is not None else None
                ),
                last_failure_at_epoch=(
                    float(raw["last_failure_at_epoch"])
                    if raw.get("last_failure_at_epoch") is not None else None
                ),
                updated_at_epoch=float(raw.get("updated_at_epoch", 0)),
            )
        except ArchiveRecoveryError:
            raise
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ArchiveRecoveryError("historical replay state is unreadable") from exc
        if state.status not in {"PAUSED", "RUNNING", "COMPLETE", "BLOCKED"}:
            raise ArchiveRecoveryError("historical replay state status is invalid")
        return state

    def _save_state(self, state: HistoricalReplayState) -> None:
        state.updated_at_epoch = time.time()
        _atomic_json(self.state_path, state.as_dict())

    def pause(self) -> HistoricalReplayState:
        state = self._load_state()
        if state.status not in {"COMPLETE", "BLOCKED"}:
            state.status = "PAUSED"
        self._save_state(state)
        return state

    def run_batch(
        self,
        *,
        operator_approved: bool,
        limit: int = 100,
        records_per_second: float = 10.0,
    ) -> HistoricalReplayState:
        if not operator_approved:
            raise ArchiveRecoveryError(
                "historical replay requires explicit operator approval for this batch"
            )
        if not 1 <= limit <= 1_000:
            raise ValueError("historical replay limit must be between 1 and 1000")
        if not 0.1 <= records_per_second <= 1_000:
            raise ValueError("historical replay rate must be between 0.1 and 1000 records/second")
        archive_path = _validate_generation(self.generation, full_digest=True)
        state = self._load_state()
        checkpoint_at_eof = _validate_replay_checkpoint(
            self.generation,
            archive_path,
            offset=state.offset,
        )
        if state.status == "COMPLETE" and not checkpoint_at_eof:
            raise ArchiveRecoveryError(
                "complete historical replay state is not positioned at archive EOF"
            )
        if state.status == "COMPLETE":
            return state
        if state.terminal_blocked or state.status == "BLOCKED":
            return state
        state.status = "RUNNING"
        processed = 0
        reached_eof = False
        minimum_interval = 1.0 / records_per_second
        last_delivery = 0.0
        with _open_archive(archive_path, self.generation.compression) as handle:
            try:
                handle.seek(state.offset)
            except (OSError, ValueError) as exc:
                raise ArchiveRecoveryError("historical replay cursor cannot be restored") from exc
            while processed < limit:
                line_start = handle.tell()
                line = handle.readline(self.max_line_bytes + 1)
                if not line:
                    reached_eof = True
                    break
                if len(line) > self.max_line_bytes:
                    while line and not line.endswith(b"\n"):
                        line = handle.readline(65_536)
                    state.offset = handle.tell()
                    state.malformed += 1
                    state.oversized += 1
                    processed += 1
                    continue
                if not line.endswith(b"\n"):
                    state.offset = handle.tell()
                    state.malformed += 1
                    processed += 1
                    reached_eof = True
                    break
                try:
                    payload = json.loads(line)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    state.offset = handle.tell()
                    state.malformed += 1
                    processed += 1
                    continue
                if not isinstance(payload, dict) or not self.selector(payload):
                    state.offset = handle.tell()
                    state.filtered += 1
                    processed += 1
                    continue
                wait_for = minimum_interval - (time.monotonic() - last_delivery)
                if last_delivery and wait_for > 0:
                    time.sleep(wait_for)
                result = self.delivery.deliver(line.rstrip(b"\r\n"))
                last_delivery = time.monotonic()
                if result in {"retry", "protocol_error"}:
                    handle.seek(line_start)
                    state.retry_attempts += 1
                    if result == "protocol_error":
                        state.protocol_errors += 1
                    state.consecutive_retries += 1
                    state.last_failure_at_epoch = time.time()
                    state.last_failure_category = result
                    state.status = "PAUSED"
                    break
                if result == "accepted":
                    state.offset = handle.tell()
                    state.accepted += 1
                elif result == "duplicate":
                    state.offset = handle.tell()
                    state.duplicates += 1
                else:
                    state.delivery_rejected += 1
                    state.terminal_blocked = True
                    state.last_failure_at_epoch = time.time()
                    state.last_failure_category = "delivery_rejected"
                    state.status = "BLOCKED"
                    handle.seek(line_start)
                    break
                state.consecutive_retries = 0
                state.last_failure_category = None
                state.last_success_at_epoch = time.time()
                processed += 1
        if reached_eof:
            _validate_generation(self.generation, full_digest=True)
            state.status = "COMPLETE"
        elif state.status == "RUNNING":
            state.status = "PAUSED"
        self._save_state(state)
        return state


def audit_malformed_records(
    generation: ArchiveGeneration,
    *,
    start_offset: int,
    max_line_bytes: int,
    output_path: Path,
    selector: Callable[[dict[str, Any]], bool] | None = None,
) -> dict[str, Any]:
    """Write a payload-free, deterministic audit of malformed archive records."""

    if start_offset < 0:
        raise ValueError("malformed audit start_offset must not be negative")
    if not output_path.is_absolute():
        raise ValueError("malformed audit output path must be absolute")
    if not 4_096 <= max_line_bytes <= 1_048_576:
        raise ValueError("max_line_bytes is outside the supported audit bound")
    archive_path = _validate_generation(generation)
    records: list[dict[str, Any]] = []
    counts = {
        "invalid_utf8": 0,
        "invalid_json": 0,
        "oversized": 0,
        "partial_line": 0,
    }
    valid_json = eligible = filtered = 0
    with _open_archive(archive_path, generation.compression) as handle:
        try:
            handle.seek(start_offset)
        except (OSError, ValueError) as exc:
            raise ArchiveRecoveryError("malformed audit cursor cannot be restored") from exc
        while True:
            line_start = handle.tell()
            line = handle.readline(max_line_bytes + 1)
            if not line:
                break
            digest = hashlib.sha256(line)
            category: str | None = None
            if len(line) > max_line_bytes:
                category = "oversized"
                while line and not line.endswith(b"\n"):
                    line = handle.readline(65_536)
                    digest.update(line)
            elif not line.endswith(b"\n"):
                category = "partial_line"
            else:
                try:
                    decoded = line.decode("utf-8")
                except UnicodeDecodeError:
                    category = "invalid_utf8"
                else:
                    try:
                        payload = json.loads(decoded)
                    except json.JSONDecodeError:
                        category = "invalid_json"
                    else:
                        valid_json += 1
                        if selector is not None:
                            if isinstance(payload, dict) and selector(payload):
                                eligible += 1
                            else:
                                filtered += 1
            if category is None:
                continue
            counts[category] += 1
            line_digest = digest.hexdigest()
            end_offset = handle.tell()
            record_key = (
                f"{generation.generation_id}:{line_start}:{end_offset}:{line_digest}:{category}"
            )
            records.append(
                {
                    "record_id": hashlib.sha256(record_key.encode("utf-8")).hexdigest(),
                    "generation_id": generation.generation_id,
                    "start_offset": line_start,
                    "end_offset": end_offset,
                    "line_sha256": line_digest,
                    "category": category,
                }
            )
    _validate_generation(generation, full_digest=True)
    result = {
        "version": 1,
        "generation_id": generation.generation_id,
        "source_sha256": generation.sha256,
        "start_offset": start_offset,
        "counts": {**counts, "total": sum(counts.values())},
        "inventory": {
            "valid_json_records": valid_json,
            "eligible_records": eligible if selector is not None else None,
            "filtered_records": filtered if selector is not None else None,
        },
        "records": records,
        "contains_raw_payload": False,
        "captured_at_epoch": time.time(),
    }
    _atomic_json(output_path, result)
    return result


def audit_active_malformed_records(
    archive_path: Path,
    state_path: Path,
    *,
    max_line_bytes: int,
    output_path: Path,
    selector: Callable[[dict[str, Any]], bool] | None = None,
) -> dict[str, Any]:
    """Audit only the acknowledged prefix of the active archive without changing its cursor."""

    if not archive_path.is_absolute() or not state_path.is_absolute():
        raise ValueError("active archive and cursor paths must be absolute")
    if not output_path.is_absolute():
        raise ValueError("malformed audit output path must be absolute")
    if not 4_096 <= max_line_bytes <= 1_048_576:
        raise ValueError("max_line_bytes is outside the supported audit bound")
    try:
        raw_state = json.loads(state_path.read_text(encoding="utf-8"))
        before = archive_path.stat()
        device = int(raw_state["device"])
        inode = int(raw_state["inode"])
        snapshot_end = int(raw_state["offset"])
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ArchiveRecoveryError("active archive cursor is unavailable or malformed") from exc
    if (device, inode) != (before.st_dev, before.st_ino):
        raise ArchiveRecoveryError("active archive identity does not match its cursor")
    if not 0 <= snapshot_end <= before.st_size:
        raise ArchiveRecoveryError("active archive cursor is outside the source file")
    generation_key = f"active-archive-v1:{device}:{inode}"
    generation_id = hashlib.sha256(generation_key.encode("utf-8")).hexdigest()
    records: list[dict[str, Any]] = []
    counts = {
        "invalid_utf8": 0,
        "invalid_json": 0,
        "oversized": 0,
        "partial_line": 0,
    }
    valid_json = eligible = filtered = 0
    with archive_path.open("rb") as handle:
        while handle.tell() < snapshot_end:
            line_start = handle.tell()
            remaining = snapshot_end - line_start
            line = handle.readline(min(max_line_bytes + 1, remaining))
            if not line:
                break
            digest = hashlib.sha256(line)
            category: str | None = None
            if len(line) > max_line_bytes or (
                not line.endswith(b"\n") and handle.tell() < snapshot_end
            ):
                category = "oversized"
                while handle.tell() < snapshot_end and not line.endswith(b"\n"):
                    remaining = snapshot_end - handle.tell()
                    line = handle.readline(min(65_536, remaining))
                    digest.update(line)
            elif not line.endswith(b"\n"):
                category = "partial_line"
            else:
                try:
                    decoded = line.decode("utf-8")
                except UnicodeDecodeError:
                    category = "invalid_utf8"
                else:
                    try:
                        payload = json.loads(decoded)
                    except json.JSONDecodeError:
                        category = "invalid_json"
                    else:
                        valid_json += 1
                        if selector is not None:
                            if isinstance(payload, dict) and selector(payload):
                                eligible += 1
                            else:
                                filtered += 1
            if category is None:
                continue
            counts[category] += 1
            line_digest = digest.hexdigest()
            end_offset = handle.tell()
            record_key = f"{generation_id}:{line_start}:{end_offset}:{line_digest}:{category}"
            records.append(
                {
                    "record_id": hashlib.sha256(record_key.encode("utf-8")).hexdigest(),
                    "generation_id": generation_id,
                    "start_offset": line_start,
                    "end_offset": end_offset,
                    "line_sha256": line_digest,
                    "category": category,
                }
            )
    after = archive_path.stat()
    if (after.st_dev, after.st_ino) != (device, inode) or after.st_size < snapshot_end:
        raise ArchiveRecoveryError("active archive rotated or truncated during malformed audit")
    result = {
        "version": 1,
        "generation_id": generation_id,
        "source_identity": {
            "device": device,
            "inode": inode,
            "snapshot_end_offset": snapshot_end,
            "archive_size_at_start": before.st_size,
        },
        "counts": {**counts, "total": sum(counts.values())},
        "inventory": {
            "valid_json_records": valid_json,
            "eligible_records": eligible if selector is not None else None,
            "filtered_records": filtered if selector is not None else None,
        },
        "records": records,
        "contains_raw_payload": False,
        "captured_at_epoch": time.time(),
    }
    _atomic_json(output_path, result)
    return result
