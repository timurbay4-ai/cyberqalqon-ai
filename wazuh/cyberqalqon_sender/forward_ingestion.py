"""Independent generation-aware forward ingestion primitives.

The engine is exposed through an approval-gated CLI/service, while the unresolved
legacy cursor stays read-only in a separate namespace.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import re
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, BinaryIO, Callable, Iterator

from .durable_state import durable_atomic_json


class ForwardIngestionError(RuntimeError):
    """Raised when a forward source or cursor cannot be trusted."""


_LOWER_NAMESPACE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _absolute_file(path: str, *, label: str) -> Path:
    candidate = Path(path)
    if not candidate.is_absolute():
        raise ForwardIngestionError(f"{label} path must be absolute")
    return candidate


class ForwardCheckpointLock:
    """Cross-platform advisory lock for one independent checkpoint.

    The lock file may remain after a crash; the OS-level lock is automatically
    released when the process exits. This avoids unsafe stale-PID deletion.
    """

    def __init__(self, state_path: Path) -> None:
        if not state_path.is_absolute():
            raise ValueError("forward state path must be absolute")
        self.path = state_path.with_suffix(f"{state_path.suffix}.lock")
        self._handle: BinaryIO | None = None

    def __enter__(self) -> "ForwardCheckpointLock":
        self.path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
        handle = self.path.open("a+b")
        try:
            if os.name == "posix":
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                os.chmod(self.path, 0o600)
            elif os.name == "nt":
                import msvcrt

                if handle.seek(0, os.SEEK_END) == 0:
                    handle.write(b"\0")
                    handle.flush()
                    os.fsync(handle.fileno())
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                raise ForwardIngestionError("checkpoint locking is unsupported")
        except (BlockingIOError, OSError) as exc:
            handle.close()
            raise ForwardIngestionError(
                "forward checkpoint is already owned by another process"
            ) from exc
        except Exception:
            handle.close()
            raise
        self._handle = handle
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        if self._handle is None:
            return
        try:
            if os.name == "posix":
                import fcntl

                fcntl.flock(self._handle.fileno(), fcntl.LOCK_UN)
            elif os.name == "nt":
                import msvcrt

                self._handle.seek(0)
                msvcrt.locking(self._handle.fileno(), msvcrt.LK_UNLCK, 1)
        finally:
            self._handle.close()
            self._handle = None


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


@contextmanager
def _open_source(path: Path, compression: str) -> Iterator[BinaryIO]:
    handle: BinaryIO
    try:
        if compression == "GZIP":
            handle = gzip.open(path, "rb")
        else:
            handle = path.open("rb")
    except OSError as exc:
        raise ForwardIngestionError("forward source cannot be decoded safely") from exc
    try:
        yield handle
    except (EOFError, gzip.BadGzipFile) as exc:
        raise ForwardIngestionError("forward source cannot be decoded safely") from exc
    finally:
        handle.close()


def _chain_seed() -> str:
    return hashlib.sha256(b"m21-forward-record-chain-v1").hexdigest()


def _chain_next(previous: str, line: bytes) -> str:
    return _chain_next_digest(previous, hashlib.sha256(line).digest())


def _chain_next_digest(previous: str, line_sha256: bytes) -> str:
    digest = hashlib.sha256()
    digest.update(bytes.fromhex(previous))
    digest.update(line_sha256)
    return digest.hexdigest()


def _read_bounded_record(
    handle: BinaryIO,
    *,
    max_line_bytes: int,
    snapshot_end: int | None,
) -> tuple[bytes | None, bytes | None, bool, bool]:
    """Read one newline-terminated record without retaining an oversized payload.

    Returns ``(payload, sha256_digest, complete, oversized)``. The handle is
    left at the end of the record on success and callers must restore their
    starting position when ``complete`` is false.
    """

    start = handle.tell()
    if snapshot_end is not None:
        remaining = snapshot_end - start
        if remaining <= 0:
            return None, None, False, False
        first = handle.readline(min(max_line_bytes + 1, remaining))
    else:
        first = handle.readline(max_line_bytes + 1)
    if not first:
        return None, None, False, False

    oversized = len(first) > max_line_bytes
    digest = hashlib.sha256()
    digest.update(first)
    retained: bytearray | None = None if oversized else bytearray(first)
    tail = first
    while tail and not tail.endswith(b"\n"):
        if snapshot_end is not None:
            remaining = snapshot_end - handle.tell()
            if remaining <= 0:
                return None, None, False, oversized
            tail = handle.readline(min(65_536, remaining))
        else:
            tail = handle.readline(65_536)
        if not tail:
            return None, None, False, oversized
        digest.update(tail)
        if retained is not None:
            if len(retained) + len(tail) > max_line_bytes:
                retained = None
                oversized = True
            else:
                retained.extend(tail)
    return bytes(retained) if retained is not None else None, digest.digest(), True, oversized


def _decoded_prefix_sha256(path: Path, compression: str, length: int) -> str:
    digest = hashlib.sha256()
    remaining = length
    with _open_source(path, compression) as handle:
        while remaining:
            chunk = handle.read(min(1024 * 1024, remaining))
            if not chunk:
                raise ForwardIngestionError("forward start boundary exceeds the source")
            digest.update(chunk)
            remaining -= len(chunk)
    return digest.hexdigest()


def _validate_boundary(path: Path, compression: str, offset: int) -> bool:
    if offset < 0:
        raise ForwardIngestionError("forward cursor is negative")
    with _open_source(path, compression) as handle:
        if offset:
            try:
                handle.seek(offset - 1)
                previous = handle.read(1)
            except (OSError, ValueError) as exc:
                raise ForwardIngestionError("forward cursor cannot be restored") from exc
            if not previous:
                raise ForwardIngestionError("forward cursor is beyond the source")
            if previous != b"\n":
                raise ForwardIngestionError("forward cursor is not on a record boundary")
        try:
            handle.seek(offset)
            return handle.read(1) == b""
        except (OSError, ValueError) as exc:
            raise ForwardIngestionError("forward cursor cannot be restored") from exc


@dataclass(slots=True)
class ForwardGenerationState:
    namespace: str
    generation_id: str
    source_path: str
    compression: str
    source_device: int
    source_inode: int
    source_size_at_registration: int
    source_ctime_ns_at_registration: int
    source_stored_sha256: str | None
    original_device: int
    original_inode: int
    start_offset: int
    start_prefix_sha256: str
    offset: int
    record_chain_sha256: str
    records: int = 0
    accepted: int = 0
    duplicates: int = 0
    filtered: int = 0
    malformed: int = 0
    oversized: int = 0
    retry_attempts: int = 0
    protocol_errors: int = 0
    delivery_rejected: int = 0
    consecutive_retries: int = 0
    terminal_blocked: bool = False
    status: str = "PAUSED"
    last_failure_category: str | None = None
    last_success_at_epoch: float | None = None
    last_failure_at_epoch: float | None = None
    legacy_state_path: str | None = None
    legacy_state_sha256: str | None = None
    legacy_cursor_at_registration: int | None = None
    updated_at_epoch: float = 0.0

    def as_dict(self) -> dict[str, Any]:
        return {"version": 1, **asdict(self), "contains_raw_payload": False}

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "ForwardGenerationState":
        if raw.get("version") != 1:
            raise ForwardIngestionError("forward state version is unsupported")
        if raw.get("contains_raw_payload") is not False:
            raise ForwardIngestionError("forward state payload marker is invalid")
        fields = cls.__dataclass_fields__
        try:
            values = {name: raw[name] for name in fields}
            state = cls(**values)
        except (KeyError, TypeError, ValueError) as exc:
            raise ForwardIngestionError("forward state is malformed") from exc
        integer_fields = (
            "source_device",
            "source_inode",
            "source_size_at_registration",
            "source_ctime_ns_at_registration",
            "original_device",
            "original_inode",
            "start_offset",
            "offset",
            "records",
            "accepted",
            "duplicates",
            "filtered",
            "malformed",
            "oversized",
            "retry_attempts",
            "protocol_errors",
            "delivery_rejected",
            "consecutive_retries",
        )
        for name in integer_fields:
            value = getattr(state, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ForwardIngestionError(f"forward state {name} is invalid")
        if not isinstance(state.terminal_blocked, bool):
            raise ForwardIngestionError("forward state terminal flag is invalid")
        if not isinstance(state.namespace, str) or not _LOWER_NAMESPACE.fullmatch(
            state.namespace
        ):
            raise ForwardIngestionError("forward state namespace is invalid")
        if not isinstance(state.source_path, str):
            raise ForwardIngestionError("forward source path is invalid")
        _absolute_file(state.source_path, label="forward source")
        if state.compression not in {"NONE", "GZIP"}:
            raise ForwardIngestionError("forward source compression is unsupported")
        if state.status not in {"PAUSED", "WAITING", "BLOCKED"}:
            raise ForwardIngestionError("forward state status is invalid")
        if state.offset < state.start_offset:
            raise ForwardIngestionError("forward cursor precedes its explicit start")
        if not _is_sha256(state.generation_id) or not _is_sha256(
            state.record_chain_sha256
        ):
            raise ForwardIngestionError("forward state digest is malformed")
        if not _is_sha256(state.start_prefix_sha256):
            raise ForwardIngestionError("forward start-prefix digest is malformed")
        if state.source_stored_sha256 is not None and not _is_sha256(
            state.source_stored_sha256
        ):
            raise ForwardIngestionError("forward source digest is malformed")
        if state.compression == "GZIP" and state.source_stored_sha256 is None:
            raise ForwardIngestionError("immutable forward source digest is missing")
        if state.last_failure_category is not None and not isinstance(
            state.last_failure_category, str
        ):
            raise ForwardIngestionError("forward failure category is invalid")
        legacy_values = (
            state.legacy_state_path,
            state.legacy_state_sha256,
            state.legacy_cursor_at_registration,
        )
        if any(value is not None for value in legacy_values) and not all(
            value is not None for value in legacy_values
        ):
            raise ForwardIngestionError("legacy state inventory is incomplete")
        if state.legacy_state_path is not None:
            if not isinstance(state.legacy_state_path, str):
                raise ForwardIngestionError("legacy state path is invalid")
            _absolute_file(state.legacy_state_path, label="legacy state")
            if not _is_sha256(state.legacy_state_sha256):
                raise ForwardIngestionError("legacy state digest is malformed")
            if (
                isinstance(state.legacy_cursor_at_registration, bool)
                or not isinstance(state.legacy_cursor_at_registration, int)
                or state.legacy_cursor_at_registration < 0
            ):
                raise ForwardIngestionError("legacy cursor inventory is invalid")
        for name in ("last_success_at_epoch", "last_failure_at_epoch"):
            value = getattr(state, name)
            if value is not None and (
                isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0
            ):
                raise ForwardIngestionError(f"forward state {name} is invalid")
        if (
            isinstance(state.updated_at_epoch, bool)
            or not isinstance(state.updated_at_epoch, (int, float))
            or state.updated_at_epoch < 0
        ):
            raise ForwardIngestionError("forward state update timestamp is invalid")
        if state.records != (
            state.accepted + state.duplicates + state.filtered + state.malformed
        ):
            raise ForwardIngestionError("forward state record counters are inconsistent")
        if state.oversized > state.malformed:
            raise ForwardIngestionError("forward oversized counter is inconsistent")
        if state.terminal_blocked != (state.status == "BLOCKED"):
            raise ForwardIngestionError("forward blocked state is inconsistent")
        return state


def initialize_forward_generation(
    source_path: Path,
    state_directory: Path,
    *,
    namespace: str,
    start_offset: int,
    legacy_state_path: Path | None = None,
) -> Path:
    """Create an independent cursor without changing the legacy cursor."""

    if not source_path.is_absolute() or not source_path.is_file():
        raise ForwardIngestionError("forward source must be an existing absolute file")
    if not state_directory.is_absolute():
        raise ValueError("forward state directory must be absolute")
    if not _LOWER_NAMESPACE.fullmatch(namespace):
        raise ValueError("forward namespace must be lowercase alphanumeric with '-' or '_'")
    if legacy_state_path is not None:
        resolved_state_directory = state_directory.resolve()
        resolved_legacy = legacy_state_path.resolve()
        if (
            resolved_state_directory == resolved_legacy.parent
            or resolved_legacy.is_relative_to(resolved_state_directory)
        ):
            raise ForwardIngestionError("forward and legacy state directories must be isolated")
    compression = "GZIP" if source_path.suffix.casefold() == ".gz" else "NONE"
    before = source_path.stat()
    _validate_boundary(source_path, compression, start_offset)
    prefix_sha256 = _decoded_prefix_sha256(source_path, compression, start_offset)
    after = source_path.stat()
    if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
        raise ForwardIngestionError("forward source rotated during initialization")
    if after.st_size < before.st_size:
        raise ForwardIngestionError("forward source truncated during initialization")

    # Preserve checkpoints prepared before the content-bound identity was added.
    # This keeps repeated preparation of an already-enrolled generation idempotent.
    legacy_identity = "\x00".join(
        (
            "m22-forward-generation-v1",
            namespace,
            str(after.st_dev),
            str(after.st_ino),
            str(start_offset),
            prefix_sha256,
        )
    )
    legacy_generation_id = hashlib.sha256(legacy_identity.encode("utf-8")).hexdigest()
    compatible_state_path = state_directory / namespace / f"{legacy_generation_id}.json"
    if compatible_state_path.exists():
        existing = load_forward_state(compatible_state_path)
        if (
            existing.generation_id != legacy_generation_id
            or existing.source_path != str(source_path)
            or existing.source_device != after.st_dev
            or existing.source_inode != after.st_ino
            or existing.start_offset != start_offset
            or existing.start_prefix_sha256 != prefix_sha256
        ):
            raise ForwardIngestionError("existing forward state identity is inconsistent")
        ForwardIngestionWorker._validate_legacy_inventory(existing)
        validate_forward_checkpoint(compatible_state_path, deep=True)
        return compatible_state_path

    # Device/inode pairs can be reused after unlink on POSIX filesystems. Bind new
    # zero-offset generations to the first complete record as well, while keeping
    # the identifier stable when that same active file is only appended to.
    with _open_source(source_path, compression) as handle:
        _first, first_digest, first_complete, _oversized = _read_bounded_record(
            handle,
            max_line_bytes=1_048_576,
            snapshot_end=None,
        )
    if after.st_size and not first_complete:
        raise ForwardIngestionError("forward source has no complete first record")
    first_record_sha256 = (
        first_digest.hex() if first_digest is not None else hashlib.sha256(b"").hexdigest()
    )
    identity = "\x00".join(
        (
            "m22-forward-generation-v2",
            namespace,
            str(after.st_dev),
            str(after.st_ino),
            str(start_offset),
            prefix_sha256,
            first_record_sha256,
        )
    )
    generation_id = hashlib.sha256(identity.encode("utf-8")).hexdigest()
    state_path = state_directory / namespace / f"{generation_id}.json"
    with ForwardCheckpointLock(state_path):
        if state_path.exists():
            existing = load_forward_state(state_path)
            if (
                existing.generation_id != generation_id
                or existing.source_path != str(source_path)
                or existing.source_device != after.st_dev
                or existing.source_inode != after.st_ino
                or existing.start_offset != start_offset
                or existing.start_prefix_sha256 != prefix_sha256
            ):
                raise ForwardIngestionError("existing forward state identity is inconsistent")
            ForwardIngestionWorker._validate_legacy_inventory(existing)
            return state_path
        legacy_sha = None
        legacy_cursor = None
        if legacy_state_path is not None:
            if not legacy_state_path.is_absolute() or not legacy_state_path.is_file():
                raise ForwardIngestionError("legacy state must be an existing absolute file")
            legacy_sha = _sha256_file(legacy_state_path)
            try:
                legacy_raw = json.loads(legacy_state_path.read_text(encoding="utf-8"))
                legacy_cursor = int(legacy_raw["offset"])
            except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                raise ForwardIngestionError("legacy state cannot be inventoried safely") from exc
        state = ForwardGenerationState(
            namespace=namespace,
            generation_id=generation_id,
            source_path=str(source_path),
            compression=compression,
            source_device=after.st_dev,
            source_inode=after.st_ino,
            source_size_at_registration=after.st_size,
            source_ctime_ns_at_registration=after.st_ctime_ns,
            source_stored_sha256=_sha256_file(source_path) if compression == "GZIP" else None,
            original_device=after.st_dev,
            original_inode=after.st_ino,
            start_offset=start_offset,
            start_prefix_sha256=prefix_sha256,
            offset=start_offset,
            record_chain_sha256=_chain_seed(),
            legacy_state_path=str(legacy_state_path) if legacy_state_path else None,
            legacy_state_sha256=legacy_sha,
            legacy_cursor_at_registration=legacy_cursor,
        )
        durable_atomic_json(state_path, state.as_dict())
    return state_path


def load_forward_state(state_path: Path) -> ForwardGenerationState:
    try:
        raw = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise ForwardIngestionError("forward state is unreadable") from exc
    if not isinstance(raw, dict):
        raise ForwardIngestionError("forward state is malformed")
    return ForwardGenerationState.from_dict(raw)


class ForwardIngestionWorker:
    def __init__(
        self,
        state_path: Path,
        *,
        selector: Callable[[dict[str, Any]], bool],
        delivery: Any,
        max_line_bytes: int = 1_048_576,
        state_writer: Callable[[Path, dict[str, Any]], None] = durable_atomic_json,
    ) -> None:
        if not state_path.is_absolute():
            raise ValueError("forward state path must be absolute")
        if not 4_096 <= max_line_bytes <= 1_048_576:
            raise ValueError("max_line_bytes is outside the supported bound")
        self.state_path = state_path
        self.selector = selector
        self.delivery = delivery
        self.max_line_bytes = max_line_bytes
        self.state_writer = state_writer

    def _save(self, state: ForwardGenerationState) -> None:
        state.updated_at_epoch = time.time()
        self.state_writer(self.state_path, state.as_dict())

    @staticmethod
    def _validate_legacy_inventory(state: ForwardGenerationState) -> None:
        if state.legacy_state_path is None:
            return
        legacy_path = Path(state.legacy_state_path)
        if legacy_path.resolve() == Path(state.source_path).resolve():
            raise ForwardIngestionError("legacy state aliases the forward source")
        try:
            legacy_sha = _sha256_file(legacy_path)
            raw = json.loads(legacy_path.read_text(encoding="utf-8"))
            cursor = int(raw["offset"])
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ForwardIngestionError("legacy state inventory cannot be revalidated") from exc
        if legacy_sha != state.legacy_state_sha256:
            raise ForwardIngestionError("legacy state changed after forward registration")
        if cursor != state.legacy_cursor_at_registration:
            raise ForwardIngestionError("legacy cursor changed after forward registration")

    @staticmethod
    def _validate_source(state: ForwardGenerationState) -> tuple[Path, int]:
        path = Path(state.source_path)
        try:
            stat = path.stat()
        except OSError as exc:
            raise ForwardIngestionError("forward source is unavailable") from exc
        if (stat.st_dev, stat.st_ino) != (state.source_device, state.source_inode):
            raise ForwardIngestionError("forward source generation identity changed")
        if state.compression == "NONE":
            if stat.st_size < state.offset:
                raise ForwardIngestionError("forward source truncated behind the cursor")
        else:
            if state.source_stored_sha256 is None:
                raise ForwardIngestionError("immutable forward source digest is missing")
            if (
                stat.st_size != state.source_size_at_registration
                or _sha256_file(path) != state.source_stored_sha256
            ):
                raise ForwardIngestionError("immutable forward source changed")
        return path, stat.st_size

    def run_batch(
        self, *, limit: int = 100, checkpoint_lock_owned: bool = False
    ) -> ForwardGenerationState:
        if not 1 <= limit <= 1_000:
            raise ValueError("forward batch limit must be between 1 and 1000")
        if not checkpoint_lock_owned:
            with ForwardCheckpointLock(self.state_path):
                return self.run_batch(limit=limit, checkpoint_lock_owned=True)
        state = load_forward_state(self.state_path)
        if state.status == "BLOCKED" or state.terminal_blocked:
            return state
        self._validate_legacy_inventory(state)
        path, snapshot_size = self._validate_source(state)
        _validate_boundary(path, state.compression, state.offset)
        processed = 0
        state.status = "PAUSED"
        with _open_source(path, state.compression) as handle:
            handle.seek(state.offset)
            while processed < limit:
                line_start = handle.tell()
                line, line_digest, complete, oversized = _read_bounded_record(
                    handle,
                    max_line_bytes=self.max_line_bytes,
                    snapshot_end=snapshot_size if state.compression == "NONE" else None,
                )
                if not complete or line_digest is None:
                    handle.seek(line_start)
                    state.status = "WAITING"
                    break
                if oversized:
                    state.offset = handle.tell()
                    state.records += 1
                    state.malformed += 1
                    state.oversized += 1
                    state.record_chain_sha256 = _chain_next_digest(
                        state.record_chain_sha256, line_digest
                    )
                    processed += 1
                    continue
                if not (line is not None):
                    raise RuntimeError("Internal forward_ingestion invariant failed")
                try:
                    payload = json.loads(line.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    state.offset = handle.tell()
                    state.records += 1
                    state.malformed += 1
                    state.record_chain_sha256 = _chain_next_digest(
                        state.record_chain_sha256, line_digest
                    )
                    processed += 1
                    continue
                if not isinstance(payload, dict) or not self.selector(payload):
                    state.offset = handle.tell()
                    state.records += 1
                    state.filtered += 1
                    state.record_chain_sha256 = _chain_next_digest(
                        state.record_chain_sha256, line_digest
                    )
                    processed += 1
                    continue
                result = self.delivery.deliver(line.rstrip(b"\r\n"))
                if result in {"retry", "protocol_error"}:
                    state.retry_attempts += 1
                    if result == "protocol_error":
                        state.protocol_errors += 1
                    state.consecutive_retries += 1
                    state.last_failure_category = result
                    state.last_failure_at_epoch = time.time()
                    state.status = "PAUSED"
                    self._save(state)
                    break
                if result not in {"accepted", "duplicate"}:
                    state.delivery_rejected += 1
                    state.terminal_blocked = True
                    state.status = "BLOCKED"
                    state.last_failure_category = "delivery_rejected"
                    state.last_failure_at_epoch = time.time()
                    self._save(state)
                    break
                state.offset = handle.tell()
                state.records += 1
                state.accepted += int(result == "accepted")
                state.duplicates += int(result == "duplicate")
                state.consecutive_retries = 0
                state.last_failure_category = None
                state.last_success_at_epoch = time.time()
                state.record_chain_sha256 = _chain_next_digest(
                    state.record_chain_sha256, line_digest
                )
                processed += 1
                self._save(state)
        self._validate_legacy_inventory(state)
        self._validate_source(state)
        self._save(state)
        return state


def verify_rotated_candidate(state_path: Path, candidate_path: Path) -> dict[str, Any]:
    """Prove that a plain/gzip rotated candidate contains the processed prefix."""

    state = load_forward_state(state_path)
    if not candidate_path.is_absolute() or not candidate_path.is_file():
        raise ForwardIngestionError("rotated candidate must be an existing absolute file")
    compression = "GZIP" if candidate_path.suffix.casefold() == ".gz" else "NONE"
    before = candidate_path.stat()
    stored_sha256 = _sha256_file(candidate_path)
    after = candidate_path.stat()
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
        raise ForwardIngestionError("rotated candidate changed during verification")
    if _decoded_prefix_sha256(candidate_path, compression, state.start_offset) != state.start_prefix_sha256:
        raise ForwardIngestionError("rotated candidate start prefix does not match")
    chain = _chain_seed()
    with _open_source(candidate_path, compression) as handle:
        handle.seek(state.start_offset)
        while handle.tell() < state.offset:
            start = handle.tell()
            _line, line_digest, complete, _oversized = _read_bounded_record(
                handle,
                max_line_bytes=1_048_576,
                snapshot_end=state.offset,
            )
            if (
                not complete
                or line_digest is None
                or handle.tell() <= start
                or handle.tell() > state.offset
            ):
                raise ForwardIngestionError("rotated candidate does not preserve the cursor")
            chain = _chain_next_digest(chain, line_digest)
        if handle.tell() != state.offset or chain != state.record_chain_sha256:
            raise ForwardIngestionError("rotated candidate processed-prefix chain does not match")
    return {
        "path": str(candidate_path),
        "compression": compression,
        "device": after.st_dev,
        "inode": after.st_ino,
        "size": after.st_size,
        "mtime_ns": after.st_mtime_ns,
        "stored_sha256": stored_sha256,
        "generation_id": state.generation_id,
        "verified_through_offset": state.offset,
        "contains_raw_payload": False,
    }


def validate_forward_checkpoint(
    state_path: Path,
    *,
    deep: bool = False,
    max_line_bytes: int = 1_048_576,
) -> dict[str, Any]:
    """Validate an independent state without changing it or its source."""

    if not state_path.is_absolute():
        raise ValueError("forward state path must be absolute")
    state_before = _sha256_file(state_path)
    state = load_forward_state(state_path)
    ForwardIngestionWorker._validate_legacy_inventory(state)
    source, source_size = ForwardIngestionWorker._validate_source(state)
    at_eof = _validate_boundary(source, state.compression, state.offset)
    prefix_verified = False
    chain_verified = False
    verified_records: int | None = None
    if deep:
        prefix_verified = (
            _decoded_prefix_sha256(source, state.compression, state.start_offset)
            == state.start_prefix_sha256
        )
        if not prefix_verified:
            raise ForwardIngestionError("forward start prefix no longer matches")
        chain = _chain_seed()
        records = 0
        with _open_source(source, state.compression) as handle:
            handle.seek(state.start_offset)
            while handle.tell() < state.offset:
                start = handle.tell()
                _line, line_digest, complete, _oversized = _read_bounded_record(
                    handle,
                    max_line_bytes=max_line_bytes,
                    snapshot_end=state.offset,
                )
                if (
                    not complete
                    or line_digest is None
                    or handle.tell() <= start
                    or handle.tell() > state.offset
                ):
                    raise ForwardIngestionError(
                        "forward processed prefix is not a complete record sequence"
                    )
                chain = _chain_next_digest(chain, line_digest)
                records += 1
            verified_end = handle.tell()
        if verified_end != state.offset:
            raise ForwardIngestionError("forward processed prefix exceeds its cursor")
        if chain != state.record_chain_sha256 or records != state.records:
            raise ForwardIngestionError("forward processed-prefix chain does not match")
        chain_verified = True
        verified_records = records
    if _sha256_file(state_path) != state_before:
        raise ForwardIngestionError("forward state changed during validation")
    return {
        "status": "VALID",
        "state_path": str(state_path),
        "state_sha256": state_before,
        "namespace": state.namespace,
        "generation_id": state.generation_id,
        "source_path": state.source_path,
        "source_device": state.source_device,
        "source_inode": state.source_inode,
        "source_size": source_size,
        "start_offset": state.start_offset,
        "offset": state.offset,
        "byte_lag": max(0, source_size - state.offset)
        if state.compression == "NONE"
        else None,
        "at_eof": at_eof,
        "legacy_state_unchanged": state.legacy_state_path is not None,
        "prefix_verified": prefix_verified,
        "chain_verified": chain_verified,
        "verified_records": verified_records,
        "counters": {
            "records": state.records,
            "accepted": state.accepted,
            "duplicates": state.duplicates,
            "filtered": state.filtered,
            "malformed": state.malformed,
            "oversized": state.oversized,
            "retry_attempts": state.retry_attempts,
            "protocol_errors": state.protocol_errors,
            "delivery_rejected": state.delivery_rejected,
        },
        "contains_raw_payload": False,
    }


def dry_run_forward_records(
    state_path: Path,
    *,
    limit: int = 100,
    max_line_bytes: int = 1_048_576,
) -> dict[str, Any]:
    """Classify a bounded future batch without delivery or checkpoint writes."""

    if not 1 <= limit <= 10_000:
        raise ValueError("dry-run limit must be between 1 and 10000")
    state_sha = _sha256_file(state_path)
    state = load_forward_state(state_path)
    ForwardIngestionWorker._validate_legacy_inventory(state)
    source, snapshot_size = ForwardIngestionWorker._validate_source(state)
    _validate_boundary(source, state.compression, state.offset)
    counts = {"records": 0, "eligible": 0, "filtered": 0, "malformed": 0, "oversized": 0}
    end_offset = state.offset
    partial_tail = False
    with _open_source(source, state.compression) as handle:
        handle.seek(state.offset)
        while counts["records"] < limit:
            record_start = handle.tell()
            line, _digest, complete, oversized = _read_bounded_record(
                handle,
                max_line_bytes=max_line_bytes,
                snapshot_end=snapshot_size if state.compression == "NONE" else None,
            )
            if not complete:
                partial_tail = record_start < snapshot_size
                handle.seek(record_start)
                break
            counts["records"] += 1
            end_offset = handle.tell()
            if oversized:
                counts["malformed"] += 1
                counts["oversized"] += 1
                continue
            if not (line is not None):
                raise RuntimeError("Internal forward_ingestion invariant failed")
            try:
                payload = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                counts["malformed"] += 1
                continue
            if isinstance(payload, dict) and select_forward_payload(payload):
                counts["eligible"] += 1
            else:
                counts["filtered"] += 1
    if _sha256_file(state_path) != state_sha:
        raise ForwardIngestionError("forward state changed during dry-run")
    return {
        "status": "DRY_RUN",
        "state_path": str(state_path),
        "state_sha256": state_sha,
        "generation_id": state.generation_id,
        "start_offset": state.offset,
        "end_offset": end_offset,
        "partial_tail": partial_tail,
        "counts": counts,
        "delivery_attempted": False,
        "checkpoint_modified": False,
        "contains_raw_payload": False,
    }


def select_forward_payload(payload: dict[str, Any]) -> bool:
    """Late import avoids a module cycle while sharing the production allowlist."""

    from .event_shipper import select_archive_event

    return select_archive_event(payload)


def rebind_rotated_candidate(
    state_path: Path,
    candidate_path: Path,
    *,
    operator_approved: bool,
) -> ForwardGenerationState:
    if not operator_approved:
        raise ForwardIngestionError("rotated-source rebind requires explicit operator approval")
    with ForwardCheckpointLock(state_path):
        binding = verify_rotated_candidate(state_path, candidate_path)
        state = load_forward_state(state_path)
        ForwardIngestionWorker._validate_legacy_inventory(state)
        state.source_path = str(candidate_path)
        state.compression = str(binding["compression"])
        state.source_device = int(binding["device"])
        state.source_inode = int(binding["inode"])
        state.source_size_at_registration = int(binding["size"])
        state.source_ctime_ns_at_registration = candidate_path.stat().st_ctime_ns
        state.source_stored_sha256 = str(binding["stored_sha256"])
        state.status = "PAUSED"
        state.updated_at_epoch = time.time()
        durable_atomic_json(state_path, state.as_dict())
    return state
