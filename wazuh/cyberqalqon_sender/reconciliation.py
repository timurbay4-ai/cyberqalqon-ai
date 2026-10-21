"""Read-only archive reconciliation against a retained backend identity inventory.

The scanner never writes to the source archive or backend database.  Its only mutable
output is a payload-free durable checkpoint under an operator-selected evidence path.
Absence from a retention-capped backend is deliberately not treated as proof that an
event was never ingested.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, BinaryIO, Callable, Iterator

from .durable_state import durable_atomic_json


class ReconciliationError(RuntimeError):
    """Raised when evidence identity or a durable scan checkpoint is unsafe."""


def canonical_event_fingerprint(payload: dict[str, Any]) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


@contextmanager
def open_archive(path: Path, compression: str) -> Iterator[BinaryIO]:
    handle: BinaryIO
    try:
        if compression == "GZIP":
            handle = gzip.open(path, "rb")
        else:
            handle = path.open("rb")
    except OSError as exc:
        raise ReconciliationError("archive cannot be decoded safely") from exc
    try:
        yield handle
    except (EOFError, gzip.BadGzipFile) as exc:
        raise ReconciliationError("archive cannot be decoded safely") from exc
    finally:
        handle.close()


@dataclass(frozen=True, slots=True)
class RetainedIdentityInventory:
    fingerprints: frozenset[str]
    source_ids: frozenset[str]
    available: bool = True
    retention_capped: bool = True

    @classmethod
    def unavailable(cls) -> "RetainedIdentityInventory":
        return cls(frozenset(), frozenset(), available=False, retention_capped=True)

    @classmethod
    def from_sqlite(cls, database: Path) -> "RetainedIdentityInventory":
        if not database.is_absolute() or not database.is_file():
            raise ReconciliationError("backend database must be an existing absolute file")
        connection = sqlite3.connect(f"file:{database.as_posix()}?mode=ro", uri=True)
        try:
            connection.execute("PRAGMA query_only=ON")
            rows = connection.execute(
                "SELECT deduplication_id, source_event_id FROM security_events "
                "WHERE ingestion_source = 'wazuh_archives'"
            ).fetchall()
        except sqlite3.Error as exc:
            raise ReconciliationError("backend identity inventory is unavailable") from exc
        finally:
            connection.close()
        return cls(
            frozenset(str(row[0]) for row in rows),
            frozenset(str(row[1]) for row in rows if row[1] is not None),
        )

    @classmethod
    def from_payload_free_export(cls, export: Path) -> "RetainedIdentityInventory":
        """Load the M20 payload-free ``F``/``S`` identity export.

        The first line is a JSON manifest. Remaining tab-separated rows contain
        only canonical fingerprints (``F``) or source identifiers (``S``).
        """

        if not export.is_absolute() or not export.is_file():
            raise ReconciliationError("backend identity export must be an existing absolute file")
        opener = gzip.open if export.suffix.casefold() == ".gz" else Path.open
        fingerprints: set[str] = set()
        source_ids: set[str] = set()
        try:
            if opener is gzip.open:
                handle = gzip.open(export, "rt", encoding="utf-8", newline="")
            else:
                handle = export.open("rt", encoding="utf-8", newline="")
            with handle:
                manifest = json.loads(handle.readline())
                if not isinstance(manifest, dict) or manifest.get("version") != 1:
                    raise ReconciliationError("backend identity export manifest is unsupported")
                for raw_line in handle:
                    kind, separator, value = raw_line.rstrip("\r\n").partition("\t")
                    if not separator or not value:
                        raise ReconciliationError("backend identity export row is malformed")
                    if kind == "F":
                        if len(value) != 64:
                            raise ReconciliationError("backend fingerprint is malformed")
                        fingerprints.add(value)
                    elif kind == "S":
                        source_ids.add(value)
                    else:
                        raise ReconciliationError("backend identity export row type is unsupported")
        except ReconciliationError:
            raise
        except (EOFError, OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ReconciliationError("backend identity export is unreadable") from exc
        return cls(frozenset(fingerprints), frozenset(source_ids))


@dataclass(frozen=True, slots=True)
class ReconciliationSource:
    path: str
    compression: str
    device: int
    inode: int
    stored_size: int
    mtime_ns: int
    stored_sha256: str
    generation_id: str

    @classmethod
    def capture(cls, path: Path) -> "ReconciliationSource":
        if not path.is_absolute() or not path.is_file():
            raise ReconciliationError("archive must be an existing absolute file")
        before = path.stat()
        digest = sha256_file(path)
        after = path.stat()
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        )
        if before_identity != after_identity:
            raise ReconciliationError("archive changed while its identity was captured")
        identity = "\x00".join(
            (
                "m21-reconciliation-v1",
                str(after.st_dev),
                str(after.st_ino),
                str(after.st_size),
                str(after.st_mtime_ns),
                digest,
            )
        )
        return cls(
            path=str(path),
            compression="GZIP" if path.suffix.casefold() == ".gz" else "NONE",
            device=after.st_dev,
            inode=after.st_ino,
            stored_size=after.st_size,
            mtime_ns=after.st_mtime_ns,
            stored_sha256=digest,
            generation_id=hashlib.sha256(identity.encode("utf-8")).hexdigest(),
        )

    def validate(self, *, full_digest: bool = True) -> Path:
        path = Path(self.path)
        try:
            stat = path.stat()
        except OSError as exc:
            raise ReconciliationError("archive generation is unavailable") from exc
        observed = (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)
        expected = (self.device, self.inode, self.stored_size, self.mtime_ns)
        if observed != expected:
            raise ReconciliationError("archive generation identity changed")
        if full_digest and sha256_file(path) != self.stored_sha256:
            raise ReconciliationError("archive generation digest changed")
        return path


@dataclass(slots=True)
class ReconciliationCounts:
    records: int = 0
    valid_json: int = 0
    filtered: int = 0
    proven_already_ingested: int = 0
    probable_duplicate_not_proven: int = 0
    present_archive_absent_retained_database: int = 0
    unable_to_classify: int = 0
    malformed_or_incomplete: int = 0
    invalid_utf8: int = 0
    invalid_json: int = 0
    partial_tail: int = 0
    oversized: int = 0
    exact_archive_duplicates: int = 0


@dataclass(slots=True)
class ReconciliationState:
    generation_id: str
    offset: int = 0
    status: str = "PAUSED"
    counts: ReconciliationCounts = field(default_factory=ReconciliationCounts)
    updated_at_epoch: float = 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": 1,
            "generation_id": self.generation_id,
            "offset": self.offset,
            "status": self.status,
            "counts": asdict(self.counts),
            "updated_at_epoch": self.updated_at_epoch,
            "contains_raw_payload": False,
        }


def validate_decoded_boundary(source: ReconciliationSource, offset: int) -> bool:
    if offset < 0:
        raise ReconciliationError("reconciliation checkpoint is negative")
    path = source.validate(full_digest=False)
    with open_archive(path, source.compression) as handle:
        if offset:
            try:
                handle.seek(offset - 1)
                previous = handle.read(1)
            except (OSError, ValueError) as exc:
                raise ReconciliationError("reconciliation checkpoint cannot be restored") from exc
            if not previous:
                raise ReconciliationError("reconciliation checkpoint is beyond the archive")
            if previous != b"\n":
                raise ReconciliationError(
                    "reconciliation checkpoint is not on a record boundary"
                )
        try:
            handle.seek(offset)
            return handle.read(1) == b""
        except (OSError, ValueError) as exc:
            raise ReconciliationError("reconciliation checkpoint cannot be restored") from exc


def decoded_prefix_sha256(path: Path, length: int) -> str:
    if length < 0:
        raise ValueError("prefix length must not be negative")
    source = ReconciliationSource.capture(path)
    digest = hashlib.sha256()
    remaining = length
    with open_archive(path, source.compression) as handle:
        while remaining:
            chunk = handle.read(min(1024 * 1024, remaining))
            if not chunk:
                raise ReconciliationError("decoded prefix exceeds the archive")
            digest.update(chunk)
            remaining -= len(chunk)
    return digest.hexdigest()


class ArchiveReconciler:
    """Bounded resumable classifier with a payload-free durable checkpoint."""

    def __init__(
        self,
        source: ReconciliationSource,
        inventory: RetainedIdentityInventory,
        state_path: Path,
        *,
        selector: Callable[[dict[str, Any]], bool],
        max_line_bytes: int = 1_048_576,
    ) -> None:
        if not state_path.is_absolute():
            raise ValueError("reconciliation state path must be absolute")
        if not 4_096 <= max_line_bytes <= 1_048_576:
            raise ValueError("max_line_bytes is outside the supported bound")
        self.source = source
        self.inventory = inventory
        self.state_path = state_path
        self.selector = selector
        self.max_line_bytes = max_line_bytes
        self._seen_fingerprints: set[str] | None = None

    def _load_state(self) -> ReconciliationState:
        if not self.state_path.exists():
            return ReconciliationState(generation_id=self.source.generation_id)
        try:
            raw = json.loads(self.state_path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict) or raw.get("version") != 1:
                raise ReconciliationError("reconciliation state version is unsupported")
            if raw.get("generation_id") != self.source.generation_id:
                raise ReconciliationError("reconciliation source generation does not match")
            raw_counts = raw.get("counts")
            if not isinstance(raw_counts, dict):
                raise ReconciliationError("reconciliation counts are malformed")
            counts = ReconciliationCounts(
                **{
                    name: max(0, int(raw_counts.get(name, 0)))
                    for name in ReconciliationCounts.__dataclass_fields__
                }
            )
            state = ReconciliationState(
                generation_id=self.source.generation_id,
                offset=int(raw.get("offset", 0)),
                status=str(raw.get("status", "PAUSED")),
                counts=counts,
                updated_at_epoch=float(raw.get("updated_at_epoch", 0)),
            )
        except ReconciliationError:
            raise
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ReconciliationError("reconciliation state is unreadable") from exc
        if state.status not in {"PAUSED", "COMPLETE"}:
            raise ReconciliationError("reconciliation state status is invalid")
        return state

    def _save_state(self, state: ReconciliationState) -> None:
        state.updated_at_epoch = time.time()
        durable_atomic_json(self.state_path, state.as_dict())

    def _rebuild_seen(self, path: Path, offset: int) -> set[str]:
        seen: set[str] = set()
        with open_archive(path, self.source.compression) as handle:
            while handle.tell() < offset:
                line = handle.readline(self.max_line_bytes + 1)
                if not line:
                    raise ReconciliationError("saved reconciliation cursor is beyond EOF")
                if len(line) > self.max_line_bytes:
                    while line and not line.endswith(b"\n"):
                        line = handle.readline(65_536)
                    continue
                if not line.endswith(b"\n"):
                    continue
                try:
                    payload = json.loads(line.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue
                if isinstance(payload, dict) and self.selector(payload):
                    seen.add(canonical_event_fingerprint(payload))
            if handle.tell() != offset:
                raise ReconciliationError("saved reconciliation cursor crosses a record")
        return seen

    def run_batch(self, *, limit: int = 1_000) -> ReconciliationState:
        if not 1 <= limit <= 100_000:
            raise ValueError("reconciliation batch limit must be between 1 and 100000")
        path = self.source.validate(full_digest=True)
        state = self._load_state()
        at_eof = validate_decoded_boundary(self.source, state.offset)
        if state.status == "COMPLETE":
            if not at_eof:
                raise ReconciliationError("complete reconciliation state is not at EOF")
            return state
        if self._seen_fingerprints is None:
            self._seen_fingerprints = self._rebuild_seen(path, state.offset)
        processed = 0
        reached_eof = False
        with open_archive(path, self.source.compression) as handle:
            handle.seek(state.offset)
            while processed < limit:
                line = handle.readline(self.max_line_bytes + 1)
                if not line:
                    reached_eof = True
                    break
                state.counts.records += 1
                processed += 1
                if len(line) > self.max_line_bytes:
                    while line and not line.endswith(b"\n"):
                        line = handle.readline(65_536)
                    state.counts.malformed_or_incomplete += 1
                    state.counts.oversized += 1
                    state.offset = handle.tell()
                    continue
                if not line.endswith(b"\n"):
                    state.counts.malformed_or_incomplete += 1
                    state.counts.partial_tail += 1
                    state.offset = handle.tell()
                    reached_eof = True
                    break
                try:
                    payload = json.loads(line.decode("utf-8"))
                except UnicodeDecodeError:
                    state.counts.malformed_or_incomplete += 1
                    state.counts.invalid_utf8 += 1
                    state.offset = handle.tell()
                    continue
                except json.JSONDecodeError:
                    state.counts.malformed_or_incomplete += 1
                    state.counts.invalid_json += 1
                    state.offset = handle.tell()
                    continue
                if not isinstance(payload, dict):
                    state.counts.malformed_or_incomplete += 1
                    state.counts.invalid_json += 1
                    state.offset = handle.tell()
                    continue
                state.counts.valid_json += 1
                if not self.selector(payload):
                    state.counts.filtered += 1
                    state.offset = handle.tell()
                    continue
                fingerprint = canonical_event_fingerprint(payload)
                if fingerprint in self._seen_fingerprints:
                    state.counts.exact_archive_duplicates += 1
                else:
                    self._seen_fingerprints.add(fingerprint)
                source_id = payload.get("id")
                if not self.inventory.available:
                    state.counts.unable_to_classify += 1
                elif fingerprint in self.inventory.fingerprints:
                    state.counts.proven_already_ingested += 1
                elif source_id is not None and str(source_id) in self.inventory.source_ids:
                    state.counts.probable_duplicate_not_proven += 1
                else:
                    state.counts.present_archive_absent_retained_database += 1
                state.offset = handle.tell()
        state.status = "COMPLETE" if reached_eof else "PAUSED"
        self.source.validate(full_digest=True)
        self._save_state(state)
        return state


def state_report(
    source: ReconciliationSource,
    state: ReconciliationState,
    inventory: RetainedIdentityInventory,
) -> dict[str, Any]:
    return {
        "version": 1,
        "source": asdict(source),
        "checkpoint": state.as_dict(),
        "retained_identity_inventory": {
            "available": inventory.available,
            "fingerprints": len(inventory.fingerprints),
            "source_ids": len(inventory.source_ids),
            "retention_capped": inventory.retention_capped,
            "absence_is_proof_of_never_ingested": False,
        },
        "contains_raw_payload": False,
    }
