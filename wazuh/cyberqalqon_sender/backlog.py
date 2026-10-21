"""Read-only, point-in-time accounting for an event-shipper archive backlog."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import time
from typing import Any


class BacklogAuditError(RuntimeError):
    """Raised when a durable cursor cannot safely identify the active archive."""


@dataclass(frozen=True, slots=True)
class BacklogAudit:
    archive_path: str
    state_path: str
    device: int
    inode: int
    cursor: int
    archive_size: int
    byte_lag: int
    unread_records: int
    eligible_records: int
    filtered_records: int
    malformed_records: int
    oversized_records: int
    partial_tail_records: int
    scan_seconds: float
    scan_mib_per_second: float
    captured_at_epoch: float
    cursor_updated_at_epoch: float | None
    identity_matches: bool = True
    source_of_truth: str = "ARCHIVE_CURSOR_STREAMING_SCAN"

    def as_dict(self) -> dict[str, str | int | float | bool | None]:
        return asdict(self)


def _discard_to_snapshot_line_end(handle: Any, snapshot_size: int) -> bool:
    """Discard one oversized record without reading beyond the captured file size."""

    while handle.tell() < snapshot_size:
        remaining = snapshot_size - handle.tell()
        chunk = handle.readline(min(65_536, remaining))
        if chunk.endswith(b"\n"):
            return True
        if not chunk:
            break
    return False


def scan_archive_backlog(
    archive_path: Path,
    state_path: Path,
    *,
    max_line_bytes: int,
    selector: Callable[[dict[str, Any]], bool],
) -> BacklogAudit:
    """Count unread records without mutating the cursor or consuming the archive.

    The archive size and identity are captured before the scan. Bytes appended later are
    intentionally excluded so every returned counter describes one reproducible boundary.
    """

    if not 4_096 <= max_line_bytes <= 1_048_576:
        raise ValueError("max_line_bytes is outside the supported audit bound")
    try:
        raw_state = json.loads(state_path.read_text(encoding="utf-8"))
        stat = archive_path.stat()
        device = int(raw_state["device"])
        inode = int(raw_state["inode"])
        cursor = int(raw_state["offset"])
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        raise BacklogAuditError("durable shipper state is unavailable or malformed") from exc
    if device != stat.st_dev or inode != stat.st_ino:
        raise BacklogAuditError(
            "durable cursor identity does not match the active archive; rotation requires operator review"
        )
    if cursor < 0 or cursor > stat.st_size:
        raise BacklogAuditError("durable cursor offset is outside the active archive")

    snapshot_size = stat.st_size
    unread = eligible = filtered = malformed = oversized = partial = 0
    scanned_bytes = 0
    started = time.perf_counter()
    with archive_path.open("rb") as handle:
        handle.seek(cursor)
        while handle.tell() < snapshot_size:
            line_start = handle.tell()
            remaining = snapshot_size - line_start
            line = handle.readline(min(max_line_bytes + 1, remaining))
            if not line:
                break
            scanned_bytes += len(line)
            if len(line) > max_line_bytes or (
                not line.endswith(b"\n") and handle.tell() < snapshot_size
            ):
                unread += 1
                oversized += 1
                if not line.endswith(b"\n"):
                    before = handle.tell()
                    terminated = _discard_to_snapshot_line_end(handle, snapshot_size)
                    scanned_bytes += handle.tell() - before
                    if not terminated and handle.tell() >= snapshot_size:
                        partial += 1
                continue
            if not line.endswith(b"\n"):
                partial += 1
                scanned_bytes += max(0, snapshot_size - handle.tell())
                break
            unread += 1
            try:
                payload = json.loads(line)
            except (UnicodeDecodeError, json.JSONDecodeError):
                malformed += 1
                continue
            if not isinstance(payload, dict) or not selector(payload):
                filtered += 1
            else:
                eligible += 1

    elapsed = max(time.perf_counter() - started, 0.000_001)
    updated = raw_state.get("updated_at")
    return BacklogAudit(
        archive_path=str(archive_path),
        state_path=str(state_path),
        device=stat.st_dev,
        inode=stat.st_ino,
        cursor=cursor,
        archive_size=snapshot_size,
        byte_lag=snapshot_size - cursor,
        unread_records=unread,
        eligible_records=eligible,
        filtered_records=filtered,
        malformed_records=malformed,
        oversized_records=oversized,
        partial_tail_records=partial,
        scan_seconds=round(elapsed, 6),
        scan_mib_per_second=round((scanned_bytes / 1_048_576) / elapsed, 3),
        captured_at_epoch=time.time(),
        cursor_updated_at_epoch=float(updated) if updated is not None else None,
    )
