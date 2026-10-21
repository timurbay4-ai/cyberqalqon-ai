#!/usr/bin/env python3
"""Inspect first/last complete records in a captured active-archive prefix."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any


def _canonical_fingerprint(payload: dict[str, Any]) -> str:
    encoded = json.dumps(
        payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _metadata(line: bytes, start: int, end: int) -> dict[str, Any]:
    try:
        payload = json.loads(line)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return {
            "start": start,
            "end": end,
            "valid_json": False,
            "error": type(exc).__name__,
            "line_sha256": hashlib.sha256(line).hexdigest(),
        }
    if not isinstance(payload, dict):
        return {"start": start, "end": end, "valid_json": False, "error": "non_object"}
    rule = payload.get("rule")
    return {
        "start": start,
        "end": end,
        "valid_json": True,
        "timestamp": payload.get("timestamp"),
        "source_event_id": payload.get("id"),
        "rule_id": rule.get("id") if isinstance(rule, dict) else None,
        "fingerprint": _canonical_fingerprint(payload),
        "line_sha256": hashlib.sha256(line).hexdigest(),
    }


def capture(path: Path, snapshot_size: int) -> dict[str, Any]:
    stat = path.stat()
    if stat.st_size < snapshot_size:
        raise RuntimeError("active archive is shorter than the captured snapshot")
    with path.open("rb") as handle:
        first = handle.readline(1_048_577)
        first_metadata = _metadata(first, 0, len(first))
        window_start = max(0, snapshot_size - 2 * 1024 * 1024)
        handle.seek(window_start)
        window = handle.read(snapshot_size - window_start)
    last_newline = window.rfind(b"\n")
    if last_newline < 0:
        raise RuntimeError("no complete record boundary in active snapshot tail window")
    complete_end = window_start + last_newline + 1
    previous_newline = window.rfind(b"\n", 0, last_newline)
    line_start = window_start if previous_newline < 0 else window_start + previous_newline + 1
    line = window[previous_newline + 1 : last_newline + 1]
    suffix = window[last_newline + 1 :]
    return {
        "version": 1,
        "contains_raw_payload": False,
        "path": str(path),
        "device": stat.st_dev,
        "inode": stat.st_ino,
        "current_size": stat.st_size,
        "captured_snapshot_size": snapshot_size,
        "first_record": first_metadata,
        "last_complete_record": _metadata(line, line_start, complete_end),
        "snapshot_partial_tail": {
            "start": complete_end,
            "end": snapshot_size,
            "length": len(suffix),
            "sha256": hashlib.sha256(suffix).hexdigest(),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--snapshot-size", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    output = arguments.output.resolve()
    if output.exists():
        raise SystemExit(f"refusing to overwrite existing artifact: {output}")
    payload = capture(arguments.archive.resolve(), arguments.snapshot_size)
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
