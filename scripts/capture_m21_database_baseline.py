#!/usr/bin/env python3
"""Capture a read-only, payload-free M21 live SQLite baseline."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def capture(database: Path) -> dict[str, Any]:
    before = database.stat()
    digest = _sha256(database)
    after = database.stat()
    metadata_stable = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) == (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    )
    connection = sqlite3.connect(f"file:{database.as_posix()}?mode=ro", uri=True)
    try:
        connection.execute("PRAGMA query_only=ON")
        quick_check = [row[0] for row in connection.execute("PRAGMA quick_check")]
        foreign_key_errors = sum(1 for _ in connection.execute("PRAGMA foreign_key_check"))
        schema = int(connection.execute("PRAGMA user_version").fetchone()[0])
        events = int(connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0])
        alerts = int(connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0])
    finally:
        connection.close()
    wal = Path(f"{database}-wal")
    return {
        "version": 1,
        "captured_at_epoch": time.time(),
        "capture_mode": "SQLITE_MODE_RO_QUERY_ONLY",
        "contains_raw_payload": False,
        "database": {
            "path": str(database),
            "device": after.st_dev,
            "inode": after.st_ino,
            "size": after.st_size,
            "mtime_ns": after.st_mtime_ns,
            "sha256": digest,
            "metadata_stable_during_hash": metadata_stable,
            "sha256_scope_note": "Main DB file only; WAL is inventoried separately.",
        },
        "wal": {
            "path": str(wal),
            "exists": wal.is_file(),
            "size": wal.stat().st_size if wal.is_file() else 0,
            "sha256": _sha256(wal) if wal.is_file() else None,
        },
        "integrity": {
            "quick_check": quick_check,
            "foreign_key_errors": foreign_key_errors,
            "schema_version": schema,
            "events": events,
            "alerts": alerts,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    database = arguments.database.resolve()
    output = arguments.output.resolve()
    if not database.is_file():
        raise SystemExit(f"database not found: {database}")
    if output.exists():
        raise SystemExit(f"refusing to overwrite existing manifest: {output}")
    payload = capture(database)
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
