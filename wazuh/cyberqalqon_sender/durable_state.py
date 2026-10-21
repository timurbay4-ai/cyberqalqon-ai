"""Small durable-file primitives shared by shipper state transitions."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


def _sync_directory(path: Path) -> None:
    """Best-effort POSIX directory sync after an atomic replace."""

    if os.name != "posix":
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def durable_atomic_write(path: Path, content: bytes, *, mode: int = 0o600) -> None:
    """Replace *path* only after the temporary file is flushed and synced."""

    path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    try:
        with temporary.open("wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        if os.name == "posix":
            os.chmod(temporary, mode)
        os.replace(temporary, path)
        _sync_directory(path.parent)
    except Exception:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def durable_atomic_json(path: Path, value: dict[str, Any]) -> None:
    durable_atomic_write(
        path,
        json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
    )
