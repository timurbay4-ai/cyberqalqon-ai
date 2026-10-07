"""Bounded parsing and deterministic encoding of untrusted Wazuh JSON."""

from __future__ import annotations

import hashlib
import json
import stat
from pathlib import Path
from typing import Any

from .models import AlertPayload


class PayloadError(ValueError):
    """Raised when an input is not a bounded JSON object."""


def _reject_nonstandard_constant(value: str) -> None:
    raise PayloadError(f"non-standard JSON numeric constant is not allowed: {value}")


def parse_payload_bytes(raw: bytes, *, maximum_bytes: int) -> AlertPayload:
    if len(raw) > maximum_bytes:
        raise PayloadError(
            f"input is {len(raw)} bytes; maximum is {maximum_bytes} bytes"
        )
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise PayloadError("input must be UTF-8 JSON") from exc
    try:
        value = json.loads(text, parse_constant=_reject_nonstandard_constant)
    except json.JSONDecodeError as exc:
        raise PayloadError("input must contain valid JSON") from exc
    if not isinstance(value, dict):
        raise PayloadError("input JSON must be an object")
    try:
        canonical = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise PayloadError("input contains a value that cannot be encoded as JSON") from exc
    encoded = canonical.encode("utf-8")
    if len(encoded) > maximum_bytes:
        raise PayloadError(
            f"canonical payload is {len(encoded)} bytes; maximum is {maximum_bytes} bytes"
        )

    candidate: Any = value.get("alert_id") or value.get("id")
    alert_id: str | None = None
    if not isinstance(candidate, bool) and isinstance(candidate, (str, int)):
        normalized = str(candidate).strip()
        if normalized:
            alert_id = normalized[:255]
    return AlertPayload(
        canonical_json=canonical,
        payload_bytes=len(encoded),
        payload_sha256=hashlib.sha256(encoded).hexdigest(),
        alert_id=alert_id,
    )


def read_payload_file(path: str | Path, *, maximum_bytes: int) -> AlertPayload:
    source = Path(path)
    try:
        metadata = source.stat()
    except OSError as exc:
        raise PayloadError("alert input file cannot be read") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise PayloadError("alert input path must name a regular file")
    if metadata.st_size > maximum_bytes:
        raise PayloadError(
            f"input is {metadata.st_size} bytes; maximum is {maximum_bytes} bytes"
        )
    try:
        with source.open("rb") as handle:
            raw = handle.read(maximum_bytes + 1)
    except OSError as exc:
        raise PayloadError("alert input file cannot be read") from exc
    return parse_payload_bytes(raw, maximum_bytes=maximum_bytes)
