"""Single-line structured operational logging with bounded untrusted fields."""

from __future__ import annotations

import json
import logging
import re
import sys
import unicodedata
from typing import Any


MAX_LOG_TEXT = 256
ANSI_ESCAPE = re.compile(r"\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def safe_text(value: object, *, maximum: int = MAX_LOG_TEXT) -> str:
    text = ANSI_ESCAPE.sub("", str(value))
    text = "".join(
        " " if character in "\r\n" or unicodedata.category(character) == "Cc" else character
        for character in text
    )
    text = " ".join(text.split())
    if len(text) > maximum:
        return f"{text[: maximum - 1]}…"
    return text


def _safe_value(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return safe_text(value)
    if isinstance(value, (list, tuple)):
        return [_safe_value(item) for item in value[:50]]
    if isinstance(value, dict):
        return {safe_text(key, maximum=64): _safe_value(item) for key, item in list(value.items())[:50]}
    return safe_text(value)


def configure_logging(level: str = "INFO") -> logging.Logger:
    logger = logging.getLogger("cyberqalqon_sender")
    logger.setLevel(getattr(logging, level))
    logger.propagate = False
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
    return logger


def log_event(
    logger: logging.Logger,
    level: int,
    event: str,
    **fields: Any,
) -> None:
    record = {"event": safe_text(event, maximum=96)}
    record.update({key: _safe_value(value) for key, value in fields.items()})
    logger.log(
        level,
        json.dumps(record, ensure_ascii=False, separators=(",", ":"), sort_keys=True),
    )
