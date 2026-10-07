"""Runtime assembly kept separate for CLI and Wazuh entrypoint reuse."""

from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Iterator

from .config import SenderConfig
from .http import HttpDeliveryClient
from .service import SenderService
from .spool import SQLiteSpool, SpoolLimits


def build_spool(config: SenderConfig) -> SQLiteSpool:
    spool = SQLiteSpool(
        config.database_path,
        SpoolLimits(
            queue_max_items=config.queue_max_items,
            queue_max_bytes=config.queue_max_bytes,
            dead_letter_max_items=config.dead_letter_max_items,
            dead_letter_max_bytes=config.dead_letter_max_bytes,
            busy_timeout_seconds=config.sqlite_busy_timeout_seconds,
        ),
    )
    spool.initialize()
    return spool


@contextmanager
def sender_runtime(
    config: SenderConfig,
    *,
    logger: logging.Logger | None = None,
) -> Iterator[tuple[SQLiteSpool, SenderService]]:
    spool = build_spool(config)
    with HttpDeliveryClient(config) as client:
        yield spool, SenderService(config, spool, client, logger=logger)
