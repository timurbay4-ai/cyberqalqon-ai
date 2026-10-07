"""Official Wazuh Integrator-compatible process entrypoint."""

from __future__ import annotations

import logging
import sys
from collections.abc import Sequence

from .cli import submit_file
from .config import ConfigurationError, SenderConfig
from .logging import configure_logging, log_event, safe_text
from .payloads import PayloadError
from .spool import QueueCapacityError, SpoolError


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv if argv is None else argv)
    logger = configure_logging()
    if len(arguments) < 2 or not arguments[1]:
        log_event(
            logger,
            logging.ERROR,
            "wazuh_invocation_failed",
            message="Wazuh did not provide an alert file path",
        )
        return 2

    overrides: dict[str, str] = {}
    if len(arguments) > 2 and arguments[2]:
        overrides["CYBERQALQON_INGEST_API_KEY"] = arguments[2]
    if len(arguments) > 3 and arguments[3]:
        overrides["CYBERQALQON_URL"] = arguments[3]
    try:
        config = SenderConfig.from_env(overrides=overrides)
        logger.setLevel(getattr(logging, config.log_level))
        return submit_file(config, arguments[1], logger=logger)
    except (ConfigurationError, PayloadError, QueueCapacityError, SpoolError, ValueError) as exc:
        log_event(
            logger,
            logging.ERROR,
            "wazuh_submission_failed",
            error_type=type(exc).__name__,
            message=safe_text(exc),
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
