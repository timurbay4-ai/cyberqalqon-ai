"""Operator CLI for submission, retry draining, status, and dead letters."""

from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from threading import Event
from typing import Any, Sequence

from . import __version__
from .config import ConfigurationError, SenderConfig
from .logging import configure_logging, log_event, safe_text
from .models import DeliveryClassification, ProcessOutcome
from .payloads import PayloadError, read_payload_file
from .runtime import build_spool, sender_runtime
from .spool import QueueCapacityError, ReplayRefusedError, SpoolError


def _json(value: Any) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))


def _iso(value: float | None) -> str | None:
    if value is None:
        return None
    return datetime.fromtimestamp(value, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _outcome_dict(outcome: ProcessOutcome) -> dict[str, Any]:
    return {
        "queue_id": outcome.queue_id,
        "alert_id": outcome.alert_id,
        "classification": outcome.classification.value,
        "attempt_count": outcome.attempt_count,
        "http_status": outcome.http_status,
        "next_retry_at": _iso(outcome.next_retry_at),
        "dead_letter_id": outcome.dead_letter_id,
        "dead_letter_blocked": outcome.dead_letter_blocked,
        "message": outcome.safe_message,
    }


def _outcome_exit(outcome: ProcessOutcome) -> int:
    if outcome.dead_letter_id is not None or outcome.dead_letter_blocked:
        return 4
    if outcome.classification in {
        DeliveryClassification.DELIVERED,
        DeliveryClassification.DUPLICATE,
        DeliveryClassification.TRANSIENT_FAILURE,
    }:
        return 0
    return 4


def submit_file(config: SenderConfig, path: str | Path, *, logger: logging.Logger) -> int:
    payload = read_payload_file(path, maximum_bytes=config.max_payload_bytes)
    with sender_runtime(config, logger=logger) as (_, service):
        outcome = service.submit(payload)
    _json(_outcome_dict(outcome))
    return _outcome_exit(outcome)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cyberqalqon-sender")
    parser.add_argument("--version", action="version", version=__version__)
    subcommands = parser.add_subparsers(dest="command", required=True)

    submit = subcommands.add_parser("submit", help="durably submit one Wazuh JSON file")
    submit.add_argument("file", type=Path)

    status = subcommands.add_parser("status", help="show persisted sender status")
    status.add_argument("--json", action="store_true", dest="json_output")

    drain = subcommands.add_parser("drain", help="process a bounded batch of due items")
    drain.add_argument("--limit", type=int)

    subcommands.add_parser("worker", help="run the restartable retry worker")

    dead = subcommands.add_parser("dead-letter", help="inspect or replay terminal failures")
    dead_subcommands = dead.add_subparsers(dest="dead_command", required=True)
    dead_list = dead_subcommands.add_parser("list")
    dead_list.add_argument("--limit", type=int, default=50)
    dead_inspect = dead_subcommands.add_parser("inspect")
    dead_inspect.add_argument("id", type=int)
    dead_inspect.add_argument("--include-payload", action="store_true")
    dead_replay = dead_subcommands.add_parser("replay")
    dead_replay.add_argument("id", type=int)
    dead_replay.add_argument("--force", action="store_true")
    dead_reconcile = dead_subcommands.add_parser(
        "reconcile", help="move retained terminal records after increasing capacity"
    )
    dead_reconcile.add_argument("--limit", type=int, default=100)
    return parser


def _handle_status(config: SenderConfig, *, json_output: bool) -> int:
    spool = build_spool(config)
    snapshot = spool.status()
    result = snapshot.as_dict(now=time.time())
    result["last_success_at"] = _iso(snapshot.last_success_at)
    result["last_failure_at"] = _iso(snapshot.last_failure_at)
    if json_output:
        _json(result)
    else:
        queue = result["queue"]
        dead = result["dead_letter"]
        print(
            f"queue={queue['depth']} pending={queue['pending']} "
            f"in_flight={queue['in_flight']} terminal_blocked={queue['terminal_blocked']}"
        )
        print(f"dead_letters={dead['count']} last_success={result['last_success_at'] or 'never'}")
        if result["last_failure_category"]:
            print(
                f"last_failure={result['last_failure_category']} "
                f"message={safe_text(result['last_safe_error'] or '')}"
            )
    return 0


def _handle_drain(config: SenderConfig, limit: int | None, *, logger: logging.Logger) -> int:
    if limit is not None and limit <= 0:
        raise ValueError("--limit must be greater than zero")
    with sender_runtime(config, logger=logger) as (_, service):
        summary = service.drain(limit=limit)
    _json(summary.as_dict())
    return 0 if summary.dead_letter_blocked == 0 else 4


def _handle_worker(config: SenderConfig, *, logger: logging.Logger) -> int:
    stop_event = Event()

    def stop(_signum: int, _frame: object) -> None:
        stop_event.set()

    signal.signal(signal.SIGINT, stop)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, stop)
    with sender_runtime(config, logger=logger) as (_, service):
        service.run_worker(stop_event)
    return 0


def _handle_dead_letter(
    config: SenderConfig,
    args: argparse.Namespace,
    *,
    logger: logging.Logger,
) -> int:
    if args.dead_command == "list":
        spool = build_spool(config)
        records = spool.list_dead_letters(limit=args.limit)
        _json(records)
        return 0
    if args.dead_command == "inspect":
        spool = build_spool(config)
        record = spool.get_dead_letter(args.id, include_payload=args.include_payload)
        if record is None:
            raise SpoolError("dead-letter record does not exist")
        _json(record)
        return 0
    if args.dead_command == "replay":
        with sender_runtime(config, logger=logger) as (_, service):
            outcome = service.replay_dead_letter(args.id, force=args.force)
        if outcome is None:
            _json({"dead_letter_id": args.id, "status": "queued_or_claimed"})
            return 0
        _json(_outcome_dict(outcome))
        return _outcome_exit(outcome)
    if args.dead_command == "reconcile":
        if args.limit <= 0:
            raise ValueError("--limit must be greater than zero")
        spool = build_spool(config)
        result = spool.reconcile_terminal_blocked(now=time.time(), limit=args.limit)
        _json(result)
        return 0 if result["remaining"] == 0 else 4
    raise ValueError("unsupported dead-letter command")


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    logger = configure_logging()
    try:
        config = SenderConfig.from_env()
        logger.setLevel(getattr(logging, config.log_level))
        if args.command == "submit":
            return submit_file(config, args.file, logger=logger)
        if args.command == "status":
            return _handle_status(config, json_output=args.json_output)
        if args.command == "drain":
            return _handle_drain(config, args.limit, logger=logger)
        if args.command == "worker":
            return _handle_worker(config, logger=logger)
        if args.command == "dead-letter":
            return _handle_dead_letter(config, args, logger=logger)
        return 2
    except (ConfigurationError, PayloadError, QueueCapacityError, ReplayRefusedError, SpoolError, ValueError) as exc:
        log_event(
            logger,
            logging.ERROR,
            "sender_command_failed",
            error_type=type(exc).__name__,
            message=safe_text(exc),
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
