"""Operator CLI for submission, retry draining, status, and dead letters."""

from __future__ import annotations

import argparse
from dataclasses import asdict
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
from .archive_recovery import (
    ArchiveGenerationManifest,
    ArchiveRecoveryError,
    HistoricalArchiveReplayer,
    audit_active_malformed_records,
    audit_malformed_records,
)
from .backlog import BacklogAuditError, scan_archive_backlog
from .config import ConfigurationError, SenderConfig
from .logging import configure_logging, log_event, safe_text
from .event_shipper import (
    EventDeliveryClient,
    EventShipperConfig,
    run_event_worker,
    select_archive_event,
)
from .durable_state import durable_atomic_json
from .forward_ingestion import (
    ForwardIngestionError,
    dry_run_forward_records,
    initialize_forward_generation,
    load_forward_state,
    rebind_rotated_candidate,
    validate_forward_checkpoint,
)
from .forward_service import (
    build_approval_renewal_proposal,
    build_approval_template,
    run_forward_service,
    validate_live_approval,
)
from .models import DeliveryClassification, ProcessOutcome
from .payloads import PayloadError, read_payload_file
from .runtime import build_spool, sender_runtime
from .spool import QueueCapacityError, ReplayRefusedError, SpoolError
from .state_upgrade import (
    StateUpgradeError,
    apply_v2_upgrade,
    plan_v2_upgrade,
    rollback_upgrade,
)


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
    subcommands.add_parser(
        "event-worker",
        help="ship an allowlisted incremental stream from Wazuh archives.json",
    )
    backlog = subcommands.add_parser(
        "backlog-status",
        help="read-only exact accounting of the current event archive backlog",
    )
    backlog.add_argument("--json", action="store_true", dest="json_output")

    state_upgrade = subcommands.add_parser(
        "event-state-upgrade",
        help="plan or explicitly apply a cursor-preserving v2 to v3 state upgrade",
    )
    state_upgrade.add_argument("--archive", type=Path, required=True)
    state_upgrade.add_argument("--state", type=Path, required=True)
    state_upgrade.add_argument("--backup-directory", type=Path, required=True)
    state_upgrade.add_argument("--apply", action="store_true")
    state_upgrade.add_argument("--approve-live-state-upgrade", action="store_true")

    state_rollback = subcommands.add_parser(
        "event-state-rollback",
        help="restore the verified v2 backup only before any new v3 write",
    )
    state_rollback.add_argument("--manifest", type=Path, required=True)
    state_rollback.add_argument("--approve-rollback", action="store_true")

    archive_register = subcommands.add_parser(
        "archive-register",
        help="register one immutable rotated archive without changing the live cursor",
    )
    archive_register.add_argument("archive", type=Path)
    archive_register.add_argument(
        "--manifest",
        type=Path,
        default=Path("/var/lib/cyberqalqon-sender/archive-generations.json"),
    )

    archive_replay = subcommands.add_parser(
        "archive-replay",
        help="run one bounded historical replay batch from a registered generation",
    )
    archive_replay.add_argument("generation_id")
    archive_replay.add_argument(
        "--manifest",
        type=Path,
        default=Path("/var/lib/cyberqalqon-sender/archive-generations.json"),
    )
    archive_replay.add_argument(
        "--state-directory",
        type=Path,
        default=Path("/var/lib/cyberqalqon-sender/archive-replay"),
    )
    archive_replay.add_argument("--limit", type=int, default=100)
    archive_replay.add_argument("--records-per-second", type=float, default=10.0)
    archive_replay.add_argument("--pause", action="store_true")
    archive_replay.add_argument(
        "--approve-live-replay",
        action="store_true",
        help="explicitly approve delivery for this one bounded batch",
    )

    malformed_audit = subcommands.add_parser(
        "archive-malformed-audit",
        help="write a payload-free malformed-record audit for one generation",
    )
    malformed_audit.add_argument("generation_id")
    malformed_audit.add_argument("--manifest", type=Path, required=True)
    malformed_audit.add_argument("--start-offset", type=int, default=0)
    malformed_audit.add_argument("--max-line-bytes", type=int, default=262144)
    malformed_audit.add_argument("--output", type=Path, required=True)

    active_malformed_audit = subcommands.add_parser(
        "active-malformed-audit",
        help="audit only the active archive prefix already acknowledged by its cursor",
    )
    active_malformed_audit.add_argument("--archive", type=Path, required=True)
    active_malformed_audit.add_argument("--state", type=Path, required=True)
    active_malformed_audit.add_argument("--max-line-bytes", type=int, default=262144)
    active_malformed_audit.add_argument("--output", type=Path, required=True)

    forward = subcommands.add_parser(
        "forward",
        help="prepare and inspect an independent generation-aware forward checkpoint",
    )
    forward_commands = forward.add_subparsers(dest="forward_command", required=True)
    forward_inspect = forward_commands.add_parser("inspect")
    forward_inspect.add_argument("--state", type=Path, required=True)
    forward_status = forward_commands.add_parser("status")
    forward_status.add_argument("--state", type=Path, required=True)
    forward_validate = forward_commands.add_parser("validate")
    forward_validate.add_argument("--state", type=Path, required=True)
    forward_validate.add_argument("--deep", action="store_true")
    forward_dry_run = forward_commands.add_parser("dry-run")
    forward_dry_run.add_argument("--state", type=Path, required=True)
    forward_dry_run.add_argument("--limit", type=int, default=100)
    forward_prepare = forward_commands.add_parser("prepare")
    forward_prepare.add_argument("--source", type=Path, required=True)
    forward_prepare.add_argument("--state-directory", type=Path, required=True)
    forward_prepare.add_argument("--namespace", required=True)
    forward_prepare.add_argument("--start-offset", type=int, required=True)
    forward_prepare.add_argument("--legacy-state", type=Path)
    forward_template = forward_commands.add_parser("approval-template")
    forward_template.add_argument("--state", type=Path, required=True)
    forward_template.add_argument("--output", type=Path, required=True)
    forward_template.add_argument("--valid-for-seconds", type=int, default=3600)
    forward_approval = forward_commands.add_parser("approval-check")
    forward_approval.add_argument("--state", type=Path, required=True)
    forward_approval.add_argument("--approval", type=Path, required=True)
    forward_proposal = forward_commands.add_parser("approval-proposal")
    forward_proposal.add_argument("--state", type=Path, required=True)
    forward_proposal.add_argument("--approval", type=Path, required=True)
    forward_proposal.add_argument("--output", type=Path, required=True)
    forward_proposal.add_argument(
        "--requested-expires-at-epoch", type=float, required=True
    )
    forward_rebind = forward_commands.add_parser("rebind-rotated")
    forward_rebind.add_argument("--state", type=Path, required=True)
    forward_rebind.add_argument("--candidate", type=Path, required=True)
    forward_rebind.add_argument("--approve-rotation-rebind", action="store_true")
    forward_run = forward_commands.add_parser("run")
    forward_run.add_argument("--state", type=Path, required=True)
    forward_run.add_argument("--approval", type=Path, required=True)
    forward_run.add_argument("--audit", type=Path, required=True)
    forward_run.add_argument("--batch-limit", type=int, default=10)
    forward_run.add_argument("--records-per-second", type=float, default=5.0)
    forward_run.add_argument("--poll-seconds", type=float, default=5.0)

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


def _handle_backlog_status(config: SenderConfig, *, json_output: bool) -> int:
    shipper = EventShipperConfig.from_sender(config)
    audit = scan_archive_backlog(
        shipper.archive_path,
        shipper.state_path,
        max_line_bytes=shipper.max_line_bytes,
        selector=select_archive_event,
    )
    result = audit.as_dict()
    if json_output:
        _json(result)
    else:
        print(
            f"cursor={audit.cursor} archive={audit.archive_size} byte_lag={audit.byte_lag} "
            f"unread={audit.unread_records} eligible={audit.eligible_records}"
        )
        print(
            f"filtered={audit.filtered_records} malformed={audit.malformed_records} "
            f"oversized={audit.oversized_records} partial_tail={audit.partial_tail_records}"
        )
    return 0


def _handle_event_state_upgrade(args: argparse.Namespace) -> int:
    plan = plan_v2_upgrade(args.state, args.archive, args.backup_directory)
    if not args.apply:
        _json({"status": "PLAN_ONLY", **plan.as_dict()})
        return 0
    result = apply_v2_upgrade(
        plan,
        operator_approved=args.approve_live_state_upgrade,
    )
    _json({"status": "UPGRADED", **result})
    return 0


def _handle_archive_register(archive: Path, manifest_path: Path) -> int:
    generation = ArchiveGenerationManifest(manifest_path).register(archive)
    _json(asdict(generation))
    return 0


def _handle_archive_malformed_audit(args: argparse.Namespace) -> int:
    generation = ArchiveGenerationManifest(args.manifest).get(args.generation_id)
    result = audit_malformed_records(
        generation,
        start_offset=args.start_offset,
        max_line_bytes=args.max_line_bytes,
        output_path=args.output,
        selector=select_archive_event,
    )
    _json(
        {
            "generation_id": result["generation_id"],
            "counts": result["counts"],
            "contains_raw_payload": False,
            "output": str(args.output),
        }
    )
    return 0


def _handle_active_malformed_audit(args: argparse.Namespace) -> int:
    result = audit_active_malformed_records(
        args.archive,
        args.state,
        max_line_bytes=args.max_line_bytes,
        output_path=args.output,
        selector=select_archive_event,
    )
    _json(
        {
            "generation_id": result["generation_id"],
            "source_identity": result["source_identity"],
            "counts": result["counts"],
            "contains_raw_payload": False,
            "output": str(args.output),
        }
    )
    return 0


def _handle_forward_offline(args: argparse.Namespace) -> int:
    if args.forward_command == "inspect":
        state = load_forward_state(args.state)
        _json(state.as_dict())
        return 0
    if args.forward_command == "status":
        _json(validate_forward_checkpoint(args.state, deep=False))
        return 0
    if args.forward_command == "validate":
        _json(validate_forward_checkpoint(args.state, deep=args.deep))
        return 0
    if args.forward_command == "dry-run":
        _json(dry_run_forward_records(args.state, limit=args.limit))
        return 0
    if args.forward_command == "prepare":
        state_path = initialize_forward_generation(
            args.source,
            args.state_directory,
            namespace=args.namespace,
            start_offset=args.start_offset,
            legacy_state_path=args.legacy_state,
        )
        _json(
            {
                "status": "PREPARED_NOT_APPROVED",
                "state_path": str(state_path),
                "validation": validate_forward_checkpoint(state_path, deep=True),
            }
        )
        return 0
    if args.forward_command == "approval-template":
        if not args.output.is_absolute():
            raise ValueError("approval template output must be absolute")
        if args.output.exists():
            raise ValueError("approval template output already exists")
        if not 60 <= args.valid_for_seconds <= 86_400:
            raise ValueError("approval validity must be between 60 and 86400 seconds")
        template = build_approval_template(
            args.state,
            expires_at_epoch=time.time() + args.valid_for_seconds,
        )
        durable_atomic_json(args.output, template)
        _json(
            {
                "status": "TEMPLATE_ONLY_NOT_APPROVED",
                "output": str(args.output),
                "contains_raw_payload": False,
            }
        )
        return 0
    if args.forward_command == "approval-check":
        _json(validate_live_approval(args.approval, args.state))
        return 0
    if args.forward_command == "approval-proposal":
        if not args.output.is_absolute():
            raise ValueError("approval proposal output must be absolute")
        if args.output.exists():
            raise ValueError("approval proposal output already exists")
        proposal = build_approval_renewal_proposal(
            args.approval,
            args.state,
            requested_expires_at_epoch=args.requested_expires_at_epoch,
        )
        durable_atomic_json(args.output, proposal)
        _json(
            {
                "status": proposal["status"],
                "output": str(args.output),
                "action_required": proposal["action_required"],
                "contains_raw_payload": False,
            }
        )
        return 0
    if args.forward_command == "rebind-rotated":
        state = rebind_rotated_candidate(
            args.state,
            args.candidate,
            operator_approved=args.approve_rotation_rebind,
        )
        _json(
            {
                "status": "REBOUND_PAUSED",
                "generation_id": state.generation_id,
                "source_path": state.source_path,
                "offset": state.offset,
                "contains_raw_payload": False,
            }
        )
        return 0
    raise ValueError("unsupported offline forward command")


def _handle_forward_run(config: SenderConfig, args: argparse.Namespace) -> int:
    return run_forward_service(
        config,
        state_path=args.state,
        approval_path=args.approval,
        audit_path=args.audit,
        batch_limit=args.batch_limit,
        records_per_second=args.records_per_second,
        poll_seconds=args.poll_seconds,
    )


def _handle_archive_replay(config: SenderConfig, args: argparse.Namespace) -> int:
    generation = ArchiveGenerationManifest(args.manifest).get(args.generation_id)
    shipper_config = EventShipperConfig.from_sender(config)
    delivery = EventDeliveryClient(shipper_config)
    replayer = HistoricalArchiveReplayer(
        generation,
        args.state_directory,
        max_line_bytes=shipper_config.max_line_bytes,
        selector=select_archive_event,
        delivery=delivery,
    )
    try:
        state = (
            replayer.pause()
            if args.pause
            else replayer.run_batch(
                operator_approved=args.approve_live_replay,
                limit=args.limit,
                records_per_second=args.records_per_second,
            )
        )
    finally:
        delivery.close()
    _json(state.as_dict())
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
        if args.command == "event-state-upgrade":
            return _handle_event_state_upgrade(args)
        if args.command == "event-state-rollback":
            _json(rollback_upgrade(args.manifest, operator_approved=args.approve_rollback))
            return 0
        if args.command == "archive-register":
            return _handle_archive_register(args.archive, args.manifest)
        if args.command == "archive-malformed-audit":
            return _handle_archive_malformed_audit(args)
        if args.command == "active-malformed-audit":
            return _handle_active_malformed_audit(args)
        if args.command == "forward" and args.forward_command != "run":
            return _handle_forward_offline(args)
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
        if args.command == "event-worker":
            return run_event_worker(config, logger=logger)
        if args.command == "backlog-status":
            return _handle_backlog_status(config, json_output=args.json_output)
        if args.command == "archive-replay":
            return _handle_archive_replay(config, args)
        if args.command == "forward" and args.forward_command == "run":
            return _handle_forward_run(config, args)
        if args.command == "dead-letter":
            return _handle_dead_letter(config, args, logger=logger)
        return 2
    except (
        ArchiveRecoveryError,
        BacklogAuditError,
        ConfigurationError,
        PayloadError,
        QueueCapacityError,
        ReplayRefusedError,
        SpoolError,
        StateUpgradeError,
        ForwardIngestionError,
        ValueError,
    ) as exc:
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
