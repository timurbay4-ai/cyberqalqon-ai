"""Enqueue-first delivery service, retry policy, and bounded worker loop."""

from __future__ import annotations

import hashlib
import logging
import random
import time
from collections.abc import Callable
from threading import Event
from typing import Protocol

from .config import SenderConfig
from .logging import log_event, safe_text
from .models import (
    AlertPayload,
    DeliveryClassification,
    DeliveryResult,
    DrainSummary,
    FailureCategory,
    ProcessOutcome,
    QueueItem,
)
from .payloads import PayloadError, parse_payload_bytes
from .spool import SQLiteSpool


class DeliveryClient(Protocol):
    def deliver(self, payload: bytes) -> DeliveryResult: ...


def backoff_delay(
    attempt_count: int,
    *,
    base_seconds: float,
    maximum_seconds: float,
    jitter_ratio: float,
    random_value: float,
    retry_after_seconds: float | None = None,
) -> float:
    """Return bounded exponential delay with symmetric multiplicative jitter."""

    exponent = max(0, min(attempt_count - 1, 62))
    unjittered = min(maximum_seconds, base_seconds * (2**exponent))
    bounded_random = max(0.0, min(1.0, random_value))
    factor = 1.0 + ((2.0 * bounded_random) - 1.0) * jitter_ratio
    delayed = min(maximum_seconds, max(0.0, unjittered * factor))
    if retry_after_seconds is not None:
        delayed = min(maximum_seconds, max(delayed, retry_after_seconds))
    return delayed


class SenderService:
    def __init__(
        self,
        config: SenderConfig,
        spool: SQLiteSpool,
        client: DeliveryClient,
        *,
        clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.perf_counter,
        random_source: Callable[[], float] = random.random,
        logger: logging.Logger | None = None,
    ) -> None:
        self.config = config
        self.spool = spool
        self.client = client
        self.clock = clock
        self.monotonic = monotonic
        self.random_source = random_source
        self.logger = logger or logging.getLogger("cyberqalqon_sender")

    def _redacted_message(self, value: str) -> str:
        return safe_text(value.replace(self.config.api_key, "[REDACTED]"))

    def submit(self, payload: AlertPayload) -> ProcessOutcome:
        if self.config.api_key in payload.canonical_json:
            raise PayloadError(
                "payload contains the configured sender credential and was rejected"
            )
        queue_id = self.spool.enqueue(payload, now=self.clock())
        log_event(
            self.logger,
            logging.INFO,
            "alert_enqueued",
            queue_id=queue_id,
            alert_id=payload.alert_id,
            payload_bytes=payload.payload_bytes,
        )
        outcome = self.process_queue_id(queue_id)
        if outcome is not None:
            return outcome
        return ProcessOutcome(
            queue_id=queue_id,
            alert_id=payload.alert_id,
            classification=DeliveryClassification.TRANSIENT_FAILURE,
            attempt_count=0,
            safe_message="alert is durably queued and was claimed by another worker",
        )

    def _validate_persisted_payload(self, item: QueueItem) -> bytes:
        try:
            encoded = item.payload_json.encode("utf-8")
            parsed = parse_payload_bytes(
                encoded,
                maximum_bytes=self.config.max_payload_bytes,
            )
        except (UnicodeError, PayloadError) as exc:
            raise PayloadError("persisted payload is not valid bounded JSON") from exc
        actual_digest = hashlib.sha256(encoded).hexdigest()
        if (
            len(encoded) != item.payload_bytes
            or actual_digest != item.payload_sha256
            or parsed.canonical_json != item.payload_json
        ):
            raise PayloadError("persisted payload integrity check failed")
        return encoded

    def _terminal_outcome(
        self,
        item: QueueItem,
        *,
        classification: DeliveryClassification,
        category: FailureCategory,
        safe_message: str,
        http_status: int | None,
        started_at: float,
    ) -> ProcessOutcome:
        safe_message = self._redacted_message(safe_message)
        now = self.clock()
        dead_letter_id, blocked = self.spool.finish_terminal(
            item,
            classification=classification,
            category=category,
            safe_message=safe_message,
            http_status=http_status,
            now=now,
        )
        log_event(
            self.logger,
            logging.ERROR,
            "delivery_terminal_failure",
            queue_id=item.id,
            alert_id=item.alert_id,
            attempt=item.attempt_count,
            classification=classification.value,
            failure_category=category.value,
            http_status=http_status,
            dead_letter_id=dead_letter_id,
            dead_letter_blocked=blocked,
            duration_ms=round((self.monotonic() - started_at) * 1000, 3),
            message=safe_message,
        )
        return ProcessOutcome(
            queue_id=item.id,
            alert_id=item.alert_id,
            classification=classification,
            attempt_count=item.attempt_count,
            http_status=http_status,
            dead_letter_id=dead_letter_id,
            dead_letter_blocked=blocked,
            safe_message=safe_text(safe_message),
        )

    def _process_claimed(self, item: QueueItem) -> ProcessOutcome:
        started_at = self.monotonic()
        if not item.deliver_allowed:
            return self._terminal_outcome(
                item,
                classification=DeliveryClassification.TRANSIENT_FAILURE,
                category=FailureCategory.RETRY_EXHAUSTED,
                safe_message="lease recovered after the maximum attempt count was reached",
                http_status=None,
                started_at=started_at,
            )

        try:
            encoded = self._validate_persisted_payload(item)
        except PayloadError:
            return self._terminal_outcome(
                item,
                classification=DeliveryClassification.PERMANENT_FAILURE,
                category=FailureCategory.MALFORMED_PERSISTED_RECORD,
                safe_message="persisted queue payload failed its integrity or JSON check",
                http_status=None,
                started_at=started_at,
            )

        try:
            result = self.client.deliver(encoded)
        except Exception as exc:  # Defensive worker boundary around pluggable transports.
            result = DeliveryResult(
                DeliveryClassification.TRANSIENT_FAILURE,
                FailureCategory.UNEXPECTED,
                f"delivery client raised {type(exc).__name__}; retry is safe",
            )

        if result.delivered_equivalent:
            self.spool.finish_success(item, result.classification, now=self.clock())
            log_event(
                self.logger,
                logging.INFO,
                "delivery_completed",
                queue_id=item.id,
                alert_id=item.alert_id,
                attempt=item.attempt_count,
                classification=result.classification.value,
                http_status=result.http_status,
                duration_ms=round((self.monotonic() - started_at) * 1000, 3),
            )
            return ProcessOutcome(
                queue_id=item.id,
                alert_id=item.alert_id,
                classification=result.classification,
                attempt_count=item.attempt_count,
                http_status=result.http_status,
            )

        category = result.failure_category or FailureCategory.UNEXPECTED
        message = self._redacted_message(
            result.safe_message or "delivery failed without backend detail"
        )
        if result.classification == DeliveryClassification.TRANSIENT_FAILURE:
            now = self.clock()
            delay = backoff_delay(
                item.attempt_count,
                base_seconds=self.config.backoff_base_seconds,
                maximum_seconds=self.config.backoff_max_seconds,
                jitter_ratio=self.config.backoff_jitter_ratio,
                random_value=self.random_source(),
                retry_after_seconds=result.retry_after_seconds,
            )
            dead_letter_id, blocked, next_retry_at = self.spool.finish_transient(
                item,
                category=category,
                safe_message=message,
                http_status=result.http_status,
                next_attempt_at=now + delay,
                max_attempts=self.config.max_attempts,
                now=now,
            )
            log_event(
                self.logger,
                logging.WARNING,
                "delivery_transient_failure",
                queue_id=item.id,
                alert_id=item.alert_id,
                attempt=item.attempt_count,
                classification=result.classification.value,
                failure_category=category.value,
                http_status=result.http_status,
                next_retry_at=next_retry_at,
                dead_letter_id=dead_letter_id,
                dead_letter_blocked=blocked,
                duration_ms=round((self.monotonic() - started_at) * 1000, 3),
                message=message,
            )
            return ProcessOutcome(
                queue_id=item.id,
                alert_id=item.alert_id,
                classification=result.classification,
                attempt_count=item.attempt_count,
                http_status=result.http_status,
                next_retry_at=next_retry_at,
                dead_letter_id=dead_letter_id,
                dead_letter_blocked=blocked,
                safe_message=safe_text(message),
            )

        return self._terminal_outcome(
            item,
            classification=result.classification,
            category=category,
            safe_message=message,
            http_status=result.http_status,
            started_at=started_at,
        )

    def process_queue_id(self, queue_id: int) -> ProcessOutcome | None:
        item = self.spool.claim_by_id(
            queue_id,
            now=self.clock(),
            lease_seconds=self.config.lease_seconds,
            max_attempts=self.config.max_attempts,
        )
        return self._process_claimed(item) if item is not None else None

    def process_next_due(self) -> ProcessOutcome | None:
        item = self.spool.claim_due(
            now=self.clock(),
            lease_seconds=self.config.lease_seconds,
            max_attempts=self.config.max_attempts,
        )
        return self._process_claimed(item) if item is not None else None

    def drain(self, *, limit: int | None = None) -> DrainSummary:
        maximum = self.config.worker_batch_size if limit is None else max(1, limit)
        outcomes: list[ProcessOutcome] = []
        for _ in range(maximum):
            outcome = self.process_next_due()
            if outcome is None:
                break
            outcomes.append(outcome)
        return DrainSummary(
            processed=len(outcomes),
            delivered=sum(o.classification == DeliveryClassification.DELIVERED for o in outcomes),
            duplicates=sum(o.classification == DeliveryClassification.DUPLICATE for o in outcomes),
            transient_failures=sum(
                o.classification == DeliveryClassification.TRANSIENT_FAILURE for o in outcomes
            ),
            permanent_failures=sum(
                o.classification == DeliveryClassification.PERMANENT_FAILURE for o in outcomes
            ),
            conflicts=sum(o.classification == DeliveryClassification.CONFLICT for o in outcomes),
            dead_letter_blocked=sum(o.dead_letter_blocked for o in outcomes),
        )

    def replay_dead_letter(
        self,
        dead_letter_id: int,
        *,
        force: bool = False,
    ) -> ProcessOutcome | None:
        queue_id = self.spool.replay_dead_letter(
            dead_letter_id,
            now=self.clock(),
            force=force,
        )
        return self.process_queue_id(queue_id)

    def run_worker(
        self,
        stop_event: Event,
        *,
        wait: Callable[[float], bool] | None = None,
    ) -> None:
        waiter = wait or stop_event.wait
        log_event(self.logger, logging.INFO, "worker_started")
        while not stop_event.is_set():
            summary = self.drain()
            if summary.processed == 0:
                waiter(self.config.worker_poll_seconds)
        log_event(self.logger, logging.INFO, "worker_stopped")
