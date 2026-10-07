"""Value objects shared by sender delivery, persistence, and operator commands."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class DeliveryClassification(StrEnum):
    DELIVERED = "DELIVERED"
    DUPLICATE = "DUPLICATE"
    TRANSIENT_FAILURE = "TRANSIENT_FAILURE"
    PERMANENT_FAILURE = "PERMANENT_FAILURE"
    CONFLICT = "CONFLICT"


class FailureCategory(StrEnum):
    BAD_REQUEST = "BAD_REQUEST"
    AUTHENTICATION = "AUTHENTICATION"
    AUTHORIZATION = "AUTHORIZATION"
    CONFLICT = "CONFLICT"
    PAYLOAD_TOO_LARGE = "PAYLOAD_TOO_LARGE"
    UNSUPPORTED_MEDIA_TYPE = "UNSUPPORTED_MEDIA_TYPE"
    VALIDATION = "VALIDATION"
    RATE_LIMITED = "RATE_LIMITED"
    SERVER = "SERVER"
    NETWORK = "NETWORK"
    CONNECT_TIMEOUT = "CONNECT_TIMEOUT"
    REQUEST_TIMEOUT = "REQUEST_TIMEOUT"
    PROTOCOL = "PROTOCOL"
    MALFORMED_PERSISTED_RECORD = "MALFORMED_PERSISTED_RECORD"
    QUEUE_CAPACITY = "QUEUE_CAPACITY"
    RETRY_EXHAUSTED = "RETRY_EXHAUSTED"
    CONFIGURATION = "CONFIGURATION"
    UNEXPECTED = "UNEXPECTED"


@dataclass(frozen=True, slots=True)
class DeliveryResult:
    classification: DeliveryClassification
    failure_category: FailureCategory | None = None
    safe_message: str | None = None
    http_status: int | None = None
    retry_after_seconds: float | None = None

    @property
    def delivered_equivalent(self) -> bool:
        return self.classification in {
            DeliveryClassification.DELIVERED,
            DeliveryClassification.DUPLICATE,
        }


@dataclass(frozen=True, slots=True)
class AlertPayload:
    canonical_json: str
    payload_bytes: int
    payload_sha256: str
    alert_id: str | None


@dataclass(frozen=True, slots=True)
class QueueItem:
    id: int
    alert_id: str | None
    payload_json: str
    payload_sha256: str
    payload_bytes: int
    state: str
    attempt_count: int
    next_attempt_at: float
    lease_token: str
    lease_until: float
    created_at: float
    updated_at: float
    replay_of_dead_letter_id: int | None
    deliver_allowed: bool = True


@dataclass(frozen=True, slots=True)
class ProcessOutcome:
    queue_id: int
    alert_id: str | None
    classification: DeliveryClassification
    attempt_count: int
    http_status: int | None = None
    next_retry_at: float | None = None
    dead_letter_id: int | None = None
    dead_letter_blocked: bool = False
    safe_message: str | None = None

    @property
    def accepted(self) -> bool:
        return self.classification in {
            DeliveryClassification.DELIVERED,
            DeliveryClassification.DUPLICATE,
            DeliveryClassification.TRANSIENT_FAILURE,
        }


@dataclass(frozen=True, slots=True)
class DrainSummary:
    processed: int = 0
    delivered: int = 0
    duplicates: int = 0
    transient_failures: int = 0
    permanent_failures: int = 0
    conflicts: int = 0
    dead_letter_blocked: int = 0

    def as_dict(self) -> dict[str, int]:
        return {
            "processed": self.processed,
            "delivered": self.delivered,
            "duplicates": self.duplicates,
            "transient_failures": self.transient_failures,
            "permanent_failures": self.permanent_failures,
            "conflicts": self.conflicts,
            "dead_letter_blocked": self.dead_letter_blocked,
        }


@dataclass(frozen=True, slots=True)
class StatusSnapshot:
    queue_depth: int
    queue_bytes: int
    pending_count: int
    in_flight_count: int
    terminal_blocked_count: int
    dead_letter_count: int
    dead_letter_bytes: int
    delivered_count: int
    duplicate_count: int
    transient_failure_count: int
    retry_count: int
    conflict_count: int
    permanent_failure_count: int
    queue_rejected_count: int
    dead_letter_blocked_count: int
    last_success_at: float | None
    last_failure_at: float | None
    last_failure_category: str | None
    last_safe_error: str | None
    oldest_pending_at: float | None

    def as_dict(self, *, now: float) -> dict[str, Any]:
        oldest_age = None
        if self.oldest_pending_at is not None:
            oldest_age = max(0.0, now - self.oldest_pending_at)
        return {
            "queue": {
                "depth": self.queue_depth,
                "payload_bytes": self.queue_bytes,
                "pending": self.pending_count,
                "in_flight": self.in_flight_count,
                "terminal_blocked": self.terminal_blocked_count,
                "oldest_pending_age_seconds": oldest_age,
            },
            "dead_letter": {
                "count": self.dead_letter_count,
                "payload_bytes": self.dead_letter_bytes,
            },
            "counters": {
                "delivered": self.delivered_count,
                "duplicates": self.duplicate_count,
                "transient_failures": self.transient_failure_count,
                "retries": self.retry_count,
                "conflicts": self.conflict_count,
                "permanent_failures": self.permanent_failure_count,
                "queue_rejected": self.queue_rejected_count,
                "dead_letter_blocked": self.dead_letter_blocked_count,
            },
            "last_success_at": self.last_success_at,
            "last_failure_at": self.last_failure_at,
            "last_failure_category": self.last_failure_category,
            "last_safe_error": self.last_safe_error,
        }
