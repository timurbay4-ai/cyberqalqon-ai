"""Bounded in-memory M18 ingestion metrics without database scans."""

from __future__ import annotations

import math
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any


def _percentile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    position = max(0, math.ceil(percentile * len(ordered)) - 1)
    return round(ordered[position], 3)


class IngestionMetrics:
    """Track only post-process-start observations in a bounded window."""

    def __init__(self, *, batch_enabled: bool, batch_limit: int) -> None:
        self._lock = threading.Lock()
        self._started_monotonic = time.monotonic()
        self._started_at = datetime.now(timezone.utc)
        self._batch_enabled = batch_enabled
        self._batch_limit = batch_limit
        self._requests = 0
        self._events = 0
        self._inserted = 0
        self._duplicates = 0
        self._retryable_failures = 0
        self._permanent_failures = 0
        self._single_requests = 0
        self._batch_requests = 0
        self._last_success_at: datetime | None = None
        self._last_error: str | None = None
        self._request_ms: deque[float] = deque(maxlen=512)
        self._database_ms: deque[float] = deque(maxlen=512)
        self._transaction_ms: deque[float] = deque(maxlen=512)
        self._retention_ms: deque[float] = deque(maxlen=512)
        self._lock_wait_ms: deque[float] = deque(maxlen=512)
        self._commit_ms: deque[float] = deque(maxlen=512)
        self._retention_candidate_ms: deque[float] = deque(maxlen=512)
        self._protected_check_ms: deque[float] = deque(maxlen=512)
        self._timeout_count = 0
        self._deadline_violations = 0
        self._sqlite_busy_errors = 0
        self._last_failure_stage: str | None = None
        self._last_failure_timing: dict[str, float | int | bool] | None = None

    def record_success(
        self,
        *,
        mode: str,
        events: int,
        inserted: int,
        duplicates: int,
        request_ms: float,
        database_ms: float,
        transaction_ms: float | None = None,
        retention_ms: float | None = None,
        lock_wait_ms: float | None = None,
        commit_ms: float | None = None,
        retention_candidate_ms: float | None = None,
        protected_check_ms: float | None = None,
    ) -> None:
        with self._lock:
            self._requests += 1
            self._events += events
            self._inserted += inserted
            self._duplicates += duplicates
            self._single_requests += int(mode == "single")
            self._batch_requests += int(mode == "batch")
            self._request_ms.append(max(0.0, request_ms))
            self._database_ms.append(max(0.0, database_ms))
            if transaction_ms is not None:
                self._transaction_ms.append(max(0.0, transaction_ms))
            if retention_ms is not None:
                self._retention_ms.append(max(0.0, retention_ms))
            if lock_wait_ms is not None:
                self._lock_wait_ms.append(max(0.0, lock_wait_ms))
            if commit_ms is not None:
                self._commit_ms.append(max(0.0, commit_ms))
            if retention_candidate_ms is not None:
                self._retention_candidate_ms.append(max(0.0, retention_candidate_ms))
            if protected_check_ms is not None:
                self._protected_check_ms.append(max(0.0, protected_check_ms))
            self._last_success_at = datetime.now(timezone.utc)
            self._last_error = None

    def record_failure(
        self,
        *,
        retryable: bool,
        code: str,
        stage: str | None = None,
        timing: dict[str, float | int | bool] | None = None,
    ) -> None:
        with self._lock:
            if retryable:
                self._retryable_failures += 1
            else:
                self._permanent_failures += 1
            self._last_error = code[:128]
            self._timeout_count += int(code == "batch_processing_timeout")
            self._deadline_violations += int(code == "batch_processing_timeout")
            self._sqlite_busy_errors += int(
                code == "database_temporarily_unavailable"
            )
            self._last_failure_stage = stage[:64] if stage else None
            self._last_failure_timing = (
                {
                    str(key)[:64]: value
                    for key, value in timing.items()
                    if isinstance(value, (int, float, bool))
                }
                if timing
                else None
            )

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            elapsed = max(0.001, time.monotonic() - self._started_monotonic)
            captured_at = datetime.now(timezone.utc)
            request_ms = list(self._request_ms)
            database_ms = list(self._database_ms)
            transaction_ms = list(self._transaction_ms)
            retention_ms = list(self._retention_ms)
            lock_wait_ms = list(self._lock_wait_ms)
            commit_ms = list(self._commit_ms)
            retention_candidate_ms = list(self._retention_candidate_ms)
            protected_check_ms = list(self._protected_check_ms)
            return {
                "measurement_scope": "POST_PROCESS_START_ONLY",
                "started_at": self._started_at,
                "captured_at": captured_at,
                "measurement_window_seconds": round(elapsed, 3),
                "request_latency_sample_size": len(request_ms),
                "active_request_mode": "batch" if self._batch_enabled else "single-event",
                "execution_model": "bounded-threadpool",
                "ingress_protocol_version": "m18-batch-v1",
                "configured_mode": "batch-available-disabled-by-default"
                if not self._batch_enabled
                else "batch-enabled",
                "batch_endpoint_enabled": self._batch_enabled,
                "configured_batch_limit": self._batch_limit,
                "requests": self._requests,
                "single_requests": self._single_requests,
                "batch_requests": self._batch_requests,
                "events": self._events,
                "inserted": self._inserted,
                "duplicates": self._duplicates,
                "retryable_failures": self._retryable_failures,
                "permanent_failures": self._permanent_failures,
                "requests_per_second": round(self._requests / elapsed, 6),
                "events_per_second": round(self._events / elapsed, 6),
                "inserts_per_second": round(self._inserted / elapsed, 6),
                "duplicates_per_second": round(self._duplicates / elapsed, 6),
                "events_per_request": round(self._events / self._requests, 3)
                if self._requests
                else None,
                "request_latency_p50_ms": _percentile(request_ms, 0.50),
                "request_latency_p95_ms": _percentile(request_ms, 0.95),
                "database_latency_p50_ms": _percentile(database_ms, 0.50),
                "database_latency_p95_ms": _percentile(database_ms, 0.95),
                "transaction_latency_p50_ms": _percentile(transaction_ms, 0.50),
                "transaction_latency_p95_ms": _percentile(transaction_ms, 0.95),
                "retention_latency_p50_ms": _percentile(retention_ms, 0.50),
                "retention_latency_p95_ms": _percentile(retention_ms, 0.95),
                "lock_wait_latency_p50_ms": _percentile(lock_wait_ms, 0.50),
                "lock_wait_latency_p95_ms": _percentile(lock_wait_ms, 0.95),
                "commit_latency_p50_ms": _percentile(commit_ms, 0.50),
                "commit_latency_p95_ms": _percentile(commit_ms, 0.95),
                "retention_candidate_latency_p95_ms": _percentile(
                    retention_candidate_ms, 0.95
                ),
                "protected_check_latency_p95_ms": _percentile(
                    protected_check_ms, 0.95
                ),
                "timeout_count": self._timeout_count,
                "pre_commit_deadline_violations": self._deadline_violations,
                "sqlite_busy_errors": self._sqlite_busy_errors,
                "last_failure_stage": self._last_failure_stage,
                "last_failure_timing_ms": self._last_failure_timing,
                "last_successful_acknowledgement": self._last_success_at,
                "last_successful_acknowledgement_age_seconds": round(
                    max(0.0, (captured_at - self._last_success_at).total_seconds()), 3
                )
                if self._last_success_at is not None
                else None,
                "last_error": self._last_error,
                "historical_unique_insertions": None,
                "historical_duplicate_acknowledgements": None,
            }
