"""Durable operational state, transition deduplication, and diagnostics."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator
from uuid import uuid4

from app.schemas.operations import (
    ArchiveBacklogSummary,
    ComponentObservation,
    DataQualitySummary,
    ForwardIngestionSummary,
    OperationalComponent,
    OperationalEvent,
    OperationalOverview,
    OperationalQueryMeasurement,
    OperationalSnapshot,
    StorageRetentionSummary,
    WazuhInventoryStatus,
)
from app.services.wazuh_normalizer import canonical_json


NOTIFICATION_COOLDOWN = timedelta(minutes=15)


class OperationalQueryError(RuntimeError):
    """Base class for bounded Operations read failures."""


class OperationalQueryCancelled(OperationalQueryError):
    """The HTTP caller disconnected or cancelled the read."""


class OperationalQueryTimeout(OperationalQueryError):
    """The bounded read exceeded its execution deadline."""


class OperationalQueryUnavailable(OperationalQueryError):
    """The bounded single-flight queue cannot accept more work."""


@dataclass
class _OverviewFlight:
    event: threading.Event
    epoch: int
    waiters: int = 0
    error: OperationalQueryError | None = None


def _utc(value: datetime) -> datetime:
    return value.astimezone(timezone.utc)


def _severity(state: str) -> str:
    return {
        "HEALTHY": "INFO",
        "UNKNOWN": "LOW",
        "DEGRADED": "HIGH",
        "UNAVAILABLE": "HIGH",
    }[state]


class OperationalRepository:
    def __init__(
        self,
        database_path: Path,
        *,
        retention_days: int = 30,
        max_records: int = 100_000,
        overview_cache_ttl_seconds: float = 2.0,
        overview_stale_ttl_seconds: float = 30.0,
        overview_query_deadline_seconds: float = 2.0,
        overview_max_inflight: int = 4,
        overview_max_waiters_per_query: int = 32,
    ) -> None:
        if not 0 <= overview_cache_ttl_seconds <= 30:
            raise ValueError("overview cache TTL must be between 0 and 30 seconds")
        if not overview_cache_ttl_seconds <= overview_stale_ttl_seconds <= 300:
            raise ValueError("overview stale TTL must be between cache TTL and 300 seconds")
        if not 0.05 <= overview_query_deadline_seconds <= 30:
            raise ValueError("overview query deadline must be between 0.05 and 30 seconds")
        if not 1 <= overview_max_inflight <= 8:
            raise ValueError("overview max inflight must be between 1 and 8")
        if not 1 <= overview_max_waiters_per_query <= 128:
            raise ValueError("overview max waiters must be between 1 and 128")
        self.path = database_path
        self.retention_days = retention_days
        self.max_records = max_records
        self.overview_cache_ttl_seconds = overview_cache_ttl_seconds
        self.overview_stale_ttl_seconds = overview_stale_ttl_seconds
        self.overview_query_deadline_seconds = overview_query_deadline_seconds
        self.overview_max_inflight = overview_max_inflight
        self.overview_max_waiters_per_query = overview_max_waiters_per_query
        self._overview_cache: dict[int, tuple[float, int, OperationalOverview]] = {}
        self._overview_flights: dict[tuple[int, int], _OverviewFlight] = {}
        self._overview_cache_lock = threading.Lock()
        self._overview_epoch = 0
        self._overview_cache_hits = 0
        self._overview_cache_misses = 0
        self._overview_singleflight_joins = 0
        self._overview_stale_served = 0

    def _invalidate_overview_cache(self) -> None:
        with self._overview_cache_lock:
            self._overview_cache.clear()
            self._overview_epoch += 1

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    @contextmanager
    def _overview_connection(
        self,
        *,
        cancel_event: threading.Event,
        deadline_at: float,
    ) -> Iterator[sqlite3.Connection]:
        uri = f"file:{self.path.resolve().as_posix()}?mode=ro"
        connection = sqlite3.connect(uri, uri=True, timeout=1)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 1000")

        def interrupt_if_needed() -> int:
            return int(cancel_event.is_set() or time.monotonic() >= deadline_at)

        connection.set_progress_handler(interrupt_if_needed, 1_000)
        try:
            self._assert_query_active(cancel_event, deadline_at)
            yield connection
        except sqlite3.OperationalError as error:
            if "interrupted" in str(error).lower():
                if cancel_event.is_set():
                    raise OperationalQueryCancelled("operations query cancelled") from error
                raise OperationalQueryTimeout("operations query deadline exceeded") from error
            raise OperationalQueryUnavailable(
                "operations database read unavailable"
            ) from error
        except sqlite3.DatabaseError as error:
            raise OperationalQueryUnavailable(
                "operations database read unavailable"
            ) from error
        finally:
            connection.set_progress_handler(None, 0)
            connection.close()

    @staticmethod
    def _assert_query_active(cancel_event: threading.Event, deadline_at: float) -> None:
        if cancel_event.is_set():
            raise OperationalQueryCancelled("operations query cancelled")
        if time.monotonic() >= deadline_at:
            raise OperationalQueryTimeout("operations query deadline exceeded")

    def _cache_measurement(self) -> dict[str, int]:
        return {
            "cache_hits": self._overview_cache_hits,
            "cache_misses": self._overview_cache_misses,
            "singleflight_joins": self._overview_singleflight_joins,
            "stale_served": self._overview_stale_served,
            "inflight_queries": len(self._overview_flights),
            "pending_waiters": sum(flight.waiters for flight in self._overview_flights.values()),
        }

    def _cached_overview(
        self,
        entry: tuple[float, int, OperationalOverview],
        *,
        state: str,
        reason_code: str,
        request_started: float,
    ) -> OperationalOverview:
        cached_at, _, cached_overview = entry
        cache_age = max(0.0, time.monotonic() - cached_at)
        now = datetime.now(timezone.utc)
        return cached_overview.model_copy(
            update={
                "generated_at": now,
                "snapshot_age_seconds": (
                    cached_overview.snapshot_age_seconds + cache_age
                    if cached_overview.snapshot_age_seconds is not None
                    else None
                ),
                "measurement": cached_overview.measurement.model_copy(
                    update={
                        "state": state,
                        "reason_code": reason_code,
                        "age_seconds": round(cache_age, 3),
                        "duration_ms": round((time.monotonic() - request_started) * 1000, 3),
                        **self._cache_measurement(),
                    }
                ),
            }
        )

    @staticmethod
    def _component(row: sqlite3.Row) -> OperationalComponent:
        return OperationalComponent(
            component_key=row["component_key"],
            component_kind=row["component_kind"],
            state=row["state"],
            authority=row["authority"],
            summary=row["summary"],
            metrics=json.loads(row["metrics_json"]),
            last_error=row["last_error"],
            observed_at=datetime.fromisoformat(row["observed_at"]),
            first_observed_at=datetime.fromisoformat(row["first_observed_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            version=int(row["version"]),
        )

    @staticmethod
    def _event(row: sqlite3.Row) -> OperationalEvent:
        return OperationalEvent(
            event_id=row["event_id"],
            component_key=row["component_key"],
            event_type=row["event_type"],
            severity=row["severity"],
            previous_state=row["previous_state"],
            current_state=row["current_state"],
            authority=row["authority"],
            summary=row["summary"],
            details=json.loads(row["details_json"]),
            occurred_at=datetime.fromisoformat(row["occurred_at"]),
        )

    def record_snapshot(self, snapshot: OperationalSnapshot) -> int:
        """Record only new observations and notify once per real state transition."""

        now = datetime.now(timezone.utc)
        transition_count = 0
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            for observation in snapshot.components:
                existing = connection.execute(
                    "SELECT * FROM operational_component_state WHERE component_key = ?",
                    (observation.component_key,),
                ).fetchone()
                observed_at = _utc(observation.observed_at)
                if existing is not None:
                    previous_observed = datetime.fromisoformat(existing["observed_at"])
                    if observed_at <= _utc(previous_observed):
                        continue
                previous_state = str(existing["state"]) if existing is not None else None
                first_observed = (
                    str(existing["first_observed_at"])
                    if existing is not None
                    else observed_at.isoformat()
                )
                version = int(existing["version"]) + 1 if existing is not None else 1
                metrics_json = canonical_json(observation.metrics)
                connection.execute(
                    """
                    INSERT INTO operational_component_state (
                        component_key, component_kind, state, authority, summary,
                        metrics_json, last_error, observed_at, first_observed_at,
                        updated_at, version
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(component_key) DO UPDATE SET
                        component_kind=excluded.component_kind,
                        state=excluded.state,
                        authority=excluded.authority,
                        summary=excluded.summary,
                        metrics_json=excluded.metrics_json,
                        last_error=excluded.last_error,
                        observed_at=excluded.observed_at,
                        updated_at=excluded.updated_at,
                        version=excluded.version
                    """,
                    (
                        observation.component_key,
                        observation.component_kind,
                        observation.state,
                        observation.authority,
                        observation.summary,
                        metrics_json,
                        observation.last_error,
                        observed_at.isoformat(),
                        first_observed,
                        now.isoformat(),
                        version,
                    ),
                )
                should_emit = previous_state != observation.state and (
                    previous_state is not None or observation.state != "HEALTHY"
                )
                if not should_emit:
                    continue
                if observation.state == "HEALTHY" and previous_state in {
                    "DEGRADED", "UNAVAILABLE", "UNKNOWN"
                }:
                    event_type = "RECOVERY"
                elif observation.state in {"DEGRADED", "UNAVAILABLE"}:
                    event_type = "ISSUE"
                else:
                    event_type = "STATUS_CHANGE"
                event_id = f"OPE-{uuid4().hex.upper()}"
                digest_source = (
                    f"{observation.component_key}|{previous_state}|{observation.state}|"
                    f"{observed_at.isoformat()}"
                )
                deduplication_key = hashlib.sha256(digest_source.encode()).hexdigest()
                previous_issue = connection.execute(
                    "SELECT occurred_at FROM operational_events "
                    "WHERE component_key = ? AND event_type IN ('ISSUE', 'STATUS_CHANGE') "
                    "ORDER BY occurred_at DESC, event_id DESC LIMIT 1",
                    (observation.component_key,),
                ).fetchone()
                notification_allowed = event_type == "RECOVERY" or previous_issue is None
                if previous_issue is not None and event_type != "RECOVERY":
                    previous_issue_at = _utc(datetime.fromisoformat(previous_issue["occurred_at"]))
                    notification_allowed = observed_at - previous_issue_at >= NOTIFICATION_COOLDOWN
                details = {
                    "metrics": observation.metrics,
                    "last_error": observation.last_error,
                    "notification_suppressed_by_cooldown": not notification_allowed,
                }
                connection.execute(
                    """
                    INSERT OR IGNORE INTO operational_events (
                        event_id, component_key, event_type, severity,
                        previous_state, current_state, authority, summary,
                        details_json, deduplication_key, occurred_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event_id,
                        observation.component_key,
                        event_type,
                        _severity(observation.state),
                        previous_state,
                        observation.state,
                        observation.authority,
                        observation.summary,
                        canonical_json(details),
                        deduplication_key,
                        observed_at.isoformat(),
                    ),
                )
                if connection.execute("SELECT changes()").fetchone()[0] == 0:
                    continue
                transition_count += 1
                category = (
                    "OPERATIONAL_RECOVERY" if event_type == "RECOVERY" else "OPERATIONAL_ISSUE"
                )
                title = (
                    f"Recovered: {observation.component_key}"
                    if event_type == "RECOVERY"
                    else f"Operational issue: {observation.component_key}"
                )
                if notification_allowed:
                    analysts = connection.execute(
                        "SELECT analyst_id FROM analysts WHERE is_active = 1"
                    ).fetchall()
                    for analyst in analysts:
                        connection.execute(
                            """
                            INSERT OR IGNORE INTO analyst_notifications (
                                notification_id, analyst_id, category, title, preview,
                                target_type, target_id, event_key, created_at
                            ) VALUES (?, ?, ?, ?, ?, 'operational', ?, ?, ?)
                            """,
                            (
                                f"NTF-{uuid4().hex.upper()}",
                                analyst["analyst_id"],
                                category,
                                title[:160],
                                observation.summary[:320],
                                event_id,
                                f"operational:{event_id}",
                                observed_at.isoformat(),
                            ),
                        )
                connection.execute(
                    """
                    INSERT INTO security_audit_events (
                        audit_id, action, actor_id, actor_display, target_type,
                        target_id, outcome, occurred_at, details_json
                    ) VALUES (?, ?, NULL, 'CyberQalqon operational collector',
                              'operational', ?, 'SUCCESS', ?, ?)
                    """,
                    (
                        f"AUD-{uuid4().hex.upper()}",
                        f"OPERATIONAL_{event_type}",
                        event_id,
                        observed_at.isoformat(),
                        canonical_json(
                            {
                                "component_key": observation.component_key,
                                "previous_state": previous_state,
                                "current_state": observation.state,
                                "authority": observation.authority,
                            }
                        ),
                    ),
                )
            connection.execute(
                "DELETE FROM operational_events WHERE event_id IN ("
                "SELECT event_id FROM operational_events ORDER BY occurred_at DESC, event_id DESC "
                "LIMIT -1 OFFSET 1000)"
            )
            connection.execute(
                "DELETE FROM security_audit_events WHERE audit_id IN ("
                "SELECT audit_id FROM security_audit_events ORDER BY occurred_at DESC, audit_id DESC "
                "LIMIT -1 OFFSET 10000)"
            )
        self._invalidate_overview_cache()
        return transition_count

    def overview(
        self,
        *,
        limit: int = 50,
        cancel_event: threading.Event | None = None,
        deadline_seconds: float | None = None,
    ) -> OperationalOverview:
        if not 1 <= limit <= 100:
            raise ValueError("limit must be between 1 and 100")
        request_started = time.monotonic()
        active_cancel = cancel_event or threading.Event()
        effective_deadline = (
            self.overview_query_deadline_seconds
            if deadline_seconds is None
            else deadline_seconds
        )
        if not 0.05 <= effective_deadline <= 30:
            raise ValueError("deadline must be between 0.05 and 30 seconds")
        deadline_at = request_started + effective_deadline

        with self._overview_cache_lock:
            epoch = self._overview_epoch
            cache_entry = self._overview_cache.get(limit)
            cache_age = (
                max(0.0, request_started - cache_entry[0])
                if cache_entry is not None and cache_entry[1] == epoch
                else None
            )
            if cache_entry is not None and cache_age is not None and (
                cache_age <= self.overview_cache_ttl_seconds
            ):
                self._overview_cache_hits += 1
                return self._cached_overview(
                    cache_entry,
                    state="CACHED",
                    reason_code="CACHE_HIT",
                    request_started=request_started,
                )
            flight_key = (limit, epoch)
            flight = self._overview_flights.get(flight_key)
            if flight is not None:
                if cache_entry is not None and cache_age is not None and (
                    cache_age <= self.overview_stale_ttl_seconds
                ):
                    self._overview_stale_served += 1
                    return self._cached_overview(
                        cache_entry,
                        state="STALE",
                        reason_code="REFRESH_IN_PROGRESS",
                        request_started=request_started,
                    )
                if flight.waiters >= self.overview_max_waiters_per_query:
                    raise OperationalQueryUnavailable(
                        "operations single-flight waiter limit reached"
                    )
                flight.waiters += 1
                self._overview_singleflight_joins += 1
                is_owner = False
            else:
                if len(self._overview_flights) >= self.overview_max_inflight:
                    if cache_entry is not None and cache_age is not None and (
                        cache_age <= self.overview_stale_ttl_seconds
                    ):
                        self._overview_stale_served += 1
                        return self._cached_overview(
                            cache_entry,
                            state="STALE",
                            reason_code="REFRESH_IN_PROGRESS",
                            request_started=request_started,
                        )
                    raise OperationalQueryUnavailable(
                        "operations single-flight inflight limit reached"
                    )
                flight = _OverviewFlight(event=threading.Event(), epoch=epoch)
                self._overview_flights[flight_key] = flight
                self._overview_cache_misses += 1
                is_owner = True

        if not is_owner:
            try:
                while not flight.event.wait(timeout=0.025):
                    self._assert_query_active(active_cancel, deadline_at)
                self._assert_query_active(active_cancel, deadline_at)
                with self._overview_cache_lock:
                    completed = self._overview_cache.get(limit)
                    if completed is not None and completed[1] == epoch:
                        self._overview_cache_hits += 1
                        return self._cached_overview(
                            completed,
                            state="CACHED",
                            reason_code="CACHE_HIT",
                            request_started=request_started,
                        )
                    if flight.error is not None:
                        raise flight.error
                raise OperationalQueryUnavailable(
                    "operations refresh completed without a usable snapshot"
                )
            finally:
                with self._overview_cache_lock:
                    flight.waiters = max(0, flight.waiters - 1)

        try:
            overview = self._compute_overview(
                limit=limit,
                cancel_event=active_cancel,
                deadline_at=deadline_at,
                deadline_seconds=effective_deadline,
            )
        except OperationalQueryError as error:
            with self._overview_cache_lock:
                flight.error = error
                self._overview_flights.pop(flight_key, None)
                flight.event.set()
                stale = self._overview_cache.get(limit)
                stale_age = (
                    max(0.0, time.monotonic() - stale[0])
                    if stale is not None and stale[1] == epoch
                    else None
                )
                if stale is not None and stale_age is not None and (
                    stale_age <= self.overview_stale_ttl_seconds
                ):
                    self._overview_stale_served += 1
                    return self._cached_overview(
                        stale,
                        state="STALE",
                        reason_code="REFRESH_FAILED",
                        request_started=request_started,
                    )
            raise
        except Exception:
            with self._overview_cache_lock:
                flight.error = OperationalQueryUnavailable(
                    "operations refresh failed"
                )
                self._overview_flights.pop(flight_key, None)
                flight.event.set()
            raise

        with self._overview_cache_lock:
            if self._overview_epoch == epoch:
                self._overview_cache[limit] = (time.monotonic(), epoch, overview)
                if len(self._overview_cache) > 8:
                    oldest_key = min(
                        self._overview_cache,
                        key=lambda key: self._overview_cache[key][0],
                    )
                    self._overview_cache.pop(oldest_key, None)
            self._overview_flights.pop(flight_key, None)
            flight.event.set()
        return overview

    def _compute_overview(
        self,
        *,
        limit: int,
        cancel_event: threading.Event,
        deadline_at: float,
        deadline_seconds: float,
    ) -> OperationalOverview:
        request_started = time.monotonic()
        now = datetime.now(timezone.utc)
        with self._overview_connection(
            cancel_event=cancel_event,
            deadline_at=deadline_at,
        ) as connection:
            component_rows = connection.execute(
                "SELECT * FROM operational_component_state ORDER BY component_key"
            ).fetchall()
            event_rows = connection.execute(
                "SELECT * FROM operational_events "
                "ORDER BY occurred_at DESC, event_id DESC LIMIT ?",
                (limit,),
            ).fetchall()
            self._assert_query_active(cancel_event, deadline_at)
            retention_row = connection.execute(
                "SELECT last_retention_at, last_deleted_count, retained_records FROM "
                "security_event_store_state WHERE singleton = 1"
            ).fetchone()
            oldest_event = connection.execute(
                "SELECT occurred_at FROM security_events "
                "ORDER BY occurred_at ASC, event_id ASC LIMIT 1"
            ).fetchone()
            newest_event = connection.execute(
                "SELECT occurred_at FROM security_events "
                "ORDER BY occurred_at DESC, event_id DESC LIMIT 1"
            ).fetchone()
            last_ingested = connection.execute(
                "SELECT ingested_at FROM security_events "
                "ORDER BY ingested_at DESC LIMIT 1"
            ).fetchone()
            schema_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            # The exact protected-evidence UNION scans the 100k event table twice
            # and was the dominant M18 timeout cause. Operations is observational,
            # so expose the latest retention audit measurement instead of imposing
            # that write-path-sized scan on every dashboard refresh.
            protected_audit = connection.execute(
                "SELECT details_json FROM security_audit_events "
                "WHERE action = 'SECURITY_EVENT_RETENTION' "
                "ORDER BY occurred_at DESC, audit_id DESC LIMIT 1"
            ).fetchone()
            protected_details: dict[str, object] = {}
            if protected_audit is not None:
                try:
                    parsed = json.loads(protected_audit[0])
                    if isinstance(parsed, dict):
                        protected_details = parsed
                except (TypeError, ValueError, json.JSONDecodeError):
                    protected_details = {}
            protected_records = max(
                0, int(protected_details.get("protected_records", 0) or 0)
            )
            protected_measurement = str(
                protected_details.get(
                    "protected_records_measurement", "NOT_MEASURED"
                )
            )
            if protected_measurement not in {
                "EXACT", "LOWER_BOUND", "CACHED", "NOT_MEASURED"
            }:
                protected_measurement = "NOT_MEASURED"
        components = [self._component(row) for row in component_rows]
        shipper = next(
            (item for item in components if item.component_kind == "event_shipper"), None
        )
        sender = next((item for item in components if item.component_kind == "sender"), None)
        shipper_metrics = shipper.metrics if shipper is not None else {}
        sender_metrics = sender.metrics if sender is not None else {}
        retained_records = int(retention_row["retained_records"] or 0) if retention_row else 0
        over_limit_records = max(0, retained_records - self.max_records)
        retention_state = (
            "OVER_LIMIT_PROTECTED"
            if over_limit_records
            else "AT_LIMIT"
            if retained_records >= self.max_records
            else "WITHIN_LIMIT"
        )
        replay_state = shipper_metrics.get("historical_replay_state", "NOT_CONFIGURED")
        if replay_state not in {
            "NOT_CONFIGURED", "PAUSED", "RUNNING", "COMPLETE", "BLOCKED"
        }:
            replay_state = "NOT_CONFIGURED"
        generation_state = (
            "TRACKED"
            if shipper_metrics.get("archive_generation_id")
            else "CURRENT_FILE_IDENTITY_ONLY"
            if shipper is not None
            else "UNAVAILABLE"
        )
        legacy_checkpoint_state = str(
            shipper_metrics.get("legacy_checkpoint_state", "UNKNOWN")
        )
        if legacy_checkpoint_state not in {"ACTIVE", "PAUSED", "BLOCKED", "UNKNOWN"}:
            legacy_checkpoint_state = "UNKNOWN"
        legacy_continuity = str(
            shipper_metrics.get("legacy_continuity_status", "UNKNOWN")
        )
        if legacy_continuity not in {"UNPROVEN", "PROVEN", "UNKNOWN"}:
            legacy_continuity = "UNKNOWN"
        forward_state = str(
            shipper_metrics.get(
                "forward_ingestion_state",
                "NOT_DEPLOYED" if shipper is not None else "UNKNOWN",
            )
        )
        if forward_state not in {"NOT_DEPLOYED", "READY", "ACTIVE", "BLOCKED", "UNKNOWN"}:
            forward_state = "UNKNOWN"
        approval_state = str(shipper_metrics.get("forward_approval_state", "UNKNOWN"))
        if approval_state not in {
            "ABSENT", "PRESENT_UNVERIFIED", "VALID", "EXPIRED", "MISMATCH", "INVALID", "UNKNOWN"
        }:
            approval_state = "UNKNOWN"
        if approval_state == "UNKNOWN":
            approval_state = (
                "PRESENT_UNVERIFIED"
                if shipper_metrics.get("forward_approval_present") is True
                else "ABSENT"
                if shipper is not None
                else "UNKNOWN"
            )
        forward_replay_state = {
            "NOT_CONFIGURED": "NOT_STARTED",
            "PAUSED": "PAUSED",
            "RUNNING": "RUNNING",
            "COMPLETE": "COMPLETE",
            "BLOCKED": "BLOCKED",
        }.get(str(replay_state), "UNKNOWN")
        latest = max((item.observed_at for item in components), default=None)
        api_component = next(
            (item for item in components if item.component_kind == "wazuh_api"), None
        )
        manager_component = next(
            (item for item in components if item.component_kind == "manager"), None
        )
        inventory_available = api_component is not None and api_component.state == "HEALTHY"
        measured_at = datetime.now(timezone.utc)
        overview = OperationalOverview(
            generated_at=measured_at,
            measurement=OperationalQueryMeasurement(
                state="FRESH",
                measured_at=measured_at,
                age_seconds=0.0,
                duration_ms=round((time.monotonic() - request_started) * 1000, 3),
                cache_ttl_seconds=self.overview_cache_ttl_seconds,
                stale_ttl_seconds=self.overview_stale_ttl_seconds,
                query_deadline_seconds=deadline_seconds,
                reason_code="COMPUTED",
                **self._cache_measurement(),
            ),
            snapshot_collected_at=latest,
            snapshot_age_seconds=(now - _utc(latest)).total_seconds() if latest else None,
            components=components,
            recent_events=[self._event(row) for row in event_rows],
            data_quality=DataQualitySummary(
                total_events=retained_records,
                raw_evidence_records=None,
                missing_hostname=None,
                missing_username=None,
                missing_rule_id=None,
                duplicate_events=_metric_int(sender_metrics, "duplicate_deliveries"),
                duplicate_events_scope=(
                    "CURRENT_SENDER_STATE" if sender is not None else "UNKNOWN"
                ),
                malformed_events=_metric_int(shipper_metrics, "malformed_json"),
                oversized_events=_metric_int(shipper_metrics, "oversized_lines"),
                delivery_rejected=_metric_int(shipper_metrics, "delivery_rejected"),
                shipper_counters_scope=(
                    "CURRENT_FORWARD_GENERATION"
                    if _metric_digest(shipper_metrics, "forward_generation_id") is not None
                    else "UNKNOWN"
                ),
            ),
            storage_retention=StorageRetentionSummary(
                schema_version=schema_version,
                state=retention_state,
                retention_days=self.retention_days,
                max_records=self.max_records,
                retained_records=retained_records,
                protected_records=protected_records,
                protected_records_measurement=protected_measurement,
                over_limit_records=over_limit_records,
                usage_percent=round((retained_records / self.max_records) * 100.0, 3),
                database_size_bytes=self.path.stat().st_size if self.path.exists() else 0,
                wal_size_bytes=(
                    Path(f"{self.path}-wal").stat().st_size
                    if Path(f"{self.path}-wal").exists()
                    else 0
                ),
                last_run_at=(
                    datetime.fromisoformat(retention_row["last_retention_at"])
                    if retention_row and retention_row["last_retention_at"]
                    else None
                ),
                last_deleted_count=(
                    int(retention_row["last_deleted_count"] or 0) if retention_row else 0
                ),
                oldest_event_at=(
                    datetime.fromisoformat(oldest_event["occurred_at"])
                    if oldest_event and oldest_event["occurred_at"]
                    else None
                ),
                newest_event_at=(
                    datetime.fromisoformat(newest_event["occurred_at"])
                    if newest_event and newest_event["occurred_at"]
                    else None
                ),
                last_ingested_at=(
                    datetime.fromisoformat(last_ingested["ingested_at"])
                    if last_ingested and last_ingested["ingested_at"]
                    else None
                ),
            ),
            archive_backlog=ArchiveBacklogSummary(
                state="AVAILABLE" if shipper is not None else "UNAVAILABLE",
                generation_state=generation_state,
                historical_replay_state=replay_state,
                archive_size_bytes=_metric_int(shipper_metrics, "archive_size_bytes"),
                cursor_bytes=_metric_int(shipper_metrics, "archive_cursor_bytes"),
                current_lag_bytes=_metric_int(shipper_metrics, "archive_lag_bytes"),
                current_eligible_records=_metric_int(
                    shipper_metrics, "eligible_record_backlog"
                ),
                current_filtered_records=_metric_int(
                    shipper_metrics, "filtered_record_backlog"
                ),
                current_malformed_records=_metric_int(
                    shipper_metrics, "malformed_record_backlog"
                ),
                rotated_archive_count=_metric_int(
                    shipper_metrics, "rotated_archive_count"
                ),
                historical_eligible_records=_metric_int(
                    shipper_metrics, "historical_eligible_backlog"
                ),
                recovery_readiness=(
                    "BLOCKED_RETENTION_CAP"
                    if retained_records >= self.max_records
                    else "READY_FOR_APPROVAL"
                    if _metric_int(shipper_metrics, "historical_eligible_backlog") is not None
                    else "NOT_AUDITED"
                ),
            ),
            forward_ingestion=ForwardIngestionSummary(
                legacy_checkpoint_state=legacy_checkpoint_state,
                legacy_continuity=legacy_continuity,
                forward_state=forward_state,
                historical_replay_state=forward_replay_state,
                approval_state=approval_state,
                approval_validation_basis=(
                    "BOUNDED_SCOPE_TIME_IDENTITY"
                    if shipper_metrics.get("forward_approval_validation_basis")
                    == "BOUNDED_SCOPE_TIME_IDENTITY"
                    else "PRESENCE_ONLY"
                    if approval_state == "PRESENT_UNVERIFIED"
                    else "UNKNOWN"
                ),
                approval_expires_at=_metric_epoch_datetime(
                    shipper_metrics, "forward_approval_expires_at_epoch"
                ),
                approval_remaining_seconds=_metric_float(
                    shipper_metrics, "forward_approval_remaining_seconds"
                ),
                generation_id=_metric_digest(
                    shipper_metrics, "forward_generation_id"
                ),
                source_device=_metric_int(shipper_metrics, "forward_source_device"),
                source_inode=_metric_int(shipper_metrics, "forward_source_inode"),
                source_size_bytes=_metric_int(
                    shipper_metrics, "forward_source_size_bytes"
                ),
                start_offset_bytes=_metric_int(
                    shipper_metrics, "forward_start_offset_bytes"
                ),
                cursor_bytes=_metric_int(shipper_metrics, "forward_cursor_bytes"),
                lag_bytes=_metric_int(shipper_metrics, "forward_lag_bytes"),
                unique_insertions=_metric_int(
                    shipper_metrics, "forward_unique_insertions"
                ),
                duplicate_acknowledgements=_metric_int(
                    shipper_metrics, "forward_duplicate_acknowledgements"
                ),
                filtered_records=_metric_int(
                    shipper_metrics, "forward_filtered_records"
                ),
                malformed_records=_metric_int(
                    shipper_metrics, "forward_malformed_records"
                ),
                retry_attempts=_metric_int(
                    shipper_metrics, "forward_retry_attempts"
                ),
                protocol_errors=_metric_int(
                    shipper_metrics, "forward_protocol_errors"
                ),
                delivery_rejected=_metric_int(
                    shipper_metrics, "forward_delivery_rejected"
                ),
                source_identity_matches=_metric_bool(
                    shipper_metrics, "forward_source_identity_matches"
                ),
                legacy_state_unchanged=_metric_bool(
                    shipper_metrics, "forward_legacy_state_unchanged"
                ),
                service_active=shipper_metrics.get("forward_service_active") is True,
                archive_growth_bytes_per_second=(
                    _metric_float(shipper_metrics, "archive_growth_bytes_per_second")
                    if shipper_metrics.get("rate_snapshot_status") == "FRESH"
                    else None
                ),
                cursor_progress_bytes_per_second=_metric_float(
                    shipper_metrics, "forward_cursor_progress_bytes_per_second"
                ),
                net_lag_bytes_per_second=_metric_float(
                    shipper_metrics, "forward_net_lag_bytes_per_second",
                    allow_negative=True,
                ),
                net_backlog_trend=(
                    str(shipper_metrics.get("forward_backlog_trend"))
                    if shipper_metrics.get("forward_backlog_trend")
                    in {"DRAINING", "GROWING", "STABLE"}
                    else "UNKNOWN"
                ),
                rate_measurement_state=(
                    str(shipper_metrics.get("forward_rate_measurement_state"))
                    if shipper_metrics.get("forward_rate_measurement_state")
                    in {"FRESH", "STALE"}
                    else "UNKNOWN"
                ),
                unreconciled_historical_records=_metric_int(
                    shipper_metrics, "forward_unreconciled_historical_records"
                ),
                retention_pressure=retention_state,
                last_successful_delivery=_metric_epoch_datetime(
                    shipper_metrics, "forward_last_successful_delivery_epoch"
                ),
                checkpoint_updated_at=_metric_epoch_datetime(
                    shipper_metrics, "forward_checkpoint_updated_at_epoch"
                ),
            ),
            wazuh_inventory=WazuhInventoryStatus(
                state="AVAILABLE" if inventory_available else "UNAVAILABLE",
                reason=(
                    "Read-only Wazuh API inventory was collected."
                    if inventory_available
                    else "Read-only Wazuh API credentials or trusted CA are not configured; agent states remain UNKNOWN."
                ),
                manager_identity=(
                    str(manager_component.metrics.get("identity"))
                    if manager_component and manager_component.metrics.get("identity")
                    else None
                ),
                agent_count=(
                    _metric_int(api_component.metrics, "agent_count")
                    if inventory_available and api_component is not None
                    else None
                ),
            ),
        )
        return overview


def _metric_int(metrics: dict[str, object], key: str) -> int | None:
    value = metrics.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _metric_bool(metrics: dict[str, object], key: str) -> bool | None:
    value = metrics.get(key)
    return value if isinstance(value, bool) else None


def _metric_digest(metrics: dict[str, object], key: str) -> str | None:
    value = metrics.get(key)
    if not isinstance(value, str) or len(value) != 64:
        return None
    try:
        int(value, 16)
    except ValueError:
        return None
    return value.lower()


def _metric_float(
    metrics: dict[str, object], key: str, *, allow_negative: bool = False
) -> float | None:
    value = metrics.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    numeric = float(value)
    if not allow_negative and numeric < 0:
        return None
    return numeric


def _metric_epoch_datetime(
    metrics: dict[str, object], key: str
) -> datetime | None:
    value = _metric_float(metrics, key)
    if value is None:
        return None
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None
