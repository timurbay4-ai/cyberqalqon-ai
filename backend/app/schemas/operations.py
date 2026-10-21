"""Typed contracts for bounded, evidence-backed operational telemetry."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import Field, field_validator

from app.schemas.alerts import StrictModel


OperationalState = Literal["HEALTHY", "DEGRADED", "UNAVAILABLE", "UNKNOWN"]
OperationalAuthority = Literal[
    "WAZUH_API",
    "OS_SERVICE_MANAGER",
    "DURABLE_SENDER_STATE",
    "DURABLE_SHIPPER_STATE",
    "APPLICATION_DATABASE",
]
OperationalKind = Literal[
    "manager", "wazuh_api", "sender", "event_shipper", "windows_agent", "database",
    "telemetry_source"
]


class ComponentObservation(StrictModel):
    component_key: str = Field(min_length=1, max_length=128)
    component_kind: OperationalKind
    state: OperationalState
    authority: OperationalAuthority
    summary: str = Field(min_length=1, max_length=320)
    metrics: dict[str, Any] = Field(default_factory=dict)
    last_error: str | None = Field(default=None, max_length=512)
    observed_at: datetime

    @field_validator("observed_at")
    @classmethod
    def timestamp_has_offset(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("observed_at must include a UTC offset")
        return value


class OperationalSnapshot(StrictModel):
    version: Literal[1] = 1
    collected_at: datetime
    components: list[ComponentObservation] = Field(max_length=32)

    @field_validator("collected_at")
    @classmethod
    def collected_at_has_offset(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("collected_at must include a UTC offset")
        return value


class OperationalComponent(ComponentObservation):
    first_observed_at: datetime
    updated_at: datetime
    version: int = Field(ge=1)


class OperationalEvent(StrictModel):
    event_id: str
    component_key: str
    event_type: Literal["ISSUE", "RECOVERY", "STATUS_CHANGE"]
    severity: Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    previous_state: OperationalState | None = None
    current_state: OperationalState
    authority: OperationalAuthority
    summary: str
    details: dict[str, Any] = Field(default_factory=dict)
    occurred_at: datetime


class DataQualitySummary(StrictModel):
    total_events: int = Field(ge=0)
    total_events_scope: Literal["CURRENT_RETAINED_DATABASE"] = (
        "CURRENT_RETAINED_DATABASE"
    )
    total_events_measurement: Literal["EXACT"] = "EXACT"
    raw_evidence_records: int | None = Field(default=None, ge=0)
    missing_hostname: int | None = Field(default=None, ge=0)
    missing_username: int | None = Field(default=None, ge=0)
    missing_rule_id: int | None = Field(default=None, ge=0)
    field_completeness_measurement: Literal["UNKNOWN"] = "UNKNOWN"
    field_completeness_reason: Literal["NOT_MATERIALIZED_SCHEMA17"] = (
        "NOT_MATERIALIZED_SCHEMA17"
    )
    duplicate_events: int | None = Field(default=None, ge=0)
    duplicate_events_scope: Literal["CURRENT_SENDER_STATE", "UNKNOWN"] = "UNKNOWN"
    malformed_events: int | None = Field(default=None, ge=0)
    oversized_events: int | None = Field(default=None, ge=0)
    delivery_rejected: int | None = Field(default=None, ge=0)
    shipper_counters_scope: Literal["CURRENT_FORWARD_GENERATION", "UNKNOWN"] = "UNKNOWN"
    evidence: Literal["APPLICATION_DATABASE_AND_DURABLE_SHIPPER_STATE"] = (
        "APPLICATION_DATABASE_AND_DURABLE_SHIPPER_STATE"
    )


class WazuhInventoryStatus(StrictModel):
    state: Literal["AVAILABLE", "UNAVAILABLE"]
    authority: Literal["WAZUH_API"] = "WAZUH_API"
    reason: str = Field(max_length=320)
    manager_identity: str | None = Field(default=None, max_length=255)
    agent_count: int | None = Field(default=None, ge=0)


class StorageRetentionSummary(StrictModel):
    schema_version: int = Field(ge=0)
    state: Literal["WITHIN_LIMIT", "AT_LIMIT", "OVER_LIMIT_PROTECTED"]
    retention_days: int = Field(ge=1)
    max_records: int = Field(ge=1)
    retained_records: int = Field(ge=0)
    protected_records: int = Field(ge=0)
    protected_records_measurement: Literal[
        "EXACT", "LOWER_BOUND", "CACHED", "NOT_MEASURED"
    ] = "NOT_MEASURED"
    over_limit_records: int = Field(ge=0)
    usage_percent: float = Field(ge=0)
    database_size_bytes: int = Field(ge=0)
    wal_size_bytes: int = Field(ge=0)
    last_run_at: datetime | None = None
    last_deleted_count: int = Field(ge=0)
    oldest_event_at: datetime | None = None
    newest_event_at: datetime | None = None
    last_ingested_at: datetime | None = None


class ArchiveBacklogSummary(StrictModel):
    state: Literal["AVAILABLE", "UNAVAILABLE"]
    generation_state: Literal["TRACKED", "CURRENT_FILE_IDENTITY_ONLY", "UNAVAILABLE"]
    historical_replay_state: Literal[
        "NOT_CONFIGURED", "PAUSED", "RUNNING", "COMPLETE", "BLOCKED"
    ]
    archive_size_bytes: int | None = Field(default=None, ge=0)
    cursor_bytes: int | None = Field(default=None, ge=0)
    current_lag_bytes: int | None = Field(default=None, ge=0)
    current_eligible_records: int | None = Field(default=None, ge=0)
    current_filtered_records: int | None = Field(default=None, ge=0)
    current_malformed_records: int | None = Field(default=None, ge=0)
    rotated_archive_count: int | None = Field(default=None, ge=0)
    historical_eligible_records: int | None = Field(default=None, ge=0)
    recovery_readiness: Literal[
        "BLOCKED_RETENTION_CAP", "READY_FOR_APPROVAL", "NOT_AUDITED"
    ]


class ForwardIngestionSummary(StrictModel):
    legacy_checkpoint_state: Literal["ACTIVE", "PAUSED", "BLOCKED", "UNKNOWN"]
    legacy_continuity: Literal["UNPROVEN", "PROVEN", "UNKNOWN"]
    forward_state: Literal["NOT_DEPLOYED", "READY", "ACTIVE", "BLOCKED", "UNKNOWN"]
    historical_replay_state: Literal[
        "NOT_STARTED", "PAUSED", "RUNNING", "COMPLETE", "BLOCKED", "UNKNOWN"
    ]
    approval_state: Literal[
        "ABSENT", "PRESENT_UNVERIFIED", "VALID", "EXPIRED", "MISMATCH", "INVALID", "UNKNOWN"
    ]
    approval_validation_basis: Literal[
        "BOUNDED_SCOPE_TIME_IDENTITY", "PRESENCE_ONLY", "UNKNOWN"
    ]
    approval_expires_at: datetime | None = None
    approval_remaining_seconds: float | None = Field(default=None, ge=0)
    generation_id: str | None = Field(default=None, min_length=64, max_length=64)
    source_device: int | None = Field(default=None, ge=0)
    source_inode: int | None = Field(default=None, ge=0)
    source_size_bytes: int | None = Field(default=None, ge=0)
    start_offset_bytes: int | None = Field(default=None, ge=0)
    cursor_bytes: int | None = Field(default=None, ge=0)
    lag_bytes: int | None = Field(default=None, ge=0)
    unique_insertions: int | None = Field(default=None, ge=0)
    duplicate_acknowledgements: int | None = Field(default=None, ge=0)
    filtered_records: int | None = Field(default=None, ge=0)
    malformed_records: int | None = Field(default=None, ge=0)
    retry_attempts: int | None = Field(default=None, ge=0)
    protocol_errors: int | None = Field(default=None, ge=0)
    delivery_rejected: int | None = Field(default=None, ge=0)
    source_identity_matches: bool | None = None
    legacy_state_unchanged: bool | None = None
    service_active: bool
    archive_growth_bytes_per_second: float | None = Field(default=None, ge=0)
    cursor_progress_bytes_per_second: float | None = Field(default=None, ge=0)
    net_lag_bytes_per_second: float | None = None
    net_backlog_trend: Literal["DRAINING", "GROWING", "STABLE", "UNKNOWN"]
    rate_measurement_state: Literal["FRESH", "STALE", "UNKNOWN"]
    unreconciled_historical_records: int | None = Field(default=None, ge=0)
    retention_pressure: Literal[
        "WITHIN_LIMIT", "AT_LIMIT", "OVER_LIMIT_PROTECTED"
    ]
    last_successful_delivery: datetime | None = None
    checkpoint_updated_at: datetime | None = None
    historical_gap_warning: Literal["UNPROVEN_HISTORY_NOT_REPLAYED"] = (
        "UNPROVEN_HISTORY_NOT_REPLAYED"
    )


class IngestionPerformanceSummary(StrictModel):
    measurement_scope: Literal["POST_PROCESS_START_ONLY"]
    started_at: datetime
    captured_at: datetime
    measurement_window_seconds: float = Field(ge=0)
    request_latency_sample_size: int = Field(ge=0, le=512)
    active_request_mode: Literal["single-event", "batch"]
    execution_model: Literal["bounded-threadpool"]
    ingress_protocol_version: Literal["m18-batch-v1"]
    configured_mode: Literal[
        "batch-available-disabled-by-default", "batch-enabled"
    ]
    batch_endpoint_enabled: bool
    configured_batch_limit: int = Field(ge=1, le=100)
    requests: int = Field(ge=0)
    single_requests: int = Field(ge=0)
    batch_requests: int = Field(ge=0)
    events: int = Field(ge=0)
    inserted: int = Field(ge=0)
    duplicates: int = Field(ge=0)
    retryable_failures: int = Field(ge=0)
    permanent_failures: int = Field(ge=0)
    requests_per_second: float = Field(ge=0)
    events_per_second: float = Field(ge=0)
    inserts_per_second: float = Field(ge=0)
    duplicates_per_second: float = Field(ge=0)
    events_per_request: float | None = Field(default=None, ge=0)
    request_latency_p50_ms: float | None = Field(default=None, ge=0)
    request_latency_p95_ms: float | None = Field(default=None, ge=0)
    database_latency_p50_ms: float | None = Field(default=None, ge=0)
    database_latency_p95_ms: float | None = Field(default=None, ge=0)
    transaction_latency_p50_ms: float | None = Field(default=None, ge=0)
    transaction_latency_p95_ms: float | None = Field(default=None, ge=0)
    retention_latency_p50_ms: float | None = Field(default=None, ge=0)
    retention_latency_p95_ms: float | None = Field(default=None, ge=0)
    lock_wait_latency_p50_ms: float | None = Field(default=None, ge=0)
    lock_wait_latency_p95_ms: float | None = Field(default=None, ge=0)
    commit_latency_p50_ms: float | None = Field(default=None, ge=0)
    commit_latency_p95_ms: float | None = Field(default=None, ge=0)
    retention_candidate_latency_p95_ms: float | None = Field(default=None, ge=0)
    protected_check_latency_p95_ms: float | None = Field(default=None, ge=0)
    timeout_count: int = Field(ge=0)
    pre_commit_deadline_violations: int = Field(ge=0)
    sqlite_busy_errors: int = Field(ge=0)
    last_failure_stage: str | None = Field(default=None, max_length=64)
    last_failure_timing_ms: dict[str, float | int | bool] | None = None
    last_successful_acknowledgement: datetime | None = None
    last_successful_acknowledgement_age_seconds: float | None = Field(
        default=None, ge=0
    )
    last_error: str | None = Field(default=None, max_length=128)
    historical_unique_insertions: int | None = Field(default=None, ge=0)
    historical_duplicate_acknowledgements: int | None = Field(default=None, ge=0)


class OperationalQueryMeasurement(StrictModel):
    """Freshness and cost of the bounded database portion of the overview."""

    state: Literal["FRESH", "CACHED", "STALE", "UNKNOWN"]
    measured_at: datetime
    age_seconds: float = Field(ge=0)
    duration_ms: float = Field(ge=0)
    cache_ttl_seconds: float = Field(ge=0)
    stale_ttl_seconds: float = Field(ge=0)
    query_deadline_seconds: float = Field(gt=0)
    reason_code: Literal[
        "COMPUTED", "CACHE_HIT", "REFRESH_IN_PROGRESS", "REFRESH_FAILED"
    ]
    cache_hits: int = Field(ge=0)
    cache_misses: int = Field(ge=0)
    singleflight_joins: int = Field(ge=0)
    stale_served: int = Field(ge=0)
    inflight_queries: int = Field(ge=0)
    pending_waiters: int = Field(ge=0)
    execution_model: Literal["BOUNDED_THREADPOOL"] = "BOUNDED_THREADPOOL"


class OperationalOverview(StrictModel):
    generated_at: datetime
    measurement: OperationalQueryMeasurement
    snapshot_collected_at: datetime | None = None
    snapshot_age_seconds: float | None = Field(default=None, ge=0)
    components: list[OperationalComponent]
    recent_events: list[OperationalEvent]
    data_quality: DataQualitySummary
    storage_retention: StorageRetentionSummary
    archive_backlog: ArchiveBacklogSummary
    forward_ingestion: ForwardIngestionSummary
    wazuh_inventory: WazuhInventoryStatus
    ingestion_performance: IngestionPerformanceSummary | None = None
