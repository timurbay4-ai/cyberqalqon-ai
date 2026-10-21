"""Typed contracts for the bounded SIEM security-event store."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Literal

from pydantic import ConfigDict, Field, IPvAnyAddress, field_validator, model_validator

from app.schemas.alerts import MitreContext, StrictModel


EventSourceType = Literal[
    "authentication",
    "file_integrity",
    "network",
    "web",
    "windows_event",
    "wazuh_alert",
    "wazuh_archive",
]
EventSort = Literal["newest", "oldest"]


class SecurityEventSummary(StrictModel):
    event_id: str = Field(min_length=1, max_length=64)
    source_event_id: str | None = Field(default=None, max_length=255)
    event_code: str | None = Field(default=None, max_length=128)
    timestamp: datetime
    ingested_at: datetime
    source_type: EventSourceType
    hostname: str | None = Field(default=None, max_length=255)
    agent_id: str | None = Field(default=None, max_length=128)
    agent_name: str | None = Field(default=None, max_length=255)
    operating_system: str | None = Field(default=None, max_length=255)
    manager_identity: str | None = Field(default=None, max_length=255)
    event_provider: str | None = Field(default=None, max_length=255)
    event_channel: str | None = Field(default=None, max_length=255)
    process_name: str | None = Field(default=None, max_length=1024)
    process_path: str | None = Field(default=None, max_length=2048)
    command_line: str | None = Field(default=None, max_length=8192)
    process_id: str | None = Field(default=None, max_length=128)
    parent_process_name: str | None = Field(default=None, max_length=1024)
    parent_process_path: str | None = Field(default=None, max_length=2048)
    parent_process_id: str | None = Field(default=None, max_length=128)
    normalization_schema: str = Field(min_length=1, max_length=64)
    source_ip: IPvAnyAddress | None = None
    destination_ip: IPvAnyAddress | None = None
    source_port: int | None = Field(default=None, ge=1, le=65535)
    destination_port: int | None = Field(default=None, ge=1, le=65535)
    username: str | None = Field(default=None, max_length=512)
    event_category: str | None = Field(default=None, max_length=255)
    event_action: str | None = Field(default=None, max_length=255)
    outcome: str | None = Field(default=None, max_length=128)
    rule_id: str | None = Field(default=None, max_length=128)
    severity: int | None = Field(default=None, ge=0, le=16)
    mitre: MitreContext = Field(default_factory=MitreContext)
    message: str = Field(min_length=1, max_length=4096)
    ingestion_source: str = Field(min_length=1, max_length=128)
    related_alert_id: str | None = Field(default=None, max_length=255)

    @field_validator("timestamp", "ingested_at")
    @classmethod
    def timestamps_include_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must include a UTC offset")
        return value


class SecurityEventDetail(SecurityEventSummary):
    structured_payload: dict[str, Any] = Field(default_factory=dict)
    raw_payload: dict[str, Any] = Field(default_factory=dict)
    related_incident_ids: list[str] = Field(default_factory=list)
    related_case_ids: list[str] = Field(default_factory=list)
    raw_evidence_ref: str = Field(min_length=1, max_length=64)


class SecurityEventPage(StrictModel):
    limit: int = Field(ge=1, le=100)
    next_cursor: str | None = None
    total: int = Field(ge=0)
    sort: EventSort


class SecurityEventListResponse(StrictModel):
    items: list[SecurityEventSummary]
    page: SecurityEventPage


class SecurityEventIngestResponse(StrictModel):
    status: Literal["created", "duplicate"]
    duplicate: bool
    event: SecurityEventSummary


BatchEventOutcome = Literal[
    "INSERTED",
    "DUPLICATE",
    "PERMANENTLY_INVALID",
    "RETRYABLE_FAILURE",
    "NOT_PROCESSED",
]


class SecurityEventBatchRequest(StrictModel):
    """Bounded machine-ingestion envelope for the M18 atomic batch protocol."""

    protocol_version: Literal["m18-batch-v1"] = "m18-batch-v1"
    batch_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
    )
    events: list[dict[str, Any]] = Field(min_length=1, max_length=100)


class SecurityEventBatchItemResult(StrictModel):
    index: int = Field(ge=0, le=99)
    event_id: str = Field(min_length=1, max_length=64)
    deduplication_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    outcome: Literal["INSERTED", "DUPLICATE"]


class SecurityEventBatchTiming(StrictModel):
    request_reception_ms: float = Field(ge=0)
    authentication_ms: float = Field(ge=0)
    request_parse_ms: float = Field(ge=0)
    schema_validation_ms: float = Field(ge=0)
    normalization_ms: float = Field(ge=0)
    database_ms: float = Field(ge=0)
    transaction_ms: float = Field(ge=0)
    connection_ms: float = Field(ge=0)
    lock_wait_ms: float = Field(ge=0)
    deduplication_ms: float = Field(ge=0)
    alert_lookup_ms: float = Field(ge=0)
    insertion_ms: float = Field(ge=0)
    retention_ms: float = Field(ge=0)
    retention_state_ms: float = Field(ge=0)
    retention_age_delete_ms: float = Field(ge=0)
    retention_count_ms: float = Field(ge=0)
    retention_candidate_ms: float = Field(ge=0)
    protected_check_ms: float = Field(ge=0)
    retention_delete_ms: float = Field(ge=0)
    protected_count_ms: float = Field(ge=0)
    retention_metadata_ms: float = Field(ge=0)
    retention_audit_ms: float = Field(ge=0)
    commit_ms: float = Field(ge=0)
    sql_statement_count: int = Field(ge=0)
    retention_rows_considered: int = Field(ge=0)
    retention_rows_deleted: int = Field(ge=0)
    protected_row_skips: int = Field(ge=0)
    full_age_sweep: bool
    total_ms: float = Field(ge=0)


class SecurityEventBatchIngestResponse(StrictModel):
    protocol_version: Literal["m18-batch-v1"] = "m18-batch-v1"
    batch_id: str = Field(min_length=1, max_length=128)
    status: Literal["COMMITTED"] = "COMMITTED"
    atomic: Literal[True] = True
    inserted: int = Field(ge=0, le=100)
    duplicates: int = Field(ge=0, le=100)
    results: list[SecurityEventBatchItemResult] = Field(min_length=1, max_length=100)
    timing_ms: SecurityEventBatchTiming


class SecurityEventBatchErrorItem(StrictModel):
    index: int = Field(ge=0, le=99)
    outcome: Literal["PERMANENTLY_INVALID", "RETRYABLE_FAILURE", "NOT_PROCESSED"]
    code: str | None = Field(default=None, min_length=1, max_length=128)
    field: str | None = Field(default=None, min_length=1, max_length=256)


class SecurityEventBatchErrorDetail(StrictModel):
    code: str = Field(min_length=1, max_length=128)
    message: str = Field(min_length=1, max_length=512)
    batch_id: str | None = Field(default=None, min_length=1, max_length=128)
    atomic: Literal[True] = True
    results: list[SecurityEventBatchErrorItem] = Field(default_factory=list, max_length=100)


class SecurityEventBatchErrorResponse(StrictModel):
    detail: SecurityEventBatchErrorDetail


class TelemetryCoverageEntry(StrictModel):
    source_type: EventSourceType
    event_category: str | None = None
    operating_system: str | None = None
    event_provider: str | None = None
    event_channel: str | None = None
    event_count: int = Field(ge=1)
    first_event_at: datetime
    last_event_at: datetime
    last_ingested_at: datetime
    state: Literal["OBSERVED"] = "OBSERVED"
    evidence: Literal["STORED_EVENTS"] = "STORED_EVENTS"


class TelemetryCoverageReport(StrictModel):
    start_time: datetime
    end_time: datetime
    generated_at: datetime
    total_events: int = Field(ge=0)
    entries: list[TelemetryCoverageEntry]


class TimeSeriesPoint(StrictModel):
    timestamp: datetime
    count: int = Field(ge=0)


class NamedCount(StrictModel):
    name: str
    count: int = Field(ge=0)


class SeverityCount(StrictModel):
    severity: str
    count: int = Field(ge=0)


class IngestionHealth(StrictModel):
    state: Literal["ACTIVE", "STALE", "EMPTY"]
    last_event_at: datetime | None = None
    last_ingested_at: datetime | None = None
    lag_seconds: float | None = Field(default=None, ge=0)


class PipelineActivity(StrictModel):
    component: Literal["wazuh_sender", "event_shipper"]
    state: Literal["ACTIVE", "STALE", "EMPTY"]
    evidence: Literal["DELIVERY_ACTIVITY"] = "DELIVERY_ACTIVITY"
    last_delivery_at: datetime | None = None
    delivered_records: int = Field(ge=0)


class RetentionStatus(StrictModel):
    state: Literal["WITHIN_LIMIT", "AT_LIMIT", "OVER_LIMIT_PROTECTED"]
    retention_days: int = Field(ge=1)
    max_records: int = Field(ge=100)
    retained_records: int = Field(ge=0)
    protected_records: int = Field(default=0, ge=0)
    over_limit_records: int = Field(default=0, ge=0)
    usage_percent: float = Field(default=0, ge=0)
    oldest_event_at: datetime | None = None
    newest_event_at: datetime | None = None
    last_run_at: datetime | None = None
    last_deleted_count: int = Field(ge=0)


class SecurityOverview(StrictModel):
    start_time: datetime
    end_time: datetime
    total_events: int = Field(ge=0)
    total_alerts: int = Field(ge=0)
    events_per_minute: float = Field(ge=0)
    active_incidents: int = Field(ge=0)
    reporting_agents: int = Field(ge=0)
    active_sources: int = Field(ge=0)
    stale_sources: int = Field(ge=0)
    database_size_bytes: int = Field(ge=0)
    alerts_by_severity: list[SeverityCount]
    incidents_by_status: list[NamedCount]
    events_over_time: list[TimeSeriesPoint]
    alerts_over_time: list[TimeSeriesPoint]
    top_source_ips: list[NamedCount]
    top_hosts: list[NamedCount]
    top_destination_hosts: list[NamedCount]
    top_rules: list[NamedCount]
    top_event_categories: list[NamedCount]
    event_sources: list[NamedCount]
    latest_high_alerts: list[dict[str, Any]]
    ingestion: IngestionHealth
    pipeline_activity: list[PipelineActivity]
    retention: RetentionStatus


class SavedEventSearchQuery(StrictModel):
    relative_minutes: Literal[15, 60, 1440, 10080, 43200] | None = None
    start_time: datetime | None = None
    end_time: datetime | None = None
    source_ip: IPvAnyAddress | None = None
    destination_ip: IPvAnyAddress | None = None
    hostname: str | None = Field(default=None, min_length=1, max_length=255)
    username: str | None = Field(default=None, min_length=1, max_length=512)
    operating_system: str | None = Field(default=None, min_length=1, max_length=255)
    event_provider: str | None = Field(default=None, min_length=1, max_length=255)
    event_channel: str | None = Field(default=None, min_length=1, max_length=255)
    process_name: str | None = Field(default=None, min_length=1, max_length=1024)
    event_id: str | None = Field(default=None, min_length=1, max_length=255)
    rule_id: str | None = Field(default=None, min_length=1, max_length=128)
    event_category: str | None = Field(default=None, min_length=1, max_length=255)
    event_action: str | None = Field(default=None, min_length=1, max_length=255)
    outcome: str | None = Field(default=None, min_length=1, max_length=128)
    severity_min: int | None = Field(default=None, ge=0, le=16)
    severity_max: int | None = Field(default=None, ge=0, le=16)
    source_type: EventSourceType | None = None
    search: str | None = Field(default=None, min_length=1, max_length=200)
    sort: EventSort = "newest"

    @model_validator(mode="after")
    def validate_range(self) -> "SavedEventSearchQuery":
        if self.relative_minutes is not None and (self.start_time is not None or self.end_time is not None):
            raise ValueError("relative_minutes cannot be combined with custom timestamps")
        if (self.start_time is None) != (self.end_time is None):
            raise ValueError("start_time and end_time must be supplied together")
        if self.start_time is not None and self.end_time is not None:
            for value in (self.start_time, self.end_time):
                if value.tzinfo is None or value.utcoffset() is None:
                    raise ValueError("saved-search timestamps must include a UTC offset")
            if self.start_time > self.end_time:
                raise ValueError("start_time must not exceed end_time")
            if self.end_time - self.start_time > timedelta(days=31):
                raise ValueError("saved-search range must not exceed 31 days")
        if (
            self.severity_min is not None
            and self.severity_max is not None
            and self.severity_min > self.severity_max
        ):
            raise ValueError("severity_min must not exceed severity_max")
        return self


class SavedEventSearchCreate(StrictModel):
    name: str = Field(min_length=1, max_length=100)
    query: SavedEventSearchQuery

    @field_validator("name")
    @classmethod
    def name_not_blank(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("name must not be blank")
        return normalized


class SavedEventSearchUpdate(SavedEventSearchCreate):
    pass


class SavedEventSearch(StrictModel):
    saved_search_id: str = Field(min_length=1, max_length=64)
    name: str = Field(min_length=1, max_length=100)
    query: SavedEventSearchQuery
    created_at: datetime
    updated_at: datetime


class NormalizedSecurityEvent(StrictModel):
    """Internal validated event produced before persistence."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    event_id: str
    deduplication_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_event_id: str | None = None
    event_code: str | None = None
    timestamp: datetime
    source_type: EventSourceType
    hostname: str | None = None
    agent_id: str | None = None
    agent_name: str | None = None
    operating_system: str | None = None
    manager_identity: str | None = None
    event_provider: str | None = None
    event_channel: str | None = None
    process_name: str | None = None
    process_path: str | None = None
    command_line: str | None = None
    process_id: str | None = None
    parent_process_name: str | None = None
    parent_process_path: str | None = None
    parent_process_id: str | None = None
    normalization_schema: str = "wazuh-event-v3"
    source_ip: IPvAnyAddress | None = None
    destination_ip: IPvAnyAddress | None = None
    source_port: int | None = Field(default=None, ge=1, le=65535)
    destination_port: int | None = Field(default=None, ge=1, le=65535)
    username: str | None = None
    event_category: str | None = None
    event_action: str | None = None
    outcome: str | None = None
    rule_id: str | None = None
    severity: int | None = Field(default=None, ge=0, le=16)
    mitre: MitreContext = Field(default_factory=MitreContext)
    message: str = Field(min_length=1, max_length=4096)
    ingestion_source: str
    structured_payload: dict[str, Any]
    raw_payload: dict[str, Any]
    raw_size_bytes: int = Field(ge=2)

    @field_validator("timestamp")
    @classmethod
    def timestamp_includes_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must include a UTC offset")
        return value
