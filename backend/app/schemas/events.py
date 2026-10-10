"""Typed contracts for the bounded SIEM security-event store."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Literal

from pydantic import ConfigDict, Field, IPvAnyAddress, field_validator, model_validator

from app.schemas.alerts import StrictModel


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
    state: Literal["WITHIN_LIMIT", "AT_LIMIT"]
    retention_days: int = Field(ge=1)
    max_records: int = Field(ge=100)
    retained_records: int = Field(ge=0)
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
    event_id: str | None = Field(default=None, min_length=1, max_length=255)
    rule_id: str | None = Field(default=None, min_length=1, max_length=128)
    event_category: str | None = Field(default=None, min_length=1, max_length=255)
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
