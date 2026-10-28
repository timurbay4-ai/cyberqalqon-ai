"""API contracts for bounded CQQL event search and analytics."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Literal

from pydantic import Field, field_validator, model_validator

from app.schemas.alerts import StrictModel
from app.schemas.events import EventSort, SecurityEventSummary


class CQQLSearchRequest(StrictModel):
    query: str = Field(min_length=1, max_length=2_000)
    start_time: datetime
    end_time: datetime
    sort: EventSort = "newest"
    limit: int = Field(default=50, ge=1, le=100)
    cursor: str | None = Field(default=None, min_length=1, max_length=2_048)

    @field_validator("query")
    @classmethod
    def query_not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("query must not be blank")
        return value

    @model_validator(mode="after")
    def bounded_time_range(self) -> "CQQLSearchRequest":
        for value in (self.start_time, self.end_time):
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError("CQQL timestamps must include a UTC offset")
        if self.start_time > self.end_time:
            raise ValueError("start_time must not exceed end_time")
        if self.end_time - self.start_time > timedelta(days=31):
            raise ValueError("CQQL time range must not exceed 31 days")
        return self


class CQQLSearchPage(StrictModel):
    limit: int = Field(ge=1, le=100)
    next_cursor: str | None = None
    total: None = None
    count_mode: Literal["UNKNOWN"] = "UNKNOWN"
    sort: EventSort


class CQQLSearchMetadata(StrictModel):
    version: Literal["cqql-v1"] = "cqql-v1"
    execution_ms: float = Field(ge=0)
    query_status: Literal["COMPLETE"] = "COMPLETE"
    warnings: list[str] = Field(default_factory=list)
    truncated: bool
    data_freshness: datetime | None = None
    clause_count: int = Field(ge=1, le=32)
    ast_depth: int = Field(ge=1, le=8)
    fts_used: bool
    cost_class: Literal["LOW", "MODERATE", "HIGH"]
    plan_class: Literal[
        "INDEX_FRIENDLY", "BOOLEAN_COMPLEX", "FTS_SELECTIVITY_UNKNOWN",
        "RESOURCE_LIMITED", "UNKNOWN_COST",
    ]
    planner_strategy: Literal["DEFAULT", "TIME_ORDERED_OR", "TIME_ORDERED_BOOLEAN"]
    diagnostic_reasons: list[Literal[
        "INDEXED_EQUALITY", "RANGE_COMPARISON", "BOOLEAN_OR", "NEGATION_SCAN",
        "DERIVED_FIELD", "UNINDEXED_FIELD", "FTS_CANDIDATE_MATERIALIZATION",
        "TIME_ORDERED_OR", "TIME_ORDERED_BOOLEAN",
    ]]


class CQQLSearchResponse(StrictModel):
    items: list[SecurityEventSummary]
    page: CQQLSearchPage
    metadata: CQQLSearchMetadata


class CQQLFieldDescriptor(StrictModel):
    name: str
    data_type: Literal["string", "integer", "ip", "mitre", "text", "timestamp"]
    operators: list[str]
    indexed: bool
    sensitivity: Literal["standard", "identity", "network", "evidence"]
    source: str
    derived: bool
    searchable: bool


class CQQLCatalogLimits(StrictModel):
    maximum_query_length: int
    maximum_tokens: int
    maximum_ast_depth: int
    maximum_boolean_clauses: int
    maximum_page_size: int
    maximum_time_range_days: int
    execution_deadline_ms: int
    maximum_concurrent_queries: int


class CQQLFieldCatalogResponse(StrictModel):
    version: Literal["cqql-v1"] = "cqql-v1"
    fields: list[CQQLFieldDescriptor]
    limits: CQQLCatalogLimits


CQQLGroupField = Literal[
    "event.provider",
    "host.name",
    "source.ip",
    "event.severity",
    "event.code",
    "event.category",
    "event.source_type",
    "event.outcome",
    "rule.id",
]


class CQQLAnalyticsRequest(StrictModel):
    query: str = Field(min_length=1, max_length=2_000)
    start_time: datetime
    end_time: datetime
    group_by: list[CQQLGroupField] = Field(default_factory=list, max_length=3)
    top_n: int = Field(default=10, ge=1, le=20)
    interval: Literal["hour", "day"] = "hour"

    @field_validator("query")
    @classmethod
    def analytics_query_not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("query must not be blank")
        return value

    @field_validator("group_by")
    @classmethod
    def unique_groups(cls, value: list[CQQLGroupField]) -> list[CQQLGroupField]:
        if len(set(value)) != len(value):
            raise ValueError("group_by fields must be unique")
        return value

    @model_validator(mode="after")
    def bounded_analytics_range(self) -> "CQQLAnalyticsRequest":
        for value in (self.start_time, self.end_time):
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError("CQQL timestamps must include a UTC offset")
        if self.start_time > self.end_time:
            raise ValueError("start_time must not exceed end_time")
        duration = self.end_time - self.start_time
        if duration > timedelta(days=31):
            raise ValueError("CQQL analytics range must not exceed 31 days")
        if self.interval == "hour" and duration > timedelta(days=7):
            raise ValueError("hour interval is limited to seven days; use day")
        return self


class CQQLNamedBucket(StrictModel):
    name: str
    count: int = Field(ge=0)


class CQQLGroupResult(StrictModel):
    field: CQQLGroupField
    buckets: list[CQQLNamedBucket]
    truncated: bool


class CQQLTimeBucket(StrictModel):
    timestamp: datetime
    count: int = Field(ge=0)


class CQQLAnalyticsResponse(StrictModel):
    version: Literal["cqql-v1"] = "cqql-v1"
    query_status: Literal["COMPLETE"] = "COMPLETE"
    execution_ms: float = Field(ge=0)
    completeness: Literal["EXACT_WITHIN_BOUNDED_RANGE"] = "EXACT_WITHIN_BOUNDED_RANGE"
    sparse_time_series: Literal[True] = True
    matching_events: int = Field(ge=0)
    groups: list[CQQLGroupResult]
    time_series: list[CQQLTimeBucket]
    clause_count: int = Field(ge=1, le=32)
    fts_used: bool


CQQLExportField = Literal[
    "timestamp",
    "event_id",
    "event_code",
    "severity",
    "source_type",
    "hostname",
    "source_ip",
    "destination_ip",
    "username",
    "rule_id",
    "event_category",
    "outcome",
    "message",
]


class CQQLExportRequest(StrictModel):
    query: str = Field(min_length=1, max_length=2_000)
    start_time: datetime
    end_time: datetime
    sort: EventSort = "newest"
    limit: int = Field(default=1_000, ge=1, le=1_000)
    fields: list[CQQLExportField] = Field(
        default_factory=lambda: [
            "timestamp",
            "event_id",
            "event_code",
            "severity",
            "source_type",
            "hostname",
            "source_ip",
            "rule_id",
        ],
        min_length=1,
        max_length=13,
    )

    @field_validator("query")
    @classmethod
    def export_query_not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("query must not be blank")
        return value

    @field_validator("fields")
    @classmethod
    def unique_export_fields(cls, value: list[CQQLExportField]) -> list[CQQLExportField]:
        if len(value) != len(set(value)):
            raise ValueError("export fields must be unique")
        return value

    @model_validator(mode="after")
    def bounded_export_range(self) -> "CQQLExportRequest":
        for value in (self.start_time, self.end_time):
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError("CQQL timestamps must include a UTC offset")
        if self.start_time > self.end_time:
            raise ValueError("start_time must not exceed end_time")
        if self.end_time - self.start_time > timedelta(days=31):
            raise ValueError("CQQL export range must not exceed 31 days")
        return self
