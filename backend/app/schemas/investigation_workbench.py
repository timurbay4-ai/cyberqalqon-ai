"""Read-only contracts for the bounded M12 analyst investigation workbench."""

from __future__ import annotations

from datetime import datetime, timedelta
import re
from typing import Any, Literal

from pydantic import Field, field_serializer, field_validator, model_validator

from app.schemas.alerts import StrictModel
from app.schemas.detection_engineering import (
    AdvancedDetectionFinding,
    AdvancedDetectionRule,
)
from app.schemas.events import SecurityEventDetail, SecurityEventSummary
from app.schemas.shadow_history import FindingDetail


WorkbenchTargetType = Literal[
    "EVENT", "ALERT", "INCIDENT", "CASE", "CORRELATION_GROUP", "M11_FINDING",
    "SHADOW_FINDING", "DURABLE_SHADOW_FINDING", "ENTITY"
]
InvestigationEntityType = Literal[
    "IPV4", "IPV6", "HOSTNAME", "USERNAME", "AGENT_ID", "RULE_ID",
    "PROCESS_NAME", "PROCESS_ID", "FILE_HASH", "DOMAIN",
]


class WorkbenchRequest(StrictModel):
    target_type: WorkbenchTargetType
    target_id: str | None = Field(default=None, min_length=1, max_length=255)
    entity_type: InvestigationEntityType | None = None
    entity_value: str | None = Field(default=None, min_length=1, max_length=2048)
    rule_id: str | None = Field(default=None, pattern=r"^DET-00[1-9]$")
    finding_key: str | None = Field(default=None, pattern=r"^[0-9A-Fa-f]{64}$")
    shadow_revision: int | None = Field(default=None, ge=1, le=8192)
    start_time: datetime | None = None
    end_time: datetime | None = None
    relative_minutes: int | None = Field(default=1440, ge=15, le=44_640)
    related_limit: int = Field(default=25, ge=1, le=100)
    related_cursor: str | None = Field(default=None, min_length=1, max_length=2048)
    timeline_limit: int = Field(default=100, ge=1, le=200)
    sort: Literal["oldest", "newest"] = "oldest"
    max_execution_ms: int = Field(default=1000, ge=50, le=5000)

    @field_validator("target_id", "entity_value")
    @classmethod
    def no_blank_values(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("value must not be blank")
        return normalized

    @model_validator(mode="after")
    def validate_target(self) -> "WorkbenchRequest":
        if self.shadow_revision is not None and self.target_type != "DURABLE_SHADOW_FINDING":
            raise ValueError("shadow_revision requires a durable finding target")
        if self.target_type == "DURABLE_SHADOW_FINDING" and (
            self.target_id is None or not re.fullmatch(r'DSF-[a-f0-9]{64}', self.target_id)
        ):
            raise ValueError("invalid durable finding identity")
        if self.target_type == "ENTITY":
            if self.entity_type is None or self.entity_value is None:
                raise ValueError("entity_type and entity_value are required for ENTITY targets")
        elif self.target_type == "M11_FINDING":
            if self.rule_id is None or self.finding_key is None:
                raise ValueError("rule_id and finding_key are required for M11_FINDING targets")
        elif self.target_id is None:
            raise ValueError("target_id is required for this target type")
        if self.relative_minutes is not None and (self.start_time is not None or self.end_time is not None):
            raise ValueError("relative_minutes cannot be combined with explicit timestamps")
        if (self.start_time is None) != (self.end_time is None):
            raise ValueError("start_time and end_time must be supplied together")
        if self.related_cursor is not None and (
            self.start_time is None or self.end_time is None or self.relative_minutes is not None
        ):
            raise ValueError(
                "related_cursor requires explicit start_time and end_time with relative_minutes disabled"
            )
        if self.start_time is not None and self.end_time is not None:
            if self.start_time.tzinfo is None or self.end_time.tzinfo is None:
                raise ValueError("timestamps must include a UTC offset")
            if self.start_time > self.end_time:
                raise ValueError("start_time must not exceed end_time")
            if self.end_time - self.start_time > timedelta(days=31):
                raise ValueError("investigation range must not exceed 31 days")
        return self


class InvestigationEntity(StrictModel):
    entity_type: InvestigationEntityType
    value: str = Field(min_length=1, max_length=2048)
    label: str = Field(min_length=1, max_length=80)
    sensitive: bool
    pivot_supported: bool
    evidence_field: str = Field(min_length=1, max_length=128)


class RelatedInvestigationEvent(StrictModel):
    event: SecurityEventSummary
    relationship_types: list[str] = Field(min_length=1, max_length=12)


class InvestigationLink(StrictModel):
    target_type: Literal["ALERT", "INCIDENT", "CASE", "CORRELATION_GROUP"]
    target_id: str = Field(min_length=1, max_length=255)
    title: str = Field(min_length=1, max_length=320)
    status: str | None = Field(default=None, max_length=64)
    severity: str | None = Field(default=None, max_length=32)


class InvestigationTimelineItem(StrictModel):
    item_id: str = Field(min_length=1, max_length=255)
    item_type: Literal[
        "SECURITY_EVENT", "ALERT", "DETECTION_FINDING", "INCIDENT_ACTIVITY",
        "ANALYST_NOTE", "CASE_ACTIVITY", "CASE_COMMENT", "EVIDENCE_ACTION",
    ]
    timestamp: datetime
    timestamp_kind: Literal["EVENT_TIME", "ANALYST_ACTION_TIME"]
    timestamp_status: Literal["NORMAL", "FUTURE"]
    title: str = Field(min_length=1, max_length=512)
    source_id: str = Field(min_length=1, max_length=255)
    severity: int | None = Field(default=None, ge=0, le=16)
    actor_display: str | None = Field(default=None, max_length=256)
    relationship_types: list[str] = Field(default_factory=list, max_length=12)
    details: dict[str, Any] = Field(default_factory=dict)


class InvestigationIOCMatch(StrictModel):
    indicator_id: str
    indicator_type: Literal["IPV4", "IPV6", "DOMAIN", "FILE_HASH"]
    value: str
    source: str
    confidence: int = Field(ge=0, le=100)
    expires_at: datetime | None = None
    evidence_field: str
    caveat: Literal["IOC_MATCH_IS_NOT_PROOF_OF_COMPROMISE"] = "IOC_MATCH_IS_NOT_PROOF_OF_COMPROMISE"


class InvestigationCorrelationGroup(StrictModel):
    group_id: str
    correlation_rule: str
    classification: str
    confidence: str
    grouping_keys: dict[str, str]
    first_seen: datetime
    last_seen: datetime
    evidence_count: int = Field(ge=2)
    explanation: str
    incident_id: str


class InvestigationDetectionContext(StrictModel):
    rule: AdvancedDetectionRule
    finding: AdvancedDetectionFinding
    evaluated_event_count: int = Field(ge=0, le=5000)
    execution_budget_ms: int = Field(ge=50, le=5000)
    source_kind: Literal["HISTORICAL_DRY_RUN", "SHADOW"] = "HISTORICAL_DRY_RUN"
    shadow_run_id: str | None = None
    side_effects: Literal[False] = False


class InvestigationSummary(StrictModel):
    observations: list[str] = Field(min_length=1, max_length=20)
    interpretations: list[str] = Field(max_length=10)
    missing_fields: list[str] = Field(max_length=30)


class InvestigationQueryMetadata(StrictModel):
    start_time: datetime
    end_time: datetime
    related_limit: int = Field(ge=1, le=100)
    related_cursor: str | None = Field(default=None, max_length=2048)
    related_next_cursor: str | None = Field(default=None, max_length=2048)
    timeline_limit: int = Field(ge=1, le=200)
    sort: Literal["oldest", "newest"]
    execution_ms: float = Field(ge=0)
    related_truncated: bool
    schema_version: int = Field(ge=0)
    unavailable_relationships: list[str]


class InvestigationWorkbench(StrictModel):
    target_type: WorkbenchTargetType
    target_label: str
    primary_event: SecurityEventDetail
    summary: InvestigationSummary
    entities: list[InvestigationEntity]
    related_events: list[RelatedInvestigationEvent]
    links: list[InvestigationLink]
    timeline: list[InvestigationTimelineItem]
    ioc_matches: list[InvestigationIOCMatch]
    correlation_groups: list[InvestigationCorrelationGroup]
    detection_context: InvestigationDetectionContext | None = None
    durable_shadow_context: FindingDetail | None = None
    query: InvestigationQueryMetadata

    @field_serializer('durable_shadow_context', when_used='json')
    def preserve_durable_snapshot(self, value):
        # The workbench omits unrelated nullable fields. Immutable CDRC snapshots
        # must retain their full canonical definition, including explicit nulls.
        return value.model_dump(mode='json') if value is not None else None
