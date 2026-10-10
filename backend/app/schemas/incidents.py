"""Typed contracts for deterministic incident management."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Annotated, Any

from pydantic import Field, field_validator

from app.schemas.alerts import StrictModel


class IncidentSeverity(str, Enum):
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IncidentStatus(str, Enum):
    NEW = "NEW"
    TRIAGED = "TRIAGED"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class IncidentEventType(str, Enum):
    CREATED = "CREATED"
    STATUS_CHANGED = "STATUS_CHANGED"
    ALERT_LINKED = "ALERT_LINKED"
    NOTE_ADDED = "NOTE_ADDED"
    ASSIGNMENT_CHANGED = "ASSIGNMENT_CHANGED"


class CorrelationConfidence(str, Enum):
    EXACT_MATCH = "EXACT_MATCH"
    STRONG_MATCH = "STRONG_MATCH"


AlertIdentifier = Annotated[str, Field(min_length=1, max_length=255)]


class IncidentCreate(StrictModel):
    title: str = Field(min_length=1, max_length=255)
    description: str = Field(default="", max_length=4096)
    severity: IncidentSeverity
    assigned_to: str | None = Field(default=None, min_length=1, max_length=128)
    alert_ids: list[AlertIdentifier] = Field(default_factory=list, max_length=100)

    @field_validator("alert_ids")
    @classmethod
    def alert_ids_must_be_unique(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("alert_ids must not contain duplicates")
        return value


class IncidentStatusUpdate(StrictModel):
    status: IncidentStatus


class IncidentAlertLink(StrictModel):
    alert_id: AlertIdentifier


class IncidentNoteCreate(StrictModel):
    body: str = Field(min_length=1, max_length=4096)


class IncidentAssignmentUpdate(StrictModel):
    assigned_to: str | None = Field(default=None, min_length=1, max_length=128)


class IncidentSummary(StrictModel):
    incident_id: str
    title: str
    description: str
    severity: IncidentSeverity
    status: IncidentStatus
    assigned_to: str | None = None
    created_at: datetime
    updated_at: datetime
    alert_count: int = Field(ge=0)
    auto_correlated: bool = False
    correlation_rule: str | None = None
    classification: str | None = None


class IncidentNote(StrictModel):
    note_id: str
    body: str
    author: str
    author_id: str | None = None
    created_at: datetime


class IncidentHistoryEvent(StrictModel):
    event_id: str
    event_type: IncidentEventType
    actor: str
    actor_id: str | None = None
    occurred_at: datetime
    details: dict[str, Any]


class IncidentCorrelation(StrictModel):
    correlation_rule: str
    classification: str
    confidence: CorrelationConfidence
    source_identity: str
    target_identity: str
    explanation: str
    first_seen: datetime
    last_seen: datetime
    related_alert_count: int = Field(ge=2)


class IncidentTimelineAlert(StrictModel):
    alert_id: str
    occurred_at: datetime
    rule_id: str
    rule_level: int = Field(ge=0, le=16)
    rule_description: str
    agent_id: str
    agent_name: str
    source_ip: str | None = None
    destination_ip: str | None = None
    mitre_ids: list[str] = Field(default_factory=list)


class IncidentDetail(IncidentSummary):
    alert_ids: list[str]
    notes: list[IncidentNote]
    history: list[IncidentHistoryEvent]
    correlation: IncidentCorrelation | None = None
    timeline: list[IncidentTimelineAlert] = Field(default_factory=list)


class IncidentPage(StrictModel):
    limit: int = Field(ge=1, le=100)
    next_cursor: str | None = None
    total: int = Field(ge=0)


class IncidentListResponse(StrictModel):
    items: list[IncidentSummary]
    page: IncidentPage
