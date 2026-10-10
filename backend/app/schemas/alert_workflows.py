"""Contracts for durable alert triage and bounded bulk operations."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Annotated, Any

from pydantic import Field, field_validator, model_validator

from app.schemas.alerts import NormalizedAlert, StrictModel


class AlertWorkflowStatus(str, Enum):
    NEW = "NEW"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class AlertWorkflowEventType(str, Enum):
    STATUS_CHANGED = "STATUS_CHANGED"
    ASSIGNMENT_CHANGED = "ASSIGNMENT_CHANGED"
    NOTE_ADDED = "NOTE_ADDED"


class AlertWorkflowSort(str, Enum):
    TIME_DESC = "time_desc"
    TIME_ASC = "time_asc"
    SEVERITY_DESC = "severity_desc"
    SEVERITY_ASC = "severity_asc"
    ACTIVITY_DESC = "activity_desc"


class AlertAssignee(StrictModel):
    analyst_id: str
    username: str
    display_name: str


class AlertWorkflowSummary(StrictModel):
    alert: NormalizedAlert
    status: AlertWorkflowStatus
    assignee: AlertAssignee | None = None
    version: int = Field(ge=1)
    created_at: datetime
    updated_at: datetime
    last_activity_at: datetime
    note_count: int = Field(ge=0)


class AlertWorkflowNote(StrictModel):
    note_id: str
    body: str
    author_id: str | None = None
    author_display: str
    created_at: datetime


class AlertWorkflowHistoryEvent(StrictModel):
    event_id: str
    event_type: AlertWorkflowEventType
    actor_id: str | None = None
    actor_display: str
    occurred_at: datetime
    details: dict[str, Any]
    version: int = Field(ge=2)


class AlertWorkflowDetail(AlertWorkflowSummary):
    notes: list[AlertWorkflowNote]
    history: list[AlertWorkflowHistoryEvent]


class AlertWorkflowCounts(StrictModel):
    total: int = Field(ge=0)
    actionable: int = Field(ge=0)
    unassigned: int = Field(ge=0)
    by_status: dict[AlertWorkflowStatus, int]


class AlertWorkflowPage(StrictModel):
    limit: int = Field(ge=1, le=100)
    next_cursor: str | None = None
    total: int = Field(ge=0)
    sort: AlertWorkflowSort


class AlertWorkflowListResponse(StrictModel):
    items: list[AlertWorkflowSummary]
    page: AlertWorkflowPage
    counts: AlertWorkflowCounts


class AlertStatusUpdate(StrictModel):
    status: AlertWorkflowStatus
    expected_version: int = Field(ge=1)


class AlertAssignmentUpdate(StrictModel):
    assigned_to: str | None = Field(default=None, min_length=1, max_length=64)
    expected_version: int = Field(ge=1)


class AlertNoteCreate(StrictModel):
    body: str = Field(min_length=1, max_length=4096)
    expected_version: int = Field(ge=1)

    @field_validator("body")
    @classmethod
    def note_must_not_be_blank(cls, value: str) -> str:
        body = value.strip()
        if not body:
            raise ValueError("body must not be blank")
        return body


class AlertBulkAction(str, Enum):
    ACKNOWLEDGE = "ACKNOWLEDGE"
    SET_STATUS = "SET_STATUS"
    ASSIGN = "ASSIGN"


class AlertBulkItem(StrictModel):
    alert_id: Annotated[str, Field(min_length=1, max_length=255)]
    expected_version: int = Field(ge=1)


class AlertBulkRequest(StrictModel):
    action: AlertBulkAction
    items: list[AlertBulkItem] = Field(min_length=1, max_length=50)
    status: AlertWorkflowStatus | None = None
    assigned_to: str | None = Field(default=None, min_length=1, max_length=64)

    @field_validator("items")
    @classmethod
    def items_must_be_unique(cls, value: list[AlertBulkItem]) -> list[AlertBulkItem]:
        identifiers = [item.alert_id for item in value]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("items must not contain duplicate alert identifiers")
        return value

    @model_validator(mode="after")
    def action_payload_must_match(self) -> "AlertBulkRequest":
        if self.action is AlertBulkAction.SET_STATUS and self.status is None:
            raise ValueError("status is required for SET_STATUS")
        if self.action is not AlertBulkAction.SET_STATUS and self.status is not None:
            raise ValueError("status is only accepted for SET_STATUS")
        if self.action is not AlertBulkAction.ASSIGN and self.assigned_to is not None:
            raise ValueError("assigned_to is only accepted for ASSIGN")
        return self


class AlertBulkResponse(StrictModel):
    action: AlertBulkAction
    selected_count: int = Field(ge=1, le=50)
    updated_count: int = Field(ge=1, le=50)
    items: list[AlertWorkflowSummary]


class AlertBulkFailure(StrictModel):
    alert_id: str
    code: str
    message: str
