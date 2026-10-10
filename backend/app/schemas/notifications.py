"""Per-analyst notification contracts."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import Field

from app.schemas.alerts import StrictModel


class NotificationCategory(str, Enum):
    CRITICAL_ALERT = "CRITICAL_ALERT"
    HIGH_ALERT = "HIGH_ALERT"
    ALERT_ASSIGNED = "ALERT_ASSIGNED"
    INCIDENT_ASSIGNED = "INCIDENT_ASSIGNED"
    OPERATIONAL_ISSUE = "OPERATIONAL_ISSUE"
    OPERATIONAL_RECOVERY = "OPERATIONAL_RECOVERY"
    CASE_ASSIGNED = "CASE_ASSIGNED"
    CASE_HANDOFF = "CASE_HANDOFF"
    CASE_SLA = "CASE_SLA"


class AnalystNotification(StrictModel):
    notification_id: str
    category: NotificationCategory
    title: str
    preview: str
    target_type: Literal["alert", "incident", "operational", "case"]
    target_id: str
    created_at: datetime
    read_at: datetime | None = None


class NotificationListResponse(StrictModel):
    items: list[AnalystNotification]
    unread_count: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)


class NotificationReadAllResponse(StrictModel):
    updated_count: int = Field(ge=0)
    unread_count: Literal[0] = 0
