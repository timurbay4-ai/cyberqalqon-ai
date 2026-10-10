"""Bounded security audit-log contracts."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import Field

from app.schemas.alerts import StrictModel


class SecurityAuditEvent(StrictModel):
    audit_id: str = Field(min_length=1, max_length=64)
    action: str = Field(min_length=1, max_length=100)
    actor_id: str | None = Field(default=None, max_length=64)
    actor_display: str = Field(min_length=1, max_length=256)
    target_type: str = Field(min_length=1, max_length=64)
    target_id: str | None = Field(default=None, max_length=255)
    outcome: Literal["SUCCESS", "DENIED", "FAILURE"]
    occurred_at: datetime
    details: dict[str, Any] = Field(default_factory=dict)


class SecurityAuditPage(StrictModel):
    items: list[SecurityAuditEvent]
    limit: int = Field(ge=1, le=100)
