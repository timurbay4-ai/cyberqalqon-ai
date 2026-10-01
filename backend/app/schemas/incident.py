"""Incident API response schemas."""

from datetime import datetime
from typing import Any
from pydantic import BaseModel, ConfigDict
from app.schemas.review import ReviewResponse


class IncidentResponse(BaseModel):
    id: str
    alert_id: str | None
    event_timestamp: datetime | None
    created_at: datetime
    updated_at: datetime
    agent_id: str | None
    agent_name: str | None
    agent_ip: str | None
    rule_id: str | None
    rule_level: int | None
    rule_description: str | None
    rule_metadata: dict[str, Any]
    mitre_ids: list[str]
    mitre_tactics: list[str]
    mitre_techniques: list[str]
    source_ip: str | None
    destination_ip: str | None
    user: str | None
    source_user: str | None
    destination_user: str | None
    location: str | None
    decoder: dict[str, Any] | None
    full_log: str | None
    raw_event: dict[str, Any]
    severity: str
    priority_score: int
    repetition_count: int
    asset_importance: str
    ai_status: str
    review_status: str
    reviews: list[ReviewResponse]
    model_config = ConfigDict(from_attributes=True)


class IncidentListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[IncidentResponse]


class SeverityCounts(BaseModel):
    low: int
    medium: int
    high: int
    critical: int


class ReviewStatusCounts(BaseModel):
    needs_review: int
    confirmed: int
    false_positive: int


class IncidentStatsResponse(BaseModel):
    total: int
    severity: SeverityCounts
    review_status: ReviewStatusCounts
