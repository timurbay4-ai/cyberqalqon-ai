"""Normalized alert schema used inside the backend."""

from datetime import datetime
from typing import Any
from pydantic import BaseModel, ConfigDict, Field


class AgentData(BaseModel):
    id: str | None = None
    name: str | None = None
    ip: str | None = None


class RuleData(BaseModel):
    id: str | None = None
    level: int | None = Field(default=None, ge=0, le=15)
    description: str | None = None


class MitreData(BaseModel):
    ids: list[str] = Field(default_factory=list)
    tactics: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)


class EndpointData(BaseModel):
    ip: str | None = None


class NormalizedAlert(BaseModel):
    model_config = ConfigDict(extra="forbid")
    alert_id: str | None = None
    timestamp: datetime | None = None
    agent: AgentData = Field(default_factory=AgentData)
    rule: RuleData = Field(default_factory=RuleData)
    mitre: MitreData = Field(default_factory=MitreData)
    source: EndpointData = Field(default_factory=EndpointData)
    destination: EndpointData = Field(default_factory=EndpointData)
    user: str | None = None
    source_user: str | None = None
    destination_user: str | None = None
    location: str | None = None
    decoder: dict[str, Any] | None = None
    full_log: str | None = None
    rule_metadata: dict[str, Any] = Field(default_factory=dict)
    raw_event: dict[str, Any]
