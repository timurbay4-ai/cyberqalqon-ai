"""Typed contracts for normalized alerts and ingestion responses."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class Agent(StrictModel):
    id: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=255)
    ip: IPvAnyAddress | None = None


class Rule(StrictModel):
    id: str = Field(min_length=1, max_length=128)
    level: int = Field(ge=0, le=16)
    description: str = Field(min_length=1, max_length=4096)
    groups: list[str] = Field(default_factory=list)


class MitreContext(StrictModel):
    ids: list[str] = Field(default_factory=list)
    tactics: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)


class NetworkEndpoint(StrictModel):
    ip: IPvAnyAddress | None = None
    port: int | None = Field(default=None, ge=1, le=65535)


class WindowsEventContext(StrictModel):
    event_id: str = Field(min_length=1, max_length=64)
    channel: str = Field(min_length=1, max_length=512)
    provider: str | None = Field(default=None, max_length=512)
    computer: str | None = Field(default=None, max_length=512)


class NormalizedAlert(StrictModel):
    alert_id: str = Field(min_length=1, max_length=255)
    timestamp: datetime
    agent: Agent
    rule: Rule
    mitre: MitreContext = Field(default_factory=MitreContext)
    source: NetworkEndpoint | None = None
    destination: NetworkEndpoint | None = None
    user: str | None = Field(default=None, max_length=512)
    location: str | None = Field(default=None, max_length=1024)
    decoder_name: str | None = Field(default=None, max_length=255)
    windows: WindowsEventContext | None = None

    @field_validator("timestamp")
    @classmethod
    def timestamp_must_include_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must include a UTC offset")
        return value


class AlertIngestResponse(StrictModel):
    status: Literal["created", "duplicate"]
    duplicate: bool
    ingested_at: datetime
    alert: NormalizedAlert


class AlertPage(StrictModel):
    limit: int = Field(ge=1, le=100)
    next_cursor: str | None = None
    total: int = Field(ge=0)


class AlertListResponse(StrictModel):
    items: list[NormalizedAlert]
    page: AlertPage


class ErrorBody(StrictModel):
    code: str
    message: str
    field: str | None = None


class ErrorResponse(StrictModel):
    detail: ErrorBody


JsonObject = dict[str, Any]
