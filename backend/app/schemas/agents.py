"""Contracts for authoritative and telemetry-evidence agent inventory."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field, field_validator

from app.schemas.alerts import StrictModel


AgentConnectionStatus = Literal["ONLINE", "DISCONNECTED", "NEVER_CONNECTED", "UNKNOWN"]
AgentEnrollmentStatus = Literal["ENROLLED", "NEVER_ENROLLED", "UNKNOWN"]
AgentStatusAuthority = Literal["WAZUH_API", "TELEMETRY_EVIDENCE"]
FreshnessState = Literal["ACTIVE", "STALE", "NO_DATA"]


class AgentTelemetrySource(StrictModel):
    source_type: str = Field(min_length=1, max_length=64)
    ingestion_source: str = Field(min_length=1, max_length=128)
    last_event_at: datetime
    last_ingested_at: datetime
    event_count: int = Field(ge=0)
    freshness: FreshnessState


class AgentSummary(StrictModel):
    agent_key: str = Field(min_length=16, max_length=96)
    agent_id: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=255)
    operating_system: str | None = Field(default=None, max_length=255)
    os_platform: str | None = Field(default=None, max_length=128)
    os_version: str | None = Field(default=None, max_length=128)
    agent_version: str | None = Field(default=None, max_length=128)
    manager: str | None = Field(default=None, max_length=255)
    ip_address: str | None = Field(default=None, max_length=64)
    groups: list[str] = Field(default_factory=list, max_length=128)
    service_status: Literal["RUNNING", "STOPPED", "UNKNOWN"] = "UNKNOWN"
    enrollment_status: AgentEnrollmentStatus
    connection_status: AgentConnectionStatus
    status_authority: AgentStatusAuthority
    last_keepalive: datetime | None = None
    disconnected_at: datetime | None = None
    enrolled_at: datetime | None = None
    last_security_event: datetime | None = None
    data_freshness: FreshnessState
    pipeline_health: Literal["ACTIVE", "STALE", "EMPTY"]
    observed_at: datetime
    cache_expires_at: datetime | None = None
    cache_stale: bool
    observed_only: bool

    @field_validator(
        "last_keepalive",
        "disconnected_at",
        "enrolled_at",
        "last_security_event",
        "observed_at",
        "cache_expires_at",
    )
    @classmethod
    def timestamps_have_offsets(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("agent timestamps must include a UTC offset")
        return value


class AgentDetail(AgentSummary):
    telemetry_sources: list[AgentTelemetrySource]
    recent_event_ids: list[str] = Field(max_length=25)
    related_alert_ids: list[str] = Field(max_length=25)
    related_incident_ids: list[str] = Field(max_length=25)
    troubleshooting: list[str] = Field(max_length=16)


class AgentHealthRecord(StrictModel):
    history_id: str
    connection_status: AgentConnectionStatus
    previous_status: AgentConnectionStatus | None = None
    authority: Literal["WAZUH_API"]
    observed_at: datetime
    details: dict[str, object]


class AgentHealthResponse(StrictModel):
    agent_key: str
    status_authority: AgentStatusAuthority
    items: list[AgentHealthRecord]


class AgentPage(StrictModel):
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)
    total: int = Field(ge=0)


class AgentListResponse(StrictModel):
    items: list[AgentSummary]
    page: AgentPage
    authoritative_inventory: bool
    partial: bool
    observation_timestamp: datetime
    cache_age_seconds: float | None = Field(default=None, ge=0)
    message: str = Field(min_length=1, max_length=320)


class WazuhIntegrationStatus(StrictModel):
    state: Literal["AVAILABLE", "UNAVAILABLE"]
    configured: bool
    authority: Literal["WAZUH_API"] = "WAZUH_API"
    reason: str = Field(min_length=1, max_length=320)
    manager_identity: str | None = Field(default=None, max_length=255)
    manager_version: str | None = Field(default=None, max_length=128)
    manager_health: Literal["HEALTHY", "DEGRADED", "UNKNOWN"] | None = None
    agent_count: int | None = Field(default=None, ge=0)
    rejected_agent_count: int = Field(default=0, ge=0)
    observed_at: datetime
    cache_expires_at: datetime
    cache_age_seconds: float = Field(ge=0)
    cache_stale: bool
    tls_verification: Literal["SYSTEM_TRUST", "CUSTOM_CA"]
    connectivity_scope: Literal["HTTPS_LOOPBACK"] = "HTTPS_LOOPBACK"
    read_only: Literal[True] = True
