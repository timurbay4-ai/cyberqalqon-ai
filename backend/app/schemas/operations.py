"""Typed contracts for bounded, evidence-backed operational telemetry."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import Field, field_validator

from app.schemas.alerts import StrictModel


OperationalState = Literal["HEALTHY", "DEGRADED", "UNAVAILABLE", "UNKNOWN"]
OperationalAuthority = Literal[
    "WAZUH_API",
    "OS_SERVICE_MANAGER",
    "DURABLE_SENDER_STATE",
    "DURABLE_SHIPPER_STATE",
    "APPLICATION_DATABASE",
]
OperationalKind = Literal[
    "manager", "wazuh_api", "sender", "event_shipper", "windows_agent", "database"
]


class ComponentObservation(StrictModel):
    component_key: str = Field(min_length=1, max_length=128)
    component_kind: OperationalKind
    state: OperationalState
    authority: OperationalAuthority
    summary: str = Field(min_length=1, max_length=320)
    metrics: dict[str, Any] = Field(default_factory=dict)
    last_error: str | None = Field(default=None, max_length=512)
    observed_at: datetime

    @field_validator("observed_at")
    @classmethod
    def timestamp_has_offset(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("observed_at must include a UTC offset")
        return value


class OperationalSnapshot(StrictModel):
    version: Literal[1] = 1
    collected_at: datetime
    components: list[ComponentObservation] = Field(max_length=32)

    @field_validator("collected_at")
    @classmethod
    def collected_at_has_offset(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("collected_at must include a UTC offset")
        return value


class OperationalComponent(ComponentObservation):
    first_observed_at: datetime
    updated_at: datetime
    version: int = Field(ge=1)


class OperationalEvent(StrictModel):
    event_id: str
    component_key: str
    event_type: Literal["ISSUE", "RECOVERY", "STATUS_CHANGE"]
    severity: Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    previous_state: OperationalState | None = None
    current_state: OperationalState
    authority: OperationalAuthority
    summary: str
    details: dict[str, Any] = Field(default_factory=dict)
    occurred_at: datetime


class DataQualitySummary(StrictModel):
    total_events: int = Field(ge=0)
    raw_evidence_records: int = Field(ge=0)
    missing_hostname: int = Field(ge=0)
    missing_username: int = Field(ge=0)
    missing_rule_id: int = Field(ge=0)
    duplicate_events: int | None = Field(default=None, ge=0)
    malformed_events: int | None = Field(default=None, ge=0)
    oversized_events: int | None = Field(default=None, ge=0)
    delivery_rejected: int | None = Field(default=None, ge=0)
    evidence: Literal["APPLICATION_DATABASE_AND_DURABLE_SHIPPER_STATE"] = (
        "APPLICATION_DATABASE_AND_DURABLE_SHIPPER_STATE"
    )


class WazuhInventoryStatus(StrictModel):
    state: Literal["AVAILABLE", "UNAVAILABLE"]
    authority: Literal["WAZUH_API"] = "WAZUH_API"
    reason: str = Field(max_length=320)
    manager_identity: str | None = Field(default=None, max_length=255)
    agent_count: int | None = Field(default=None, ge=0)


class OperationalOverview(StrictModel):
    generated_at: datetime
    snapshot_collected_at: datetime | None = None
    snapshot_age_seconds: float | None = Field(default=None, ge=0)
    components: list[OperationalComponent]
    recent_events: list[OperationalEvent]
    data_quality: DataQualitySummary
    wazuh_inventory: WazuhInventoryStatus
