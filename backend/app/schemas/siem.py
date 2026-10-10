"""Read-only inventory, rule-catalog, and reporting contracts for SIEM v0.1."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field

from app.schemas.alerts import StrictModel


class LogSourceSummary(StrictModel):
    source_name: str
    source_type: str
    hostname: str | None = None
    agent_id: str | None = None
    agent_name: str | None = None
    last_event_at: datetime
    last_ingested_at: datetime
    ingestion_lag_seconds: float = Field(ge=0)
    event_count: int = Field(ge=0)
    source_health: Literal["ACTIVE", "STALE"]
    agent_status: Literal["UNKNOWN"] = "UNKNOWN"
    collection_method: str
    pipeline_health: Literal["ACTIVE", "STALE", "EMPTY"]
    pipeline_evidence: Literal["PERSISTED_DELIVERY_ACTIVITY"] = "PERSISTED_DELIVERY_ACTIVITY"
    queue_depth: int | None = Field(default=None, ge=0)
    archive_cursor_lag_bytes: int | None = Field(default=None, ge=0)
    data_availability: Literal["AVAILABLE", "NO_DATA"]
    last_error: str | None = None


class HostSummary(StrictModel):
    hostname: str
    agent_id: str | None = None
    agent_name: str | None = None
    platform: Literal["WINDOWS", "LINUX", "UNKNOWN"]
    agent_status: Literal["UNKNOWN"] = "UNKNOWN"
    source_health: Literal["ACTIVE", "STALE"]
    last_seen: datetime
    alert_count: int = Field(ge=0)
    event_count: int = Field(ge=0)
    recent_detections: list[str] = Field(default_factory=list)


class DetectionRuleSummary(StrictModel):
    rule_id: str
    name: str
    description: str
    severity: int | None = Field(default=None, ge=0, le=16)
    source_type: str
    mitre_ids: list[str] = Field(default_factory=list)
    last_triggered: datetime | None = None
    alert_count: int = Field(ge=0)
    correlation_relationship: str | None = None
    owner: str | None = None
    documentation: str | None = None
    rule_version: str | None = None
    version_authority: Literal["AUTHORITATIVE", "UNAVAILABLE"] = "UNAVAILABLE"
    enabled_state: Literal["ENABLED", "DISABLED", "UNKNOWN"] = "UNKNOWN"
    enabled_evidence: Literal[
        "APPLICATION_SETTING", "WAZUH_API_UNAVAILABLE", "OBSERVED_ALERT_ONLY"
    ] = "WAZUH_API_UNAVAILABLE"
    tested_state: Literal["TESTED", "NOT_RECORDED"] = "NOT_RECORDED"
    management_mode: Literal["READ_ONLY_WAZUH", "LOCAL_CORRELATION"] = "READ_ONLY_WAZUH"
    editable: Literal[False] = False


class ReportCount(StrictModel):
    name: str
    count: int = Field(ge=0)


class ReportFilters(StrictModel):
    severity_min: int | None = Field(default=None, ge=0, le=16)
    severity_max: int | None = Field(default=None, ge=0, le=16)
    host: str | None = Field(default=None, max_length=255)
    rule_id: str | None = Field(default=None, max_length=128)


class SecurityActivityReport(StrictModel):
    start_time: datetime
    end_time: datetime
    generated_at: datetime
    filters: ReportFilters
    total_events: int = Field(ge=0)
    total_alerts: int = Field(ge=0)
    total_incidents: int = Field(ge=0)
    event_sources: list[ReportCount]
    alert_severities: list[ReportCount]
    top_rules: list[ReportCount]
    host_activity: list[ReportCount]
    authentication_failures: int = Field(ge=0)
    file_integrity_events: int = Field(ge=0)
