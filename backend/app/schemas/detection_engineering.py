"""Validated contracts for detection engineering, threat hunting, and local IOCs."""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Literal

from pydantic import Field, field_validator, model_validator

from app.schemas.alerts import StrictModel


MITRE_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$")
DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
HASH_LENGTHS = {32: "MD5", 40: "SHA1", 64: "SHA256"}


class RuleConditionField(str, Enum):
    SOURCE_TYPE = "source_type"
    HOSTNAME = "hostname"
    AGENT_ID = "agent_id"
    AGENT_NAME = "agent_name"
    SOURCE_IP = "source_ip"
    DESTINATION_IP = "destination_ip"
    USERNAME = "username"
    EVENT_CATEGORY = "event_category"
    EVENT_ACTION = "event_action"
    OUTCOME = "outcome"
    RULE_ID = "rule_id"
    EVENT_CODE = "event_code"
    MESSAGE = "message"


class RuleConditionOperator(str, Enum):
    EQUALS = "EQUALS"
    CONTAINS = "CONTAINS"
    STARTS_WITH = "STARTS_WITH"


class RuleCondition(StrictModel):
    field: RuleConditionField
    operator: RuleConditionOperator
    value: str = Field(min_length=1, max_length=512)

    @field_validator("value")
    @classmethod
    def nonblank_value(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("condition value must not be blank")
        return normalized

    @model_validator(mode="after")
    def valid_field_operator(self) -> "RuleCondition":
        if self.field in {RuleConditionField.SOURCE_IP, RuleConditionField.DESTINATION_IP}:
            if self.operator is not RuleConditionOperator.EQUALS:
                raise ValueError("IP conditions support EQUALS only")
            try:
                self.value = str(ipaddress.ip_address(self.value))
            except ValueError as exc:
                raise ValueError("IP condition value is invalid") from exc
        if self.operator in {RuleConditionOperator.CONTAINS, RuleConditionOperator.STARTS_WITH}:
            if self.field not in {
                RuleConditionField.MESSAGE,
                RuleConditionField.HOSTNAME,
                RuleConditionField.AGENT_NAME,
                RuleConditionField.USERNAME,
            }:
                raise ValueError("partial matching is not supported for this field")
            if len(self.value) < 3:
                raise ValueError("partial-match values require at least three characters")
        return self


class RuleDraftStatus(str, Enum):
    DRAFT = "DRAFT"
    VALIDATED = "VALIDATED"
    TESTED = "TESTED"
    READY_FOR_MANUAL_DEPLOYMENT = "READY_FOR_MANUAL_DEPLOYMENT"


class RuleDraftDefinition(StrictModel):
    name: str = Field(min_length=1, max_length=128)
    description: str = Field(min_length=1, max_length=2048)
    severity: int = Field(ge=0, le=16)
    source_type: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_]{0,63}$")
    mitre_ids: list[str] = Field(default_factory=list, max_length=20)
    conditions: list[RuleCondition] = Field(min_length=1, max_length=8)
    documentation: str = Field(default="", max_length=8192)

    @field_validator("name", "description")
    @classmethod
    def nonblank_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("value must not be blank")
        return normalized

    @field_validator("documentation")
    @classmethod
    def trim_documentation(cls, value: str) -> str:
        return value.strip()

    @field_validator("mitre_ids")
    @classmethod
    def valid_mitre_ids(cls, value: list[str]) -> list[str]:
        normalized = [item.strip().upper() for item in value]
        if len(normalized) != len(set(normalized)):
            raise ValueError("MITRE IDs must be unique")
        if any(not MITRE_PATTERN.fullmatch(item) for item in normalized):
            raise ValueError("MITRE IDs must use T#### or T####.###")
        return normalized


class RuleDraftCreate(RuleDraftDefinition):
    change_summary: str = Field(default="Initial draft", min_length=1, max_length=512)


class RuleDraftUpdate(RuleDraftDefinition):
    expected_version: int = Field(ge=1)
    change_summary: str = Field(min_length=1, max_length=512)


class RuleDraft(StrictModel):
    draft_id: str
    name: str
    description: str
    severity: int
    source_type: str
    mitre_ids: list[str]
    conditions: list[RuleCondition]
    documentation: str
    status: RuleDraftStatus
    version: int = Field(ge=1)
    owner_analyst_id: str | None = None
    owner_display: str
    last_tested_at: datetime | None = None
    last_test_match_count: int | None = Field(default=None, ge=0)
    last_test_execution_ms: float | None = Field(default=None, ge=0)
    created_at: datetime
    updated_at: datetime


class RuleDraftVersion(StrictModel):
    version_id: str
    draft_id: str
    version_number: int = Field(ge=1)
    snapshot: dict[str, object]
    change_summary: str
    actor_display: str
    created_at: datetime


class RuleValidationResult(StrictModel):
    draft: RuleDraft
    valid: bool
    errors: list[str]
    warnings: list[str]


class BoundedTimeWindow(StrictModel):
    relative_minutes: Literal[15, 60, 1440, 10080, 43200] | None = 1440
    start_time: datetime | None = None
    end_time: datetime | None = None

    @model_validator(mode="after")
    def valid_window(self) -> "BoundedTimeWindow":
        if self.relative_minutes is not None and (self.start_time is not None or self.end_time is not None):
            raise ValueError("relative_minutes cannot be combined with explicit timestamps")
        if (self.start_time is None) != (self.end_time is None):
            raise ValueError("start_time and end_time must be supplied together")
        if self.start_time is not None and self.end_time is not None:
            for value in (self.start_time, self.end_time):
                if value.tzinfo is None or value.utcoffset() is None:
                    raise ValueError("timestamps require UTC offsets")
            if self.start_time > self.end_time:
                raise ValueError("start_time must not exceed end_time")
            if self.end_time - self.start_time > timedelta(days=31):
                raise ValueError("time window must not exceed 31 days")
        return self

    def resolved(self, now: datetime | None = None) -> tuple[datetime, datetime]:
        reference = now or datetime.now(timezone.utc)
        if self.relative_minutes is not None:
            return reference - timedelta(minutes=self.relative_minutes), reference
        assert self.start_time is not None and self.end_time is not None
        return self.start_time.astimezone(timezone.utc), self.end_time.astimezone(timezone.utc)


class RuleDryRunRequest(BoundedTimeWindow):
    expected_version: int = Field(ge=1)
    max_events: int = Field(default=1000, ge=1, le=1000)


class RuleDryRunResult(StrictModel):
    draft: RuleDraft
    start_time: datetime
    end_time: datetime
    evaluated_event_count: int = Field(ge=0)
    match_count: int = Field(ge=0)
    matched_event_ids: list[str] = Field(max_length=100)
    execution_ms: float = Field(ge=0)
    result_ids_truncated: bool
    side_effects: Literal[False] = False


class DeploymentConfirmation(StrictModel):
    expected_version: int = Field(ge=1)
    confirmation: Literal["I_UNDERSTAND_MANUAL_DEPLOYMENT_REQUIRED"]
    reason: str = Field(min_length=1, max_length=512)

    @field_validator("reason")
    @classmethod
    def reason_not_blank(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("reason must not be blank")
        return normalized


class DeploymentConfirmationResult(StrictModel):
    draft: RuleDraft
    live_wazuh_modified: Literal[False] = False
    deployment_mode: Literal["MANUAL_REVIEW_ONLY"] = "MANUAL_REVIEW_ONLY"
    message: str


class RuleRollbackRequest(StrictModel):
    source_version: int = Field(ge=1)
    expected_version: int = Field(ge=1)
    change_summary: str = Field(min_length=1, max_length=512)


class ThreatHuntQuery(BoundedTimeWindow):
    ip: str | None = Field(default=None, max_length=64)
    hostname: str | None = Field(default=None, max_length=255)
    username: str | None = Field(default=None, max_length=512)
    event_category: str | None = Field(default=None, max_length=255)
    rule_id: str | None = Field(default=None, max_length=128)
    mitre_id: str | None = Field(default=None, max_length=16)
    search: str | None = Field(default=None, max_length=200)
    sort: Literal["newest", "oldest"] = "newest"

    @field_validator("hostname", "username", "event_category", "rule_id", "search")
    @classmethod
    def optional_nonblank(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("filter must not be blank")
        return normalized

    @field_validator("ip")
    @classmethod
    def valid_ip(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            return str(ipaddress.ip_address(value.strip()))
        except ValueError as exc:
            raise ValueError("invalid hunt IP") from exc

    @field_validator("mitre_id")
    @classmethod
    def valid_mitre(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().upper()
        if not MITRE_PATTERN.fullmatch(normalized):
            raise ValueError("MITRE ID must use T#### or T####.###")
        return normalized


class HuntEvent(StrictModel):
    event_id: str
    timestamp: datetime
    source_type: str
    hostname: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    username: str | None = None
    event_category: str | None = None
    rule_id: str | None = None
    severity: int | None = None
    message: str
    related_alert_id: str | None = None
    related_incident_ids: list[str]


class ThreatHuntPage(StrictModel):
    items: list[HuntEvent]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)
    next_cursor: str | None = None
    start_time: datetime
    end_time: datetime


class SavedHuntCreate(StrictModel):
    name: str = Field(min_length=1, max_length=100)
    query: ThreatHuntQuery

    @field_validator("name")
    @classmethod
    def nonblank_name(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("name must not be blank")
        return normalized


class SavedHuntUpdate(SavedHuntCreate):
    pass


class SavedHunt(StrictModel):
    saved_hunt_id: str
    name: str
    query: ThreatHuntQuery
    created_at: datetime
    updated_at: datetime


class IndicatorType(str, Enum):
    IPV4 = "IPV4"
    IPV6 = "IPV6"
    DOMAIN = "DOMAIN"
    FILE_HASH = "FILE_HASH"


def normalize_indicator(indicator_type: IndicatorType, value: str) -> tuple[str, str | None]:
    candidate = value.strip()
    if indicator_type in {IndicatorType.IPV4, IndicatorType.IPV6}:
        try:
            parsed = ipaddress.ip_address(candidate)
        except ValueError as exc:
            raise ValueError("invalid IP indicator") from exc
        expected = 4 if indicator_type is IndicatorType.IPV4 else 6
        if parsed.version != expected:
            raise ValueError(f"indicator must be IPv{expected}")
        return str(parsed), None
    if indicator_type is IndicatorType.DOMAIN:
        domain = candidate.rstrip(".").lower()
        if len(domain) > 253 or "." not in domain:
            raise ValueError("domain indicator must be a bounded FQDN")
        labels = domain.split(".")
        if any(not DOMAIN_LABEL.fullmatch(label) for label in labels):
            raise ValueError("domain indicator is invalid")
        return domain, None
    digest = candidate.lower()
    algorithm = HASH_LENGTHS.get(len(digest))
    if algorithm is None or not re.fullmatch(r"[0-9a-f]+", digest):
        raise ValueError("file hash must be MD5, SHA1, or SHA256 hexadecimal")
    return digest, algorithm


class IOCDefinition(StrictModel):
    indicator_type: IndicatorType
    value: str = Field(min_length=1, max_length=512)
    source: str = Field(min_length=1, max_length=255)
    confidence: int = Field(ge=0, le=100)
    description: str = Field(default="", max_length=2048)
    expires_at: datetime | None = None

    @field_validator("source")
    @classmethod
    def source_not_blank(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("source must not be blank")
        return normalized

    @field_validator("description")
    @classmethod
    def trim_description(cls, value: str) -> str:
        return value.strip()

    @model_validator(mode="after")
    def valid_indicator(self) -> "IOCDefinition":
        normalized, _ = normalize_indicator(self.indicator_type, self.value)
        self.value = normalized
        if self.expires_at is not None:
            if self.expires_at.tzinfo is None or self.expires_at.utcoffset() is None:
                raise ValueError("expires_at requires a UTC offset")
        return self


class IOCCreate(IOCDefinition):
    pass


class IOCUpdate(IOCDefinition):
    expected_version: int = Field(ge=1)
    is_active: bool = True


class IOCIndicator(StrictModel):
    indicator_id: str
    indicator_type: IndicatorType
    value: str
    hash_algorithm: Literal["MD5", "SHA1", "SHA256"] | None = None
    source: str
    confidence: int
    description: str
    expires_at: datetime | None = None
    is_active: bool
    expired: bool
    version: int
    created_at: datetime
    updated_at: datetime


class IOCImportRequest(StrictModel):
    indicators: list[IOCCreate] = Field(min_length=1, max_length=100)


class IOCImportResult(StrictModel):
    created: int = Field(ge=0)
    duplicates: int = Field(ge=0)
    indicators: list[IOCIndicator]


class IOCMatch(StrictModel):
    indicator_id: str
    indicator_type: IndicatorType
    value: str
    event_id: str
    event_timestamp: datetime
    matched_field: str


class IOCMatchSummary(StrictModel):
    start_time: datetime
    end_time: datetime
    total_matches: int = Field(ge=0)
    matches: list[IOCMatch]
    truncated: bool


class TechniqueCoverage(StrictModel):
    technique_id: str
    rule_ids: list[str]
    mapped_detection_count: int = Field(ge=0)
    enabled_detection_count: int = Field(ge=0)
    triggered_detection_count: int = Field(ge=0)
    tested_detection_count: int = Field(ge=0)
    alert_count: int = Field(ge=0)
    sources: list[str]
    coverage_state: Literal["MAPPED_ONLY", "ENABLED_NOT_TRIGGERED", "TRIGGERED"]


class DetectionCoverage(StrictModel):
    techniques: list[TechniqueCoverage]
    mapped_rule_count: int = Field(ge=0)
    unmapped_rule_count: int = Field(ge=0)
    validation_gap_count: int = Field(ge=0)


class FalsePositiveRuleMetric(StrictModel):
    rule_id: str
    total_alerts: int = Field(ge=0)
    dispositioned_alerts: int = Field(ge=0)
    false_positive_count: int = Field(ge=0)
    false_positive_rate: float | None = Field(default=None, ge=0, le=1)
    tuning_candidate: bool


class AnalyticsPoint(StrictModel):
    bucket: str
    count: int = Field(ge=0)


class NamedMetric(StrictModel):
    name: str
    count: int = Field(ge=0)


class AnalystDispositionMetric(StrictModel):
    analyst: str
    resolved_count: int = Field(ge=0)
    false_positive_count: int = Field(ge=0)
    total_count: int = Field(ge=0)


class DetectionAnalytics(StrictModel):
    start_time: datetime
    end_time: datetime
    alert_trend: list[AnalyticsPoint]
    false_positive_trend: list[AnalyticsPoint]
    top_rules: list[NamedMetric]
    top_source_ips: list[NamedMetric]
    top_hosts: list[NamedMetric]
    mitre_distribution: list[NamedMetric]
    ioc_matches: list[NamedMetric]
    analyst_dispositions: list[AnalystDispositionMetric]
    false_positive_rules: list[FalsePositiveRuleMetric]
    suggested_tuning_candidates: list[str]
