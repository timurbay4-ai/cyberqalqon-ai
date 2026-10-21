"""M14 detection lifecycle, tuning, shadow, readiness, and diagnostics contracts."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
import re
from typing import Literal

from pydantic import Field, field_validator, model_validator

from app.schemas.alerts import StrictModel
from app.schemas.detection_engineering import AdvancedDetectionFinding, BoundedTimeWindow


class DetectionLifecycleState(str, Enum):
    DRAFT = "DRAFT"
    VALIDATED = "VALIDATED"
    TESTED = "TESTED"
    SHADOW_READY = "SHADOW_READY"
    CANARY_READY = "CANARY_READY"
    ACTIVE = "ACTIVE"
    PAUSED = "PAUSED"
    ROLLED_BACK = "ROLLED_BACK"
    DISABLED_BY_POLICY = "DISABLED_BY_POLICY"


class DetectionValidationState(str, Enum):
    NOT_VALIDATED = "NOT_VALIDATED"
    VALID = "VALID"
    INVALID = "INVALID"


class DetectionDeploymentEligibility(str, Enum):
    BLOCKED = "BLOCKED"
    SHADOW_ONLY = "SHADOW_ONLY"
    CANARY_REVIEW_REQUIRED = "CANARY_REVIEW_REQUIRED"


class TelemetryReadinessStatus(str, Enum):
    READY = "READY"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"
    UNAVAILABLE = "UNAVAILABLE"
    FAILED = "FAILED"


class SafeExclusion(StrictModel):
    field: Literal["hostname", "username", "source_ip", "process_name"]
    operator: Literal["EQUALS", "STARTS_WITH"] = "EQUALS"
    value: str = Field(min_length=1, max_length=256)

    @field_validator("value")
    @classmethod
    def normalized_value(cls, value: str) -> str:
        result = value.strip()
        if not result or "\x00" in result:
            raise ValueError("exclusion value is invalid")
        return result


class DetectionEvaluationLimits(StrictModel):
    max_events: int = Field(default=1000, ge=1, le=5000)
    max_findings: int = Field(default=100, ge=1, le=500)
    max_execution_ms: int = Field(default=1000, ge=50, le=5000)


class DetectionConfigurationDefinition(StrictModel):
    threshold_count: int = Field(ge=1, le=100)
    time_window_seconds: int = Field(ge=30, le=86400)
    severity: int = Field(ge=0, le=16)
    supported_event_sources: list[str] = Field(min_length=1, max_length=8)
    required_normalized_fields: list[str] = Field(min_length=1, max_length=16)
    entity_grouping: list[str] = Field(default_factory=list, max_length=8)
    safe_exclusions: list[SafeExclusion] = Field(default_factory=list, max_length=20)
    evaluation_limits: DetectionEvaluationLimits = Field(default_factory=DetectionEvaluationLimits)
    state_expiration_seconds: int = Field(ge=60, le=604800)
    state_schema_version: Literal[1] = 1

    @field_validator(
        "supported_event_sources", "required_normalized_fields", "entity_grouping"
    )
    @classmethod
    def unique_items(cls, value: list[object]) -> list[object]:
        if len(value) != len(set(value)):
            raise ValueError("configuration lists must not contain duplicates")
        if any(
            not isinstance(item, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", item)
            for item in value
        ):
            raise ValueError("configuration field names must be bounded identifiers")
        return value

    @model_validator(mode="after")
    def state_outlives_window(self) -> "DetectionConfigurationDefinition":
        if self.state_expiration_seconds < self.time_window_seconds * 2:
            raise ValueError("state expiration must be at least twice the evaluation window")
        return self


class DetectionConfigurationCreate(DetectionConfigurationDefinition):
    expected_version: int = Field(ge=1)
    change_reason: str = Field(min_length=1, max_length=512)

    @field_validator("change_reason")
    @classmethod
    def reason_not_blank(cls, value: str) -> str:
        result = value.strip()
        if not result:
            raise ValueError("change reason must not be blank")
        return result


class DetectionConfigurationRestore(StrictModel):
    source_version: int = Field(ge=1)
    expected_version: int = Field(ge=1)
    change_reason: str = Field(min_length=1, max_length=512)

    @field_validator("change_reason")
    @classmethod
    def restore_reason_not_blank(cls, value: str) -> str:
        result = value.strip()
        if not result:
            raise ValueError("change reason must not be blank")
        return result


class DetectionConfigurationVersion(DetectionConfigurationDefinition):
    config_id: str
    rule_id: str = Field(pattern=r"^DET-00[1-9]$")
    version: int = Field(ge=1)
    lifecycle_state: DetectionLifecycleState
    author_id: str | None = None
    author_display: str
    change_reason: str
    created_at: datetime
    validation_results: list[str]


class DetectionConfigurationDifference(StrictModel):
    field: str
    before: object | None = None
    after: object | None = None


class DetectionConfigurationDiff(StrictModel):
    rule_id: str
    from_version: int
    to_version: int
    differences: list[DetectionConfigurationDifference]
    executable_content_present: Literal[False] = False


class DetectionRuleLifecycle(StrictModel):
    rule_id: str = Field(pattern=r"^DET-00[1-9]$")
    configuration_state: DetectionLifecycleState
    validation_state: DetectionValidationState
    deployment_eligibility: DetectionDeploymentEligibility
    runtime_activation_state: Literal["DISABLED_BY_POLICY"] = "DISABLED_BY_POLICY"
    telemetry_status: TelemetryReadinessStatus
    active_configuration_version: int = Field(ge=1)
    state_version: int = Field(ge=1)
    updated_at: datetime
    updated_by: str
    inactive_reason: str


class DetectionLifecycleTransition(StrictModel):
    expected_state_version: int = Field(ge=1)
    target_state: DetectionLifecycleState
    reason: str = Field(min_length=1, max_length=512)

    @field_validator("reason")
    @classmethod
    def transition_reason_not_blank(cls, value: str) -> str:
        result = value.strip()
        if not result:
            raise ValueError("transition reason must not be blank")
        return result


class DetectionConfigurationValidation(StrictModel):
    rule_id: str
    configuration_version: int
    valid: bool
    errors: list[str]
    warnings: list[str]
    validated_at: datetime
    lifecycle: DetectionRuleLifecycle


class TuningCandidate(StrictModel):
    threshold_count: int = Field(ge=1, le=100)
    time_window_seconds: int = Field(ge=30, le=86400)


class DetectionTuningRequest(BoundedTimeWindow):
    candidates: list[TuningCandidate] = Field(min_length=2, max_length=5)
    max_events: int = Field(default=2000, ge=1, le=5000)
    max_findings: int = Field(default=200, ge=1, le=500)
    max_execution_ms: int = Field(default=3000, ge=100, le=5000)

    @field_validator("candidates")
    @classmethod
    def unique_candidates(cls, value: list[TuningCandidate]) -> list[TuningCandidate]:
        keys = {(item.threshold_count, item.time_window_seconds) for item in value}
        if len(keys) != len(value):
            raise ValueError("tuning candidates must be unique")
        return value


class CountByEntity(StrictModel):
    entity: str
    count: int = Field(ge=0)


class TuningCandidateResult(StrictModel):
    candidate: TuningCandidate
    evaluated_event_count: int = Field(ge=0)
    finding_count: int = Field(ge=0)
    duplicate_count: int = Field(ge=0)
    missing_field_count: int = Field(ge=0)
    findings_by_source: list[CountByEntity]
    findings_by_host: list[CountByEntity]
    findings_by_user: list[CountByEntity]
    repeated_finding_count: int = Field(ge=0)
    execution_ms: float = Field(ge=0)
    truncated: bool


class DetectionTuningComparison(StrictModel):
    rule_id: str
    start_time: datetime
    end_time: datetime
    results: list[TuningCandidateResult]
    interpretation: str
    side_effects: Literal[False] = False


class ShadowRunRequest(BoundedTimeWindow):
    configuration_version: int | None = Field(default=None, ge=1)
    max_events: int = Field(default=1000, ge=1, le=5000)
    max_findings: int = Field(default=100, ge=1, le=200)
    max_execution_ms: int = Field(default=2000, ge=100, le=5000)


class ShadowRun(StrictModel):
    run_id: str
    rule_id: str
    configuration_version: int
    status: Literal["RUNNING", "COMPLETED", "FAILED"]
    started_at: datetime
    completed_at: datetime | None = None
    start_time: datetime
    end_time: datetime
    operator_display: str
    source_availability: TelemetryReadinessStatus
    evaluated_event_count: int = Field(ge=0)
    match_count: int = Field(ge=0)
    duplicate_count: int = Field(ge=0)
    missing_field_count: int = Field(ge=0)
    execution_ms: float = Field(ge=0)
    truncated: bool
    outcome: str
    error_code: str | None = None
    resource_measurements: dict[str, float | int | str | bool | None]
    side_effects: Literal[False] = False


class ShadowFinding(StrictModel):
    shadow_finding_id: str
    run_id: str
    rule_id: str
    finding: AdvancedDetectionFinding
    created_at: datetime
    namespace: Literal["SHADOW"] = "SHADOW"
    production_alert_id: Literal[None] = None
    production_incident_id: Literal[None] = None
    production_case_id: Literal[None] = None


class ShadowRunDetail(StrictModel):
    run: ShadowRun
    findings: list[ShadowFinding]


class TelemetryPrerequisiteEvidence(StrictModel):
    rule_id: str
    required_sources: list[str]
    required_event_codes: list[str]
    required_categories: list[str]
    required_fields: list[str]
    latest_observed_event: datetime | None = None
    source_freshness_seconds: int | None = Field(default=None, ge=0)
    normalization_compatible: bool
    status: TelemetryReadinessStatus
    missing_prerequisites: list[str]
    authoritative_evidence_reference: str
    explanation: str


class DetectionDiagnostics(StrictModel):
    rule_id: str
    evaluation_count: int = Field(ge=0)
    average_duration_ms: float = Field(ge=0)
    rule_match_count: int = Field(ge=0)
    finding_count: int = Field(ge=0)
    duplicate_event_count: int = Field(ge=0)
    skipped_event_count: int = Field(ge=0)
    missing_field_count: int = Field(ge=0)
    evaluation_timeout_count: int = Field(ge=0)
    state_recovery_count: int = Field(ge=0)
    configuration_validation_failure_count: int = Field(ge=0)
    truncation_count: int = Field(ge=0)
    last_successful_evaluation: datetime | None = None
    last_failed_evaluation: datetime | None = None
    evaluated_event_range_start: datetime | None = None
    evaluated_event_range_end: datetime | None = None
    source_freshness: str | None = None


class CorrelationReplayRequest(BoundedTimeWindow):
    configuration_version: int | None = Field(default=None, ge=1)
    max_events: int = Field(default=1000, ge=1, le=5000)
    max_findings: int = Field(default=100, ge=1, le=200)
    max_execution_ms: int = Field(default=2000, ge=100, le=5000)
    simulate_interruption: bool = False


class CorrelationReplayResult(StrictModel):
    rule_id: str
    configuration_version: int
    evaluated_event_count: int = Field(ge=0)
    newly_processed_event_count: int = Field(ge=0)
    duplicate_event_count: int = Field(ge=0)
    state_record_count: int = Field(ge=0)
    expired_state_count: int = Field(ge=0)
    finding_count: int = Field(ge=0)
    watermark_at: datetime | None = None
    recovered_after_restart: bool
    interrupted_transaction_rolled_back: bool
    side_effects: Literal[False] = False


class CanarySafetyStatus(StrictModel):
    rule_id: str
    prerequisites_validated: bool
    historical_evaluation_passed: bool
    configuration_reviewed: bool
    resource_budget_reviewed: bool
    false_positive_baseline_measured: bool
    version_locked: bool
    target_scope_selected: Literal[False] = False
    operator_approval_recorded: Literal[False] = False
    activation_path_enabled: Literal[False] = False
    runtime_activation_state: Literal["DISABLED_BY_POLICY"] = "DISABLED_BY_POLICY"
    blockers: list[str]
