"""Strict contracts for durable SOC case management and deterministic response work."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import Field, field_validator, model_validator

from app.schemas.alerts import StrictModel


class CaseSeverity(str, Enum):
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class CasePriority(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class CaseStatus(str, Enum):
    OPEN = "OPEN"
    TRIAGING = "TRIAGING"
    INVESTIGATING = "INVESTIGATING"
    WAITING = "WAITING"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"


class CaseSourceType(str, Enum):
    MANUAL = "MANUAL"
    ALERT = "ALERT"
    INCIDENT = "INCIDENT"


class EvidenceReferenceType(str, Enum):
    ALERT = "ALERT"
    EVENT = "EVENT"
    INCIDENT = "INCIDENT"


class EvidenceIntegrityStatus(str, Enum):
    VERIFIED = "VERIFIED"
    MISMATCH = "MISMATCH"
    UNAVAILABLE = "UNAVAILABLE"


class CaseCreate(StrictModel):
    title: str = Field(min_length=1, max_length=255)
    description: str = Field(default="", max_length=8192)
    severity: CaseSeverity
    priority: CasePriority
    owner_id: str | None = Field(default=None, min_length=1, max_length=64)
    source_type: CaseSourceType = CaseSourceType.MANUAL
    source_id: str | None = Field(default=None, min_length=1, max_length=255)

    @field_validator("title")
    @classmethod
    def title_not_blank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("title must not be blank")
        return value

    @field_validator("description")
    @classmethod
    def description_trimmed(cls, value: str) -> str:
        return value.strip()

    @model_validator(mode="after")
    def source_pair_is_valid(self) -> "CaseCreate":
        if self.source_type is CaseSourceType.MANUAL and self.source_id is not None:
            raise ValueError("manual cases must not supply source_id")
        if self.source_type is not CaseSourceType.MANUAL and self.source_id is None:
            raise ValueError("source_id is required for alert or incident cases")
        return self


class CaseMetadataUpdate(StrictModel):
    expected_version: int = Field(ge=1)
    title: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=8192)
    severity: CaseSeverity | None = None
    priority: CasePriority | None = None

    @field_validator("title")
    @classmethod
    def title_not_blank(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not value:
            raise ValueError("title must not be blank")
        return value

    @field_validator("description")
    @classmethod
    def description_trimmed(cls, value: str | None) -> str | None:
        return value.strip() if value is not None else None

    @model_validator(mode="after")
    def has_change(self) -> "CaseMetadataUpdate":
        if not ({"title", "description", "severity", "priority"} & self.model_fields_set):
            raise ValueError("at least one case field must be supplied")
        return self


class CaseStatusUpdate(StrictModel):
    status: CaseStatus
    expected_version: int = Field(ge=1)
    resolution: str | None = Field(default=None, max_length=8192)
    closure_reason: str | None = Field(default=None, max_length=4096)

    @field_validator("resolution", "closure_reason")
    @classmethod
    def text_trimmed(cls, value: str | None) -> str | None:
        return value.strip() if value is not None else None


class CaseAssignmentUpdate(StrictModel):
    owner_id: str | None = Field(default=None, min_length=1, max_length=64)
    expected_version: int = Field(ge=1)
    handoff_note: str | None = Field(default=None, max_length=4096)

    @field_validator("handoff_note")
    @classmethod
    def note_trimmed(cls, value: str | None) -> str | None:
        return value.strip() if value is not None else None


class CaseCommentCreate(StrictModel):
    body: str = Field(min_length=1, max_length=4096)
    expected_version: int = Field(ge=1)

    @field_validator("body")
    @classmethod
    def body_not_blank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("body must not be blank")
        return value


class CaseLinkCreate(StrictModel):
    reference_id: str = Field(min_length=1, max_length=255)
    expected_version: int = Field(ge=1)

    @field_validator("reference_id")
    @classmethod
    def identifier_not_blank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("reference_id must not be blank")
        return value


class CaseEvidenceCreate(StrictModel):
    reference_type: EvidenceReferenceType
    reference_id: str = Field(min_length=1, max_length=255)
    annotation: str = Field(default="", max_length=4096)
    expected_version: int = Field(ge=1)

    @field_validator("reference_id")
    @classmethod
    def identifier_not_blank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("reference_id must not be blank")
        return value

    @field_validator("annotation")
    @classmethod
    def annotation_trimmed(cls, value: str) -> str:
        return value.strip()


class CaseEvidenceAnnotationUpdate(StrictModel):
    annotation: str = Field(max_length=4096)
    expected_version: int = Field(ge=1)

    @field_validator("annotation")
    @classmethod
    def annotation_trimmed(cls, value: str) -> str:
        return value.strip()


class VersionedCaseMutation(StrictModel):
    expected_version: int = Field(ge=1)


class CaseOwner(StrictModel):
    analyst_id: str
    username: str
    display_name: str


class CaseSla(StrictModel):
    policy: str = "LOCAL_CASE_SLA_V1"
    response_due_at: datetime
    resolution_due_at: datetime
    first_response_at: datetime | None = None
    response_state: Literal["PENDING", "MET", "OVERDUE", "NOT_APPLICABLE"]
    resolution_state: Literal["PENDING", "MET", "OVERDUE", "NOT_APPLICABLE"]
    escalation_state: Literal["NONE", "RESPONSE_OVERDUE", "RESOLUTION_OVERDUE"]


class CaseSummary(StrictModel):
    case_id: str
    title: str
    description: str
    severity: CaseSeverity
    priority: CasePriority
    status: CaseStatus
    owner: CaseOwner | None = None
    source_type: CaseSourceType
    source_id: str | None = None
    created_by_display: str
    created_at: datetime
    updated_at: datetime
    resolved_at: datetime | None = None
    closed_at: datetime | None = None
    version: int = Field(ge=1)
    alert_count: int = Field(ge=0)
    incident_count: int = Field(ge=0)
    event_count: int = Field(ge=0)
    evidence_count: int = Field(ge=0)
    comment_count: int = Field(ge=0)
    sla: CaseSla


class CaseComment(StrictModel):
    comment_id: str
    comment_type: Literal["COMMENT", "HANDOFF"]
    body: str
    author_display: str
    from_owner_id: str | None = None
    to_owner_id: str | None = None
    created_at: datetime


class CustodyEvent(StrictModel):
    custody_event_id: str
    event_type: Literal["ACQUIRED", "VERIFIED", "MISMATCH", "UNAVAILABLE", "ANNOTATED"]
    actor_display: str
    occurred_at: datetime
    details: dict[str, Any]


class CaseEvidence(StrictModel):
    evidence_ref_id: str
    reference_type: EvidenceReferenceType
    reference_id: str
    source_label: str
    source_timestamp: datetime
    acquisition_method: Literal["DATABASE_REFERENCE"]
    digest_algorithm: Literal["SHA-256"]
    digest: str
    integrity_status: EvidenceIntegrityStatus
    acquired_by_display: str
    acquired_at: datetime
    last_verified_at: datetime
    annotation: str
    version: int = Field(ge=1)
    custody: list[CustodyEvent] = Field(default_factory=list)


class CaseActivity(StrictModel):
    activity_id: str
    activity_type: str
    actor_display: str
    entity_type: str
    entity_id: str
    occurred_at: datetime
    details: dict[str, Any]


class PlaybookTemplateStep(StrictModel):
    key: str
    title: str
    description: str
    step_type: Literal["ACTION", "EVIDENCE", "APPROVAL"]


class PlaybookTemplate(StrictModel):
    key: str
    version: int = Field(ge=1)
    name: str
    description: str
    steps: list[PlaybookTemplateStep]


class PlaybookInstantiate(StrictModel):
    template_key: str = Field(min_length=1, max_length=64)
    expected_version: int = Field(ge=1)


class PlaybookStepUpdate(StrictModel):
    expected_version: int = Field(ge=1)
    status: Literal["PENDING", "COMPLETED"]
    assigned_to: str | None = Field(default=None, min_length=1, max_length=64)
    evidence_ref_id: str | None = Field(default=None, min_length=1, max_length=64)
    completion_note: str = Field(default="", max_length=2048)

    @field_validator("completion_note")
    @classmethod
    def note_trimmed(cls, value: str) -> str:
        return value.strip()


class PlaybookStep(StrictModel):
    step_id: str
    template_step_key: str
    sequence: int = Field(ge=0)
    title: str
    description: str
    step_type: Literal["ACTION", "EVIDENCE", "APPROVAL"]
    status: Literal["PENDING", "COMPLETED"]
    assigned_to: CaseOwner | None = None
    evidence_ref_id: str | None = None
    completion_note: str
    completed_by_display: str | None = None
    completed_at: datetime | None = None
    version: int = Field(ge=1)


class CasePlaybook(StrictModel):
    playbook_id: str
    template_key: str
    template_version: int = Field(ge=1)
    name: str
    status: Literal["ACTIVE", "COMPLETED"]
    created_by_display: str
    created_at: datetime
    completed_at: datetime | None = None
    version: int = Field(ge=1)
    completed_steps: int = Field(ge=0)
    total_steps: int = Field(ge=0)
    steps: list[PlaybookStep]


class CaseReportRecord(StrictModel):
    report_id: str
    format: Literal["JSON", "CSV", "PDF"]
    generated_by_display: str
    generated_at: datetime
    sha256: str
    size_bytes: int = Field(ge=0)
    redaction_profile: Literal["CASE_REPORT_V1"]


class CaseDetail(CaseSummary):
    resolution: str
    closure_reason: str
    alert_ids: list[str]
    incident_ids: list[str]
    event_ids: list[str]
    comments: list[CaseComment]
    evidence: list[CaseEvidence]
    activity: list[CaseActivity]
    playbooks: list[CasePlaybook]
    report_history: list[CaseReportRecord]


class CasePage(StrictModel):
    items: list[CaseSummary]
    limit: int = Field(ge=1, le=100)
    total: int = Field(ge=0)
    next_cursor: str | None = None
    sort: Literal["newest", "oldest", "updated", "priority"]


class CaseAnalyticsCount(StrictModel):
    name: str
    count: int = Field(ge=0)


class CaseAnalytics(StrictModel):
    generated_at: datetime
    window_days: int = Field(ge=1, le=365)
    open_cases: int = Field(ge=0)
    overdue_response: int = Field(ge=0)
    overdue_resolution: int = Field(ge=0)
    mtta_minutes: float | None = Field(default=None, ge=0)
    mttr_minutes: float | None = Field(default=None, ge=0)
    by_severity: list[CaseAnalyticsCount]
    by_owner: list[CaseAnalyticsCount]
    aging_buckets: list[CaseAnalyticsCount]
    created_trend: list[CaseAnalyticsCount]
    closed_trend: list[CaseAnalyticsCount]
    definitions: dict[str, str]


class SlaEvaluationResult(StrictModel):
    evaluated_cases: int = Field(ge=0)
    notifications_created: int = Field(ge=0)
    generated_at: datetime
