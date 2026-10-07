"""Strict public contracts for advisory local-AI analysis."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Annotated, Literal

from pydantic import Field, field_validator

from app.schemas.alerts import StrictModel


AI_POLICY_VERSION = "cyberqalqon-ai-policy-v1"
AI_RESULT_SCHEMA_VERSION = "ai-analysis-v1"

BoundedText = Annotated[str, Field(min_length=1, max_length=1200)]


class AIAvailability(str, Enum):
    DISABLED = "DISABLED"
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"
    MISCONFIGURED = "MISCONFIGURED"


class AIAnalysisType(str, Enum):
    ALERT_SUMMARY = "ALERT_SUMMARY"
    INCIDENT_SUMMARY = "INCIDENT_SUMMARY"
    ANALYST_QUESTION = "ANALYST_QUESTION"


class AITargetType(str, Enum):
    ALERT = "alert"
    INCIDENT = "incident"


class AIAnalysisRequest(StrictModel):
    question: str | None = Field(default=None, min_length=1, max_length=500)

    @field_validator("question")
    @classmethod
    def reject_control_characters(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if any(ord(character) < 32 and character not in "\t\n\r" for character in value):
            raise ValueError("question contains unsupported control characters")
        return value


class AIMitreExplanation(StrictModel):
    technique_id: str = Field(min_length=1, max_length=32)
    explanation: str = Field(min_length=1, max_length=1200)
    basis: Literal["observed", "inferred"]


class AIAnalysisResult(StrictModel):
    summary: str = Field(min_length=1, max_length=2000)
    assessment: str = Field(min_length=1, max_length=4000)
    key_evidence: list[BoundedText] = Field(max_length=12)
    mitre_context: list[AIMitreExplanation] = Field(max_length=12)
    timeline_summary: str | None = Field(min_length=1, max_length=2400)
    hypotheses: list[BoundedText] = Field(max_length=10)
    investigation_steps: list[BoundedText] = Field(max_length=12)
    possible_false_positive_reasons: list[BoundedText] = Field(max_length=10)
    recommended_actions: list[BoundedText] = Field(max_length=12)
    containment_considerations: list[BoundedText] = Field(max_length=10)
    uncertainties: list[BoundedText] = Field(max_length=10)


class AIContextMetadata(StrictModel):
    context_bytes: int = Field(ge=0)
    truncated: bool
    alerts_included: int = Field(ge=0)
    alerts_available: int = Field(ge=0)
    notes_included: int = Field(ge=0)
    notes_available: int = Field(ge=0)
    history_included: int = Field(ge=0)
    history_available: int = Field(ge=0)
    raw_event_included: bool
    truncation_reasons: list[str] = Field(max_length=20)


class AIRequester(StrictModel):
    analyst_id: str
    display: str


class AIAnalysisRecord(StrictModel):
    analysis_id: str
    analysis_type: AIAnalysisType
    target_type: AITargetType
    target_id: str
    requested_by: AIRequester
    requested_at: datetime
    completed_at: datetime
    provider: Literal["ollama"]
    model: str
    model_digest: str | None = None
    policy_version: Literal[AI_POLICY_VERSION] = AI_POLICY_VERSION
    schema_version: Literal[AI_RESULT_SCHEMA_VERSION] = AI_RESULT_SCHEMA_VERSION
    context_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    context: AIContextMetadata
    stale: bool
    result: AIAnalysisResult


class AIAnalysisHistory(StrictModel):
    items: list[AIAnalysisRecord]
    limit: int = Field(ge=1, le=50)


class AIStatusResponse(StrictModel):
    state: AIAvailability
    provider: Literal["ollama"]
    model: str | None = None
    diagnostic: str | None = None
    checked_at: datetime
