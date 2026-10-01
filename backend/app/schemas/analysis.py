"""Strict AI analysis contracts exposed by the API."""

from datetime import datetime
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator
import re

MITRE_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")


class MitreAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid")
    technique_id: str
    reasoning: str = Field(min_length=1, max_length=1000)
    source: Literal["source_event", "ai_suggestion"]

    @field_validator("technique_id")
    @classmethod
    def valid_id(cls, value: str) -> str:
        value = value.strip().upper()
        if not MITRE_ID.fullmatch(value):
            raise ValueError("invalid MITRE ATT&CK technique identifier")
        return value


class AnalysisResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    summary: str = Field(min_length=1, max_length=4000)
    observed_facts: list[str] = Field(min_length=1, max_length=30)
    severity_explanation: str = Field(min_length=1, max_length=3000)
    potential_mitre_techniques: list[MitreAssessment] = Field(default_factory=list, max_length=20)
    investigation_steps: list[str] = Field(min_length=1, max_length=20)
    uncertainties: list[str] = Field(min_length=1, max_length=20)

    @field_validator("observed_facts", "investigation_steps", "uncertainties")
    @classmethod
    def bounded_items(cls, values: list[str]) -> list[str]:
        cleaned = [item.strip() for item in values if item.strip()]
        if not cleaned or any(len(item) > 2000 for item in cleaned):
            raise ValueError("items must be non-empty and at most 2000 characters")
        return cleaned


class AnalysisResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    incident_id: str
    analysis_status: Literal["not_configured", "pending", "processing", "completed", "failed"]
    provider: str
    model: str | None
    result: AnalysisResult | None
    failure_category: str | None
    failure_message: str | None
    analysis_version: str
    input_truncated: bool
    analysis_timestamp: datetime | None
