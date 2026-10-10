"""Durable incident investigation checklist, evidence, and activity contracts."""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import Field, field_validator, model_validator

from app.schemas.alerts import StrictModel


class EvidenceType(str, Enum):
    EVENT = "EVENT"
    ALERT = "ALERT"
    INCIDENT_EVIDENCE = "INCIDENT_EVIDENCE"


class InvestigationAnalyst(StrictModel):
    analyst_id: str
    username: str
    display_name: str


class ChecklistItem(StrictModel):
    checklist_item_id: str
    incident_id: str
    body: str
    is_completed: bool
    assigned_to: InvestigationAnalyst | None = None
    position: int = Field(ge=0)
    version: int = Field(ge=1)
    created_at: datetime
    updated_at: datetime
    completed_at: datetime | None = None
    created_by_display: str
    updated_by_display: str


class ChecklistCreate(StrictModel):
    body: str = Field(min_length=1, max_length=1024)
    assigned_to: str | None = Field(default=None, min_length=1, max_length=64)

    @field_validator("body")
    @classmethod
    def body_not_blank(cls, value: str) -> str:
        body = value.strip()
        if not body:
            raise ValueError("body must not be blank")
        return body


class ChecklistUpdate(StrictModel):
    expected_version: int = Field(ge=1)
    body: str | None = Field(default=None, min_length=1, max_length=1024)
    is_completed: bool | None = None
    assigned_to: str | None = Field(default=None, min_length=1, max_length=64)

    @field_validator("body")
    @classmethod
    def body_not_blank(cls, value: str | None) -> str | None:
        if value is None:
            return None
        body = value.strip()
        if not body:
            raise ValueError("body must not be blank")
        return body

    @model_validator(mode="after")
    def has_update(self) -> "ChecklistUpdate":
        if not ({"body", "is_completed", "assigned_to"} & self.model_fields_set):
            raise ValueError("at least one checklist field must be supplied")
        return self


class ChecklistReorderItem(StrictModel):
    checklist_item_id: str = Field(min_length=1, max_length=64)
    expected_version: int = Field(ge=1)


class ChecklistReorder(StrictModel):
    items: list[ChecklistReorderItem] = Field(min_length=1, max_length=100)

    @field_validator("items")
    @classmethod
    def unique_items(cls, value: list[ChecklistReorderItem]) -> list[ChecklistReorderItem]:
        identifiers = [item.checklist_item_id for item in value]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("items must be unique")
        return value


class EvidencePin(StrictModel):
    evidence_pin_id: str
    incident_id: str
    evidence_type: EvidenceType
    evidence_id: str
    annotation: str
    source_timestamp: datetime
    pinned_by_display: str
    pinned_at: datetime
    updated_at: datetime
    version: int = Field(ge=1)


class EvidencePinCreate(StrictModel):
    evidence_type: EvidenceType
    evidence_id: str = Field(min_length=1, max_length=255)
    annotation: str = Field(default="", max_length=4096)

    @field_validator("evidence_id")
    @classmethod
    def identifier_not_blank(cls, value: str) -> str:
        identifier = value.strip()
        if not identifier:
            raise ValueError("evidence_id must not be blank")
        return identifier

    @field_validator("annotation")
    @classmethod
    def annotation_trimmed(cls, value: str) -> str:
        return value.strip()


class EvidenceAnnotationUpdate(StrictModel):
    annotation: str = Field(max_length=4096)
    expected_version: int = Field(ge=1)

    @field_validator("annotation")
    @classmethod
    def annotation_trimmed(cls, value: str) -> str:
        return value.strip()


class VersionedMutation(StrictModel):
    expected_version: int = Field(ge=1)


class InvestigationWorkspace(StrictModel):
    incident_id: str
    checklist_items: list[ChecklistItem]
    evidence_pins: list[EvidencePin]
    checklist_completed: int = Field(ge=0)
    checklist_total: int = Field(ge=0)


class InvestigationActivity(StrictModel):
    activity_id: str
    activity_type: str
    entity_type: str
    entity_id: str
    actor_display: str
    action_at: datetime
    source_timestamp: datetime | None = None
    details: dict[str, object]


class InvestigationTimelinePage(StrictModel):
    items: list[InvestigationActivity]
    limit: int = Field(ge=1, le=100)
    next_cursor: str | None = None
    total: int = Field(ge=0)
