"""Analyst review API schemas."""

from datetime import datetime
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator


class ReviewCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["confirmed", "false_positive", "needs_review"]
    analyst: str = Field(min_length=1, max_length=128)
    note: str | None = Field(default=None, max_length=4000)

    @field_validator("analyst")
    @classmethod
    def strip_analyst(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("analyst must not be blank")
        return stripped

    @field_validator("note")
    @classmethod
    def strip_note(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return value.strip() or None


class ReviewResponse(BaseModel):
    id: str
    status: str
    analyst: str
    note: str | None
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)
