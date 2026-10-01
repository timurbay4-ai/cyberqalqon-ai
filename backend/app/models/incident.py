"""Persistent incident model."""

from datetime import datetime, timezone
from typing import Any
import uuid
from sqlalchemy import Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base
from app.db.types import UTCDateTime


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Incident(Base):
    __tablename__ = "incidents"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    dedupe_key: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    alert_id: Mapped[str | None] = mapped_column(String(256), nullable=True, index=True)
    event_timestamp: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now, onupdate=utc_now, nullable=False)
    agent_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    agent_name: Mapped[str | None] = mapped_column(String(256), nullable=True, index=True)
    agent_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    rule_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    rule_level: Mapped[int | None] = mapped_column(Integer, nullable=True)
    rule_description: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    rule_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    mitre_ids: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    mitre_tactics: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    mitre_techniques: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    destination_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user: Mapped[str | None] = mapped_column(String(256), nullable=True)
    source_user: Mapped[str | None] = mapped_column(String(256), nullable=True)
    destination_user: Mapped[str | None] = mapped_column(String(256), nullable=True)
    location: Mapped[str | None] = mapped_column(String(512), nullable=True)
    decoder: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    full_log: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_event: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    priority_score: Mapped[int] = mapped_column(Integer, nullable=False)
    repetition_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    asset_importance: Mapped[str] = mapped_column(String(16), default="normal", nullable=False)
    ai_status: Mapped[str] = mapped_column(String(32), default="not_configured", nullable=False)
    review_status: Mapped[str] = mapped_column(String(32), default="needs_review", nullable=False)
    reviews = relationship("Review", back_populates="incident", cascade="all, delete-orphan", order_by="Review.created_at")
