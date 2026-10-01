"""Create the verified non-AI incident and review schema.

Revision ID: 20261001_0001
Revises: None
Create Date: 2026-10-01
"""

from typing import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "20261001_0001"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "incidents",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("dedupe_key", sa.String(length=128), nullable=False),
        sa.Column("alert_id", sa.String(length=256), nullable=True),
        sa.Column("event_timestamp", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("agent_id", sa.String(length=128), nullable=True),
        sa.Column("agent_name", sa.String(length=256), nullable=True),
        sa.Column("agent_ip", sa.String(length=64), nullable=True),
        sa.Column("rule_id", sa.String(length=128), nullable=True),
        sa.Column("rule_level", sa.Integer(), nullable=True),
        sa.Column("rule_description", sa.String(length=1024), nullable=True),
        sa.Column("rule_metadata", sa.JSON(), nullable=False),
        sa.Column("mitre_ids", sa.JSON(), nullable=False),
        sa.Column("mitre_tactics", sa.JSON(), nullable=False),
        sa.Column("mitre_techniques", sa.JSON(), nullable=False),
        sa.Column("source_ip", sa.String(length=64), nullable=True),
        sa.Column("destination_ip", sa.String(length=64), nullable=True),
        sa.Column("user", sa.String(length=256), nullable=True),
        sa.Column("source_user", sa.String(length=256), nullable=True),
        sa.Column("destination_user", sa.String(length=256), nullable=True),
        sa.Column("location", sa.String(length=512), nullable=True),
        sa.Column("decoder", sa.JSON(), nullable=True),
        sa.Column("full_log", sa.Text(), nullable=True),
        sa.Column("raw_event", sa.JSON(), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("priority_score", sa.Integer(), nullable=False),
        sa.Column("repetition_count", sa.Integer(), nullable=False),
        sa.Column("asset_importance", sa.String(length=16), nullable=False),
        sa.Column("ai_status", sa.String(length=32), nullable=False),
        sa.Column("review_status", sa.String(length=32), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_incidents_agent_name", "incidents", ["agent_name"], unique=False)
    op.create_index("ix_incidents_alert_id", "incidents", ["alert_id"], unique=False)
    op.create_index("ix_incidents_dedupe_key", "incidents", ["dedupe_key"], unique=True)

    op.create_table(
        "reviews",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("incident_id", sa.String(length=36), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("analyst", sa.String(length=128), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_reviews_incident_id", "reviews", ["incident_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_reviews_incident_id", table_name="reviews")
    op.drop_table("reviews")
    op.drop_index("ix_incidents_dedupe_key", table_name="incidents")
    op.drop_index("ix_incidents_alert_id", table_name="incidents")
    op.drop_index("ix_incidents_agent_name", table_name="incidents")
    op.drop_table("incidents")
