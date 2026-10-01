"""Incident persistence operations."""

from sqlalchemy import String, cast, func, select
from sqlalchemy.orm import Session, selectinload
from app.models.incident import Incident


class IncidentRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def get_by_dedupe_key(self, dedupe_key: str) -> Incident | None:
        return self.session.scalar(select(Incident).where(Incident.dedupe_key == dedupe_key).options(selectinload(Incident.reviews)))

    def get(self, incident_id: str) -> Incident | None:
        return self.session.scalar(select(Incident).where(Incident.id == incident_id).options(selectinload(Incident.reviews)))

    def add(self, incident: Incident) -> Incident:
        self.session.add(incident)
        self.session.commit()
        return self.get(incident.id) or incident

    def list(self, *, limit: int, offset: int, severity: str | None, agent: str | None, mitre_id: str | None) -> tuple[int, list[Incident]]:
        filters = []
        if severity:
            filters.append(Incident.severity == severity)
        if agent:
            filters.append(Incident.agent_name == agent)
        if mitre_id:
            filters.append(cast(Incident.mitre_ids, String).contains(f'"{mitre_id}"'))
        total = self.session.scalar(select(func.count()).select_from(Incident).where(*filters)) or 0
        statement = (
            select(Incident)
            .where(*filters)
            .options(selectinload(Incident.reviews))
            .order_by(Incident.priority_score.desc(), Incident.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        return total, list(self.session.scalars(statement).all())

    def stats(self) -> dict[str, dict[str, int] | int]:
        severity_rows = self.session.execute(
            select(Incident.severity, func.count()).group_by(Incident.severity)
        ).all()
        review_rows = self.session.execute(
            select(Incident.review_status, func.count()).group_by(Incident.review_status)
        ).all()
        severity = {name: count for name, count in severity_rows}
        review_status = {name: count for name, count in review_rows}
        return {
            "total": sum(severity.values()),
            "severity": severity,
            "review_status": review_status,
        }
