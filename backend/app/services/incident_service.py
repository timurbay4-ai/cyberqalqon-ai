"""Incident query service."""

from sqlalchemy.orm import Session
from app.core.exceptions import IncidentNotFoundError
from app.models.incident import Incident
from app.repositories.incidents import IncidentRepository


class IncidentService:
    def __init__(self, session: Session) -> None:
        self.repository = IncidentRepository(session)

    def get(self, incident_id: str) -> Incident:
        incident = self.repository.get(incident_id)
        if incident is None:
            raise IncidentNotFoundError()
        return incident

    def list(self, **filters) -> tuple[int, list[Incident]]:
        return self.repository.list(**filters)

    def stats(self) -> dict:
        raw = self.repository.stats()
        severity = raw["severity"]
        review_status = raw["review_status"]
        return {
            "total": raw["total"],
            "severity": {
                "low": severity.get("low", 0),
                "medium": severity.get("medium", 0),
                "high": severity.get("high", 0),
                "critical": severity.get("critical", 0),
            },
            "review_status": {
                "needs_review": review_status.get("needs_review", 0),
                "confirmed": review_status.get("confirmed", 0),
                "false_positive": review_status.get("false_positive", 0),
            },
        }
