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
