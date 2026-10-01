from sqlalchemy.orm import Session
from app.models.analysis import IncidentAnalysis

class AnalysisRepository:
    def __init__(self, session: Session): self.session = session
    def get(self, incident_id: str) -> IncidentAnalysis | None: return self.session.get(IncidentAnalysis, incident_id)
    def save(self, value: IncidentAnalysis) -> IncidentAnalysis:
        self.session.add(value); self.session.commit(); self.session.refresh(value); return value
