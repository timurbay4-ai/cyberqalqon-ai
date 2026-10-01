"""Analyst review service."""

from sqlalchemy.orm import Session
from app.models.review import Review
from app.repositories.reviews import ReviewRepository
from app.schemas.review import ReviewCreate
from app.services.incident_service import IncidentService


class ReviewService:
    def __init__(self, session: Session) -> None:
        self.session = session

    def create(self, incident_id: str, data: ReviewCreate) -> Review:
        incident = IncidentService(self.session).get(incident_id)
        incident.review_status = data.status
        review = Review(incident=incident, status=data.status, analyst=data.analyst, note=data.note)
        return ReviewRepository(self.session).add(review)
