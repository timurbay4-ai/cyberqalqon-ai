"""Analyst review route."""

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.schemas.incident import IncidentResponse
from app.schemas.review import ReviewCreate
from app.services.incident_service import IncidentService
from app.services.review_service import ReviewService

router = APIRouter(prefix="/incidents", tags=["Reviews"])


@router.post("/{incident_id}/review", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
def review_incident(incident_id: str, data: ReviewCreate, session: Session = Depends(get_db)) -> IncidentResponse:
    ReviewService(session).create(incident_id, data)
    return IncidentResponse.model_validate(IncidentService(session).get(incident_id))
