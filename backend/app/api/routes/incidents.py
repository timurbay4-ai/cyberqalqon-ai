"""Incident list and detail routes."""

from typing import Literal
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.schemas.incident import IncidentListResponse, IncidentResponse
from app.services.incident_service import IncidentService

router = APIRouter(prefix="/incidents", tags=["Incidents"])


@router.get("", response_model=IncidentListResponse)
def list_incidents(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    severity: Literal["low", "medium", "high", "critical"] | None = None,
    agent: str | None = Query(default=None, min_length=1, max_length=256),
    mitre_id: str | None = Query(default=None, min_length=1, max_length=128),
    session: Session = Depends(get_db),
) -> IncidentListResponse:
    total, incidents = IncidentService(session).list(limit=limit, offset=offset, severity=severity, agent=agent, mitre_id=mitre_id)
    return IncidentListResponse(total=total, limit=limit, offset=offset, items=[IncidentResponse.model_validate(item) for item in incidents])


@router.get("/{incident_id}", response_model=IncidentResponse)
def get_incident(incident_id: str, session: Session = Depends(get_db)) -> IncidentResponse:
    return IncidentResponse.model_validate(IncidentService(session).get(incident_id))
