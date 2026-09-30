"""Wazuh ingestion route."""

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.schemas.incident import IncidentResponse
from app.schemas.wazuh import WazuhAlert
from app.services.ingest_service import IngestService

router = APIRouter(prefix="/ingest", tags=["Ingestion"])


@router.post("/wazuh", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
def ingest_wazuh(alert: WazuhAlert, response: Response, session: Session = Depends(get_db)) -> IncidentResponse:
    incident, created = IngestService(session).ingest(alert.root)
    if not created:
        response.status_code = status.HTTP_200_OK
    return IncidentResponse.model_validate(incident)
