"""Wazuh ingestion route."""

import logging
from fastapi import APIRouter, Depends, Response, status
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.schemas.incident import IncidentResponse
from app.schemas.wazuh import WazuhAlert
from app.core.security import require_wazuh_auth
from app.services.ingest_service import IngestService

logger = logging.getLogger(__name__)
router = APIRouter(
    prefix="/ingest",
    tags=["Ingestion"],
    dependencies=[Depends(require_wazuh_auth)],
)


@router.post("/wazuh", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
def ingest_wazuh(alert: WazuhAlert, response: Response, session: Session = Depends(get_db)) -> IncidentResponse:
    incident, created = IngestService(session).ingest(alert.root)
    logger.info(
        "event=wazuh_ingest outcome=%s incident_id=%s",
        "created" if created else "deduplicated",
        incident.id,
    )
    if not created:
        response.status_code = status.HTTP_200_OK
    return IncidentResponse.model_validate(incident)
