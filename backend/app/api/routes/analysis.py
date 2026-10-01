from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from app.core.security import require_api_auth
from app.db.session import get_db
from app.schemas.analysis import AnalysisResponse
from app.services.ai_service import AIAnalysisService

router = APIRouter(prefix="/incidents/{incident_id}/analysis", tags=["AI Analysis"], dependencies=[Depends(require_api_auth)])

@router.get("", response_model=AnalysisResponse)
def get_analysis(incident_id: str, session: Session = Depends(get_db)) -> AnalysisResponse:
    return AIAnalysisService(session).get(incident_id)

@router.post("", response_model=AnalysisResponse)
def run_analysis(incident_id: str, retry: bool = Query(False), session: Session = Depends(get_db)) -> AnalysisResponse:
    return AIAnalysisService(session).analyze(incident_id, retry=retry)
