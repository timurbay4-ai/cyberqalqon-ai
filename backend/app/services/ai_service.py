"""Explicit AI analysis orchestration; ingestion never calls a model."""
from datetime import datetime, timezone
from threading import BoundedSemaphore, Lock
from sqlalchemy.orm import Session
from app.ai.preprocessing import prepare_incident_evidence
from app.ai.prompt import build_prompt
from app.ai.providers import AIAnalyzer, NoOpAIAnalyzer, ProviderError, create_analyzer
from app.core.config import Settings, get_settings
from app.core.exceptions import AIRequestConflictError, AIUnavailableError, IncidentNotFoundError
from app.models.analysis import IncidentAnalysis
from app.repositories.analyses import AnalysisRepository
from app.repositories.incidents import IncidentRepository
from app.schemas.analysis import AnalysisResponse

_semaphores: dict[int, BoundedSemaphore] = {}; _semaphore_lock = Lock()

def _semaphore(limit: int) -> BoundedSemaphore:
    with _semaphore_lock: return _semaphores.setdefault(limit, BoundedSemaphore(limit))

def to_response(row: IncidentAnalysis) -> AnalysisResponse:
    return AnalysisResponse(incident_id=row.incident_id, analysis_status=row.status, provider=row.provider, model=row.model,
        result=row.result, failure_category=row.failure_category, failure_message=row.failure_message,
        analysis_version=row.analysis_version, input_truncated=row.input_truncated, analysis_timestamp=row.completed_at)

class AIAnalysisService:
    def __init__(self, session: Session, settings: Settings | None = None, analyzer: AIAnalyzer | None = None):
        self.session = session; self.settings = settings or get_settings(); self.analyzer = analyzer or create_analyzer(self.settings)
        self.incidents = IncidentRepository(session); self.analyses = AnalysisRepository(session)
    def get(self, incident_id: str) -> AnalysisResponse:
        incident = self.incidents.get(incident_id)
        if not incident: raise IncidentNotFoundError()
        row = self.analyses.get(incident_id)
        if row: return to_response(row)
        return AnalysisResponse(incident_id=incident_id, analysis_status="not_configured" if self.settings.ai_provider == "noop" else "pending", provider=self.settings.ai_provider, model=self.settings.ai_model, result=None, failure_category=None, failure_message=None, analysis_version="1", input_truncated=False, analysis_timestamp=None)
    def analyze(self, incident_id: str, retry: bool = False) -> AnalysisResponse:
        incident = self.incidents.get(incident_id)
        if not incident: raise IncidentNotFoundError()
        if self.settings.ai_provider == "noop": raise AIUnavailableError()
        row = self.analyses.get(incident_id)
        if row and row.status in {"pending", "processing", "completed"} and not retry:
            raise AIRequestConflictError("Analysis already exists or is in progress; use retry=true for intentional replacement")
        gate = _semaphore(self.settings.ai_max_concurrent_requests)
        if not gate.acquire(blocking=False): raise AIRequestConflictError("AI concurrency limit reached")
        try:
            evidence, truncated = prepare_incident_evidence(incident, self.settings.ai_max_input_chars)
            row = row or IncidentAnalysis(incident_id=incident_id, provider=self.analyzer.provider, model=self.analyzer.model)
            row.status = incident.ai_status = "processing"; row.provider = self.analyzer.provider; row.model = self.analyzer.model
            row.result = None; row.failure_category = None; row.failure_message = None; row.input_truncated = truncated; row.completed_at = None
            self.analyses.save(row)
            try:
                result = self.analyzer.analyze(build_prompt(evidence)); source_ids = set(incident.mitre_ids)
                for mapping in result.potential_mitre_techniques: mapping.source = "source_event" if mapping.technique_id in source_ids else "ai_suggestion"
                row.result = result.model_dump(mode="json"); row.status = incident.ai_status = "completed"; row.completed_at = datetime.now(timezone.utc)
            except ProviderError as exc:
                row.status = incident.ai_status = "failed"; row.failure_category = exc.category; row.failure_message = str(exc); row.completed_at = datetime.now(timezone.utc)
            except Exception:
                row.status = incident.ai_status = "failed"; row.failure_category = "provider_error"; row.failure_message = "AI provider returned an unexpected error"; row.completed_at = datetime.now(timezone.utc)
            self.session.add(incident)
            return to_response(self.analyses.save(row))
        finally: gate.release()
