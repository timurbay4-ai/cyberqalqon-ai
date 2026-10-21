"""CyberQalqon AI FastAPI application."""

from __future__ import annotations

import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from app.ai.ollama import OllamaProvider
from app.ai.provider import AIProvider
from app.ai.service import AIService
from app.api.routes.ai import router as ai_router
from app.api.routes.agents import router as agents_router
from app.api.routes.audit import router as audit_router
from app.api.routes.alerts import router as alerts_router
from app.api.routes.alert_workflows import router as alert_workflows_router
from app.api.routes.auth import router as auth_router
from app.api.routes.cases import router as cases_router
from app.api.routes.detection_engineering import router as detection_engineering_router
from app.api.routes.detection_readiness import router as detection_readiness_router
from app.api.routes.events import router as events_router
from app.api.routes.incidents import router as incidents_router
from app.api.routes.investigations import router as investigations_router
from app.api.routes.investigation_workbench import router as investigation_workbench_router
from app.api.routes.notifications import router as notifications_router
from app.api.routes.overview import router as overview_router
from app.api.routes.operations import router as operations_router
from app.api.routes.preferences import router as preferences_router
from app.api.routes.siem import router as siem_router
from app.core.config import Settings, get_settings
from app.db.alerts import AlertRepository
from app.db.agents import AgentRepository
from app.db.alert_workflows import AlertWorkflowRepository
from app.db.audit import AuditRepository
from app.db.auth import AuthRepository
from app.db.cases import CaseRepository
from app.db.detection_engineering import DetectionEngineeringRepository
from app.db.detection_readiness import DetectionReadinessRepository
from app.db.events import EventRepository
from app.db.incidents import IncidentRepository
from app.db.investigations import InvestigationRepository
from app.db.investigation_workbench import InvestigationWorkbenchRepository
from app.db.notifications import NotificationRepository
from app.db.operations import OperationalRepository
from app.db.preferences import PreferenceRepository
from app.db.siem import SiemRepository
from app.db.ai import AIRepository
from app.services.incident_correlation import IncidentCorrelationEngine
from app.services.advanced_detection import AdvancedDetectionEngine
from app.services.ingestion_metrics import IngestionMetrics
from app.version import APPLICATION_VERSION


def create_app(settings: Settings | None = None, *, ai_provider: AIProvider | None = None) -> FastAPI:
    runtime_settings = settings or get_settings()
    repository = AlertRepository(
        runtime_settings.database_url,
        migration_target_version=(18 if runtime_settings.allow_m14_schema_migration else 17),
    )
    event_repository = EventRepository(
        repository.path,
        retention_days=runtime_settings.security_event_retention_days,
        max_records=runtime_settings.security_event_max_records,
    )
    ingestion_metrics = IngestionMetrics(
        batch_enabled=runtime_settings.event_batch_ingest_enabled,
        batch_limit=runtime_settings.event_batch_max_events,
    )
    incident_repository = IncidentRepository(repository.path)
    case_repository = CaseRepository(repository.path)
    investigation_repository = InvestigationRepository(repository.path)
    investigation_workbench_repository = InvestigationWorkbenchRepository(repository.path)
    alert_workflow_repository = AlertWorkflowRepository(repository.path)
    notification_repository = NotificationRepository(repository.path)
    operational_repository = OperationalRepository(
        repository.path,
        retention_days=runtime_settings.security_event_retention_days,
        max_records=runtime_settings.security_event_max_records,
    )
    agent_repository = AgentRepository(repository.path, runtime_settings)
    preference_repository = PreferenceRepository(repository.path)
    siem_repository = SiemRepository(
        repository.path, correlation_enabled=runtime_settings.correlation_enabled
    )
    detection_engineering_repository = DetectionEngineeringRepository(repository.path)
    advanced_detection_engine = AdvancedDetectionEngine(repository.path)
    detection_readiness_repository = DetectionReadinessRepository(
        repository.path, advanced_detection_engine
    )
    correlation_engine = IncidentCorrelationEngine(
        repository.path,
        enabled=runtime_settings.correlation_enabled,
        window_seconds=runtime_settings.correlation_window_seconds,
        max_candidates=runtime_settings.correlation_max_candidates,
        max_links=runtime_settings.correlation_max_links,
        retry_attempts=runtime_settings.correlation_retry_attempts,
    )
    auth_repository = AuthRepository(repository.path, runtime_settings)
    audit_repository = AuditRepository(repository.path)
    ai_repository = AIRepository(repository.path)
    provider = ai_provider
    if provider is None and runtime_settings.ai_enabled and runtime_settings.ai_configuration_error is None:
        provider = OllamaProvider(
            base_url=runtime_settings.ollama_base_url,
            model=runtime_settings.ollama_model,
            connect_timeout_seconds=runtime_settings.ollama_connect_timeout_seconds,
            request_timeout_seconds=runtime_settings.ollama_request_timeout_seconds,
            max_output_chars=runtime_settings.ai_max_output_chars,
        )
    ai_service = AIService(settings=runtime_settings, repository=ai_repository, provider=provider)

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        repository.initialize()
        application.state.alert_repository = repository
        application.state.event_repository = event_repository
        application.state.ingestion_metrics = ingestion_metrics
        application.state.incident_repository = incident_repository
        application.state.case_repository = case_repository
        application.state.investigation_repository = investigation_repository
        application.state.investigation_workbench_repository = investigation_workbench_repository
        application.state.alert_workflow_repository = alert_workflow_repository
        application.state.notification_repository = notification_repository
        application.state.operational_repository = operational_repository
        application.state.agent_repository = agent_repository
        application.state.preference_repository = preference_repository
        application.state.siem_repository = siem_repository
        application.state.detection_engineering_repository = detection_engineering_repository
        application.state.advanced_detection_engine = advanced_detection_engine
        application.state.detection_readiness_repository = detection_readiness_repository
        application.state.correlation_engine = correlation_engine
        application.state.auth_repository = auth_repository
        application.state.audit_repository = audit_repository
        application.state.ai_repository = ai_repository
        application.state.ai_service = ai_service
        try:
            yield
        finally:
            await ai_service.close()

    application = FastAPI(
        title="CyberQalqon AI Backend",
        description="Privacy-first AI-assisted SOC investigation platform.",
        version=APPLICATION_VERSION,
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )
    application.state.settings = runtime_settings

    @application.middleware("http")
    async def capture_request_reception(request: Request, call_next):  # type: ignore[no-untyped-def]
        # A single monotonic timestamp gives ingestion diagnostics a bounded
        # routing/authentication baseline without retaining headers or bodies.
        request.state.request_received_monotonic = time.monotonic()
        return await call_next(request)

    @application.exception_handler(RequestValidationError)
    async def request_validation_error(
        _: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        first_error = exc.errors()[0] if exc.errors() else {}
        location = first_error.get("loc", ())
        field = ".".join(str(part) for part in location if part not in {"query", "path", "body"})
        return JSONResponse(
            status_code=422,
            content={
                "detail": {
                    "code": "invalid_request",
                    "message": str(first_error.get("msg", "Request validation failed")),
                    **({"field": field} if field else {}),
                }
            },
        )

    application.add_middleware(
        CORSMiddleware,
        allow_origins=list(runtime_settings.cors_origins),
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Accept", "Content-Type", "X-API-Key", "X-CSRF-Token"],
    )
    application.include_router(auth_router)
    application.include_router(agents_router)
    application.include_router(cases_router)
    application.include_router(audit_router)
    application.include_router(alerts_router)
    application.include_router(alert_workflows_router)
    application.include_router(events_router)
    application.include_router(overview_router)
    application.include_router(operations_router)
    application.include_router(siem_router)
    application.include_router(detection_engineering_router)
    application.include_router(detection_readiness_router)
    application.include_router(incidents_router)
    application.include_router(investigations_router)
    application.include_router(investigation_workbench_router)
    application.include_router(notifications_router)
    application.include_router(preferences_router)
    application.include_router(ai_router)

    @application.get(
        "/health",
        tags=["System"],
        summary="Health check",
        response_description="Service health status",
    )
    async def health() -> dict[str, str]:
        return {"status": "ok", "service": "cyberqalqon-backend"}

    @application.get(
        "/readiness",
        tags=["System"],
        summary="Storage readiness check",
        response_description="Service readiness status",
    )
    async def readiness(request: Request) -> JSONResponse:
        # Readiness may wait on SQLite's bounded busy timeout. Keep that
        # dependency check off the event loop so liveness remains responsive.
        ready = await run_in_threadpool(request.app.state.alert_repository.is_ready)
        return JSONResponse(
            status_code=status.HTTP_200_OK if ready else status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "ready" if ready else "not_ready"},
        )

    return application


app = create_app()
