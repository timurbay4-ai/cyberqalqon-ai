"""CyberQalqon AI FastAPI application."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.routes.alerts import router as alerts_router
from app.api.routes.auth import router as auth_router
from app.api.routes.incidents import router as incidents_router
from app.core.config import Settings, get_settings
from app.db.alerts import AlertRepository
from app.db.auth import AuthRepository
from app.db.incidents import IncidentRepository


def create_app(settings: Settings | None = None) -> FastAPI:
    runtime_settings = settings or get_settings()
    repository = AlertRepository(runtime_settings.database_url)
    incident_repository = IncidentRepository(repository.path)
    auth_repository = AuthRepository(repository.path, runtime_settings)

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        repository.initialize()
        application.state.alert_repository = repository
        application.state.incident_repository = incident_repository
        application.state.auth_repository = auth_repository
        yield

    application = FastAPI(
        title="CyberQalqon AI Backend",
        description="Privacy-first AI-assisted SOC investigation platform.",
        version="0.4.0",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )
    application.state.settings = runtime_settings

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
        allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
        allow_headers=["Accept", "Content-Type", "X-API-Key", "X-CSRF-Token"],
    )
    application.include_router(auth_router)
    application.include_router(alerts_router)
    application.include_router(incidents_router)

    @application.get(
        "/health",
        tags=["System"],
        summary="Health check",
        response_description="Service health status",
    )
    async def health() -> dict[str, str]:
        return {"status": "ok", "service": "cyberqalqon-backend"}

    return application


app = create_app()
