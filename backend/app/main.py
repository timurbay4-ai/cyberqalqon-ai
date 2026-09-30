"""
CyberQalqon AI — Backend API
Phase 1: Health check placeholder only.

This module intentionally exposes ONLY the /health endpoint.
No authentication, database, alert ingestion, or business logic
is implemented in Phase 1.

Next phase: Backend Developer / Codex Agent should build on this foundation.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="CyberQalqon AI Backend",
    description=(
        "Privacy-first AI-assisted SOC investigation platform. "
        "Phase 1: Foundation skeleton — health endpoint only."
    ),
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# ---------------------------------------------------------------------------
# CORS — adjust origins in production via environment variable
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Frontend dev server
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Health endpoint — the only implemented route in Phase 1
# ---------------------------------------------------------------------------
@app.get(
    "/health",
    tags=["System"],
    summary="Health check",
    response_description="Service health status",
)
async def health() -> dict:
    """
    Returns the operational status of the backend service.

    This endpoint is safe to call without authentication and
    is intended for load-balancer health checks and CI validation.
    """
    return {
        "status": "ok",
        "service": "cyberqalqon-backend",
    }
