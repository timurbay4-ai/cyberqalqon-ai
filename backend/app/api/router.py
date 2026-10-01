"""Application API router composition."""

from fastapi import APIRouter
from app.api.routes import incidents, ingest, reviews

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(ingest.router)
api_router.include_router(incidents.router)
api_router.include_router(reviews.router)
