"""Liveness and readiness routes."""

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session
from app.db.session import get_db

router = APIRouter(tags=["System"])


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "cyberqalqon-backend"}


@router.get("/ready")
def ready(session: Session = Depends(get_db)) -> dict[str, str]:
    session.execute(text("SELECT 1"))
    return {"status": "ok", "service": "cyberqalqon-backend"}
