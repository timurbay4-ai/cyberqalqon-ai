"""Bounded, database-backed SOC overview API."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.api.dependencies.auth import require_soc_reader
from app.db.events import EventRepository
from app.schemas.alerts import ErrorResponse
from app.schemas.auth import AnalystPrincipal
from app.schemas.events import SecurityOverview


router = APIRouter(prefix="/api/v1/overview", tags=["Overview"])


@router.get(
    "",
    response_model=SecurityOverview,
    response_model_exclude_none=True,
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}, 422: {"model": ErrorResponse}},
)
async def get_overview(
    request: Request,
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
    start_time: Annotated[datetime | None, Query()] = None,
    end_time: Annotated[datetime | None, Query()] = None,
) -> SecurityOverview:
    end = end_time or datetime.now(timezone.utc)
    start = start_time or end - timedelta(hours=24)
    if start.tzinfo is None or start.utcoffset() is None or end.tzinfo is None or end.utcoffset() is None:
        raise HTTPException(422, detail={"code": "invalid_request", "message": "Timestamps require UTC offsets"})
    start = start.astimezone(timezone.utc)
    end = end.astimezone(timezone.utc)
    if start > end or end - start > timedelta(days=31):
        raise HTTPException(
            422,
            detail={
                "code": "invalid_request",
                "message": "Overview range must be ordered and no longer than 31 days",
                "field": "start_time",
            },
        )
    repository: EventRepository = request.app.state.event_repository
    return repository.overview(start, end)
