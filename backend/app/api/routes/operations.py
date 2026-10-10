"""Authenticated read-only operational diagnostics."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request

from app.api.dependencies.auth import require_soc_reader
from app.schemas.auth import AnalystPrincipal
from app.schemas.operations import OperationalOverview


router = APIRouter(prefix="/api/v1/operations", tags=["Operations"])


@router.get("/overview", response_model=OperationalOverview)
async def operational_overview(
    request: Request,
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
    event_limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> OperationalOverview:
    return request.app.state.operational_repository.overview(limit=event_limit)
