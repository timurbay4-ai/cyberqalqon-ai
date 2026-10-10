"""Administrator-only security audit evidence API."""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query, Request

from app.api.dependencies.auth import require_analyst_admin
from app.schemas.audit import SecurityAuditPage
from app.schemas.auth import AnalystPrincipal


router = APIRouter(prefix="/api/v1/audit-events", tags=["Security audit"])


@router.get("", response_model=SecurityAuditPage)
async def list_audit_events(
    request: Request,
    _: Annotated[AnalystPrincipal, Depends(require_analyst_admin)],
    action: Annotated[str | None, Query(min_length=1, max_length=100)] = None,
    actor_id: Annotated[str | None, Query(min_length=1, max_length=64)] = None,
    target_type: Annotated[str | None, Query(min_length=1, max_length=64)] = None,
    outcome: Annotated[Literal["SUCCESS", "DENIED", "FAILURE"] | None, Query()] = None,
    search: Annotated[str | None, Query(min_length=1, max_length=200)] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 100,
) -> SecurityAuditPage:
    items = request.app.state.audit_repository.list(
        action=action.strip() if action else None,
        actor_id=actor_id.strip() if actor_id else None,
        target_type=target_type.strip() if target_type else None,
        outcome=outcome,
        search=search.strip() if search else None,
        limit=limit,
    )
    return SecurityAuditPage(items=items, limit=limit)
