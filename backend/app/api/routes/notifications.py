"""Per-user notification center APIs."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status

from app.api.dependencies.auth import require_soc_mutation, require_soc_reader
from app.db.notifications import NotificationNotFoundError, NotificationRepository
from app.schemas.alerts import ErrorResponse
from app.schemas.auth import AnalystPrincipal
from app.schemas.notifications import (
    AnalystNotification,
    NotificationListResponse,
    NotificationReadAllResponse,
)


router = APIRouter(prefix="/api/v1/notifications", tags=["Notifications"])


def _repository(request: Request) -> NotificationRepository:
    return request.app.state.notification_repository


@router.get("", response_model=NotificationListResponse)
async def list_notifications(
    request: Request,
    principal: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
    unread_only: Annotated[bool, Query()] = False,
) -> NotificationListResponse:
    items, unread_count = _repository(request).list(
        principal.analyst_id,
        limit=limit,
        unread_only=unread_only,
    )
    return NotificationListResponse(items=items, unread_count=unread_count, limit=limit)


@router.patch(
    "/{notification_id}/read",
    response_model=AnalystNotification,
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
)
async def mark_notification_read(
    request: Request,
    principal: Annotated[AnalystPrincipal, Depends(require_soc_mutation)],
    notification_id: Annotated[str, Path(min_length=1, max_length=64)],
) -> AnalystNotification:
    try:
        return _repository(request).mark_read(notification_id, principal)
    except NotificationNotFoundError as exc:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            detail={
                "code": "notification_not_found",
                "message": "No notification exists for this analyst",
                "field": "notification_id",
            },
        ) from exc


@router.post("/read-all", response_model=NotificationReadAllResponse)
async def mark_all_notifications_read(
    request: Request,
    principal: Annotated[AnalystPrincipal, Depends(require_soc_mutation)],
) -> NotificationReadAllResponse:
    updated = _repository(request).mark_all_read(principal)
    return NotificationReadAllResponse(updated_count=updated)
