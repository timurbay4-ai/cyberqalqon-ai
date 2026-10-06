"""Deterministic incident lifecycle and audit APIs."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status

from app.api.dependencies.auth import require_incident_mutation, require_soc_reader

from app.db.incidents import (
    DuplicateAlertLinkError,
    IncidentFilters,
    IncidentNoChangeError,
    IncidentNotFoundError,
    IncidentRepository,
    InvalidIncidentCursorError,
    InvalidIncidentTransitionError,
    LinkedAlertNotFoundError,
)
from app.schemas.alerts import ErrorResponse
from app.schemas.auth import AnalystPrincipal
from app.schemas.incidents import (
    IncidentAlertLink,
    IncidentAssignmentUpdate,
    IncidentCreate,
    IncidentDetail,
    IncidentListResponse,
    IncidentNote,
    IncidentNoteCreate,
    IncidentPage,
    IncidentSeverity,
    IncidentStatus,
    IncidentStatusUpdate,
)


router = APIRouter(prefix="/api/v1/incidents", tags=["Incidents"])


def _error(code: str, message: str, *, field: str | None = None) -> dict[str, Any]:
    body: dict[str, Any] = {"code": code, "message": message}
    if field is not None:
        body["field"] = field
    return body


def _repository(request: Request) -> IncidentRepository:
    return request.app.state.incident_repository


def _incident_not_found() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=_error(
            "incident_not_found",
            "No incident exists with the requested identifier",
            field="incident_id",
        ),
    )


def _alert_not_found() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=_error(
            "alert_not_found",
            "No alert exists with the requested identifier",
            field="alert_id",
        ),
    )


@router.post(
    "",
    response_model=IncidentDetail,
    status_code=status.HTTP_201_CREATED,
    summary="Create an incident",
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}, 404: {"model": ErrorResponse}, 422: {"model": ErrorResponse}},
)
async def create_incident(
    request: Request,
    payload: IncidentCreate,
    principal: Annotated[AnalystPrincipal, Depends(require_incident_mutation)],
) -> IncidentDetail:
    try:
        return _repository(request).create(payload, principal)
    except LinkedAlertNotFoundError as exc:
        raise _alert_not_found() from exc


@router.get(
    "",
    response_model=IncidentListResponse,
    summary="List incidents",
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}, 422: {"model": ErrorResponse}},
)
async def list_incidents(
    request: Request,
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
    incident_status: Annotated[
        list[IncidentStatus] | None,
        Query(alias="status"),
    ] = None,
    severity: Annotated[list[IncidentSeverity] | None, Query()] = None,
    assigned_to: Annotated[str | None, Query(min_length=1, max_length=128)] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    cursor: Annotated[str | None, Query(min_length=1, max_length=2048)] = None,
) -> IncidentListResponse:
    normalized_assignee = assigned_to.strip() if assigned_to else None
    if assigned_to is not None and not normalized_assignee:
        raise HTTPException(
            status_code=422,
            detail=_error(
                "invalid_request",
                "assigned_to must not be blank",
                field="assigned_to",
            ),
        )
    try:
        result = _repository(request).list(
            IncidentFilters(
                statuses=tuple(dict.fromkeys(incident_status or [])),
                severities=tuple(dict.fromkeys(severity or [])),
                assigned_to=normalized_assignee,
            ),
            limit=limit,
            cursor=cursor,
        )
    except InvalidIncidentCursorError as exc:
        raise HTTPException(
            status_code=422,
            detail=_error("invalid_cursor", str(exc), field="cursor"),
        ) from exc
    return IncidentListResponse(
        items=result.items,
        page=IncidentPage(limit=limit, next_cursor=result.next_cursor, total=result.total),
    )


@router.get(
    "/{incident_id}",
    response_model=IncidentDetail,
    summary="Get one incident",
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}, 404: {"model": ErrorResponse}, 422: {"model": ErrorResponse}},
)
async def get_incident(
    request: Request,
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
    incident_id: Annotated[str, Path(min_length=1, max_length=64)],
) -> IncidentDetail:
    incident = _repository(request).get(incident_id)
    if incident is None:
        raise _incident_not_found()
    return incident


@router.patch(
    "/{incident_id}/status",
    response_model=IncidentDetail,
    summary="Transition an incident lifecycle status",
    responses={
        401: {"model": ErrorResponse},
        403: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
        409: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
    },
)
async def update_incident_status(
    request: Request,
    payload: IncidentStatusUpdate,
    principal: Annotated[AnalystPrincipal, Depends(require_incident_mutation)],
    incident_id: Annotated[str, Path(min_length=1, max_length=64)],
) -> IncidentDetail:
    try:
        return _repository(request).update_status(incident_id, payload.status, principal)
    except IncidentNotFoundError as exc:
        raise _incident_not_found() from exc
    except InvalidIncidentTransitionError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=_error("invalid_status_transition", str(exc), field="status"),
        ) from exc


@router.post(
    "/{incident_id}/alerts",
    response_model=IncidentDetail,
    status_code=status.HTTP_201_CREATED,
    summary="Link an existing alert to an incident",
    responses={
        401: {"model": ErrorResponse},
        403: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
        409: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
    },
)
async def link_incident_alert(
    request: Request,
    payload: IncidentAlertLink,
    principal: Annotated[AnalystPrincipal, Depends(require_incident_mutation)],
    incident_id: Annotated[str, Path(min_length=1, max_length=64)],
) -> IncidentDetail:
    try:
        return _repository(request).link_alert(incident_id, payload.alert_id, principal)
    except IncidentNotFoundError as exc:
        raise _incident_not_found() from exc
    except LinkedAlertNotFoundError as exc:
        raise _alert_not_found() from exc
    except DuplicateAlertLinkError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=_error(
                "duplicate_alert_link",
                "The alert is already linked to this incident",
                field="alert_id",
            ),
        ) from exc


@router.post(
    "/{incident_id}/notes",
    response_model=IncidentNote,
    status_code=status.HTTP_201_CREATED,
    summary="Add an append-only analyst note",
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}, 404: {"model": ErrorResponse}, 422: {"model": ErrorResponse}},
)
async def add_incident_note(
    request: Request,
    payload: IncidentNoteCreate,
    principal: Annotated[AnalystPrincipal, Depends(require_incident_mutation)],
    incident_id: Annotated[str, Path(min_length=1, max_length=64)],
) -> IncidentNote:
    try:
        return _repository(request).add_note(incident_id, payload.body, principal)
    except IncidentNotFoundError as exc:
        raise _incident_not_found() from exc


@router.patch(
    "/{incident_id}/assignment",
    response_model=IncidentDetail,
    summary="Assign or unassign an incident",
    responses={
        401: {"model": ErrorResponse},
        403: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
        409: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
    },
)
async def update_incident_assignment(
    request: Request,
    payload: IncidentAssignmentUpdate,
    principal: Annotated[AnalystPrincipal, Depends(require_incident_mutation)],
    incident_id: Annotated[str, Path(min_length=1, max_length=64)],
) -> IncidentDetail:
    try:
        return _repository(request).update_assignment(
            incident_id,
            payload.assigned_to,
            principal,
        )
    except IncidentNotFoundError as exc:
        raise _incident_not_found() from exc
    except IncidentNoChangeError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=_error("assignment_unchanged", str(exc), field="assigned_to"),
        ) from exc
