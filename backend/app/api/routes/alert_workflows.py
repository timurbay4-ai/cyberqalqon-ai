"""Authenticated alert triage, history, and bounded bulk APIs."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status
from pydantic import Field

from app.api.dependencies.auth import require_alert_mutation, require_soc_reader
from app.db.alert_workflows import (
    AlertAssigneeNotFoundError,
    AlertBulkValidationError,
    AlertWorkflowConflictError,
    AlertWorkflowFilters,
    AlertWorkflowNoChangeError,
    AlertWorkflowNotFoundError,
    AlertWorkflowRepository,
    InvalidAlertWorkflowCursorError,
    InvalidAlertWorkflowTransitionError,
)
from app.schemas.alert_workflows import (
    AlertAssignee,
    AlertAssignmentUpdate,
    AlertBulkRequest,
    AlertBulkResponse,
    AlertNoteCreate,
    AlertStatusUpdate,
    AlertWorkflowDetail,
    AlertWorkflowListResponse,
    AlertWorkflowPage,
    AlertWorkflowSort,
    AlertWorkflowStatus,
)
from app.schemas.alerts import ErrorResponse
from app.schemas.auth import AnalystPrincipal
from app.services.wazuh_normalizer import MITRE_ID_PATTERN


router = APIRouter(prefix="/api/v1/alert-workflows", tags=["Alert workflows"])
RuleLevel = Annotated[int, Field(ge=0, le=16)]


def _error(code: str, message: str, *, field: str | None = None) -> dict[str, Any]:
    body: dict[str, Any] = {"code": code, "message": message}
    if field is not None:
        body["field"] = field
    return body


def _repository(request: Request) -> AlertWorkflowRepository:
    return request.app.state.alert_workflow_repository


def _not_found() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=_error(
            "alert_not_found",
            "No alert workflow exists with the requested identifier",
            field="alert_id",
        ),
    )


def _normalized_time(value: datetime | None, field: str) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        raise HTTPException(
            status_code=422,
            detail=_error("invalid_request", "Timestamp must include a UTC offset", field=field),
        )
    return value.astimezone(timezone.utc)


@router.get(
    "",
    response_model=AlertWorkflowListResponse,
    summary="List durable alert triage work items",
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}, 422: {"model": ErrorResponse}},
)
async def list_alert_workflows(
    request: Request,
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
    workflow_status: Annotated[list[AlertWorkflowStatus] | None, Query(alias="status")] = None,
    assigned_to: Annotated[str | None, Query(min_length=1, max_length=64)] = None,
    unassigned: Annotated[bool | None, Query()] = None,
    sort: Annotated[AlertWorkflowSort, Query()] = AlertWorkflowSort.TIME_DESC,
    rule_level: Annotated[list[RuleLevel] | None, Query()] = None,
    rule_id: Annotated[str | None, Query(min_length=1, max_length=128)] = None,
    agent: Annotated[str | None, Query(min_length=1, max_length=255)] = None,
    mitre_mapped: Annotated[bool | None, Query()] = None,
    mitre_id: Annotated[str | None, Query(min_length=5, max_length=9)] = None,
    start_time: Annotated[datetime | None, Query()] = None,
    end_time: Annotated[datetime | None, Query()] = None,
    search: Annotated[str | None, Query(min_length=1, max_length=200)] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    cursor: Annotated[str | None, Query(min_length=1, max_length=256)] = None,
) -> AlertWorkflowListResponse:
    normalized_start = _normalized_time(start_time, "start_time")
    normalized_end = _normalized_time(end_time, "end_time")
    if normalized_start and normalized_end and normalized_start > normalized_end:
        raise HTTPException(
            422,
            detail=_error(
                "invalid_request",
                "start_time must be less than or equal to end_time",
                field="start_time",
            ),
        )
    normalized_mitre = mitre_id.strip().upper() if mitre_id else None
    if normalized_mitre and not MITRE_ID_PATTERN.fullmatch(normalized_mitre):
        raise HTTPException(
            422,
            detail=_error("invalid_request", "Invalid MITRE ATT&CK technique ID", field="mitre_id"),
        )
    if assigned_to is not None and unassigned is True:
        raise HTTPException(
            422,
            detail=_error(
                "invalid_request",
                "assigned_to and unassigned=true cannot be combined",
                field="unassigned",
            ),
        )
    try:
        result = _repository(request).list(
            AlertWorkflowFilters(
                rule_levels=tuple(sorted(set(rule_level or []))),
                rule_id=rule_id.strip() if rule_id else None,
                agent=agent.strip() if agent else None,
                mitre_mapped=mitre_mapped,
                mitre_id=normalized_mitre,
                start_time=normalized_start,
                end_time=normalized_end,
                search=search.strip() if search else None,
                statuses=tuple(dict.fromkeys(workflow_status or [])),
                assigned_to=assigned_to,
                unassigned=unassigned,
            ),
            limit=limit,
            cursor=cursor,
            sort=sort,
        )
    except InvalidAlertWorkflowCursorError as exc:
        raise HTTPException(
            422,
            detail=_error("invalid_cursor", str(exc), field="cursor"),
        ) from exc
    return AlertWorkflowListResponse(
        items=result.items,
        page=AlertWorkflowPage(
            limit=limit,
            next_cursor=result.next_cursor,
            total=result.total,
            sort=sort,
        ),
        counts=result.counts,
    )


@router.get("/assignees", response_model=list[AlertAssignee])
async def list_alert_assignees(
    request: Request,
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
) -> list[AlertAssignee]:
    return _repository(request).list_active_assignees()


@router.post(
    "/bulk",
    response_model=AlertBulkResponse,
    summary="Apply one bounded transactional alert operation",
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}, 409: {"model": ErrorResponse}, 422: {"model": ErrorResponse}},
)
async def bulk_update_alerts(
    request: Request,
    payload: AlertBulkRequest,
    principal: Annotated[AnalystPrincipal, Depends(require_alert_mutation)],
) -> AlertBulkResponse:
    try:
        return _repository(request).bulk_update(payload, principal)
    except AlertBulkValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "code": "bulk_operation_rejected",
                "message": "No alerts were changed because one or more items failed validation",
                "failures": [failure.model_dump() for failure in exc.failures],
            },
        ) from exc


@router.get(
    "/{alert_id}",
    response_model=AlertWorkflowDetail,
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
)
async def get_alert_workflow(
    request: Request,
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
    alert_id: Annotated[str, Path(min_length=1, max_length=255)],
) -> AlertWorkflowDetail:
    detail = _repository(request).get(alert_id)
    if detail is None:
        raise _not_found()
    return detail


@router.patch(
    "/{alert_id}/status",
    response_model=AlertWorkflowDetail,
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}, 404: {"model": ErrorResponse}, 409: {"model": ErrorResponse}},
)
async def update_alert_status(
    request: Request,
    payload: AlertStatusUpdate,
    principal: Annotated[AnalystPrincipal, Depends(require_alert_mutation)],
    alert_id: Annotated[str, Path(min_length=1, max_length=255)],
) -> AlertWorkflowDetail:
    try:
        return _repository(request).update_status(
            alert_id, payload.status, payload.expected_version, principal
        )
    except AlertWorkflowNotFoundError as exc:
        raise _not_found() from exc
    except AlertWorkflowConflictError as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=_error("version_conflict", str(exc), field="expected_version"),
        ) from exc
    except InvalidAlertWorkflowTransitionError as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=_error("invalid_status_transition", str(exc), field="status"),
        ) from exc


@router.patch(
    "/{alert_id}/assignment",
    response_model=AlertWorkflowDetail,
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}, 404: {"model": ErrorResponse}, 409: {"model": ErrorResponse}},
)
async def update_alert_assignment(
    request: Request,
    payload: AlertAssignmentUpdate,
    principal: Annotated[AnalystPrincipal, Depends(require_alert_mutation)],
    alert_id: Annotated[str, Path(min_length=1, max_length=255)],
) -> AlertWorkflowDetail:
    try:
        return _repository(request).update_assignment(
            alert_id, payload.assigned_to, payload.expected_version, principal
        )
    except AlertWorkflowNotFoundError as exc:
        raise _not_found() from exc
    except AlertAssigneeNotFoundError as exc:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            detail=_error(
                "assignee_not_found",
                "The selected active analyst does not exist",
                field="assigned_to",
            ),
        ) from exc
    except AlertWorkflowConflictError as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=_error("version_conflict", str(exc), field="expected_version"),
        ) from exc
    except AlertWorkflowNoChangeError as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=_error("assignment_unchanged", str(exc), field="assigned_to"),
        ) from exc


@router.post(
    "/{alert_id}/notes",
    response_model=AlertWorkflowDetail,
    status_code=status.HTTP_201_CREATED,
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}, 404: {"model": ErrorResponse}, 409: {"model": ErrorResponse}},
)
async def add_alert_note(
    request: Request,
    payload: AlertNoteCreate,
    principal: Annotated[AnalystPrincipal, Depends(require_alert_mutation)],
    alert_id: Annotated[str, Path(min_length=1, max_length=255)],
) -> AlertWorkflowDetail:
    try:
        return _repository(request).add_note(
            alert_id, payload.body, payload.expected_version, principal
        )
    except AlertWorkflowNotFoundError as exc:
        raise _not_found() from exc
    except AlertWorkflowConflictError as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=_error("version_conflict", str(exc), field="expected_version"),
        ) from exc
