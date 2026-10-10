"""Authenticated machine ingestion and analyst search for security events."""

from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, Response, status
from pydantic import Field

from app.api.dependencies.auth import require_authenticated_mutation, require_soc_reader
from app.api.routes.alerts import _read_json_object, require_ingest_key
from app.db.events import (
    EventFilters,
    EventIdConflictError,
    EventOutsideRetentionError,
    EventRepository,
    InvalidEventCursorError,
    DuplicateSavedSearchError,
    SavedSearchLimitError,
    SavedSearchNotFoundError,
)
from app.schemas.alerts import ErrorResponse
from app.schemas.auth import AnalystPrincipal
from app.schemas.events import (
    EventSort,
    EventSourceType,
    SecurityEventDetail,
    SecurityEventIngestResponse,
    SecurityEventListResponse,
    SecurityEventPage,
    SavedEventSearch,
    SavedEventSearchCreate,
    SavedEventSearchUpdate,
)
from app.services.event_normalizer import (
    EventNormalizationError,
    encoded_event_size,
    normalize_wazuh_event,
)


router = APIRouter(prefix="/api/v1/events", tags=["Security Events"])
Severity = Annotated[int, Field(ge=0, le=16)]


def _error(code: str, message: str, *, field: str | None = None) -> dict[str, Any]:
    body: dict[str, Any] = {"code": code, "message": message}
    if field:
        body["field"] = field
    return body


def _utc(value: datetime | None, field: str) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        raise HTTPException(
            status_code=422,
            detail=_error("invalid_request", "Timestamp must include a UTC offset", field=field),
        )
    return value.astimezone(timezone.utc)


def _nonblank(value: str | None, field: str) -> str | None:
    if value is None:
        return None
    result = value.strip()
    if not result:
        raise HTTPException(
            status_code=422,
            detail=_error("invalid_request", f"{field} must not be blank", field=field),
        )
    return result


def _ip(value: str | None, field: str) -> str | None:
    normalized = _nonblank(value, field)
    if normalized is None:
        return None
    try:
        return str(ipaddress.ip_address(normalized))
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail=_error("invalid_request", "Invalid IP address", field=field),
        ) from exc


@router.post(
    "/ingest",
    response_model=SecurityEventIngestResponse,
    status_code=status.HTTP_201_CREATED,
    response_model_exclude_none=True,
    summary="Normalize and persist one bounded Wazuh archive event",
    responses={
        400: {"model": ErrorResponse},
        401: {"model": ErrorResponse},
        409: {"model": ErrorResponse},
        413: {"model": ErrorResponse},
        415: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
    },
)
async def ingest_event(
    request: Request,
    response: Response,
    _: Annotated[None, Depends(require_ingest_key)],
) -> SecurityEventIngestResponse:
    maximum = request.app.state.settings.max_event_ingest_bytes
    payload = await _read_json_object(request, maximum)
    size = encoded_event_size(payload)
    if size > maximum:
        raise HTTPException(
            status_code=413,
            detail=_error(
                "payload_too_large",
                f"Request payload is {size} bytes; maximum is {maximum} bytes",
            ),
        )
    try:
        normalized = normalize_wazuh_event(payload)
    except EventNormalizationError as exc:
        raise HTTPException(
            status_code=422,
            detail=_error("invalid_security_event", exc.message, field=exc.field),
        ) from exc
    repository: EventRepository = request.app.state.event_repository
    try:
        stored = repository.ingest(normalized)
    except EventOutsideRetentionError as exc:
        raise HTTPException(
            status_code=422,
            detail=_error("outside_retention_window", str(exc), field="timestamp"),
        ) from exc
    except EventIdConflictError as exc:
        raise HTTPException(
            status_code=409,
            detail=_error("event_id_conflict", str(exc), field="event_id"),
        ) from exc
    if stored.duplicate:
        response.status_code = status.HTTP_200_OK
    return SecurityEventIngestResponse(
        status="duplicate" if stored.duplicate else "created",
        duplicate=stored.duplicate,
        event=stored.event,
    )


@router.get(
    "",
    response_model=SecurityEventListResponse,
    response_model_exclude_none=True,
    summary="Search the bounded security-event store",
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}, 422: {"model": ErrorResponse}},
)
async def list_events(
    request: Request,
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
    start_time: Annotated[datetime | None, Query()] = None,
    end_time: Annotated[datetime | None, Query()] = None,
    source_ip: Annotated[str | None, Query(max_length=64)] = None,
    destination_ip: Annotated[str | None, Query(max_length=64)] = None,
    hostname: Annotated[str | None, Query(max_length=255)] = None,
    username: Annotated[str | None, Query(max_length=512)] = None,
    event_id: Annotated[str | None, Query(max_length=255)] = None,
    rule_id: Annotated[str | None, Query(max_length=128)] = None,
    event_category: Annotated[str | None, Query(max_length=255)] = None,
    outcome: Annotated[str | None, Query(max_length=128)] = None,
    severity_min: Annotated[Severity | None, Query()] = None,
    severity_max: Annotated[Severity | None, Query()] = None,
    source_type: Annotated[EventSourceType | None, Query()] = None,
    search: Annotated[str | None, Query(max_length=200)] = None,
    related_alert_id: Annotated[str | None, Query(max_length=255)] = None,
    sort: EventSort = "newest",
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    cursor: Annotated[str | None, Query(min_length=1, max_length=2048)] = None,
) -> SecurityEventListResponse:
    start = _utc(start_time, "start_time")
    end = _utc(end_time, "end_time")
    if start and end and start > end:
        raise HTTPException(
            status_code=422,
            detail=_error("invalid_request", "start_time must not exceed end_time", field="start_time"),
        )
    if start and end and end - start > timedelta(days=31):
        raise HTTPException(
            status_code=422,
            detail=_error("invalid_request", "time range must not exceed 31 days", field="start_time"),
        )
    if severity_min is not None and severity_max is not None and severity_min > severity_max:
        raise HTTPException(
            status_code=422,
            detail=_error("invalid_request", "severity_min must not exceed severity_max", field="severity_min"),
        )
    filters = EventFilters(
        start_time=start,
        end_time=end,
        source_ip=_ip(source_ip, "source_ip"),
        destination_ip=_ip(destination_ip, "destination_ip"),
        hostname=_nonblank(hostname, "hostname"),
        username=_nonblank(username, "username"),
        event_identifier=_nonblank(event_id, "event_id"),
        rule_id=_nonblank(rule_id, "rule_id"),
        event_category=_nonblank(event_category, "event_category"),
        outcome=_nonblank(outcome, "outcome"),
        severity_min=severity_min,
        severity_max=severity_max,
        source_type=source_type,
        keyword=_nonblank(search, "search"),
        related_alert_id=_nonblank(related_alert_id, "related_alert_id"),
    )
    repository: EventRepository = request.app.state.event_repository
    try:
        result = repository.list(filters, limit=limit, sort=sort, cursor=cursor)
    except InvalidEventCursorError as exc:
        raise HTTPException(
            status_code=422,
            detail=_error("invalid_cursor", str(exc), field="cursor"),
        ) from exc
    return SecurityEventListResponse(
        items=result.items,
        page=SecurityEventPage(
            limit=limit,
            next_cursor=result.next_cursor,
            total=result.total,
            sort=sort,
        ),
    )


@router.get(
    "/saved-searches",
    response_model=list[SavedEventSearch],
    summary="List saved Discover searches owned by the current analyst",
)
async def list_saved_searches(
    request: Request,
    principal: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
) -> list[SavedEventSearch]:
    return request.app.state.event_repository.list_saved_searches(principal.analyst_id)


@router.post(
    "/saved-searches",
    response_model=SavedEventSearch,
    status_code=status.HTTP_201_CREATED,
    summary="Save a validated Discover search for the current analyst",
)
async def create_saved_search(
    request: Request,
    payload: SavedEventSearchCreate,
    principal: Annotated[AnalystPrincipal, Depends(require_authenticated_mutation)],
) -> SavedEventSearch:
    try:
        saved = request.app.state.event_repository.create_saved_search(principal.analyst_id, payload)
    except DuplicateSavedSearchError as exc:
        raise HTTPException(409, detail=_error("saved_search_exists", "A saved search with this name already exists", field="name")) from exc
    except SavedSearchLimitError as exc:
        raise HTTPException(409, detail=_error("saved_search_limit", str(exc))) from exc
    request.app.state.audit_repository.append(
        action="SAVED_SEARCH_CREATED", actor_id=principal.analyst_id,
        actor_display=principal.audit_display, target_type="saved_search",
        target_id=saved.saved_search_id, details={"name": saved.name},
    )
    return saved


@router.patch(
    "/saved-searches/{saved_search_id}",
    response_model=SavedEventSearch,
    summary="Replace one owned saved Discover search",
)
async def update_saved_search(
    request: Request,
    payload: SavedEventSearchUpdate,
    saved_search_id: Annotated[str, Path(min_length=1, max_length=64)],
    principal: Annotated[AnalystPrincipal, Depends(require_authenticated_mutation)],
) -> SavedEventSearch:
    try:
        saved = request.app.state.event_repository.update_saved_search(
            principal.analyst_id, saved_search_id, payload
        )
    except DuplicateSavedSearchError as exc:
        raise HTTPException(409, detail=_error("saved_search_exists", "A saved search with this name already exists", field="name")) from exc
    except SavedSearchNotFoundError as exc:
        raise HTTPException(404, detail=_error("saved_search_not_found", "No owned saved search has this identifier", field="saved_search_id")) from exc
    request.app.state.audit_repository.append(
        action="SAVED_SEARCH_UPDATED", actor_id=principal.analyst_id,
        actor_display=principal.audit_display, target_type="saved_search",
        target_id=saved.saved_search_id, details={"name": saved.name},
    )
    return saved


@router.delete(
    "/saved-searches/{saved_search_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    response_model=None,
    summary="Delete one owned saved Discover search",
)
async def delete_saved_search(
    request: Request,
    saved_search_id: Annotated[str, Path(min_length=1, max_length=64)],
    principal: Annotated[AnalystPrincipal, Depends(require_authenticated_mutation)],
) -> Response:
    try:
        request.app.state.event_repository.delete_saved_search(principal.analyst_id, saved_search_id)
    except SavedSearchNotFoundError as exc:
        raise HTTPException(404, detail=_error("saved_search_not_found", "No owned saved search has this identifier", field="saved_search_id")) from exc
    request.app.state.audit_repository.append(
        action="SAVED_SEARCH_DELETED", actor_id=principal.analyst_id,
        actor_display=principal.audit_display, target_type="saved_search",
        target_id=saved_search_id,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/{event_id}",
    response_model=SecurityEventDetail,
    response_model_exclude_none=True,
    summary="Get redacted structured evidence for one security event",
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
)
async def get_event(
    request: Request,
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
    event_id: Annotated[str, Path(min_length=1, max_length=64)],
) -> SecurityEventDetail:
    repository: EventRepository = request.app.state.event_repository
    event = repository.get(event_id)
    if event is None:
        raise HTTPException(
            status_code=404,
            detail=_error("event_not_found", "No security event has this identifier", field="event_id"),
        )
    return event
