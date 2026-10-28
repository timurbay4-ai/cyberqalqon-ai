"""Authenticated machine ingestion and analyst search for security events."""

from __future__ import annotations

import ipaddress
import json
import logging
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, Response, status
from pydantic import Field, ValidationError
from starlette.concurrency import run_in_threadpool

from app.api.dependencies.auth import require_authenticated_mutation, require_soc_reader
from app.api.routes.alerts import _read_json_object, require_ingest_key
from app.db.events import (
    BatchItemConflictError,
    BatchItemValidationError,
    BatchProcessingTimeoutError,
    EventFilters,
    EventIdConflictError,
    EventOutsideRetentionError,
    RetentionCapacityError,
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
    SecurityEventBatchErrorItem,
    SecurityEventBatchErrorResponse,
    SecurityEventBatchIngestResponse,
    SecurityEventBatchItemResult,
    SecurityEventBatchRequest,
    SecurityEventBatchTiming,
    SecurityEventIngestResponse,
    SecurityEventListResponse,
    SecurityEventPage,
    SavedEventSearch,
    SavedEventSearchCreate,
    SavedEventSearchUpdate,
    TelemetryCoverageReport,
)
from app.services.event_normalizer import (
    EventNormalizationError,
    encoded_event_size,
    normalize_wazuh_event,
)
from app.services.source_adapters import SourceContext
from app.services.request_tracing import span, traced_threadpool


router = APIRouter(prefix="/api/v1/events", tags=["Security Events"])
Severity = Annotated[int, Field(ge=0, le=16)]
LOGGER = logging.getLogger(__name__)


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
    request_started = time.monotonic()
    maximum = request.app.state.settings.max_event_ingest_bytes
    with span("INGEST_BODY_VALIDATION"):
        payload = await _read_json_object(request, maximum)
    try:
        with span("INGEST_ENCODING_VALIDATION"):
            size = encoded_event_size(payload)
    except (UnicodeError, RecursionError, ValueError) as exc:
        raise HTTPException(422, detail=_error("invalid_security_event", "Payload encoding is invalid")) from exc
    if size > maximum:
        raise HTTPException(
            status_code=413,
            detail=_error(
                "payload_too_large",
                f"Request payload is {size} bytes; maximum is {maximum} bytes",
            ),
        )
    try:
        request.app.state.ingestion_metrics.record_normalization("RECEIVED")
        with span("INGEST_NORMALIZATION"):
            normalized = normalize_wazuh_event(
                payload, context=SourceContext(transport_authenticated=True)
            )
    except EventNormalizationError as exc:
        request.app.state.ingestion_metrics.record_normalization(exc.code)
        request.app.state.ingestion_metrics.record_failure(
            retryable=False, code="invalid_security_event"
        )
        raise HTTPException(
            status_code=422,
            detail=_error("invalid_security_event", exc.message, field=exc.field),
        ) from exc
    cuse = normalized.structured_payload["_cuse"]
    request.app.state.ingestion_metrics.record_normalization(
        cuse["normalization_status"], cuse["source_family"]
    )
    repository: EventRepository = request.app.state.event_repository
    database_started = time.monotonic()
    try:
        # sqlite3 work is synchronous. Running it on the ASGI event loop would
        # queue even the dependency-free /health endpoint behind retention and
        # commit latency. Each repository call owns its SQLite connection, so
        # the bounded Starlette worker thread preserves transaction semantics.
        stored = await traced_threadpool(repository.ingest, normalized)
    except EventOutsideRetentionError as exc:
        request.app.state.ingestion_metrics.record_failure(
            retryable=False, code="outside_retention_window"
        )
        raise HTTPException(
            status_code=422,
            detail=_error("outside_retention_window", str(exc), field="timestamp"),
        ) from exc
    except EventIdConflictError as exc:
        request.app.state.ingestion_metrics.record_failure(
            retryable=False, code="event_id_conflict"
        )
        raise HTTPException(
            status_code=409,
            detail=_error("event_id_conflict", str(exc), field="event_id"),
        ) from exc
    except RetentionCapacityError as exc:
        request.app.state.ingestion_metrics.record_failure(
            retryable=True, code="retention_capacity_exhausted"
        )
        raise HTTPException(503, detail=_error(
            "retention_capacity_exhausted", "Protected evidence exhausts event retention capacity"
        ), headers={"Retry-After": "5"}) from exc
    except (sqlite3.OperationalError, sqlite3.IntegrityError) as exc:
        request.app.state.ingestion_metrics.record_failure(
            retryable=True, code="database_temporarily_unavailable"
        )
        raise HTTPException(503, detail=_error(
            "database_temporarily_unavailable", "Event storage is temporarily unavailable"
        )) from exc
    database_ms = (time.monotonic() - database_started) * 1000
    request.app.state.ingestion_metrics.record_success(
        mode="single",
        events=1,
        inserted=0 if stored.duplicate else 1,
        duplicates=1 if stored.duplicate else 0,
        request_ms=(time.monotonic() - request_started) * 1000,
        database_ms=database_ms,
    )
    if stored.duplicate:
        response.status_code = status.HTTP_200_OK
    return SecurityEventIngestResponse(
        status="duplicate" if stored.duplicate else "created",
        duplicate=stored.duplicate,
        event=stored.event,
    )


def _batch_failure_detail(
    *,
    code: str,
    message: str,
    batch_id: str | None,
    item_count: int,
    outcome: str,
    failing_index: int | None = None,
    field: str | None = None,
) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    for index in range(item_count):
        item_outcome = (
            outcome
            if failing_index is None or index == failing_index
            else "NOT_PROCESSED"
        )
        item = SecurityEventBatchErrorItem(
            index=index,
            outcome=item_outcome,
            code=code if failing_index is None or index == failing_index else None,
            field=field if index == failing_index else None,
        )
        results.append(item.model_dump(exclude_none=True))
    return {
        "code": code,
        "message": message,
        "batch_id": batch_id,
        "atomic": True,
        "results": results,
    }


@router.post(
    "/ingest-batch",
    response_model=SecurityEventBatchIngestResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Atomically persist one bounded M18 security-event batch",
    description=(
        "Feature-gated atomic whole-batch protocol. No event is acknowledged "
        "before the SQLite transaction commits durably."
    ),
    responses={
        200: {"model": SecurityEventBatchIngestResponse},
        400: {"model": ErrorResponse},
        401: {"model": ErrorResponse},
        409: {"model": SecurityEventBatchErrorResponse},
        413: {"model": ErrorResponse | SecurityEventBatchErrorResponse},
        415: {"model": ErrorResponse},
        422: {"model": SecurityEventBatchErrorResponse},
        503: {"model": SecurityEventBatchErrorResponse},
    },
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "required": ["protocol_version", "batch_id", "events"],
                        "additionalProperties": False,
                        "properties": {
                            "protocol_version": {
                                "type": "string",
                                "const": "m18-batch-v1",
                            },
                            "batch_id": {"type": "string", "maxLength": 128},
                            "events": {
                                "type": "array",
                                "minItems": 1,
                                "maxItems": 100,
                                "items": {
                                    "type": "object",
                                    "additionalProperties": True,
                                },
                            },
                        },
                    }
                }
            },
        }
    },
)
async def ingest_event_batch(
    request: Request,
    response: Response,
    _: Annotated[None, Depends(require_ingest_key)],
) -> SecurityEventBatchIngestResponse:
    request_started = time.monotonic()
    request_received = getattr(
        request.state, "request_received_monotonic", request_started
    )
    request_reception_ms = max(0.0, (request_started - request_received) * 1000)
    authentication_ms = max(0.0, float(getattr(request.state, "ingest_auth_ms", 0.0)))
    settings = request.app.state.settings
    metrics = request.app.state.ingestion_metrics
    if not settings.event_batch_ingest_enabled:
        metrics.record_failure(retryable=True, code="batch_ingestion_disabled")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=_batch_failure_detail(
                code="batch_ingestion_disabled",
                message="M18 batch ingestion is disabled by the deployment feature gate",
                batch_id=None,
                item_count=0,
                outcome="RETRYABLE_FAILURE",
            ),
        )

    raw_envelope = await _read_json_object(request, settings.event_batch_max_bytes)
    parsed_at = time.monotonic()
    raw_events = raw_envelope.get("events")
    if (
        isinstance(raw_events, list)
        and len(raw_events) > settings.event_batch_max_events
    ):
        metrics.record_failure(retryable=False, code="batch_event_limit_exceeded")
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=_batch_failure_detail(
                code="batch_event_limit_exceeded",
                message=(
                    f"Batch contains {len(raw_events)} events; configured maximum "
                    f"is {settings.event_batch_max_events}"
                ),
                batch_id=None,
                item_count=0,
                outcome="PERMANENTLY_INVALID",
            ),
        )
    schema_validation_started = time.monotonic()
    try:
        envelope = SecurityEventBatchRequest.model_validate(raw_envelope)
    except ValidationError as exc:
        metrics.record_failure(retryable=False, code="invalid_batch_envelope")
        first = exc.errors()[0] if exc.errors() else {}
        location = first.get("loc", ())
        field = ".".join(str(part) for part in location) or None
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=_batch_failure_detail(
                code="invalid_batch_envelope",
                message=str(first.get("msg", "Batch envelope validation failed")),
                batch_id=None,
                item_count=0,
                outcome="PERMANENTLY_INVALID",
                field=field,
            ),
        ) from exc
    schema_validation_ms = (time.monotonic() - schema_validation_started) * 1000
    if len(envelope.events) > settings.event_batch_max_events:
        metrics.record_failure(retryable=False, code="batch_event_limit_exceeded")
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=_batch_failure_detail(
                code="batch_event_limit_exceeded",
                message=(
                    f"Batch contains {len(envelope.events)} events; configured maximum "
                    f"is {settings.event_batch_max_events}"
                ),
                batch_id=envelope.batch_id,
                item_count=len(envelope.events),
                outcome="PERMANENTLY_INVALID",
            ),
        )

    normalization_started = time.monotonic()
    normalized_events = []
    for index, payload in enumerate(envelope.events):
        size = encoded_event_size(payload)
        if size > settings.max_event_ingest_bytes:
            metrics.record_failure(retryable=False, code="event_payload_too_large")
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=_batch_failure_detail(
                    code="event_payload_too_large",
                    message=(
                        f"Batch event {index} is {size} bytes; maximum is "
                        f"{settings.max_event_ingest_bytes} bytes"
                    ),
                    batch_id=envelope.batch_id,
                    item_count=len(envelope.events),
                    outcome="PERMANENTLY_INVALID",
                    failing_index=index,
                ),
            )
        try:
            normalized_events.append(normalize_wazuh_event(payload))
        except EventNormalizationError as exc:
            metrics.record_failure(retryable=False, code="invalid_security_event")
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=_batch_failure_detail(
                    code="invalid_security_event",
                    message=exc.message,
                    batch_id=envelope.batch_id,
                    item_count=len(envelope.events),
                    outcome="PERMANENTLY_INVALID",
                    failing_index=index,
                    field=exc.field,
                ),
            ) from exc
    normalization_ms = (time.monotonic() - normalization_started) * 1000

    repository: EventRepository = request.app.state.event_repository
    try:
        stored = await run_in_threadpool(
            repository.ingest_batch,
            normalized_events,
            max_processing_seconds=settings.event_batch_processing_timeout_seconds,
        )
    except BatchItemValidationError as exc:
        metrics.record_failure(retryable=False, code="outside_retention_window")
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=_batch_failure_detail(
                code="outside_retention_window",
                message=str(exc),
                batch_id=envelope.batch_id,
                item_count=len(envelope.events),
                outcome="PERMANENTLY_INVALID",
                failing_index=exc.index,
                field=exc.field,
            ),
        ) from exc
    except BatchItemConflictError as exc:
        metrics.record_failure(retryable=False, code="event_id_conflict")
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=_batch_failure_detail(
                code="event_id_conflict",
                message=str(exc),
                batch_id=envelope.batch_id,
                item_count=len(envelope.events),
                outcome="PERMANENTLY_INVALID",
                failing_index=exc.index,
                field="event_id",
            ),
        ) from exc
    except RetentionCapacityError as exc:
        metrics.record_failure(retryable=True, code="retention_capacity_exhausted")
        raise HTTPException(503, detail=_batch_failure_detail(
            code="retention_capacity_exhausted",
            message="Protected evidence exhausts event retention capacity",
            batch_id=envelope.batch_id, item_count=len(envelope.events),
            outcome="RETRYABLE_FAILURE",
        ), headers={"Retry-After": "5"}) from exc
    except BatchProcessingTimeoutError as exc:
        metrics.record_failure(
            retryable=True,
            code="batch_processing_timeout",
            stage=exc.stage,
            timing=exc.timing,
        )
        LOGGER.warning(
            "batch_ingestion_timeout stage=%s timing=%s",
            exc.stage,
            json.dumps(exc.timing, sort_keys=True, separators=(",", ":")),
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=_batch_failure_detail(
                code="batch_processing_timeout",
                message=str(exc),
                batch_id=envelope.batch_id,
                item_count=len(envelope.events),
                outcome="RETRYABLE_FAILURE",
            ),
        ) from exc
    except sqlite3.OperationalError as exc:
        metrics.record_failure(
            retryable=True,
            code="database_temporarily_unavailable",
            stage="sqlite",
        )
        LOGGER.warning(
            "batch_ingestion_sqlite_operational_error code=%s",
            getattr(exc, "sqlite_errorcode", "unknown"),
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=_batch_failure_detail(
                code="database_temporarily_unavailable",
                message="The event store could not acquire a bounded write transaction",
                batch_id=envelope.batch_id,
                item_count=len(envelope.events),
                outcome="RETRYABLE_FAILURE",
            ),
        ) from exc
    except sqlite3.DatabaseError as exc:
        metrics.record_failure(retryable=True, code="database_internal_failure")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=_batch_failure_detail(
                code="database_internal_failure",
                message="The event store transaction failed and was rolled back",
                batch_id=envelope.batch_id,
                item_count=len(envelope.events),
                outcome="RETRYABLE_FAILURE",
            ),
        ) from exc

    total_ms = (time.monotonic() - request_received) * 1000
    metrics.record_success(
        mode="batch",
        events=len(envelope.events),
        inserted=stored.inserted,
        duplicates=stored.duplicates,
        request_ms=total_ms,
        database_ms=stored.database_ms,
        transaction_ms=stored.transaction_ms,
        retention_ms=stored.retention_ms,
        lock_wait_ms=stored.lock_wait_ms,
        commit_ms=stored.commit_ms,
        retention_candidate_ms=stored.retention_candidate_ms,
        protected_check_ms=stored.protected_check_ms,
    )
    if stored.inserted == 0:
        response.status_code = status.HTTP_200_OK
    return SecurityEventBatchIngestResponse(
        batch_id=envelope.batch_id,
        inserted=stored.inserted,
        duplicates=stored.duplicates,
        results=[
            SecurityEventBatchItemResult(
                index=item.index,
                event_id=item.event_id,
                deduplication_id=item.deduplication_id,
                outcome="DUPLICATE" if item.duplicate else "INSERTED",
            )
            for item in stored.items
        ],
        timing_ms=SecurityEventBatchTiming(
            request_reception_ms=round(request_reception_ms, 3),
            authentication_ms=round(authentication_ms, 3),
            request_parse_ms=round((parsed_at - request_started) * 1000, 3),
            schema_validation_ms=round(schema_validation_ms, 3),
            normalization_ms=round(normalization_ms, 3),
            database_ms=stored.database_ms,
            transaction_ms=stored.transaction_ms,
            connection_ms=stored.connection_ms,
            lock_wait_ms=stored.lock_wait_ms,
            deduplication_ms=stored.deduplication_ms,
            alert_lookup_ms=stored.alert_lookup_ms,
            insertion_ms=stored.insert_ms,
            retention_ms=stored.retention_ms,
            retention_state_ms=stored.retention_state_ms,
            retention_age_delete_ms=stored.retention_age_delete_ms,
            retention_count_ms=stored.retention_count_ms,
            retention_candidate_ms=stored.retention_candidate_ms,
            protected_check_ms=stored.protected_check_ms,
            retention_delete_ms=stored.retention_delete_ms,
            protected_count_ms=stored.protected_count_ms,
            retention_metadata_ms=stored.retention_metadata_ms,
            retention_audit_ms=stored.retention_audit_ms,
            commit_ms=stored.commit_ms,
            sql_statement_count=stored.sql_statement_count,
            retention_rows_considered=stored.retention_rows_considered,
            retention_rows_deleted=stored.retention_rows_deleted,
            protected_row_skips=stored.protected_row_skips,
            full_age_sweep=stored.full_age_sweep,
            total_ms=round(total_ms, 3),
        ),
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
    operating_system: Annotated[str | None, Query(max_length=255)] = None,
    event_provider: Annotated[str | None, Query(max_length=255)] = None,
    event_channel: Annotated[str | None, Query(max_length=255)] = None,
    process_name: Annotated[str | None, Query(max_length=1024)] = None,
    event_id: Annotated[str | None, Query(max_length=255)] = None,
    rule_id: Annotated[str | None, Query(max_length=128)] = None,
    event_category: Annotated[str | None, Query(max_length=255)] = None,
    event_action: Annotated[str | None, Query(max_length=255)] = None,
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
        operating_system=_nonblank(operating_system, "operating_system"),
        event_provider=_nonblank(event_provider, "event_provider"),
        event_channel=_nonblank(event_channel, "event_channel"),
        process_name=_nonblank(process_name, "process_name"),
        event_identifier=_nonblank(event_id, "event_id"),
        rule_id=_nonblank(rule_id, "rule_id"),
        event_category=_nonblank(event_category, "event_category"),
        event_action=_nonblank(event_action, "event_action"),
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
    "/coverage",
    response_model=TelemetryCoverageReport,
    response_model_exclude_none=True,
    summary="Report telemetry coverage backed only by stored event evidence",
)
async def get_telemetry_coverage(
    request: Request,
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
    start_time: Annotated[datetime | None, Query()] = None,
    end_time: Annotated[datetime | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 100,
) -> TelemetryCoverageReport:
    end = _utc(end_time, "end_time") or datetime.now(timezone.utc)
    start = _utc(start_time, "start_time") or end - timedelta(hours=24)
    if start > end:
        raise HTTPException(
            status_code=422,
            detail=_error("invalid_request", "start_time must not exceed end_time", field="start_time"),
        )
    if end - start > timedelta(days=31):
        raise HTTPException(
            status_code=422,
            detail=_error("invalid_request", "time range must not exceed 31 days", field="start_time"),
        )
    return request.app.state.event_repository.telemetry_coverage(start, end, limit=limit)


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
