"""Alert ingestion and deterministic read APIs."""

from __future__ import annotations

import hmac
import json
import logging
import time
from datetime import datetime, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException, Path, Query, Request, Response, status
from starlette.requests import ClientDisconnect
from pydantic import Field

from app.api.dependencies.auth import require_soc_reader
from app.db.alerts import (
    AlertFilters,
    AlertIdConflictError,
    AlertRepository,
    InvalidAlertCursorError,
)
from app.schemas.alerts import AlertIngestResponse, AlertListResponse, AlertPage, ErrorResponse, NormalizedAlert
from app.schemas.auth import AnalystPrincipal
from app.services.wazuh_normalizer import (
    MITRE_ID_PATTERN,
    AlertNormalizationError,
    normalize_wazuh_alert,
    raw_event_fingerprint,
    raw_event_size,
)
from app.services.event_normalizer import normalize_wazuh_event


router = APIRouter(prefix="/api/v1/alerts", tags=["Alerts"])
LOGGER = logging.getLogger(__name__)
RuleLevel = Annotated[int, Field(ge=0, le=16)]


def _error(code: str, message: str, *, field: str | None = None) -> dict[str, Any]:
    body: dict[str, Any] = {"code": code, "message": message}
    if field is not None:
        body["field"] = field
    return body


def _payload_too_large(size: int, maximum: int) -> HTTPException:
    return HTTPException(
        status_code=413,
        detail=_error(
            "payload_too_large",
            f"Request payload is {size} bytes; maximum is {maximum} bytes",
        ),
    )


async def _read_json_object(request: Request, maximum: int) -> dict[str, Any]:
    content_type = request.headers.get("content-type", "").partition(";")[0].strip().lower()
    if content_type != "application/json":
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail=_error("unsupported_media_type", "Content-Type must be application/json"),
        )

    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            declared_size = int(content_length)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=_error("invalid_content_length", "Content-Length must be an integer"),
            ) from exc
        if declared_size > maximum:
            raise _payload_too_large(declared_size, maximum)

    chunks: list[bytes] = []
    received = 0
    try:
        async for chunk in request.stream():
            received += len(chunk)
            if received > maximum:
                raise _payload_too_large(received, maximum)
            chunks.append(chunk)
    except ClientDisconnect as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=_error("client_disconnected", "The request body was not received completely"),
        ) from exc

    try:
        payload = json.loads(b"".join(chunks))
    except (ValueError, UnicodeDecodeError, RecursionError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=_error("invalid_json", "Request body must contain valid UTF-8 JSON"),
        ) from exc
    if not isinstance(payload, dict):
        raise HTTPException(
            status_code=422,
            detail=_error("invalid_wazuh_alert", "payload must be a JSON object"),
        )
    return payload


def require_ingest_key(
    request: Request,
    x_api_key: Annotated[str | None, Header()] = None,
) -> None:
    auth_started = time.monotonic()
    from app.services.request_tracing import span
    try:
        with span("INGEST_AUTH"):
            expected_key = request.app.state.settings.wazuh_ingest_api_key
            if expected_key is None:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail=_error(
                        "ingestion_not_configured",
                        "Wazuh ingestion is disabled until WAZUH_INGEST_API_KEY is configured",
                    ),
                )
            if x_api_key is None or not hmac.compare_digest(x_api_key, expected_key):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=_error("invalid_api_key", "A valid X-API-Key header is required"),
                    headers={"WWW-Authenticate": "ApiKey"},
                )
    finally:
        request.state.ingest_auth_ms = round(
            (time.monotonic() - auth_started) * 1000, 3
        )


@router.post(
    "/ingest",
    response_model=AlertIngestResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Normalize and persist one Wazuh alert",
    responses={
        400: {"model": ErrorResponse},
        401: {"model": ErrorResponse},
        409: {"model": ErrorResponse},
        413: {"model": ErrorResponse},
        415: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
        503: {"model": ErrorResponse},
    },
    response_model_exclude_none=True,
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/json": {
                    "schema": {"type": "object", "additionalProperties": True}
                }
            },
        }
    },
)
async def ingest_alert(
    request: Request,
    response: Response,
    _: Annotated[None, Depends(require_ingest_key)],
) -> AlertIngestResponse:
    settings = request.app.state.settings
    payload = await _read_json_object(request, settings.max_ingest_bytes)
    if (size := raw_event_size(payload)) > settings.max_ingest_bytes:
        raise _payload_too_large(size, settings.max_ingest_bytes)

    try:
        normalized = normalize_wazuh_alert(payload)
    except AlertNormalizationError as exc:
        raise HTTPException(
            status_code=422,
            detail=_error("invalid_wazuh_alert", exc.message, field=exc.field),
        ) from exc

    repository: AlertRepository = request.app.state.alert_repository
    try:
        stored = repository.ingest(normalized, payload, raw_event_fingerprint(payload))
    except AlertIdConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=_error("alert_id_conflict", str(exc), field="alert_id"),
        ) from exc

    if stored.duplicate:
        response.status_code = status.HTTP_200_OK
    else:
        try:
            request.app.state.correlation_engine.correlate(stored.alert.alert_id)
        except Exception:
            alert_digest = hmac.new(
                b"cyberqalqon-correlation-log-v1",
                stored.alert.alert_id.encode("utf-8"),
                "sha256",
            ).hexdigest()[:16]
            LOGGER.exception(
                "incident correlation failed after alert persistence (alert_digest=%s)",
                alert_digest,
            )
    try:
        security_event = normalize_wazuh_event(payload, ingestion_source="wazuh_alert")
        request.app.state.event_repository.ingest(
            security_event,
            related_alert_id=stored.alert.alert_id,
        )
    except Exception:
        alert_digest = hmac.new(
            b"cyberqalqon-event-store-log-v1",
            stored.alert.alert_id.encode("utf-8"),
            "sha256",
        ).hexdigest()[:16]
        LOGGER.exception(
            "security-event projection failed after alert persistence (alert_digest=%s)",
            alert_digest,
        )
    return AlertIngestResponse(
        status="duplicate" if stored.duplicate else "created",
        duplicate=stored.duplicate,
        ingested_at=stored.ingested_at,
        alert=stored.alert,
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
    response_model=AlertListResponse,
    summary="List normalized alerts",
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}, 422: {"model": ErrorResponse}},
)
async def list_alerts(
    request: Request,
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
    rule_level: Annotated[list[RuleLevel] | None, Query()] = None,
    rule_id: Annotated[str | None, Query(min_length=1, max_length=128)] = None,
    agent: Annotated[str | None, Query(min_length=1, max_length=255)] = None,
    mitre_mapped: Annotated[bool | None, Query()] = None,
    mitre_id: Annotated[str | None, Query(min_length=5, max_length=9)] = None,
    start_time: Annotated[datetime | None, Query()] = None,
    end_time: Annotated[datetime | None, Query()] = None,
    search: Annotated[str | None, Query(min_length=1, max_length=200)] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    cursor: Annotated[str | None, Query(min_length=1, max_length=2048)] = None,
) -> AlertListResponse:
    normalized_start = _normalized_time(start_time, "start_time")
    normalized_end = _normalized_time(end_time, "end_time")
    if normalized_start and normalized_end and normalized_start > normalized_end:
        raise HTTPException(
            status_code=422,
            detail=_error(
                "invalid_request",
                "start_time must be less than or equal to end_time",
                field="start_time",
            ),
        )

    normalized_mitre_id = mitre_id.strip().upper() if mitre_id else None
    if normalized_mitre_id and not MITRE_ID_PATTERN.fullmatch(normalized_mitre_id):
        raise HTTPException(
            status_code=422,
            detail=_error("invalid_request", "Invalid MITRE ATT&CK technique ID", field="mitre_id"),
        )
    normalized_rule_id = rule_id.strip() if rule_id else None
    normalized_agent = agent.strip() if agent else None
    normalized_search = search.strip() if search else None
    if rule_id is not None and not normalized_rule_id:
        raise HTTPException(
            status_code=422,
            detail=_error("invalid_request", "rule_id must not be blank", field="rule_id"),
        )
    if agent is not None and not normalized_agent:
        raise HTTPException(
            status_code=422,
            detail=_error("invalid_request", "agent must not be blank", field="agent"),
        )
    if search is not None and not normalized_search:
        raise HTTPException(
            status_code=422,
            detail=_error("invalid_request", "search must not be blank", field="search"),
        )

    repository: AlertRepository = request.app.state.alert_repository
    try:
        result = repository.list(
            AlertFilters(
                rule_levels=tuple(sorted(set(rule_level or []))),
                rule_id=normalized_rule_id,
                agent=normalized_agent,
                mitre_mapped=mitre_mapped,
                mitre_id=normalized_mitre_id,
                start_time=normalized_start,
                end_time=normalized_end,
                search=normalized_search,
            ),
            limit=limit,
            cursor=cursor,
        )
    except InvalidAlertCursorError as exc:
        raise HTTPException(
            status_code=422,
            detail=_error("invalid_cursor", str(exc), field="cursor"),
        ) from exc

    return AlertListResponse(
        items=result.items,
        page=AlertPage(limit=limit, next_cursor=result.next_cursor, total=result.total),
    )


@router.get(
    "/{alert_id}",
    response_model=NormalizedAlert,
    summary="Get one normalized alert",
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}, 404: {"model": ErrorResponse}, 422: {"model": ErrorResponse}},
    response_model_exclude_none=True,
)
async def get_alert(
    request: Request,
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
    alert_id: Annotated[str, Path(min_length=1, max_length=255)],
) -> NormalizedAlert:
    repository: AlertRepository = request.app.state.alert_repository
    alert = repository.get(alert_id)
    if alert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=_error(
                "alert_not_found",
                "No alert exists with the requested identifier",
                field="alert_id",
            ),
        )
    return alert
