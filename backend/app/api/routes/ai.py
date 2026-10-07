"""Authenticated APIs for bounded advisory AI analysis and history."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status

from app.ai.context import AIContextTooLarge, AITargetNotFound
from app.ai.provider import (
    AIInvalidResponse,
    AIModelUnavailable,
    AIProviderTimeout,
    AIProviderUnavailable,
    AIResponseTooLarge,
)
from app.ai.service import AIBusy, AIDisabled, AIMisconfigured, AIRateLimited, AIService
from app.api.dependencies.auth import require_ai_analysis, require_soc_reader
from app.schemas.ai import (
    AIAnalysisHistory,
    AIAnalysisRecord,
    AIAnalysisRequest,
    AIStatusResponse,
    AITargetType,
)
from app.schemas.alerts import ErrorResponse
from app.schemas.auth import AnalystPrincipal


router = APIRouter(prefix="/api/v1/ai", tags=["AI analyst"])


def _error(code: str, message: str, *, field: str | None = None) -> dict[str, Any]:
    return {"code": code, "message": message, **({"field": field} if field else {})}


def _service(request: Request) -> AIService:
    return request.app.state.ai_service


def _analysis_error(exc: Exception) -> HTTPException:
    if isinstance(exc, AIDisabled):
        return HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, _error("ai_disabled", "AI analysis is disabled"))
    if isinstance(exc, AIMisconfigured):
        return HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, _error("ai_misconfigured", "AI analysis is not configured safely"))
    if isinstance(exc, AIBusy):
        return HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, _error("ai_busy", "Local AI inference capacity is busy"))
    if isinstance(exc, AIRateLimited):
        return HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, _error("ai_rate_limited", "Wait briefly before requesting another analysis"))
    if isinstance(exc, AIProviderTimeout):
        return HTTPException(status.HTTP_504_GATEWAY_TIMEOUT, _error("ai_timeout", "Local AI analysis timed out"))
    if isinstance(exc, AIModelUnavailable):
        return HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, _error("ai_model_unavailable", "The configured local AI model is unavailable"))
    if isinstance(exc, AIResponseTooLarge):
        return HTTPException(status.HTTP_502_BAD_GATEWAY, _error("ai_response_too_large", "Local AI returned an oversized response"))
    if isinstance(exc, AIInvalidResponse):
        return HTTPException(status.HTTP_502_BAD_GATEWAY, _error("ai_invalid_response", "Local AI returned an invalid structured response"))
    if isinstance(exc, AIContextTooLarge):
        return HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, _error("ai_context_too_large", "The selected evidence cannot fit the configured AI context limit"))
    if isinstance(exc, AIProviderUnavailable):
        return HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, _error("ai_unavailable", "Local AI is unavailable"))
    raise exc


async def _analyze(
    request: Request,
    payload: AIAnalysisRequest,
    principal: AnalystPrincipal,
    target_type: AITargetType,
    target_id: str,
) -> AIAnalysisRecord:
    try:
        return await _service(request).analyze(
            target_type=target_type,
            target_id=target_id,
            question=payload.question,
            principal=principal,
        )
    except AITargetNotFound as exc:
        name = target_type.value
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            _error(f"{name}_not_found", f"No {name} exists with the requested identifier", field=f"{name}_id"),
        ) from exc
    except (AIDisabled, AIMisconfigured, AIBusy, AIRateLimited, AIProviderTimeout,
            AIModelUnavailable, AIResponseTooLarge, AIInvalidResponse,
            AIContextTooLarge, AIProviderUnavailable) as exc:
        raise _analysis_error(exc) from exc


@router.get("/status", response_model=AIStatusResponse, responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}})
async def ai_status(
    request: Request,
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
) -> AIStatusResponse:
    return await _service(request).status()


@router.post("/alerts/{alert_id}/analyze", response_model=AIAnalysisRecord, responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}, 404: {"model": ErrorResponse}, 422: {"model": ErrorResponse}, 429: {"model": ErrorResponse}, 502: {"model": ErrorResponse}, 503: {"model": ErrorResponse}, 504: {"model": ErrorResponse}})
async def analyze_alert(
    request: Request,
    payload: AIAnalysisRequest,
    principal: Annotated[AnalystPrincipal, Depends(require_ai_analysis)],
    alert_id: Annotated[str, Path(min_length=1, max_length=255)],
) -> AIAnalysisRecord:
    return await _analyze(request, payload, principal, AITargetType.ALERT, alert_id)


@router.post("/incidents/{incident_id}/analyze", response_model=AIAnalysisRecord, responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}, 404: {"model": ErrorResponse}, 422: {"model": ErrorResponse}, 429: {"model": ErrorResponse}, 502: {"model": ErrorResponse}, 503: {"model": ErrorResponse}, 504: {"model": ErrorResponse}})
async def analyze_incident(
    request: Request,
    payload: AIAnalysisRequest,
    principal: Annotated[AnalystPrincipal, Depends(require_ai_analysis)],
    incident_id: Annotated[str, Path(min_length=1, max_length=64)],
) -> AIAnalysisRecord:
    return await _analyze(request, payload, principal, AITargetType.INCIDENT, incident_id)


@router.get("/analyses/{analysis_id}", response_model=AIAnalysisRecord, responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}, 404: {"model": ErrorResponse}})
async def get_analysis(
    request: Request,
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
    analysis_id: Annotated[str, Path(min_length=1, max_length=64)],
) -> AIAnalysisRecord:
    record = _service(request).get(analysis_id)
    if record is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, _error("analysis_not_found", "No AI analysis exists with the requested identifier", field="analysis_id"))
    return record


async def _history(request: Request, target_type: AITargetType, target_id: str, limit: int) -> AIAnalysisHistory:
    try:
        return _service(request).history(target_type, target_id, limit=limit)
    except AITargetNotFound as exc:
        name = target_type.value
        raise HTTPException(status.HTTP_404_NOT_FOUND, _error(f"{name}_not_found", f"No {name} exists with the requested identifier", field=f"{name}_id")) from exc
    except AIContextTooLarge as exc:
        raise _analysis_error(exc) from exc


@router.get("/alerts/{alert_id}/analyses", response_model=AIAnalysisHistory, responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}, 404: {"model": ErrorResponse}})
async def alert_analysis_history(
    request: Request,
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
    alert_id: Annotated[str, Path(min_length=1, max_length=255)],
    limit: Annotated[int, Query(ge=1, le=50)] = 20,
) -> AIAnalysisHistory:
    return await _history(request, AITargetType.ALERT, alert_id, limit)


@router.get("/incidents/{incident_id}/analyses", response_model=AIAnalysisHistory, responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}, 404: {"model": ErrorResponse}})
async def incident_analysis_history(
    request: Request,
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
    incident_id: Annotated[str, Path(min_length=1, max_length=64)],
    limit: Annotated[int, Query(ge=1, le=50)] = 20,
) -> AIAnalysisHistory:
    return await _history(request, AITargetType.INCIDENT, incident_id, limit)
