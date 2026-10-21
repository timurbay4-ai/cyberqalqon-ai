"""Authenticated M14 detection readiness APIs with hard activation isolation."""

from __future__ import annotations

import sqlite3
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status

from app.api.dependencies.auth import (
    require_admin_mutation,
    require_alert_mutation,
    require_soc_reader,
)
from app.db.detection_readiness import (
    DetectionReadinessConflictError,
    DetectionReadinessEvaluationError,
    DetectionReadinessLifecycleError,
    DetectionReadinessNotFoundError,
    DetectionReadinessSchemaUnavailableError,
)
from app.schemas.auth import AnalystPrincipal
from app.schemas.detection_readiness import (
    CanarySafetyStatus,
    CorrelationReplayRequest,
    CorrelationReplayResult,
    DetectionConfigurationCreate,
    DetectionConfigurationDiff,
    DetectionConfigurationRestore,
    DetectionConfigurationValidation,
    DetectionConfigurationVersion,
    DetectionDiagnostics,
    DetectionLifecycleTransition,
    DetectionRuleLifecycle,
    DetectionTuningComparison,
    DetectionTuningRequest,
    ShadowRun,
    ShadowRunDetail,
    ShadowRunRequest,
    TelemetryPrerequisiteEvidence,
)


router = APIRouter(prefix="/api/v1/detection-readiness", tags=["Detection readiness"])
RuleId = Annotated[str, Path(pattern=r"^DET-00[1-9]$")]


def _error(code: str, message: str, field: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"code": code, "message": message}
    if field:
        result["field"] = field
    return result


def _translate(exc: Exception) -> HTTPException:
    if isinstance(exc, DetectionReadinessSchemaUnavailableError):
        return HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=_error("schema_approval_required", str(exc)),
        )
    if isinstance(exc, sqlite3.OperationalError) and (
        "locked" in str(exc).casefold() or "busy" in str(exc).casefold()
    ):
        return HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=_error(
                "database_busy",
                "Detection readiness storage is busy; no activation or production side effect occurred",
            ),
        )
    if isinstance(exc, DetectionReadinessNotFoundError):
        return HTTPException(404, detail=_error("not_found", str(exc)))
    if isinstance(exc, DetectionReadinessConflictError):
        return HTTPException(409, detail=_error("stale_version", str(exc), "expected_version"))
    if isinstance(exc, DetectionReadinessLifecycleError):
        return HTTPException(409, detail=_error("lifecycle_blocked", str(exc)))
    if isinstance(exc, DetectionReadinessEvaluationError):
        return HTTPException(409, detail=_error("evaluation_failed_closed", str(exc)))
    raise exc


@router.get("/rules", response_model=list[DetectionRuleLifecycle])
async def lifecycle_inventory(
    request: Request,
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
) -> list[DetectionRuleLifecycle]:
    try:
        return request.app.state.detection_readiness_repository.lifecycle_inventory()
    except DetectionReadinessLifecycleError as exc:
        raise _translate(exc) from exc


@router.get("/rules/{rule_id}/lifecycle", response_model=DetectionRuleLifecycle)
async def lifecycle_detail(
    request: Request,
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
    rule_id: RuleId,
) -> DetectionRuleLifecycle:
    try:
        return request.app.state.detection_readiness_repository.lifecycle(rule_id)
    except (DetectionReadinessNotFoundError, DetectionReadinessLifecycleError) as exc:
        raise _translate(exc) from exc


@router.post("/rules/{rule_id}/lifecycle", response_model=DetectionRuleLifecycle)
async def transition_lifecycle(
    request: Request,
    payload: DetectionLifecycleTransition,
    principal: Annotated[AnalystPrincipal, Depends(require_admin_mutation)],
    rule_id: RuleId,
) -> DetectionRuleLifecycle:
    try:
        return request.app.state.detection_readiness_repository.transition(
            rule_id, payload, principal
        )
    except (
        DetectionReadinessNotFoundError,
        DetectionReadinessConflictError,
        DetectionReadinessLifecycleError,
        sqlite3.OperationalError,
    ) as exc:
        raise _translate(exc) from exc


@router.get(
    "/rules/{rule_id}/configurations",
    response_model=list[DetectionConfigurationVersion],
)
async def configuration_history(
    request: Request,
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
    rule_id: RuleId,
) -> list[DetectionConfigurationVersion]:
    try:
        return request.app.state.detection_readiness_repository.configurations(rule_id)
    except (DetectionReadinessNotFoundError, DetectionReadinessLifecycleError) as exc:
        raise _translate(exc) from exc


@router.post(
    "/rules/{rule_id}/configurations",
    response_model=DetectionConfigurationVersion,
    status_code=status.HTTP_201_CREATED,
)
async def create_configuration(
    request: Request,
    payload: DetectionConfigurationCreate,
    principal: Annotated[AnalystPrincipal, Depends(require_admin_mutation)],
    rule_id: RuleId,
) -> DetectionConfigurationVersion:
    try:
        return request.app.state.detection_readiness_repository.create_configuration(
            rule_id, payload, principal
        )
    except (
        DetectionReadinessNotFoundError,
        DetectionReadinessConflictError,
        DetectionReadinessLifecycleError,
        sqlite3.OperationalError,
    ) as exc:
        raise _translate(exc) from exc


@router.post(
    "/rules/{rule_id}/configurations/{version}/validate",
    response_model=DetectionConfigurationValidation,
)
async def validate_configuration(
    request: Request,
    principal: Annotated[AnalystPrincipal, Depends(require_admin_mutation)],
    rule_id: RuleId,
    version: Annotated[int, Path(ge=1)],
) -> DetectionConfigurationValidation:
    try:
        return request.app.state.detection_readiness_repository.validate_configuration(
            rule_id, version, principal
        )
    except (
        DetectionReadinessNotFoundError,
        DetectionReadinessConflictError,
        DetectionReadinessLifecycleError,
        sqlite3.OperationalError,
    ) as exc:
        raise _translate(exc) from exc


@router.post(
    "/rules/{rule_id}/configurations/restore",
    response_model=DetectionConfigurationVersion,
)
async def restore_configuration(
    request: Request,
    payload: DetectionConfigurationRestore,
    principal: Annotated[AnalystPrincipal, Depends(require_admin_mutation)],
    rule_id: RuleId,
) -> DetectionConfigurationVersion:
    try:
        return request.app.state.detection_readiness_repository.restore_configuration(
            rule_id, payload.source_version, payload.expected_version,
            payload.change_reason, principal,
        )
    except (
        DetectionReadinessNotFoundError,
        DetectionReadinessConflictError,
        DetectionReadinessLifecycleError,
        sqlite3.OperationalError,
    ) as exc:
        raise _translate(exc) from exc


@router.get(
    "/rules/{rule_id}/configurations/diff",
    response_model=DetectionConfigurationDiff,
)
async def configuration_diff(
    request: Request,
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
    rule_id: RuleId,
    from_version: Annotated[int, Query(ge=1)],
    to_version: Annotated[int, Query(ge=1)],
) -> DetectionConfigurationDiff:
    try:
        return request.app.state.detection_readiness_repository.configuration_diff(
            rule_id, from_version, to_version
        )
    except (DetectionReadinessNotFoundError, DetectionReadinessLifecycleError) as exc:
        raise _translate(exc) from exc


@router.post("/rules/{rule_id}/tuning", response_model=DetectionTuningComparison)
async def tuning_comparison(
    request: Request,
    payload: DetectionTuningRequest,
    _: Annotated[AnalystPrincipal, Depends(require_alert_mutation)],
    rule_id: RuleId,
) -> DetectionTuningComparison:
    try:
        return request.app.state.detection_readiness_repository.tuning_comparison(
            rule_id, payload
        )
    except (
        DetectionReadinessNotFoundError,
        DetectionReadinessEvaluationError,
        DetectionReadinessLifecycleError,
        sqlite3.OperationalError,
    ) as exc:
        raise _translate(exc) from exc


@router.post("/rules/{rule_id}/shadow-runs", response_model=ShadowRunDetail)
async def execute_shadow_run(
    request: Request,
    payload: ShadowRunRequest,
    principal: Annotated[AnalystPrincipal, Depends(require_alert_mutation)],
    rule_id: RuleId,
) -> ShadowRunDetail:
    try:
        return request.app.state.detection_readiness_repository.run_shadow(
            rule_id, payload, principal
        )
    except (
        DetectionReadinessNotFoundError,
        DetectionReadinessLifecycleError,
        DetectionReadinessEvaluationError,
        sqlite3.OperationalError,
    ) as exc:
        raise _translate(exc) from exc


@router.get("/rules/{rule_id}/shadow-runs", response_model=list[ShadowRun])
async def list_shadow_runs(
    request: Request,
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
    rule_id: RuleId,
    limit: Annotated[int, Query(ge=1, le=50)] = 20,
) -> list[ShadowRun]:
    try:
        return request.app.state.detection_readiness_repository.shadow_runs(
            rule_id, limit=limit
        )
    except (DetectionReadinessNotFoundError, DetectionReadinessLifecycleError) as exc:
        raise _translate(exc) from exc


@router.get("/shadow-runs/{run_id}", response_model=ShadowRunDetail)
async def shadow_run_detail(
    request: Request,
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
    run_id: Annotated[str, Path(pattern=r"^SHADOW-[A-F0-9]{32}$")],
) -> ShadowRunDetail:
    try:
        return request.app.state.detection_readiness_repository.shadow_run(run_id)
    except (DetectionReadinessNotFoundError, DetectionReadinessLifecycleError) as exc:
        raise _translate(exc) from exc


@router.post(
    "/rules/{rule_id}/correlation-replay",
    response_model=CorrelationReplayResult,
)
async def correlation_replay(
    request: Request,
    payload: CorrelationReplayRequest,
    _: Annotated[AnalystPrincipal, Depends(require_alert_mutation)],
    rule_id: RuleId,
) -> CorrelationReplayResult:
    try:
        return request.app.state.detection_readiness_repository.replay_correlation_state(
            rule_id, payload
        )
    except (
        DetectionReadinessNotFoundError,
        DetectionReadinessLifecycleError,
        DetectionReadinessEvaluationError,
        sqlite3.OperationalError,
    ) as exc:
        raise _translate(exc) from exc


@router.get(
    "/rules/{rule_id}/telemetry",
    response_model=TelemetryPrerequisiteEvidence,
)
async def telemetry_readiness(
    request: Request,
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
    rule_id: RuleId,
) -> TelemetryPrerequisiteEvidence:
    try:
        return request.app.state.detection_readiness_repository.telemetry_readiness(rule_id)
    except (DetectionReadinessNotFoundError, DetectionReadinessLifecycleError) as exc:
        raise _translate(exc) from exc


@router.get("/telemetry", response_model=list[TelemetryPrerequisiteEvidence])
async def telemetry_inventory(
    request: Request,
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
) -> list[TelemetryPrerequisiteEvidence]:
    return request.app.state.detection_readiness_repository.telemetry_inventory()


@router.get("/rules/{rule_id}/diagnostics", response_model=DetectionDiagnostics)
async def detection_diagnostics(
    request: Request,
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
    rule_id: RuleId,
) -> DetectionDiagnostics:
    try:
        return request.app.state.detection_readiness_repository.diagnostics(rule_id)
    except (DetectionReadinessNotFoundError, DetectionReadinessLifecycleError) as exc:
        raise _translate(exc) from exc


@router.get("/rules/{rule_id}/canary-safety", response_model=CanarySafetyStatus)
async def canary_safety(
    request: Request,
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
    rule_id: RuleId,
) -> CanarySafetyStatus:
    try:
        return request.app.state.detection_readiness_repository.canary_safety(rule_id)
    except (DetectionReadinessNotFoundError, DetectionReadinessLifecycleError) as exc:
        raise _translate(exc) from exc
