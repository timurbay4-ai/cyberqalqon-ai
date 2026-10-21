"""Authenticated, bounded M12 analyst investigation projections."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request

from app.api.dependencies.auth import require_soc_mutation
from app.db.investigation_workbench import (
    InvalidWorkbenchCursorError,
    InvestigationWorkbenchRepository,
    WorkbenchEvaluationLimitError,
    WorkbenchTargetNotFoundError,
)
from app.db.detection_readiness import DetectionReadinessNotFoundError
from app.schemas.auth import AnalystPrincipal
from app.schemas.detection_engineering import AdvancedRuleDryRunRequest
from app.schemas.investigation_workbench import InvestigationWorkbench, WorkbenchRequest
from app.services.advanced_detection import AdvancedDetectionEvaluationLimitError


router = APIRouter(prefix="/api/v1/investigations", tags=["Investigation Workbench"])


def _error(code: str, message: str, *, field: str | None = None) -> dict[str, Any]:
    return {"code": code, "message": message, **({"field": field} if field else {})}


@router.post(
    "/workbench",
    response_model=InvestigationWorkbench,
    response_model_exclude_none=True,
    summary="Build one bounded, read-only analyst investigation projection",
)
async def investigation_workbench(
    request: Request,
    payload: WorkbenchRequest,
    _: Annotated[AnalystPrincipal, Depends(require_soc_mutation)],
) -> InvestigationWorkbench:
    end = payload.end_time.astimezone(timezone.utc) if payload.end_time else datetime.now(timezone.utc)
    start = (
        payload.start_time.astimezone(timezone.utc)
        if payload.start_time
        else end - timedelta(minutes=payload.relative_minutes or 1440)
    )
    rule = finding = None
    evaluated_event_count = 0
    detection_source = "HISTORICAL_DRY_RUN"
    shadow_run_id = None
    if payload.target_type == "M11_FINDING":
        try:
            result = request.app.state.advanced_detection_engine.evaluate(
                str(payload.rule_id),
                AdvancedRuleDryRunRequest(
                    relative_minutes=None, start_time=start, end_time=end,
                    max_events=1000, max_findings=100,
                    max_execution_ms=payload.max_execution_ms,
                ),
            )
        except KeyError as exc:
            raise HTTPException(404, detail=_error("rule_not_found", "M11 rule does not exist")) from exc
        except AdvancedDetectionEvaluationLimitError as exc:
            raise HTTPException(
                409, detail=_error("evaluation_limit", "M11 finding re-evaluation exceeded its budget")
            ) from exc
        finding = next(
            (item for item in result.findings if item.deduplication_key == payload.finding_key), None
        )
        if finding is None:
            raise HTTPException(
                404,
                detail=_error(
                    "finding_not_found",
                    "The deterministic finding is not present in the requested bounded time window",
                ),
            )
        rule = result.rule
        evaluated_event_count = result.evaluated_event_count
    elif payload.target_type == "SHADOW_FINDING":
        try:
            shadow_finding, shadow_run = (
                request.app.state.detection_readiness_repository.shadow_finding(
                    str(payload.target_id)
                )
            )
            config = request.app.state.detection_readiness_repository.configuration(
                shadow_finding.rule_id, shadow_run.configuration_version
            )
            rule = request.app.state.advanced_detection_engine.rule(
                shadow_finding.rule_id
            ).model_copy(update={
                "threshold": config.threshold_count,
                "window_seconds": config.time_window_seconds,
                "severity": config.severity,
            })
            finding = shadow_finding.finding
            evaluated_event_count = shadow_run.evaluated_event_count
            detection_source = "SHADOW"
            shadow_run_id = shadow_run.run_id
        except (DetectionReadinessNotFoundError, KeyError) as exc:
            raise HTTPException(
                404,
                detail=_error(
                    "shadow_finding_not_found",
                    "The requested shadow finding is not available",
                ),
            ) from exc
    repository: InvestigationWorkbenchRepository = request.app.state.investigation_workbench_repository
    try:
        return repository.build(
            payload, start=start, end=end, detection_rule=rule,
            detection_finding=finding, evaluated_event_count=evaluated_event_count,
            detection_source=detection_source, shadow_run_id=shadow_run_id,
        )
    except WorkbenchTargetNotFoundError as exc:
        raise HTTPException(
            404, detail=_error("investigation_target_not_found", "No stored evidence resolves this target")
        ) from exc
    except WorkbenchEvaluationLimitError as exc:
        raise HTTPException(
            409, detail=_error("investigation_limit", "Investigation query exceeded its bounded execution budget")
        ) from exc
    except InvalidWorkbenchCursorError as exc:
        raise HTTPException(
            422,
            detail=_error("invalid_cursor", str(exc), field="related_cursor"),
        ) from exc
