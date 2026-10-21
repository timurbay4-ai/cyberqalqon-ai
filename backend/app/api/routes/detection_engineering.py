"""Authenticated detection engineering, threat hunting, analytics, and IOC APIs."""

from __future__ import annotations

import csv
import io
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, Response, status
from pydantic import ValidationError

from app.api.dependencies.auth import require_alert_mutation, require_soc_reader
from app.api.routes.siem import _safe_cell
from app.db.detection_engineering import (
    DetectionEngineeringConflictError,
    DetectionEngineeringLifecycleError,
    DetectionEngineeringLimitError,
    DetectionEngineeringNotFoundError,
    InvalidHuntCursorError,
)
from app.schemas.auth import AnalystPrincipal
from app.schemas.detection_engineering import (
    AdvancedDetectionRule,
    AdvancedRuleDryRunRequest,
    AdvancedRuleDryRunResult,
    DeploymentConfirmation,
    DeploymentConfirmationResult,
    DetectionAnalytics,
    DetectionCoverage,
    DetectionQualityReport,
    IndicatorType,
    IOCImportRequest,
    IOCImportResult,
    IOCIndicator,
    IOCMatchSummary,
    IOCCreate,
    IOCUpdate,
    RuleDraft,
    RuleDraftCreate,
    RuleDraftUpdate,
    RuleDraftVersion,
    RuleDryRunRequest,
    RuleDryRunResult,
    RuleRollbackRequest,
    RuleValidationResult,
    SavedHunt,
    SavedHuntCreate,
    ThreatHuntPage,
    ThreatHuntQuery,
)
from app.schemas.investigations import VersionedMutation
from app.schemas.siem import DetectionRuleSummary
from app.services.advanced_detection import AdvancedDetectionEvaluationLimitError
from app.services.detection_quality import quality_catalog, quality_report


router = APIRouter(prefix="/api/v1", tags=["Detection engineering"])


def _error(code: str, message: str, field: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"code": code, "message": message}
    if field:
        result["field"] = field
    return result


def _translate(exc: Exception) -> HTTPException:
    if isinstance(exc, DetectionEngineeringNotFoundError):
        return HTTPException(404, detail=_error("not_found", "The requested detection resource does not exist"))
    if isinstance(exc, DetectionEngineeringConflictError):
        return HTTPException(409, detail=_error("conflict", str(exc), "expected_version"))
    if isinstance(exc, DetectionEngineeringLimitError):
        return HTTPException(409, detail=_error("resource_limit", str(exc)))
    if isinstance(exc, DetectionEngineeringLifecycleError):
        return HTTPException(409, detail=_error("invalid_rule_lifecycle", str(exc)))
    raise exc


def _hunt_query(
    *,
    relative_minutes: int | None,
    start_time: datetime | None,
    end_time: datetime | None,
    ip: str | None,
    hostname: str | None,
    username: str | None,
    event_category: str | None,
    rule_id: str | None,
    mitre_id: str | None,
    search: str | None,
    sort: Literal["newest", "oldest"],
) -> ThreatHuntQuery:
    try:
        return ThreatHuntQuery(
            relative_minutes=None if start_time is not None or end_time is not None else relative_minutes,
            start_time=start_time,
            end_time=end_time,
            ip=ip,
            hostname=hostname,
            username=username,
            event_category=event_category,
            rule_id=rule_id,
            mitre_id=mitre_id,
            search=search,
            sort=sort,
        )
    except ValidationError as exc:
        first = exc.errors()[0] if exc.errors() else {}
        location = first.get("loc", ())
        field = ".".join(str(part) for part in location)
        raise HTTPException(
            422,
            detail=_error(
                "invalid_request", str(first.get("msg", "Invalid hunt query")), field or None
            ),
        ) from exc


@router.get("/detection-engineering/rules", response_model=list[DetectionRuleSummary])
async def detection_inventory(
    request: Request,
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
) -> list[DetectionRuleSummary]:
    return request.app.state.siem_repository.rules()


@router.get("/detection-engineering/rules/{rule_id}", response_model=DetectionRuleSummary)
async def detection_rule_detail(
    request: Request,
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
    rule_id: Annotated[str, Path(min_length=1, max_length=128)],
) -> DetectionRuleSummary:
    rule = next(
        (item for item in request.app.state.siem_repository.rules() if item.rule_id == rule_id),
        None,
    )
    if rule is None:
        raise HTTPException(404, detail=_error("rule_not_found", "Detection rule does not exist"))
    return rule


@router.get("/detection-engineering/coverage", response_model=DetectionCoverage)
async def detection_coverage(
    request: Request,
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
) -> DetectionCoverage:
    return request.app.state.detection_engineering_repository.coverage(
        request.app.state.siem_repository.rules()
    )


@router.get(
    "/detection-engineering/advanced-rules",
    response_model=list[AdvancedDetectionRule],
)
async def advanced_detection_inventory(
    request: Request,
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
    days: Annotated[int, Query(ge=1, le=31)] = 30,
) -> list[AdvancedDetectionRule]:
    """Return the disabled M11 catalog with evidence-based telemetry availability."""
    try:
        return request.app.state.advanced_detection_engine.catalog(days=days)
    except AdvancedDetectionEvaluationLimitError as exc:
        raise HTTPException(
            503,
            detail=_error("catalog_limit", "Advanced detection catalog exceeded its bounded read budget"),
        ) from exc


@router.get(
    "/detection-engineering/advanced-rules/{rule_id}",
    response_model=AdvancedDetectionRule,
)
async def advanced_detection_detail(
    request: Request,
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
    rule_id: Annotated[str, Path(pattern=r"^DET-00[1-9]$")],
) -> AdvancedDetectionRule:
    try:
        return request.app.state.advanced_detection_engine.rule(rule_id)
    except KeyError as exc:
        raise HTTPException(404, detail=_error("rule_not_found", "Advanced detection rule does not exist")) from exc
    except AdvancedDetectionEvaluationLimitError as exc:
        raise HTTPException(
            503,
            detail=_error("catalog_limit", "Advanced detection rule detail exceeded its bounded read budget"),
        ) from exc


@router.get(
    "/detection-engineering/advanced-quality",
    response_model=list[DetectionQualityReport],
)
async def advanced_detection_quality_catalog(
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
) -> list[DetectionQualityReport]:
    """Evaluate labeled synthetic fixtures only; no live event or alert writes occur."""

    return quality_catalog()


@router.get(
    "/detection-engineering/advanced-quality/{rule_id}",
    response_model=DetectionQualityReport,
)
async def advanced_detection_quality_detail(
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
    rule_id: Annotated[str, Path(pattern=r"^DET-00[1-9]$")],
) -> DetectionQualityReport:
    try:
        return quality_report(rule_id)
    except KeyError as exc:
        raise HTTPException(
            404,
            detail=_error("rule_not_found", "Advanced detection rule does not exist"),
        ) from exc


@router.post(
    "/detection-engineering/advanced-rules/{rule_id}/dry-run",
    response_model=AdvancedRuleDryRunResult,
)
async def advanced_detection_dry_run(
    request: Request,
    payload: AdvancedRuleDryRunRequest,
    principal: Annotated[AnalystPrincipal, Depends(require_alert_mutation)],
    rule_id: Annotated[str, Path(pattern=r"^DET-00[1-9]$")],
) -> AdvancedRuleDryRunResult:
    try:
        result = request.app.state.advanced_detection_engine.evaluate(rule_id, payload)
    except KeyError as exc:
        raise HTTPException(404, detail=_error("rule_not_found", "Advanced detection rule does not exist")) from exc
    except AdvancedDetectionEvaluationLimitError as exc:
        raise HTTPException(
            409,
            detail=_error("evaluation_limit", "Advanced detection dry-run exceeded its bounded execution budget"),
        ) from exc
    request.app.state.audit_repository.append(
        action="ADVANCED_DETECTION_DRY_RUN",
        actor_id=principal.analyst_id,
        actor_display=principal.audit_display,
        target_type="advanced_detection_rule",
        target_id=rule_id,
        details={
            "start_time": result.start_time.isoformat(),
            "end_time": result.end_time.isoformat(),
            "evaluated_events": result.evaluated_event_count,
            "findings": result.finding_count,
            "result_truncated": result.result_truncated,
            "execution_budget_ms": result.execution_budget_ms,
            "live_activation": False,
        },
    )
    return result


@router.get("/detection-engineering/analytics", response_model=DetectionAnalytics)
async def detection_analytics(
    request: Request,
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
    days: Annotated[int, Query(ge=1, le=31)] = 30,
) -> DetectionAnalytics:
    return request.app.state.detection_engineering_repository.analytics(days=days)


@router.get("/detection-engineering/drafts", response_model=list[RuleDraft])
async def list_rule_drafts(
    request: Request,
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
) -> list[RuleDraft]:
    return request.app.state.detection_engineering_repository.list_drafts()


@router.post(
    "/detection-engineering/drafts", response_model=RuleDraft,
    status_code=status.HTTP_201_CREATED,
)
async def create_rule_draft(
    request: Request,
    payload: RuleDraftCreate,
    principal: Annotated[AnalystPrincipal, Depends(require_alert_mutation)],
) -> RuleDraft:
    try:
        return request.app.state.detection_engineering_repository.create_draft(payload, principal)
    except (DetectionEngineeringLimitError, DetectionEngineeringConflictError) as exc:
        raise _translate(exc) from exc


@router.get("/detection-engineering/drafts/{draft_id}", response_model=RuleDraft)
async def get_rule_draft(
    request: Request,
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
    draft_id: Annotated[str, Path(min_length=1, max_length=64)],
) -> RuleDraft:
    try:
        return request.app.state.detection_engineering_repository.get_draft(draft_id)
    except DetectionEngineeringNotFoundError as exc:
        raise _translate(exc) from exc


@router.put("/detection-engineering/drafts/{draft_id}", response_model=RuleDraft)
async def update_rule_draft(
    request: Request,
    payload: RuleDraftUpdate,
    principal: Annotated[AnalystPrincipal, Depends(require_alert_mutation)],
    draft_id: Annotated[str, Path(min_length=1, max_length=64)],
) -> RuleDraft:
    try:
        return request.app.state.detection_engineering_repository.update_draft(
            draft_id, payload, principal
        )
    except (DetectionEngineeringNotFoundError, DetectionEngineeringConflictError) as exc:
        raise _translate(exc) from exc


@router.post("/detection-engineering/drafts/{draft_id}/validate", response_model=RuleValidationResult)
async def validate_rule_draft(
    request: Request,
    payload: VersionedMutation,
    principal: Annotated[AnalystPrincipal, Depends(require_alert_mutation)],
    draft_id: Annotated[str, Path(min_length=1, max_length=64)],
) -> RuleValidationResult:
    try:
        return request.app.state.detection_engineering_repository.validate_draft(
            draft_id, payload.expected_version, principal
        )
    except (DetectionEngineeringNotFoundError, DetectionEngineeringConflictError) as exc:
        raise _translate(exc) from exc


@router.post("/detection-engineering/drafts/{draft_id}/dry-run", response_model=RuleDryRunResult)
async def dry_run_rule_draft(
    request: Request,
    payload: RuleDryRunRequest,
    principal: Annotated[AnalystPrincipal, Depends(require_alert_mutation)],
    draft_id: Annotated[str, Path(min_length=1, max_length=64)],
) -> RuleDryRunResult:
    try:
        return request.app.state.detection_engineering_repository.dry_run(
            draft_id, payload, principal
        )
    except (
        DetectionEngineeringNotFoundError,
        DetectionEngineeringConflictError,
        DetectionEngineeringLifecycleError,
    ) as exc:
        raise _translate(exc) from exc


@router.post(
    "/detection-engineering/drafts/{draft_id}/confirm-manual-deployment",
    response_model=DeploymentConfirmationResult,
)
async def confirm_manual_deployment(
    request: Request,
    payload: DeploymentConfirmation,
    principal: Annotated[AnalystPrincipal, Depends(require_alert_mutation)],
    draft_id: Annotated[str, Path(min_length=1, max_length=64)],
) -> DeploymentConfirmationResult:
    try:
        return request.app.state.detection_engineering_repository.confirm_manual_deployment(
            draft_id, payload.expected_version, payload.reason, principal
        )
    except (
        DetectionEngineeringNotFoundError,
        DetectionEngineeringConflictError,
        DetectionEngineeringLifecycleError,
    ) as exc:
        raise _translate(exc) from exc


@router.get(
    "/detection-engineering/drafts/{draft_id}/versions",
    response_model=list[RuleDraftVersion],
)
async def rule_draft_versions(
    request: Request,
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
    draft_id: Annotated[str, Path(min_length=1, max_length=64)],
) -> list[RuleDraftVersion]:
    try:
        return request.app.state.detection_engineering_repository.versions(draft_id)
    except DetectionEngineeringNotFoundError as exc:
        raise _translate(exc) from exc


@router.post("/detection-engineering/drafts/{draft_id}/rollback", response_model=RuleDraft)
async def rollback_rule_draft(
    request: Request,
    payload: RuleRollbackRequest,
    principal: Annotated[AnalystPrincipal, Depends(require_alert_mutation)],
    draft_id: Annotated[str, Path(min_length=1, max_length=64)],
) -> RuleDraft:
    try:
        return request.app.state.detection_engineering_repository.rollback(
            draft_id, payload, principal
        )
    except (DetectionEngineeringNotFoundError, DetectionEngineeringConflictError) as exc:
        raise _translate(exc) from exc


@router.get("/threat-hunts", response_model=ThreatHuntPage)
async def run_threat_hunt(
    request: Request,
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
    relative_minutes: Annotated[int | None, Query()] = 1440,
    start_time: Annotated[datetime | None, Query()] = None,
    end_time: Annotated[datetime | None, Query()] = None,
    ip: Annotated[str | None, Query(max_length=64)] = None,
    hostname: Annotated[str | None, Query(max_length=255)] = None,
    username: Annotated[str | None, Query(max_length=512)] = None,
    event_category: Annotated[str | None, Query(max_length=255)] = None,
    rule_id: Annotated[str | None, Query(max_length=128)] = None,
    mitre_id: Annotated[str | None, Query(max_length=16)] = None,
    search: Annotated[str | None, Query(max_length=200)] = None,
    sort: Literal["newest", "oldest"] = "newest",
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    cursor: Annotated[str | None, Query(min_length=1, max_length=256)] = None,
) -> ThreatHuntPage:
    query = _hunt_query(
        relative_minutes=relative_minutes, start_time=start_time, end_time=end_time,
        ip=ip, hostname=hostname, username=username, event_category=event_category,
        rule_id=rule_id, mitre_id=mitre_id, search=search, sort=sort,
    )
    try:
        return request.app.state.detection_engineering_repository.hunt(
            query, limit=limit, cursor=cursor
        )
    except InvalidHuntCursorError as exc:
        raise HTTPException(422, detail=_error("invalid_cursor", str(exc), "cursor")) from exc


@router.get("/threat-hunts/saved", response_model=list[SavedHunt])
async def list_saved_hunts(
    request: Request,
    principal: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
) -> list[SavedHunt]:
    return request.app.state.detection_engineering_repository.list_saved_hunts(
        principal.analyst_id
    )


@router.post("/threat-hunts/saved", response_model=SavedHunt, status_code=status.HTTP_201_CREATED)
async def save_threat_hunt(
    request: Request,
    payload: SavedHuntCreate,
    principal: Annotated[AnalystPrincipal, Depends(require_alert_mutation)],
) -> SavedHunt:
    try:
        return request.app.state.detection_engineering_repository.create_saved_hunt(payload, principal)
    except (DetectionEngineeringConflictError, DetectionEngineeringLimitError) as exc:
        raise _translate(exc) from exc


@router.delete("/threat-hunts/saved/{saved_hunt_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_saved_hunt(
    request: Request,
    principal: Annotated[AnalystPrincipal, Depends(require_alert_mutation)],
    saved_hunt_id: Annotated[str, Path(min_length=1, max_length=64)],
) -> Response:
    try:
        request.app.state.detection_engineering_repository.delete_saved_hunt(
            saved_hunt_id, principal
        )
    except DetectionEngineeringNotFoundError as exc:
        raise _translate(exc) from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)


def _hunt_export_query(**values: Any) -> ThreatHuntQuery:
    return _hunt_query(**values)


@router.get("/threat-hunts/export.csv", response_class=Response)
async def export_threat_hunt_csv(
    request: Request,
    principal: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
    relative_minutes: Annotated[int | None, Query()] = 1440,
    start_time: Annotated[datetime | None, Query()] = None,
    end_time: Annotated[datetime | None, Query()] = None,
    ip: Annotated[str | None, Query(max_length=64)] = None,
    hostname: Annotated[str | None, Query(max_length=255)] = None,
    username: Annotated[str | None, Query(max_length=512)] = None,
    event_category: Annotated[str | None, Query(max_length=255)] = None,
    rule_id: Annotated[str | None, Query(max_length=128)] = None,
    mitre_id: Annotated[str | None, Query(max_length=16)] = None,
    search: Annotated[str | None, Query(max_length=200)] = None,
    sort: Literal["newest", "oldest"] = "newest",
) -> Response:
    query = _hunt_export_query(
        relative_minutes=relative_minutes, start_time=start_time, end_time=end_time,
        ip=ip, hostname=hostname, username=username, event_category=event_category,
        rule_id=rule_id, mitre_id=mitre_id, search=search, sort=sort,
    )
    repository = request.app.state.detection_engineering_repository
    rows = []
    cursor: str | None = None
    total = 0
    while len(rows) < 1000:
        page = repository.hunt(query, limit=100, cursor=cursor)
        total = page.total
        rows.extend(page.items)
        cursor = page.next_cursor
        if not cursor:
            break
    rows = rows[:1000]
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\r\n")
    writer.writerow([
        "event_id", "timestamp", "source_type", "hostname", "source_ip",
        "destination_ip", "username", "event_category", "rule_id", "severity",
        "message", "related_alert_id", "related_incident_ids",
    ])
    for item in rows:
        writer.writerow([
            _safe_cell(item.event_id), item.timestamp.isoformat(), _safe_cell(item.source_type),
            _safe_cell(item.hostname or ""), _safe_cell(item.source_ip or ""),
            _safe_cell(item.destination_ip or ""), _safe_cell(item.username or ""),
            _safe_cell(item.event_category or ""), _safe_cell(item.rule_id or ""),
            item.severity if item.severity is not None else "", _safe_cell(item.message),
            _safe_cell(item.related_alert_id or ""), _safe_cell(";".join(item.related_incident_ids)),
        ])
    request.app.state.audit_repository.append(
        action="THREAT_HUNT_EXPORTED", actor_id=principal.analyst_id,
        actor_display=principal.audit_display, target_type="threat_hunt",
        target_id="csv", details={"exported_rows": len(rows), "total_matches": total},
    )
    return Response(
        content="\ufeff" + output.getvalue(), media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": "attachment; filename=cyberqalqon-threat-hunt.csv",
            "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store",
            "X-Result-Truncated": "true" if total > len(rows) else "false",
        },
    )


@router.get("/iocs", response_model=list[IOCIndicator])
async def list_iocs(
    request: Request,
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
    indicator_type: IndicatorType | None = None,
    active_only: bool = False,
    search: Annotated[str | None, Query(max_length=200)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
) -> list[IOCIndicator]:
    return request.app.state.detection_engineering_repository.list_iocs(
        indicator_type=indicator_type, active_only=active_only,
        search=search.strip() if search else None, limit=limit,
    )


@router.post("/iocs", response_model=IOCIndicator, status_code=status.HTTP_201_CREATED)
async def create_ioc(
    request: Request,
    payload: IOCCreate,
    principal: Annotated[AnalystPrincipal, Depends(require_alert_mutation)],
) -> IOCIndicator:
    try:
        return request.app.state.detection_engineering_repository.create_ioc(payload, principal)
    except (DetectionEngineeringConflictError, DetectionEngineeringLimitError) as exc:
        raise _translate(exc) from exc


@router.put("/iocs/{indicator_id}", response_model=IOCIndicator)
async def update_ioc(
    request: Request,
    payload: IOCUpdate,
    principal: Annotated[AnalystPrincipal, Depends(require_alert_mutation)],
    indicator_id: Annotated[str, Path(min_length=1, max_length=64)],
) -> IOCIndicator:
    try:
        return request.app.state.detection_engineering_repository.update_ioc(
            indicator_id, payload, payload.expected_version, payload.is_active, principal
        )
    except (DetectionEngineeringNotFoundError, DetectionEngineeringConflictError) as exc:
        raise _translate(exc) from exc


@router.post("/iocs/import", response_model=IOCImportResult)
async def import_iocs(
    request: Request,
    payload: IOCImportRequest,
    principal: Annotated[AnalystPrincipal, Depends(require_alert_mutation)],
) -> IOCImportResult:
    try:
        return request.app.state.detection_engineering_repository.import_iocs(
            payload.indicators, principal
        )
    except DetectionEngineeringLimitError as exc:
        raise _translate(exc) from exc


@router.get("/iocs/matches", response_model=IOCMatchSummary)
async def ioc_matches(
    request: Request,
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
    days: Annotated[int, Query(ge=1, le=31)] = 7,
    limit: Annotated[int, Query(ge=1, le=1000)] = 500,
) -> IOCMatchSummary:
    return request.app.state.detection_engineering_repository.ioc_matches(days=days, limit=limit)


@router.get("/iocs/export.json", response_class=Response)
async def export_iocs_json(
    request: Request,
    principal: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
) -> Response:
    indicators = request.app.state.detection_engineering_repository.export_iocs()
    request.app.state.audit_repository.append(
        action="IOC_EXPORTED", actor_id=principal.analyst_id,
        actor_display=principal.audit_display, target_type="ioc_export",
        target_id="json", details={"count": len(indicators)},
    )
    content = "[\n" + ",\n".join(item.model_dump_json(indent=2) for item in indicators) + "\n]"
    return Response(
        content=content, media_type="application/json",
        headers={
            "Content-Disposition": "attachment; filename=cyberqalqon-local-iocs.json",
            "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store",
        },
    )
