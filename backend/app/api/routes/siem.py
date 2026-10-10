"""Authenticated SIEM inventory, catalog, and bounded evidence-report APIs."""

from __future__ import annotations

import csv
import io
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response

from app.api.dependencies.auth import require_soc_reader
from app.db.siem import SiemRepository
from app.schemas.auth import AnalystPrincipal
from app.schemas.siem import DetectionRuleSummary, HostSummary, LogSourceSummary, ReportFilters, SecurityActivityReport


router = APIRouter(prefix="/api/v1", tags=["SIEM"])


def _range(start_time: datetime | None, end_time: datetime | None) -> tuple[datetime, datetime]:
    end = end_time or datetime.now(timezone.utc)
    start = start_time or end - timedelta(hours=24)
    if start.tzinfo is None or start.utcoffset() is None or end.tzinfo is None or end.utcoffset() is None:
        raise HTTPException(422, detail={"code": "invalid_request", "message": "Timestamps require UTC offsets"})
    start, end = start.astimezone(timezone.utc), end.astimezone(timezone.utc)
    if start > end or end - start > timedelta(days=31):
        raise HTTPException(422, detail={"code": "invalid_request", "message": "Report range must be ordered and no longer than 31 days", "field": "start_time"})
    return start, end


def _filters(
    severity_min: int | None,
    severity_max: int | None,
    host: str | None,
    rule_id: str | None,
) -> ReportFilters:
    if severity_min is not None and severity_max is not None and severity_min > severity_max:
        raise HTTPException(422, detail={"code": "invalid_request", "message": "severity_min must not exceed severity_max", "field": "severity_min"})
    normalized_host = host.strip() if host else None
    normalized_rule = rule_id.strip() if rule_id else None
    if host is not None and not normalized_host:
        raise HTTPException(422, detail={"code": "invalid_request", "message": "host must not be blank", "field": "host"})
    if rule_id is not None and not normalized_rule:
        raise HTTPException(422, detail={"code": "invalid_request", "message": "rule_id must not be blank", "field": "rule_id"})
    return ReportFilters(
        severity_min=severity_min,
        severity_max=severity_max,
        host=normalized_host,
        rule_id=normalized_rule,
    )


@router.get("/sources", response_model=list[LogSourceSummary])
async def list_sources(request: Request, _: Annotated[AnalystPrincipal, Depends(require_soc_reader)]) -> list[LogSourceSummary]:
    return request.app.state.siem_repository.sources()


@router.get("/hosts", response_model=list[HostSummary])
async def list_hosts(request: Request, _: Annotated[AnalystPrincipal, Depends(require_soc_reader)]) -> list[HostSummary]:
    return request.app.state.siem_repository.hosts()


@router.get("/rules", response_model=list[DetectionRuleSummary])
async def list_rules(request: Request, _: Annotated[AnalystPrincipal, Depends(require_soc_reader)]) -> list[DetectionRuleSummary]:
    return request.app.state.siem_repository.rules()


@router.get("/reports/security-activity", response_model=SecurityActivityReport)
async def security_activity_report(
    request: Request,
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
    start_time: Annotated[datetime | None, Query()] = None,
    end_time: Annotated[datetime | None, Query()] = None,
    severity_min: Annotated[int | None, Query(ge=0, le=16)] = None,
    severity_max: Annotated[int | None, Query(ge=0, le=16)] = None,
    host: Annotated[str | None, Query(max_length=255)] = None,
    rule_id: Annotated[str | None, Query(max_length=128)] = None,
) -> SecurityActivityReport:
    start, end = _range(start_time, end_time)
    return request.app.state.siem_repository.report(
        start, end, _filters(severity_min, severity_max, host, rule_id)
    )


def _safe_cell(value: object) -> object:
    if isinstance(value, str) and value.lstrip(" \t\r\n")[:1] in {"=", "+", "-", "@"}:
        return "'" + value
    return value


def _audit_export(
    request: Request,
    principal: AnalystPrincipal,
    report: SecurityActivityReport,
    filters: ReportFilters,
    target_id: str,
) -> None:
    request.app.state.audit_repository.append(
        action="SECURITY_ACTIVITY_EXPORTED",
        actor_id=principal.analyst_id,
        actor_display=principal.audit_display,
        target_type="report",
        target_id=target_id,
        details={
            "start_time": report.start_time.isoformat(),
            "end_time": report.end_time.isoformat(),
            "filters": filters.model_dump(mode="json", exclude_none=True),
            "total_events": report.total_events,
            "total_alerts": report.total_alerts,
            "total_incidents": report.total_incidents,
        },
    )


@router.get("/reports/security-activity.json", response_class=Response)
async def security_activity_json(
    request: Request,
    principal: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
    start_time: Annotated[datetime | None, Query()] = None,
    end_time: Annotated[datetime | None, Query()] = None,
    severity_min: Annotated[int | None, Query(ge=0, le=16)] = None,
    severity_max: Annotated[int | None, Query(ge=0, le=16)] = None,
    host: Annotated[str | None, Query(max_length=255)] = None,
    rule_id: Annotated[str | None, Query(max_length=128)] = None,
) -> Response:
    start, end = _range(start_time, end_time)
    filters = _filters(severity_min, severity_max, host, rule_id)
    report: SecurityActivityReport = request.app.state.siem_repository.report(start, end, filters)
    _audit_export(request, principal, report, filters, "security-activity.json")
    stamp = report.generated_at.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return Response(
        content=report.model_dump_json(indent=2),
        media_type="application/json",
        headers={
            "Content-Disposition": f"attachment; filename=cyberqalqon-security-activity-{stamp}.json",
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
        },
    )


@router.get("/reports/security-activity.csv", response_class=Response)
async def security_activity_csv(
    request: Request,
    principal: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
    start_time: Annotated[datetime | None, Query()] = None,
    end_time: Annotated[datetime | None, Query()] = None,
    severity_min: Annotated[int | None, Query(ge=0, le=16)] = None,
    severity_max: Annotated[int | None, Query(ge=0, le=16)] = None,
    host: Annotated[str | None, Query(max_length=255)] = None,
    rule_id: Annotated[str | None, Query(max_length=128)] = None,
) -> Response:
    start, end = _range(start_time, end_time)
    filters = _filters(severity_min, severity_max, host, rule_id)
    report: SecurityActivityReport = request.app.state.siem_repository.report(start, end, filters)
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\r\n")
    writer.writerow(["section", "metric", "value"])
    writer.writerow(["summary", "start_time", report.start_time.isoformat()])
    writer.writerow(["summary", "end_time", report.end_time.isoformat()])
    writer.writerow(["summary", "generated_at", report.generated_at.isoformat()])
    for name, value in report.filters.model_dump(exclude_none=True).items():
        writer.writerow(["filter", name, _safe_cell(value)])
    writer.writerow(["summary", "total_events", report.total_events])
    writer.writerow(["summary", "total_alerts", report.total_alerts])
    writer.writerow(["summary", "total_incidents", report.total_incidents])
    writer.writerow(["summary", "authentication_failures", report.authentication_failures])
    writer.writerow(["summary", "file_integrity_events", report.file_integrity_events])
    for section, rows in (("event_sources", report.event_sources), ("alert_severities", report.alert_severities), ("top_rules", report.top_rules), ("host_activity", report.host_activity)):
        for row in rows:
            writer.writerow([section, _safe_cell(row.name), row.count])
    _audit_export(request, principal, report, filters, "security-activity.csv")
    stamp = report.generated_at.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return Response(
        content="\ufeff" + output.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename=cyberqalqon-security-activity-{stamp}.csv", "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"},
    )
