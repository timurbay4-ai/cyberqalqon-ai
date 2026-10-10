"""Authenticated SOC case, evidence, playbook, analytics, and reporting APIs."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status
from fastapi.responses import Response

from app.api.dependencies.auth import require_incident_mutation, require_soc_reader
from app.db.cases import (
    CaseConflictError,
    CaseFilters,
    CaseNotFoundError,
    CaseOwnerNotFoundError,
    CaseReferenceNotFoundError,
    CaseRepository,
    InvalidCaseCursorError,
    InvalidCaseTransitionError,
    PlaybookTemplateNotFoundError,
)
from app.schemas.alerts import ErrorResponse
from app.schemas.auth import AnalystPrincipal
from app.schemas.cases import (
    CaseAnalytics,
    CaseAssignmentUpdate,
    CaseCommentCreate,
    CaseCreate,
    CaseDetail,
    CaseEvidenceAnnotationUpdate,
    CaseEvidenceCreate,
    CaseLinkCreate,
    CaseMetadataUpdate,
    CasePage,
    CasePriority,
    CaseSeverity,
    CaseStatus,
    CaseStatusUpdate,
    PlaybookInstantiate,
    PlaybookStepUpdate,
    PlaybookTemplate,
    VersionedCaseMutation,
    SlaEvaluationResult,
)
from app.services.case_reports import render_report


router = APIRouter(prefix="/api/v1/cases", tags=["SOC cases"])


def _repository(request: Request) -> CaseRepository:
    return request.app.state.case_repository


def _error(code: str, message: str, *, field: str | None = None) -> dict[str, Any]:
    detail: dict[str, Any] = {"code": code, "message": message}
    if field:
        detail["field"] = field
    return detail


def _translate(exc: Exception) -> HTTPException:
    if isinstance(exc, CaseNotFoundError):
        return HTTPException(404, detail=_error("case_not_found", "No case exists with the requested identifier", field="case_id"))
    if isinstance(exc, CaseOwnerNotFoundError):
        return HTTPException(404, detail=_error("case_owner_not_found", "The requested active analyst owner does not exist", field="owner_id"))
    if isinstance(exc, CaseReferenceNotFoundError):
        return HTTPException(404, detail=_error("case_reference_not_found", "The requested related record does not exist", field="reference_id"))
    if isinstance(exc, PlaybookTemplateNotFoundError):
        return HTTPException(404, detail=_error("playbook_template_not_found", "The requested safe playbook template does not exist", field="template_key"))
    if isinstance(exc, InvalidCaseTransitionError):
        return HTTPException(409, detail=_error("invalid_case_transition", str(exc), field="status"))
    if isinstance(exc, CaseConflictError):
        return HTTPException(409, detail=_error("case_conflict", str(exc), field="expected_version"))
    raise exc


@router.post(
    "",
    response_model=CaseDetail,
    status_code=status.HTTP_201_CREATED,
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}, 404: {"model": ErrorResponse}, 409: {"model": ErrorResponse}},
)
async def create_case(
    request: Request,
    payload: CaseCreate,
    principal: Annotated[AnalystPrincipal, Depends(require_incident_mutation)],
) -> CaseDetail:
    try:
        return _repository(request).create(payload, principal)
    except (CaseOwnerNotFoundError, CaseReferenceNotFoundError, CaseConflictError) as exc:
        raise _translate(exc) from exc


@router.get("", response_model=CasePage)
async def list_cases(
    request: Request,
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
    case_status: Annotated[list[CaseStatus] | None, Query(alias="status")] = None,
    severity: Annotated[list[CaseSeverity] | None, Query()] = None,
    priority: Annotated[list[CasePriority] | None, Query()] = None,
    owner_id: Annotated[str | None, Query(min_length=1, max_length=64)] = None,
    search: Annotated[str | None, Query(min_length=1, max_length=200)] = None,
    sort: Annotated[Literal["newest", "oldest", "updated", "priority"], Query()] = "updated",
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    cursor: Annotated[str | None, Query(min_length=1, max_length=2048)] = None,
) -> CasePage:
    try:
        result = _repository(request).list(
            CaseFilters(
                statuses=tuple(dict.fromkeys(case_status or [])),
                severities=tuple(dict.fromkeys(severity or [])),
                priorities=tuple(dict.fromkeys(priority or [])),
                owner_id=owner_id.strip() if owner_id else None,
                search=search.strip() if search else None,
            ),
            sort=sort,
            limit=limit,
            cursor=cursor,
        )
    except InvalidCaseCursorError as exc:
        raise HTTPException(422, detail=_error("invalid_cursor", str(exc), field="cursor")) from exc
    return CasePage(items=result.items, limit=limit, total=result.total, next_cursor=result.next_cursor, sort=sort)


@router.get("/analytics", response_model=CaseAnalytics)
async def case_analytics(
    request: Request,
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
    days: Annotated[int, Query(ge=1, le=365)] = 30,
) -> CaseAnalytics:
    return _repository(request).analytics(days)


@router.get("/playbooks/templates", response_model=list[PlaybookTemplate])
async def list_playbook_templates(
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
) -> list[PlaybookTemplate]:
    return CaseRepository.templates()


@router.post("/sla/evaluate", response_model=SlaEvaluationResult)
async def evaluate_case_sla(
    request: Request,
    principal: Annotated[AnalystPrincipal, Depends(require_incident_mutation)],
) -> SlaEvaluationResult:
    evaluated, created, generated_at = _repository(request).evaluate_sla(principal)
    return SlaEvaluationResult(
        evaluated_cases=evaluated,
        notifications_created=created,
        generated_at=generated_at,
    )


@router.get("/{case_id}", response_model=CaseDetail)
async def get_case(
    request: Request,
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
    case_id: Annotated[str, Path(min_length=1, max_length=64)],
) -> CaseDetail:
    try:
        return _repository(request).get(case_id)
    except CaseNotFoundError as exc:
        raise _translate(exc) from exc


@router.patch("/{case_id}", response_model=CaseDetail)
async def update_case(
    request: Request,
    payload: CaseMetadataUpdate,
    principal: Annotated[AnalystPrincipal, Depends(require_incident_mutation)],
    case_id: Annotated[str, Path(min_length=1, max_length=64)],
) -> CaseDetail:
    try:
        return _repository(request).update_metadata(case_id, payload, principal)
    except (CaseNotFoundError, CaseConflictError) as exc:
        raise _translate(exc) from exc


@router.post("/{case_id}/status", response_model=CaseDetail)
async def transition_case(
    request: Request,
    payload: CaseStatusUpdate,
    principal: Annotated[AnalystPrincipal, Depends(require_incident_mutation)],
    case_id: Annotated[str, Path(min_length=1, max_length=64)],
) -> CaseDetail:
    try:
        return _repository(request).transition(case_id, payload, principal)
    except (CaseNotFoundError, CaseConflictError, InvalidCaseTransitionError) as exc:
        raise _translate(exc) from exc


@router.post("/{case_id}/assignment", response_model=CaseDetail)
async def assign_case(
    request: Request,
    payload: CaseAssignmentUpdate,
    principal: Annotated[AnalystPrincipal, Depends(require_incident_mutation)],
    case_id: Annotated[str, Path(min_length=1, max_length=64)],
) -> CaseDetail:
    try:
        return _repository(request).assign(case_id, payload, principal)
    except (CaseNotFoundError, CaseOwnerNotFoundError, CaseConflictError) as exc:
        raise _translate(exc) from exc


@router.post("/{case_id}/comments", response_model=CaseDetail, status_code=201)
async def add_case_comment(
    request: Request,
    payload: CaseCommentCreate,
    principal: Annotated[AnalystPrincipal, Depends(require_incident_mutation)],
    case_id: Annotated[str, Path(min_length=1, max_length=64)],
) -> CaseDetail:
    try:
        return _repository(request).add_comment(case_id, payload, principal)
    except (CaseNotFoundError, CaseConflictError) as exc:
        raise _translate(exc) from exc


@router.post("/{case_id}/related/{kind}", response_model=CaseDetail, status_code=201)
async def link_case_reference(
    request: Request,
    payload: CaseLinkCreate,
    principal: Annotated[AnalystPrincipal, Depends(require_incident_mutation)],
    case_id: Annotated[str, Path(min_length=1, max_length=64)],
    kind: Annotated[Literal["alert", "incident", "event"], Path()],
) -> CaseDetail:
    try:
        return _repository(request).link_reference(case_id, kind, payload, principal)
    except (CaseNotFoundError, CaseReferenceNotFoundError, CaseConflictError) as exc:
        raise _translate(exc) from exc


@router.post("/{case_id}/evidence", response_model=CaseDetail, status_code=201)
async def acquire_case_evidence(
    request: Request,
    payload: CaseEvidenceCreate,
    principal: Annotated[AnalystPrincipal, Depends(require_incident_mutation)],
    case_id: Annotated[str, Path(min_length=1, max_length=64)],
) -> CaseDetail:
    try:
        return _repository(request).acquire_evidence(case_id, payload, principal)
    except (CaseNotFoundError, CaseReferenceNotFoundError, CaseConflictError) as exc:
        raise _translate(exc) from exc


@router.post("/{case_id}/evidence/{evidence_id}/verify", response_model=CaseDetail)
async def verify_case_evidence(
    request: Request,
    payload: VersionedCaseMutation,
    principal: Annotated[AnalystPrincipal, Depends(require_incident_mutation)],
    case_id: Annotated[str, Path(min_length=1, max_length=64)],
    evidence_id: Annotated[str, Path(min_length=1, max_length=64)],
) -> CaseDetail:
    try:
        return _repository(request).verify_evidence(case_id, evidence_id, payload.expected_version, principal)
    except (CaseNotFoundError, CaseReferenceNotFoundError, CaseConflictError) as exc:
        raise _translate(exc) from exc


@router.patch("/{case_id}/evidence/{evidence_id}", response_model=CaseDetail)
async def annotate_case_evidence(
    request: Request,
    payload: CaseEvidenceAnnotationUpdate,
    principal: Annotated[AnalystPrincipal, Depends(require_incident_mutation)],
    case_id: Annotated[str, Path(min_length=1, max_length=64)],
    evidence_id: Annotated[str, Path(min_length=1, max_length=64)],
) -> CaseDetail:
    try:
        return _repository(request).annotate_evidence(case_id, evidence_id, payload, principal)
    except (CaseNotFoundError, CaseReferenceNotFoundError, CaseConflictError) as exc:
        raise _translate(exc) from exc


@router.post("/{case_id}/playbooks", response_model=CaseDetail, status_code=201)
async def instantiate_case_playbook(
    request: Request,
    payload: PlaybookInstantiate,
    principal: Annotated[AnalystPrincipal, Depends(require_incident_mutation)],
    case_id: Annotated[str, Path(min_length=1, max_length=64)],
) -> CaseDetail:
    try:
        return _repository(request).instantiate_playbook(case_id, payload, principal)
    except (CaseNotFoundError, PlaybookTemplateNotFoundError, CaseConflictError) as exc:
        raise _translate(exc) from exc


@router.patch("/{case_id}/playbooks/{playbook_id}/steps/{step_id}", response_model=CaseDetail)
async def update_case_playbook_step(
    request: Request,
    payload: PlaybookStepUpdate,
    principal: Annotated[AnalystPrincipal, Depends(require_incident_mutation)],
    case_id: Annotated[str, Path(min_length=1, max_length=64)],
    playbook_id: Annotated[str, Path(min_length=1, max_length=64)],
    step_id: Annotated[str, Path(min_length=1, max_length=64)],
) -> CaseDetail:
    try:
        return _repository(request).update_playbook_step(case_id, playbook_id, step_id, payload, principal)
    except (CaseNotFoundError, CaseOwnerNotFoundError, CaseReferenceNotFoundError, CaseConflictError) as exc:
        raise _translate(exc) from exc


@router.post("/{case_id}/reports/{format_name}")
async def export_case_report(
    request: Request,
    principal: Annotated[AnalystPrincipal, Depends(require_incident_mutation)],
    case_id: Annotated[str, Path(min_length=1, max_length=64)],
    format_name: Annotated[Literal["json", "csv", "pdf"], Path()],
) -> Response:
    try:
        repository = _repository(request)
        content, media_type, filename = render_report(repository.report_payload(case_id), format_name)
        repository.record_report(case_id, format_name.upper(), content, principal)
    except CaseNotFoundError as exc:
        raise _translate(exc) from exc
    return Response(
        content=content,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
        },
    )
