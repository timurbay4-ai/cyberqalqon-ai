"""Authenticated, durable incident investigation workspace APIs."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status

from app.api.dependencies.auth import require_incident_mutation, require_soc_reader
from app.db.investigations import (
    InvalidInvestigationCursorError,
    InvestigationAssigneeNotFoundError,
    InvestigationConflictError,
    InvestigationDuplicateError,
    InvestigationEvidenceNotFoundError,
    InvestigationNoChangeError,
    InvestigationNotFoundError,
    InvestigationRepository,
)
from app.schemas.alerts import ErrorResponse
from app.schemas.auth import AnalystPrincipal
from app.schemas.investigations import (
    ChecklistCreate,
    ChecklistReorder,
    ChecklistUpdate,
    EvidenceAnnotationUpdate,
    EvidencePinCreate,
    InvestigationTimelinePage,
    InvestigationWorkspace,
    VersionedMutation,
)


router = APIRouter(prefix="/api/v1/incidents", tags=["Incident investigations"])


def _repository(request: Request) -> InvestigationRepository:
    return request.app.state.investigation_repository


def _error(code: str, message: str, *, field: str | None = None) -> dict[str, Any]:
    body: dict[str, Any] = {"code": code, "message": message}
    if field is not None:
        body["field"] = field
    return body


def _translate(exc: Exception) -> HTTPException:
    if isinstance(exc, InvestigationEvidenceNotFoundError):
        return HTTPException(
            404, detail=_error("evidence_not_found", "The referenced evidence does not exist", field="evidence_id")
        )
    if isinstance(exc, InvestigationAssigneeNotFoundError):
        return HTTPException(
            404, detail=_error("assignee_not_found", "The active analyst does not exist", field="assigned_to")
        )
    if isinstance(exc, InvestigationNotFoundError):
        return HTTPException(
            404, detail=_error("investigation_resource_not_found", "The incident investigation resource does not exist")
        )
    if isinstance(exc, InvestigationDuplicateError):
        return HTTPException(409, detail=_error("duplicate_evidence", str(exc), field="evidence_id"))
    if isinstance(exc, InvestigationNoChangeError):
        return HTTPException(409, detail=_error("unchanged", str(exc)))
    if isinstance(exc, InvestigationConflictError):
        return HTTPException(409, detail=_error("version_conflict", str(exc), field="expected_version"))
    raise exc


@router.get(
    "/{incident_id}/investigation",
    response_model=InvestigationWorkspace,
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
)
async def get_investigation(
    request: Request,
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
    incident_id: Annotated[str, Path(min_length=1, max_length=64)],
) -> InvestigationWorkspace:
    try:
        return _repository(request).get_workspace(incident_id)
    except InvestigationNotFoundError as exc:
        raise _translate(exc) from exc


@router.post(
    "/{incident_id}/investigation/checklist",
    response_model=InvestigationWorkspace,
    status_code=status.HTTP_201_CREATED,
)
async def create_checklist_item(
    request: Request,
    payload: ChecklistCreate,
    principal: Annotated[AnalystPrincipal, Depends(require_incident_mutation)],
    incident_id: Annotated[str, Path(min_length=1, max_length=64)],
) -> InvestigationWorkspace:
    try:
        return _repository(request).create_checklist_item(incident_id, payload, principal)
    except (InvestigationNotFoundError, InvestigationAssigneeNotFoundError, InvestigationConflictError) as exc:
        raise _translate(exc) from exc


@router.patch(
    "/{incident_id}/investigation/checklist/{item_id}",
    response_model=InvestigationWorkspace,
)
async def update_checklist_item(
    request: Request,
    payload: ChecklistUpdate,
    principal: Annotated[AnalystPrincipal, Depends(require_incident_mutation)],
    incident_id: Annotated[str, Path(min_length=1, max_length=64)],
    item_id: Annotated[str, Path(min_length=1, max_length=64)],
) -> InvestigationWorkspace:
    try:
        return _repository(request).update_checklist_item(incident_id, item_id, payload, principal)
    except (
        InvestigationNotFoundError, InvestigationAssigneeNotFoundError,
        InvestigationConflictError, InvestigationNoChangeError,
    ) as exc:
        raise _translate(exc) from exc


@router.post(
    "/{incident_id}/investigation/checklist/reorder",
    response_model=InvestigationWorkspace,
)
async def reorder_checklist(
    request: Request,
    payload: ChecklistReorder,
    principal: Annotated[AnalystPrincipal, Depends(require_incident_mutation)],
    incident_id: Annotated[str, Path(min_length=1, max_length=64)],
) -> InvestigationWorkspace:
    try:
        return _repository(request).reorder_checklist(incident_id, payload, principal)
    except (InvestigationNotFoundError, InvestigationConflictError, InvestigationNoChangeError) as exc:
        raise _translate(exc) from exc


@router.post(
    "/{incident_id}/investigation/evidence",
    response_model=InvestigationWorkspace,
    status_code=status.HTTP_201_CREATED,
)
async def pin_evidence(
    request: Request,
    payload: EvidencePinCreate,
    principal: Annotated[AnalystPrincipal, Depends(require_incident_mutation)],
    incident_id: Annotated[str, Path(min_length=1, max_length=64)],
) -> InvestigationWorkspace:
    try:
        return _repository(request).pin_evidence(incident_id, payload, principal)
    except (
        InvestigationNotFoundError, InvestigationEvidenceNotFoundError,
        InvestigationDuplicateError, InvestigationConflictError,
    ) as exc:
        raise _translate(exc) from exc


@router.patch(
    "/{incident_id}/investigation/evidence/{pin_id}",
    response_model=InvestigationWorkspace,
)
async def annotate_evidence(
    request: Request,
    payload: EvidenceAnnotationUpdate,
    principal: Annotated[AnalystPrincipal, Depends(require_incident_mutation)],
    incident_id: Annotated[str, Path(min_length=1, max_length=64)],
    pin_id: Annotated[str, Path(min_length=1, max_length=64)],
) -> InvestigationWorkspace:
    try:
        return _repository(request).annotate_evidence(incident_id, pin_id, payload, principal)
    except (InvestigationNotFoundError, InvestigationConflictError, InvestigationNoChangeError) as exc:
        raise _translate(exc) from exc


@router.post(
    "/{incident_id}/investigation/evidence/{pin_id}/unpin",
    response_model=InvestigationWorkspace,
)
async def unpin_evidence(
    request: Request,
    payload: VersionedMutation,
    principal: Annotated[AnalystPrincipal, Depends(require_incident_mutation)],
    incident_id: Annotated[str, Path(min_length=1, max_length=64)],
    pin_id: Annotated[str, Path(min_length=1, max_length=64)],
) -> InvestigationWorkspace:
    try:
        return _repository(request).unpin_evidence(
            incident_id, pin_id, payload.expected_version, principal
        )
    except (InvestigationNotFoundError, InvestigationConflictError) as exc:
        raise _translate(exc) from exc


@router.get(
    "/{incident_id}/investigation/timeline",
    response_model=InvestigationTimelinePage,
)
async def investigation_timeline(
    request: Request,
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
    incident_id: Annotated[str, Path(min_length=1, max_length=64)],
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    cursor: Annotated[str | None, Query(min_length=1, max_length=256)] = None,
) -> InvestigationTimelinePage:
    try:
        return _repository(request).timeline(incident_id, limit=limit, cursor=cursor)
    except InvestigationNotFoundError as exc:
        raise _translate(exc) from exc
    except InvalidInvestigationCursorError as exc:
        raise HTTPException(422, detail=_error("invalid_cursor", str(exc), field="cursor")) from exc
