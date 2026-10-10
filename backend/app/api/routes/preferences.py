"""Current-analyst isolated preference APIs."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request

from app.api.dependencies.auth import require_soc_mutation, require_soc_reader
from app.db.preferences import PreferenceConflictError, PreferenceRepository
from app.schemas.auth import AnalystPrincipal
from app.schemas.investigations import VersionedMutation
from app.schemas.preferences import AnalystPreferences, AnalystPreferencesUpdate


router = APIRouter(prefix="/api/v1/preferences", tags=["Analyst preferences"])


def _repository(request: Request) -> PreferenceRepository:
    return request.app.state.preference_repository


@router.get("", response_model=AnalystPreferences)
async def get_preferences(
    request: Request,
    principal: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
) -> AnalystPreferences:
    return _repository(request).get(principal.analyst_id)


@router.put("", response_model=AnalystPreferences)
async def update_preferences(
    request: Request,
    payload: AnalystPreferencesUpdate,
    principal: Annotated[AnalystPrincipal, Depends(require_soc_mutation)],
) -> AnalystPreferences:
    try:
        return _repository(request).update(payload, principal)
    except PreferenceConflictError as exc:
        raise HTTPException(
            409,
            detail={"code": "version_conflict", "message": str(exc), "field": "expected_version"},
        ) from exc


@router.post("/reset", response_model=AnalystPreferences)
async def reset_preferences(
    request: Request,
    payload: VersionedMutation,
    principal: Annotated[AnalystPrincipal, Depends(require_soc_mutation)],
) -> AnalystPreferences:
    try:
        return _repository(request).reset(payload.expected_version, principal)
    except PreferenceConflictError as exc:
        raise HTTPException(
            409,
            detail={"code": "version_conflict", "message": str(exc), "field": "expected_version"},
        ) from exc
