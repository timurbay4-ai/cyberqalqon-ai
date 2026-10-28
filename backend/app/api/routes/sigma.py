"""Authenticated, audited, non-activating Sigma preview."""
from typing import Annotated
import threading

from fastapi import APIRouter, Depends, HTTPException, Request
from starlette.concurrency import run_in_threadpool

from app.api.dependencies.auth import require_alert_mutation
from app.api.routes.alerts import _read_json_object
from app.api.routes.shadow_detection import _audit
from app.schemas.auth import AnalystPrincipal
from app.services.sigma import convert_sigma, SigmaImportError, MAX_BYTES

router = APIRouter(prefix='/api/v1/detection-engineering/sigma', tags=['Detection engineering'])
_preview_slots = threading.BoundedSemaphore(2)


@router.post('/preview')
async def preview(request: Request, principal: Annotated[AnalystPrincipal, Depends(require_alert_mutation)]):
    if not _preview_slots.acquire(blocking=False):
        raise HTTPException(503, detail={'code':'sigma_preview_busy','message':'Sigma preview capacity reached'},
                            headers={'Retry-After':'1'})
    try:
        return await _preview(request, principal)
    finally:
        _preview_slots.release()


async def _preview(request, principal):
    try:
        body = await _read_json_object(request, MAX_BYTES + 8192)
    except (ValueError, UnicodeError, RecursionError):
        raise HTTPException(422, detail={'code':'invalid_sigma_encoding','message':'Invalid Sigma request encoding'}) from None
    if set(body) != {'yaml', 'profile'} or body.get('profile') != 'CQ_ENDPOINT_SHADOW_V1':
        raise HTTPException(422, detail={'code': 'explicit_sigma_profile_required', 'message': 'Explicit endpoint shadow profile required'})
    try:
        result = await run_in_threadpool(convert_sigma, body['yaml'])
    except SigmaImportError as exc:
        await _audit(request, principal, 'SIGMA_PREVIEW_REJECTED', outcome='FAILURE', code=str(exc))
        raise HTTPException(422, detail={'code': str(exc), 'message': 'Unsupported or invalid Sigma profile'}) from None
    await _audit(request, principal, 'SIGMA_PREVIEW_CONVERTED')
    return result
