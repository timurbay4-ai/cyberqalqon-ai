"""Durable history extends the existing shadow-v2 family; explicit offline gate."""
from typing import Annotated
from uuid import uuid4
import sqlite3
from fastapi import APIRouter,Depends,Request,HTTPException,Query
from pydantic import ValidationError
from app.api.dependencies.auth import require_soc_reader,require_alert_mutation
from app.api.routes.alerts import _read_json_object
from app.api.routes.cqql import _run_cancellable,_execution_error
from app.db.cqql import CQQLQueryBusyError,CQQLQueryCancelledError,CQQLQueryTimeoutError,CQQLExecutionError
from app.db.shadow_history import ShadowStoreError
from app.schemas.auth import AnalystPrincipal
from app.schemas.shadow_history import DurableEvaluationRequest,FindingTransition,FindingDetail,FindingPage,DurableRun
from app.schemas.evidence_consistency import ReconciliationPage
from app.services.shadow_detection import ShadowResourceLimitError
from app.services.shadow_scheduling import ShadowAdmissionError
from app.services.shadow_rules import validate_mitre

router=APIRouter(prefix='/api/v1/detection-engineering/shadow-v2',tags=['Detection engineering'])


def service(request):
    value=getattr(request.app.state,'shadow_history_service',None)
    if value is None:raise HTTPException(409,detail={'code':'disposable_history_required','message':'Durable history is not configured.'})
    return value


def execution_error(request,exc):
    code=str(exc)
    if isinstance(exc,(CQQLQueryBusyError,CQQLQueryCancelledError,CQQLQueryTimeoutError,CQQLExecutionError)):
        return _execution_error(exc)
    status=(503 if code=='SHADOW_SHUTDOWN' else
        409 if code in {'RECOVERY_EVIDENCE_GAP_OR_CHANGE','INVALID_RECOVERY_SNAPSHOT','SOURCE_RECORD_CONFLICT','EVENT_IDENTITY_CONFLICT','UNSEALED_SOURCE_SET_CHANGED'} else
        429 if isinstance(exc,ShadowAdmissionError) else 429 if isinstance(exc,ShadowResourceLimitError) else
        404 if code in {'RUN_NOT_FOUND','FINDING_NOT_FOUND','REVISION_NOT_FOUND'} else
        422 if code in {'INVALID_CURSOR','INVALID_LIMIT','INVALID_SUPERSESSION','SHADOW_REQUEST_TOO_LARGE'} else
        503 if code in {'SHADOW_STORE_BUSY','SHADOW_STORE_WRITE_FAILED','SHADOW_STORE_READ_FAILED','SHADOW_STORE_CORRUPT','SHADOW_CAPACITY_EXCEEDED','SHADOW_SHUTDOWN_INCOMPLETE','SHADOW_WORKER_EXCEPTION'} else 409)
    return HTTPException(status,detail={'code':code,'message':'Durable shadow operation rejected.',
        'request_id':getattr(request.state,'shadow_request_id',uuid4().hex),
        'run_id':getattr(exc,'run_id',None),
        'retryable':code in {'SHADOW_STORE_BUSY','SHADOW_QUEUE_FULL','SHADOW_QUEUE_EXPIRED','SHADOW_HISTORY_BUSY'},
        'resume_required':code in {'RUN_REQUIRES_EXPLICIT_RESUME','UNSEALED_RECOVERY_BLOCKED','UNSEALED_VERIFICATION_REQUIRED','UNSEALED_SOURCE_SET_CHANGED'}},
        headers={'Retry-After':'1'} if status in (429,503) else None)


async def execute(request,function,*args,**kwargs):
    try:return await _run_cancellable(request,function,*args,**kwargs)
    except (ShadowStoreError,ShadowAdmissionError,ShadowResourceLimitError,CQQLQueryBusyError,
            CQQLQueryCancelledError,CQQLQueryTimeoutError,CQQLExecutionError) as exc:
        raise execution_error(request,exc) from None
    except sqlite3.Error as exc:
        code='SHADOW_STORE_BUSY' if getattr(exc,'sqlite_errorcode',None) in (sqlite3.SQLITE_BUSY,sqlite3.SQLITE_LOCKED) else 'SHADOW_STORE_READ_FAILED'
        raise execution_error(request,ShadowStoreError(code)) from None
    except ValueError:raise execution_error(request,ShadowStoreError('SHADOW_STORE_CORRUPT')) from None


@router.get('/history-status')
async def status(request:Request,_:Annotated[AnalystPrincipal,Depends(require_soc_reader)]):
    value=getattr(request.app.state,'shadow_history_service',None)
    if value is not None:return await execute(request,value.status)
    return {'enabled':value is not None,'scope':'DISPOSABLE_DURABLE_SHADOW','production_active':False,
        'schema_version':1 if value else None,'resource_state':value.scheduler.snapshot() if value else None}


@router.post('/runs',response_model=DurableRun)
async def create_run(request:Request,principal:Annotated[AnalystPrincipal,Depends(require_alert_mutation)]):
    value=service(request);raw=await _read_json_object(request,30000)
    try:
        body=DurableEvaluationRequest.model_validate(raw);validate_mitre(body.simulation.rule)
    except (ValidationError,ValueError):raise HTTPException(422,detail={'code':'invalid_durable_request','message':'Invalid bounded evaluation definition.'}) from None
    return await execute(request,value.evaluate,body,principal.audit_display)


@router.get('/runs/{run_id}',response_model=DurableRun)
async def run_detail(run_id:str,request:Request,_:Annotated[AnalystPrincipal,Depends(require_soc_reader)]):
    return await execute(request,service(request).summary,run_id)


@router.post('/runs/{run_id}/resume',response_model=DurableRun)
async def resume(run_id:str,request:Request,principal:Annotated[AnalystPrincipal,Depends(require_alert_mutation)]):
    return await execute(request,service(request).resume,run_id,principal.audit_display)


@router.get('/findings',response_model=FindingPage)
async def findings(request:Request,_:Annotated[AnalystPrincipal,Depends(require_soc_reader)],limit:int=Query(20,ge=1,le=50),cursor:str|None=Query(None,max_length=512)):
    return await execute(request,service(request).page,limit,cursor)


@router.get('/reconciliation',response_model=ReconciliationPage)
async def reconciliation(request:Request,_:Annotated[AnalystPrincipal,Depends(require_soc_reader)],limit:int=Query(20,ge=1,le=50),cursor:str|None=Query(None,max_length=512)):
    return await execute(request,service(request).reconcile,limit,cursor)


@router.get('/findings/{finding_id}',response_model=FindingDetail)
async def detail(finding_id:str,request:Request,_:Annotated[AnalystPrincipal,Depends(require_soc_reader)],revision:int|None=Query(None,ge=1,le=8192)):
    return await execute(request,service(request).detail,finding_id,revision)


@router.post('/findings/{finding_id}/transitions',response_model=FindingDetail)
async def transition(finding_id:str,request:Request,principal:Annotated[AnalystPrincipal,Depends(require_alert_mutation)]):
    raw=await _read_json_object(request,4096)
    try:body=FindingTransition.model_validate(raw)
    except ValidationError:raise HTTPException(422,detail={'code':'invalid_transition','message':'Invalid typed transition.'}) from None
    return await execute(request,service(request).transition,finding_id,body,principal.audit_display)
