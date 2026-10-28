"""Shadow-only CDRC extension. Simulation unavailable in normal app construction."""
import sqlite3
from typing import Annotated

from fastapi import APIRouter,Depends,HTTPException,Request
from pydantic import ValidationError
from starlette.concurrency import run_in_threadpool

from app.api.dependencies.auth import require_soc_reader,require_alert_mutation
from app.api.routes.alerts import _read_json_object
from app.api.routes.cqql import _run_cancellable,_execution_error
from app.db.cqql import CQQLQueryBusyError,CQQLQueryCancelledError,CQQLQueryTimeoutError,CQQLExecutionError
from app.schemas.auth import AnalystPrincipal
from app.schemas.shadow_detection import ShadowRule,ShadowSimulationRequest,ShadowSimulationResult,EXTENSION_FIELDS
from app.services.shadow_rules import catalog,legacy_compatibility,validate_mitre
from app.services.shadow_detection import (ShadowResourceLimitError,MAX_EVENTS,MAX_GROUPS,MAX_EVENTS_PER_GROUP,
    MAX_INPUT_BYTES,MAX_FINDINGS,MAX_GRAPH_NODES,MAX_GRAPH_EDGES)
from app.services.cqql import public_field_catalog

router = APIRouter(prefix='/api/v1/detection-engineering/shadow-v2',tags=['Detection engineering'])


def _error(code,status=422):
    return HTTPException(status,detail={'code':code,'message':'Shadow operation rejected: '+code})


async def _audit(request,principal,action,*,rule=None,outcome='SUCCESS',code='OK'):
    try:
        repository=getattr(request.app.state,'shadow_audit_repository',request.app.state.audit_repository)
        await run_in_threadpool(repository.append,
            action=action,actor_id=principal.analyst_id,actor_display=principal.audit_display,
            target_type='shadow_rule_v2',target_id=rule.rule_id if rule else None,outcome=outcome,
            details={'rule_version':rule.rule_version if rule else None,'reason_code':code,'live_activation':False},budget_ms=100)
    except sqlite3.Error as exc:
        error=_error('audit_unavailable',503)
        # Extended SQLite codes retain their primary category in the low byte.
        primary=(getattr(exc,'sqlite_errorcode',0) or 0)&255
        error.detail['reason_code']=('AUDIT_SQLITE_BUSY' if primary in (sqlite3.SQLITE_BUSY,sqlite3.SQLITE_LOCKED) else
            'AUDIT_BUDGET_EXPIRED' if primary==sqlite3.SQLITE_INTERRUPT else 'AUDIT_WRITE_FAILED')
        error.headers={'Retry-After':'1'}
        raise error from None


@router.get('/catalog')
async def get_catalog(request: Request,_: Annotated[AnalystPrincipal,Depends(require_soc_reader)]):
    return {'version':'cdrc-v2','scope':'SOURCE_TEST_RESULTS','production_active':False,
        'simulation_enabled':request.app.state.disposable_detection_simulation,
        'rules':[{'definition':rule.model_dump(mode='json'),'rule_version':rule.rule_version} for rule in catalog()],
        'legacy_compatibility':legacy_compatibility(),'fields':public_field_catalog(),
        'source_specific_extensions':sorted(EXTENSION_FIELDS),'limits':{'max_events':MAX_EVENTS,
            'max_groups':MAX_GROUPS,'max_events_per_group':MAX_EVENTS_PER_GROUP,'max_input_bytes':MAX_INPUT_BYTES,
            'max_findings':MAX_FINDINGS,'max_graph_nodes':MAX_GRAPH_NODES,'max_graph_edges':MAX_GRAPH_EDGES,
            'max_concurrent_evaluations':2,'cqql_deadline_ms':1500,'cqql_slots':4},
        'mandatory_source_scope':['manager_identity','agent_id','host.name'],
        'state_scope':'PER_REQUEST_ONLY','window_completion':'NO_GLOBAL_WATERMARK',
        'management':'CONTENT_ADDRESSED_DEFINITIONS_NOT_PERSISTENT_RULE_MANAGEMENT'}


@router.post('/validate')
async def validate(request: Request,principal: Annotated[AnalystPrincipal,Depends(require_alert_mutation)]):
    raw = await _read_json_object(request,24_000)
    try:
        rule = ShadowRule.model_validate(raw)
        validate_mitre(rule)
    except (ValidationError,ValueError):
        await _audit(request,principal,'SHADOW_V2_VALIDATE',outcome='FAILURE',code='INVALID_RULE')
        raise _error('invalid_rule_definition') from None
    await _audit(request,principal,'SHADOW_V2_VALIDATE',rule=rule)
    return {'valid':True,'rule_version':rule.rule_version,'definition':rule.model_dump(mode='json'),
        'production_active':False,'warnings':['STATELESS_SIMULATION_ONLY','CLAIMED_SOURCE_IDENTITY','HISTORICAL_CONTINUITY_UNPROVEN']}


@router.post('/simulate',response_model=ShadowSimulationResult)
async def simulate(request: Request,principal: Annotated[AnalystPrincipal,Depends(require_alert_mutation)]):
    if not request.app.state.disposable_detection_simulation:
        raise _error('disposable_simulation_required',409)
    raw = await _read_json_object(request,28_000)
    try: payload = ShadowSimulationRequest.model_validate(raw)
    except ValidationError: raise _error('invalid_simulation_request') from None
    try:
        result = await _run_cancellable(request,request.app.state.advanced_detection_engine.simulate_contract,
            payload,request.app.state.cqql_search_repository)
    except ShadowResourceLimitError as exc:
        await _audit(request,principal,'SHADOW_V2_SIMULATE',rule=payload.rule,outcome='FAILURE',code=str(exc))
        raise _error('shadow_resource_limit',429) from None
    except (CQQLQueryBusyError,CQQLQueryTimeoutError,CQQLQueryCancelledError,CQQLExecutionError) as exc:
        await _audit(request,principal,'SHADOW_V2_SIMULATE',rule=payload.rule,outcome='FAILURE',code=type(exc).__name__)
        raise _execution_error(exc) from None
    except ValueError:
        await _audit(request,principal,'SHADOW_V2_SIMULATE',rule=payload.rule,outcome='FAILURE',code='INVALID_RULE')
        raise _error('invalid_rule_definition') from None
    except sqlite3.Error:
        raise _error('storage_unavailable',503) from None
    await _audit(request,principal,'SHADOW_V2_SIMULATE',rule=payload.rule,
                 code='RULE_DISABLED' if result.status == 'RULE_DISABLED' else 'SIMULATION_COMPLETE')
    return result
