from contextlib import closing
from datetime import timedelta
import json
import sqlite3

import pytest

from app.db.shadow_history import ShadowStoreError
from app.schemas.shadow_history import DurableEvaluationRequest
from app.services.continuous_shadow import ContinuousShadowWorker
from scripts.m30_synthetic import win
from tests.test_m31_history import prepared, client, ingest, payload, PREFIX, BASE
from tests.test_m34_continuous import worker_for


def crash_at(stage):
    def fail(current):
        if current==stage:raise RuntimeError('SYNTHETIC controlled interruption')
    return fail


def unsealed(client,prepared):
    ingest(client);service=client.app.state.shadow_history_service
    service._fault=crash_at('AFTER_RUN_BEGIN')
    response=client.post(PREFIX+'/runs',json=payload())
    service._fault=lambda stage:None
    assert response.status_code==503
    with closing(sqlite3.connect(prepared[1].path)) as connection:
        return connection.execute('SELECT run_id FROM shadow_runs').fetchone()[0]


@pytest.mark.parametrize('stage',['AFTER_RUN_BEGIN','BEFORE_SNAPSHOT_SEAL','AFTER_SNAPSHOT_COMMIT','BEFORE_FINDING_COMMIT','AFTER_FINDING_COMMIT'])
def test_m35_each_durable_run_boundary_resumes_same_identity(client,prepared,stage):
    ingest(client);service=client.app.state.shadow_history_service;body=payload()
    service._fault=crash_at(stage)
    assert client.post(PREFIX+'/runs',json=body).status_code==503
    service._fault=lambda value:None
    with closing(sqlite3.connect(prepared[1].path)) as c:run_id=c.execute('SELECT run_id FROM shadow_runs').fetchone()[0]
    before=client.get(PREFIX+'/runs/'+run_id).json()
    assert before['recovery_intent']['version']=='m35-bounded-snapshot-intent-v1'
    if stage in {'AFTER_RUN_BEGIN','BEFORE_SNAPSHOT_SEAL'}:
        assert before['checkpoint']=='UNSEALED' and before['recovery_state']=='UNSEALED_VERIFICATION_REQUIRED'
    result=client.post(PREFIX+'/runs/'+run_id+'/resume')
    assert result.status_code==200,result.text
    assert result.json()['status']=='COMPLETED' and len(result.json()['result']['finding_ids'])==1
    again=client.post(PREFIX+'/runs',json=body).json()
    assert again['run_id']==run_id and again['result']==result.json()['result']
    with closing(sqlite3.connect(prepared[1].path)) as c:
        assert c.execute('SELECT COUNT(*) FROM shadow_findings').fetchone()[0]==1
        assert c.execute('SELECT COUNT(*) FROM shadow_revisions').fetchone()[0]==1
        assert c.execute('PRAGMA quick_check').fetchone()[0]=='ok'
        assert c.execute('PRAGMA foreign_key_check').fetchall()==[]


@pytest.mark.parametrize('stage',['BEFORE_UNSEALED_RECONCILE','AFTER_UNSEALED_READ','BEFORE_UNSEALED_CLAIM','AFTER_UNSEALED_CLAIM'])
def test_m35_interruption_during_unsealed_recovery_is_repeatable(client,prepared,stage):
    run_id=unsealed(client,prepared);service=client.app.state.shadow_history_service
    service._fault=crash_at(stage)
    assert client.post(PREFIX+'/runs/'+run_id+'/resume').status_code==503
    service._fault=lambda value:None
    response=client.post(PREFIX+'/runs/'+run_id+'/resume')
    assert response.status_code==200,response.text
    assert response.json()['status']=='COMPLETED'


@pytest.mark.parametrize('mode',['missing','changed','new-eligible'])
def test_m35_changed_unsealed_candidate_set_blocks_without_claim_or_findings(client,prepared,mode):
    run_id=unsealed(client,prepared)
    if mode=='new-eligible':
        new_id=ingest(client,[win(35001,BASE+timedelta(seconds=2),'4625')])[0]
        # The normal repository uses current ingestion time. Deliberately model
        # clock rollback/backdated data in this owned synthetic source only.
        with closing(sqlite3.connect(prepared[1].source)) as c:
            c.execute('UPDATE security_events SET ingested_at=? WHERE event_id=?',((BASE+timedelta(seconds=5)).isoformat(),new_id));c.commit()
    else:
        with closing(sqlite3.connect(prepared[1].source)) as c:
            if mode=='missing':c.execute('DELETE FROM security_events')
            else:c.execute("UPDATE security_events SET hostname='SYNTHETIC-tampered'")
            c.commit()
    response=client.post(PREFIX+'/runs/'+run_id+'/resume')
    assert response.status_code==409 and response.json()['detail']['code']=='UNSEALED_SOURCE_SET_CHANGED'
    with closing(sqlite3.connect(prepared[1].path)) as c:
        row=c.execute('SELECT attempts,snapshot_json FROM shadow_runs').fetchone()
        assert row[0]==1 and row[1] is None
        assert c.execute('SELECT COUNT(*) FROM shadow_findings').fetchone()[0]==0


def test_m35_intent_corruption_is_not_recoverable_success(client,prepared):
    run_id=unsealed(client,prepared)
    with closing(sqlite3.connect(prepared[1].path)) as c:
        row=c.execute('SELECT request_json FROM shadow_runs').fetchone()
        body=json.loads(row[0]);body['recovery_intent']['manifest_sha256']='f'*64
        c.execute('UPDATE shadow_runs SET request_json=?',(json.dumps(body),));c.commit()
    response=client.post(PREFIX+'/runs/'+run_id+'/resume')
    assert response.status_code==503 and response.json()['detail']['code']=='SHADOW_STORE_CORRUPT'


def test_m35_continuous_pending_unsealed_run_recovers_without_cursor_skip(client,prepared):
    ingest(client);service=client.app.state.shadow_history_service;worker=worker_for(client,prepared)
    with worker:
        service._fault=crash_at('AFTER_RUN_BEGIN')
        with pytest.raises(ShadowStoreError):worker.tick()
        service._fault=lambda value:None
        assert worker.status()['ticks_committed']==0 and worker.status()['pending_evaluation']
    with ContinuousShadowWorker(worker.path,service,worker.rule,disposable_only=True) as restarted:
        state=restarted.tick()
        assert state['ticks_committed']==1 and len(state['last_finding_ids'])==1
        assert not state['pending_evaluation'] and state['historical_continuity']=='UNPROVEN'


def test_m35_unsealed_claim_cas_rejects_stale_attempt(client,prepared):
    run_id=unsealed(client,prepared);store=prepared[1]
    with pytest.raises(ShadowStoreError,match='RUN_STATE_CONFLICT'):
        store.claim(run_id,'SYNTHETIC',expected_attempts=2)


def test_m35_offline_backup_checks_new_intent_without_rebinding_source(client,prepared):
    from app.services.shadow_backup import capture_pair,validate_backup,inspect_pair
    ingest(client)
    assert client.post(PREFIX+'/runs',json=payload()).status_code==200
    service=client.app.state.shadow_history_service;destination=prepared[1].path.parent/'m35-verified-pair'
    receipt=capture_pair(service,destination,disposable_only=True)
    checked=validate_backup(destination,receipt['manifest_sha256'])
    assert checked['source_binding']==service.store.binding
    with closing(sqlite3.connect(prepared[1].path)) as c:
        body=json.loads(c.execute('SELECT request_json FROM shadow_runs').fetchone()[0])
        body['recovery_intent']['manifest_sha256']='f'*64
        c.execute('UPDATE shadow_runs SET request_json=?',(json.dumps(body),));c.commit()
    with pytest.raises(ValueError,match='INVALID_RECOVERY_INTENT'):
        inspect_pair(prepared[1].source,prepared[1].path)
