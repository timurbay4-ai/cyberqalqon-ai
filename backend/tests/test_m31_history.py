from __future__ import annotations
import copy
import hashlib
import hmac
import json
import sqlite3
import threading
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
import time
from contextlib import closing
from datetime import datetime,timedelta,timezone
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from app.main import create_app
from app.core.config import Settings
from app.db.alerts import AlertRepository
from app.db.shadow_history import initialize,rollback_empty,ShadowHistoryRepository,ShadowStoreError
from app.db.cqql import CQQLSearchRepository,CQQLQueryCancelledError
from app.schemas.shadow_history import DurableEvaluationRequest,IdentityPolicy,FindingTransition
from app.schemas.shadow_detection import ShadowRule
from app.services.shadow_detection import read_snapshot
from app.services.shadow_history import ShadowHistoryService
from app.services.shadow_rules import catalog
from app.services.identity_resolution import IdentityResolver
from app.services.shadow_scheduling import ShadowScheduler,ShadowAdmissionError
from app.services.wazuh_normalizer import canonical_json
from tests.conftest import bootstrap_and_login,TEST_PASSWORD
from scripts.m30_synthetic import auth,win,ssh

BASE=datetime.now(timezone.utc).replace(microsecond=0)-timedelta(minutes=20)
PREFIX='/api/v1/detection-engineering/shadow-v2'


def payload(rule_id='SHADOW-WINDOWS-AUTH',**changes):
    value={'simulation':{'rule':next(rule for rule in catalog() if rule.rule_id==rule_id).model_dump(mode='json'),
        'start_time':(BASE-timedelta(seconds=1)).isoformat(),'end_time':(BASE+timedelta(minutes=15)).isoformat(),
        'evaluation_time':datetime.now(timezone.utc).isoformat()},'identity_policy':{'minimum':'PARTIAL'}}
    value.update(changes);return value


@pytest.fixture
def prepared(database_path):
    settings=Settings(database_url=f'sqlite:///{database_path.as_posix()}',allow_m14_schema_migration=False,
        wazuh_ingest_api_key='SYNTHETIC-m31-key',correlation_enabled=False,ai_enabled=False)
    AlertRepository(settings.database_url,migration_target_version=17).initialize()
    sidecar=database_path.parent/'m31-history.db';initialize(sidecar,database_path,disposable_only=True)
    return settings,ShadowHistoryRepository(sidecar,database_path)


@pytest.fixture
def client(prepared):
    settings,store=prepared
    with TestClient(create_app(settings,disposable_detection_simulation=True,shadow_history=store)) as value:
        bootstrap_and_login(value)
        yield value


def ingest(client,raws=None):
    ids=[]
    for raw in raws or auth(BASE):
        response=client.post('/api/v1/events/ingest',headers={'X-API-Key':'SYNTHETIC-m31-key'},json=raw)
        assert response.status_code in (200,201),response.text
        ids.append(response.json()['event']['event_id'])
    return ids


def evaluate(client,body=None):
    response=client.post(PREFIX+'/runs',json=body or payload())
    assert response.status_code==200,response.text
    value=response.json();assert value['status']=='COMPLETED'
    return value


def test_durable_dedup_actual_api(client,prepared):
    ingest(client);body=payload();first=evaluate(client,body);again=evaluate(client,body)
    assert first['run_id']==again['run_id']
    finding=first['result']['finding_ids'][0]
    detail=client.get(PREFIX+'/findings/'+finding).json()
    assert detail['state']=='SHADOW_CANDIDATE' and detail['revision']==1
    assert all(value=='AVAILABLE' for value in detail['current_evidence_availability'].values())
    assert detail['matching_evidence']['rule_version']==ShadowRule.model_validate(body['simulation']['rule']).rule_version
    assert len(detail['identity']['entities'])==7 and not any(entity['status']=='VERIFIED' for entity in detail['identity']['entities'])
    assert client.get(PREFIX+'/findings?limit=1').json()['items'][0]['finding_id']==finding
    store=prepared[1]
    with closing(sqlite3.connect(store.path)) as c:
        assert c.execute('SELECT COUNT(*) FROM shadow_findings').fetchone()[0]==1
        assert c.execute('SELECT COUNT(*) FROM shadow_revisions').fetchone()[0]==1
        assert c.execute('PRAGMA quick_check').fetchone()[0]=='ok'
        assert not c.execute('PRAGMA foreign_key_check').fetchall()


def test_migration_is_explicit_repeatable_and_empty_rollback(prepared):
    settings,store=prepared
    with pytest.raises(ShadowStoreError):initialize(store.path,store.source)
    initialize(store.path,store.source,disposable_only=True)
    rollback_empty(store.path,store.source,disposable_only=True)
    initialize(store.path,store.source,disposable_only=True)
    with closing(sqlite3.connect(store.source)) as c:assert c.execute('PRAGMA user_version').fetchone()[0]==17


def test_acknowledged_history_cannot_be_rolled_back(client,prepared):
    ingest(client);evaluate(client)
    with pytest.raises(ShadowStoreError,match='ACKNOWLEDGED_HISTORY'):
        rollback_empty(prepared[1].path,prepared[1].source,disposable_only=True)


def test_single_owner_prevents_live_run_stealing(client,prepared):
    store=ShadowHistoryRepository(prepared[1].path,prepared[1].source)
    another=ShadowHistoryService(store,CQQLSearchRepository(store.source))
    with pytest.raises(ShadowStoreError,match='SHADOW_OWNER_LOCKED'):another.open()


def test_default_closed_gate_and_csrf(client,prepared):
    assert client.post(PREFIX+'/runs',headers={'X-CSRF-Token':'wrong'},json=payload()).status_code==403
    with pytest.raises(ValueError):create_app(prepared[0],shadow_history=prepared[1])
    original=client.app.state.shadow_history_service
    client.app.state.shadow_history_service=None
    try:assert client.post(PREFIX+'/runs',json=payload()).status_code==409
    finally:client.app.state.shadow_history_service=original


def test_retention_reference_unavailable_not_fake_complete_or_auto_pin(client,prepared):
    ids=ingest(client);finding=evaluate(client)['result']['finding_ids'][0]
    with closing(sqlite3.connect(prepared[1].source)) as c:
        c.execute('DELETE FROM security_events WHERE event_id=?',(ids[0],));c.commit()
    detail=client.get(PREFIX+'/findings/'+finding).json()
    assert detail['current_evidence_availability'][ids[0]]=='MISSING'
    assert detail['historical_continuity']=='UNPROVEN'
    transition={'expected_revision':1,'expected_state':'SHADOW_CANDIDATE','target':'SHADOW_CONFIRMED_MATCH','reason':'ANALYST_PATTERN_REVIEW'}
    assert client.post(PREFIX+'/findings/'+finding+'/transitions',json=transition).status_code==409
    transition.update(target='INCOMPLETE_EVIDENCE',reason='EVIDENCE_UNAVAILABLE')
    assert client.post(PREFIX+'/findings/'+finding+'/transitions',json=transition).json()['state']=='INCOMPLETE_EVIDENCE'


def test_state_transition_cas_and_terminal_history(client):
    ingest(client);finding=evaluate(client)['result']['finding_ids'][0]
    body={'expected_revision':1,'expected_state':'SHADOW_CANDIDATE','target':'SHADOW_CONFIRMED_MATCH','reason':'ANALYST_PATTERN_REVIEW'}
    response=client.post(PREFIX+'/findings/'+finding+'/transitions',json=body)
    assert response.status_code==200,response.text
    assert client.post(PREFIX+'/findings/'+finding+'/transitions',json=body).status_code==409
    body.update(expected_state='SHADOW_CONFIRMED_MATCH',target='INVALIDATED',reason='PROVENANCE_CONFLICT')
    assert client.post(PREFIX+'/findings/'+finding+'/transitions',json=body).status_code==200
    body.update(expected_state='INVALIDATED',target='SHADOW_CONFIRMED_MATCH',reason='ANALYST_PATTERN_REVIEW')
    assert client.post(PREFIX+'/findings/'+finding+'/transitions',json=body).status_code==409


def test_strict_identity_does_not_upgrade_claimed_names(client):
    ingest(client);body=payload(identity_policy={'minimum':'VERIFIED'})
    result=evaluate(client,body)
    assert result['result']['finding_ids']==[] and result['result']['identity_rejected']==1
    assert result['result']['graph_edges']==[]


def records(client):
    ingest(client)
    return read_snapshot(DurableEvaluationRequest.model_validate(payload()).simulation,
        client.app.state.cqql_search_repository,include_raw=True).records


@pytest.mark.parametrize('kind,field,left,right',[
    ('ACCOUNT','user.sid','S-1-5-21-1','S-1-5-21-2'),
    ('PROCESS','process.guid','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000002')])
def test_identity_native_conflict_is_not_verified(client,kind,field,left,right):
    sample=list(copy.deepcopy(records(client)))[:2]
    sample[0]['values'][field]=left;sample[1]['values'][field]=right
    assessment=IdentityResolver().assess(sample,catalog()[0],IdentityPolicy())
    assert next(entity for entity in assessment.entities if entity.kind==kind).status=='CONFLICTING'


def test_signed_independent_inventory_positive_expired_and_forged(client):
    sample=list(records(client));scope=sample[0]['scope'];key=b'SYNTHETIC-authority-root-32-bytes-long'
    inventory={'issuer':'SYNTHETIC-INVENTORY','key_id':'SYNTHETIC-ROOT','evidence_sha256':'a'*64,
        'issued_at':(BASE-timedelta(days=1)).isoformat(),'expires_at':(datetime.now(timezone.utc)+timedelta(days=1)).isoformat(),
        'entries':[{'kind':'HOST','scope':scope,'native_key':scope[2],'entity_id':'SYNTHETIC-HOST-1','evidence_fingerprints':[value['sha'] for value in sample]},
            {'kind':'ACCOUNT','scope':scope,'native_key':'NAME:'+sample[0]['values']['user.name'],'entity_id':'SYNTHETIC-ACCOUNT-1','evidence_fingerprints':[value['sha'] for value in sample]}]}
    from app.schemas.shadow_history import AuthorityInventory
    signature=hmac.new(key,canonical_json(AuthorityInventory.model_validate(inventory).model_dump(mode='json')).encode(),hashlib.sha256).hexdigest()
    resolver=IdentityResolver.from_signed_inventory(inventory,signature,{'SYNTHETIC-ROOT':key})
    assessment=resolver.assess(sample,catalog()[0],IdentityPolicy(minimum='VERIFIED'))
    assert assessment.satisfied
    forged=copy.deepcopy(sample);forged[0]['sha']='b'*64
    assert not resolver.assess(forged,catalog()[0],IdentityPolicy(minimum='VERIFIED')).satisfied
    assert not resolver.assess(sample,catalog()[0],IdentityPolicy(minimum='VERIFIED'),at=datetime.now(timezone.utc)+timedelta(days=2)).satisfied
    with pytest.raises(ValueError):IdentityResolver.from_signed_inventory(inventory,'0'*64,{'SYNTHETIC-ROOT':key})


def test_fifo_queue_expiry_cancel_and_recovery():
    scheduler=ShadowScheduler(workers=1,queue_size=1,wait_seconds=.05)
    errors=[]
    def waiting():
        try:
            with scheduler.admit():pass
        except Exception as exc:errors.append(str(exc))
    with scheduler.admit():
        thread=threading.Thread(target=waiting);thread.start();thread.join(1)
    assert errors==['SHADOW_QUEUE_EXPIRED']
    cancel=threading.Event();cancel.set()
    with pytest.raises(CQQLQueryCancelledError):
        with scheduler.admit(cancel):pass
    with scheduler.admit():pass
    assert scheduler.snapshot()['inflight']==scheduler.snapshot()['queue_depth']==0


def test_corrupt_persisted_finding_is_rejected(client,prepared):
    ingest(client);finding=evaluate(client)['result']['finding_ids'][0]
    with closing(sqlite3.connect(prepared[1].path)) as c:
        c.execute("UPDATE shadow_revisions SET match_json='{}'");c.commit()
    response=client.get(PREFIX+'/findings/'+finding)
    assert response.status_code==503 and response.json()['detail']['code']=='SHADOW_STORE_CORRUPT'


def login(client):
    response=client.post('/api/v1/auth/login',headers={'Origin':'http://localhost:5173'},json={'username':'admin','password':TEST_PASSWORD})
    assert response.status_code==200
    client.headers.update({'Origin':'http://localhost:5173','X-CSRF-Token':response.json()['csrf_token']})


def test_real_application_restart_preserves_history(prepared):
    settings,store=prepared
    with TestClient(create_app(settings,disposable_detection_simulation=True,shadow_history=store)) as first:
        bootstrap_and_login(first);ingest(first);body=payload();before=evaluate(first,body)
    reopened=ShadowHistoryRepository(store.path,store.source)
    with TestClient(create_app(settings,disposable_detection_simulation=True,shadow_history=reopened)) as second:
        login(second);after=evaluate(second,body)
        assert before['run_id']==after['run_id'] and before['result']==after['result']
        assert second.get(PREFIX+'/findings/'+after['result']['finding_ids'][0]).status_code==200


@pytest.mark.parametrize('stage',['AFTER_SNAPSHOT_COMMIT','MID_FINDING_TRANSACTION','AFTER_FINDING_COMMIT','AFTER_RUN_BEGIN'])
def test_real_process_kill_recovery(prepared,stage):
    settings,store=prepared
    with TestClient(create_app(settings,disposable_detection_simulation=True,shadow_history=store)) as initial:
        bootstrap_and_login(initial);ingest(initial)
    body=payload()
    code='''import os,sys,json,sqlite3
from pathlib import Path
sys.path[:0]=[sys.argv[1]]
from app.db.shadow_history import ShadowHistoryRepository
from app.db.cqql import CQQLSearchRepository
from app.services.shadow_history import ShadowHistoryService
from app.schemas.shadow_history import DurableEvaluationRequest
stage=sys.argv[5]
if stage=='MID_FINDING_TRANSACTION':
    original=sqlite3.connect
    class Fatal(sqlite3.Connection):
        def execute(self,sql,parameters=()):
            result=super().execute(sql,parameters)
            if sql.startswith('INSERT INTO shadow_revisions'):os._exit(27)
            return result
    def connect(*args,**kwargs):
        kwargs['factory']=Fatal
        return original(*args,**kwargs)
    sqlite3.connect=connect
def fault(value):
    if value==stage:os._exit(27)
store=ShadowHistoryRepository(Path(sys.argv[2]),Path(sys.argv[3]))
service=ShadowHistoryService(store,CQQLSearchRepository(store.source),fault_hook=fault)
service.open();service.evaluate(DurableEvaluationRequest.model_validate(json.loads(sys.argv[4])),'SYNTHETIC-crash')
'''
    root=Path(__file__).parents[2]
    result=subprocess.run([sys.executable,'-c',code,str(root/'backend'),str(store.path),str(store.source),json.dumps(body),stage],capture_output=True,timeout=30)
    assert result.returncode==27,result.stderr.decode(errors='replace')
    with closing(sqlite3.connect(store.path)) as c:
        run_id=c.execute('SELECT run_id FROM shadow_runs').fetchone()[0]
        assert c.execute('SELECT COUNT(*) FROM shadow_findings').fetchone()[0]==int(stage=='AFTER_FINDING_COMMIT')
        assert c.execute('PRAGMA quick_check').fetchone()[0]=='ok'
        assert not c.execute('PRAGMA foreign_key_check').fetchall()
    with TestClient(create_app(settings,disposable_detection_simulation=True,shadow_history=ShadowHistoryRepository(store.path,store.source))) as recovered:
        login(recovered)
        # M35 commits a bounded snapshot intent with the run. Even the
        # pre-seal crash can now be verified and resumed, without new evidence.
        response=recovered.post(PREFIX+'/runs/'+run_id+'/resume')
        assert response.status_code==200,response.text
        finding=response.json()['result']['finding_ids'][0]
        assert recovered.post(PREFIX+'/runs',json=body).json()['result']['finding_ids']==[finding]
        with closing(sqlite3.connect(store.path)) as c:
            assert c.execute('SELECT COUNT(*) FROM shadow_findings').fetchone()[0]==1
            assert c.execute('SELECT COUNT(*) FROM shadow_revisions').fetchone()[0]==1


def test_failed_finding_transaction_rolls_back_and_resumes(client,prepared):
    ingest(client)
    with closing(sqlite3.connect(prepared[1].path)) as c:
        c.execute("CREATE TRIGGER synthetic_fail BEFORE INSERT ON shadow_revisions BEGIN SELECT RAISE(ABORT,'SYNTHETIC-private-fault'); END");c.commit()
    response=client.post(PREFIX+'/runs',json=payload())
    assert response.status_code==503 and 'private-fault' not in response.text
    with closing(sqlite3.connect(prepared[1].path)) as c:
        assert c.execute('SELECT COUNT(*) FROM shadow_findings').fetchone()[0]==0
        run_id=c.execute('SELECT run_id FROM shadow_runs').fetchone()[0]
        c.execute('DROP TRIGGER synthetic_fail');c.commit()
    response=client.post(PREFIX+'/runs/'+run_id+'/resume')
    assert response.status_code==200 and len(response.json()['result']['finding_ids'])==1


def test_source_writer_lock_does_not_block_sidecar_audit_or_history(client,prepared):
    ingest(client)
    with closing(sqlite3.connect(prepared[1].source)) as c:
        c.execute('BEGIN IMMEDIATE')
        try:
            assert client.post(PREFIX+'/simulate',json=payload()['simulation']).status_code==200
            result=evaluate(client)
            assert len(result['result']['finding_ids'])==1
        finally:c.rollback()


def test_bounded_sidecar_busy_recovery_and_request_identity(client,prepared):
    ingest(client)
    with closing(sqlite3.connect(prepared[1].path)) as c:
        c.execute('BEGIN IMMEDIATE')
        response=client.post(PREFIX+'/runs',json=payload())
        c.rollback()
    assert response.status_code==503 and response.json()['detail']['code']=='SHADOW_STORE_BUSY'
    assert response.headers['Retry-After']=='1' and len(response.headers['X-Correlation-ID'])==32
    evaluate(client)


def test_explicit_resume_detects_missing_or_changed_sealed_evidence(client,prepared):
    ids=ingest(client);service=client.app.state.shadow_history_service
    def failed(stage):
        if stage=='AFTER_SNAPSHOT_COMMIT':raise RuntimeError('SYNTHETIC-secret-stack')
    service._fault=failed
    response=client.post(PREFIX+'/runs',json=payload())
    assert response.status_code==503 and 'secret-stack' not in response.text
    with closing(sqlite3.connect(prepared[1].path)) as c:run_id=c.execute('SELECT run_id FROM shadow_runs').fetchone()[0]
    with closing(sqlite3.connect(prepared[1].source)) as c:c.execute('DELETE FROM security_events WHERE event_id=?',(ids[0],));c.commit()
    service._fault=lambda stage:None
    response=client.post(PREFIX+'/runs/'+run_id+'/resume')
    assert response.status_code==409 and response.json()['detail']['code']=='RECOVERY_EVIDENCE_GAP_OR_CHANGE'
    assert client.get(PREFIX+'/runs/'+run_id).json()['status']=='FAILED'


def test_migration_failure_is_atomic(prepared,monkeypatch,tmp_path):
    path=tmp_path/'broken-disposable.db';original=sqlite3.connect
    class Failed(sqlite3.Connection):
        def execute(self,sql,parameters=()):
            if sql.startswith('CREATE TABLE shadow_runs'):raise sqlite3.OperationalError('SYNTHETIC-migration-failure')
            return super().execute(sql,parameters)
    def connect(*args,**kwargs):kwargs['factory']=Failed;return original(*args,**kwargs)
    monkeypatch.setattr(sqlite3,'connect',connect)
    with pytest.raises(sqlite3.Error):initialize(path,prepared[1].source,disposable_only=True)
    monkeypatch.setattr(sqlite3,'connect',original)
    with closing(sqlite3.connect(path)) as c:
        assert c.execute('PRAGMA user_version').fetchone()[0]==0
        assert c.execute("SELECT COUNT(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").fetchone()[0]==0
    initialize(path,prepared[1].source,disposable_only=True)


def test_physical_evidence_revision_preserves_semantic_finding_and_history(client,prepared):
    ids=ingest(client);first=evaluate(client);finding=first['result']['finding_ids'][0]
    with closing(sqlite3.connect(prepared[1].source)) as c:c.executemany('DELETE FROM security_events WHERE event_id=?',[(value,) for value in ids]);c.commit()
    raws=auth(BASE)
    for raw in raws:raw['id']='SYNTHETIC-ALTERNATE-'+raw['id']
    ingest(client,raws);second=evaluate(client)
    assert second['result']['finding_ids']==[finding]
    detail=client.get(PREFIX+'/findings/'+finding).json()
    assert detail['revision']==2 and len(detail['history'])==2
    old=client.get(PREFIX+'/findings/'+finding+'?revision=1').json()
    assert set(old['current_evidence_availability'].values())=={'MISSING'}


@pytest.mark.parametrize('alteration',['host','agent','uid','missing_sid','untrusted_status'])
def test_identity_false_correlation_cases(client,alteration):
    sample=list(copy.deepcopy(records(client)))[:2]
    if alteration=='host':sample[1]['scope']=(*sample[1]['scope'][:2],'SYNTHETIC-OTHER-HOST')
    if alteration=='agent':sample[1]['scope']=(sample[1]['scope'][0],'SYNTHETIC-OTHER-AGENT',sample[1]['scope'][2])
    if alteration=='uid':
        sample[0]['raw']['data']['uid']='1000';sample[1]['raw']['data']['uid']='1001'
    if alteration=='missing_sid':sample[0]['values']['user.sid']='S-1-5-21-1000'
    if alteration=='untrusted_status':sample[1]['raw']['verified_identity']={'status':'VERIFIED','issuer':'pretend'}
    value=IdentityResolver().assess(sample,catalog()[0],IdentityPolicy(minimum='VERIFIED'))
    assert value.satisfied is False and not any(entity.status=='VERIFIED' for entity in value.entities)


@pytest.mark.parametrize('family,field,expected',[
    ('LINUX_AUTH','uid','CONFLICTING'),('JOURNALD','uid','CONFLICTING'),
    ('LINUX_AUTH','journald','PARTIAL'),('WINDOWS_EVENTCHANNEL','uid','PARTIAL')])
def test_uid_subject_and_source_family_are_not_confused(client,family,field,expected):
    if family=='WINDOWS_EVENTCHANNEL':
        sample=list(copy.deepcopy(records(client)))[:2]
    else:
        ingest(client,[ssh(i+10000,BASE+timedelta(seconds=i)) for i in range(2)])
        request=DurableEvaluationRequest.model_validate(payload('SHADOW-SSH-AUTH')).simulation
        sample=list(copy.deepcopy(read_snapshot(request,client.app.state.cqql_search_repository,include_raw=True).records))
        assert len(sample)==2 and all(row['family']=='LINUX_AUTH' for row in sample)
    for index,row in enumerate(sample):
        row['family']=family
        row['raw'].setdefault('data',{})[field]={'_UID':str(index)} if field=='journald' else str(index)
    value=IdentityResolver().assess(sample,catalog()[0],IdentityPolicy())
    assert next(entity for entity in value.entities if entity.kind=='ACCOUNT').status==expected


@pytest.mark.parametrize('protocols,expected',[
    (('tcp','TCP'),'PARTIAL'),(('tcp','udp'),'CONFLICTING'),((None,None),'UNVERIFIED'),(('invented','invented'),'UNVERIFIED')])
def test_network_endpoint_requires_explicit_transport(client,protocols,expected):
    raws=[win(11000+i,BASE+timedelta(seconds=i),'3',sysmon=True) for i in range(2)]
    for raw,protocol in zip(raws,protocols):
        data=raw['data']['win']['eventdata'];data['sourcePort']='50230'
        if protocol is None:data.pop('protocol',None)
        else:data['protocol']=protocol
    ingest(client,raws)
    request=DurableEvaluationRequest.model_validate(payload('SHADOW-PROCESS-NETWORK')).simulation
    sample=read_snapshot(request,client.app.state.cqql_search_repository,include_raw=True).records
    assert len(sample)==2 and all(row['family']=='SYSMON' for row in sample)
    value=IdentityResolver().assess(sample,catalog()[0],IdentityPolicy())
    assert next(entity for entity in value.entities if entity.kind=='NETWORK_ENDPOINT').status==expected


def test_api_queue_saturation_is_typed_backpressure_not_worker_failure(client):
    ingest(client);service=client.app.state.shadow_history_service
    service.scheduler=ShadowScheduler(workers=1,queue_size=0,wait_seconds=.05)
    with service.scheduler.admit():
        response=client.post(PREFIX+'/runs',json=payload())
        assert response.status_code==429 and response.json()['detail']['code']=='SHADOW_QUEUE_FULL'
    assert evaluate(client)['status']=='COMPLETED'
    assert service.scheduler.snapshot()['queue_peak']==0


def test_concurrent_identical_evaluations_are_idempotent(client,prepared):
    ingest(client);body=payload()
    with ThreadPoolExecutor(max_workers=4) as pool:
        responses=list(pool.map(lambda index:client.post(PREFIX+'/runs',json=body),range(4)))
    assert all(response.status_code==200 for response in responses),[response.text for response in responses]
    assert len({response.json()['run_id'] for response in responses})==1
    with closing(sqlite3.connect(prepared[1].path)) as c:assert c.execute('SELECT COUNT(*) FROM shadow_findings').fetchone()[0]==1


def test_capacity_does_not_break_cached_acknowledgements(client,monkeypatch):
    ingest(client);monkeypatch.setattr('app.db.shadow_history.MAX_RUNS',1)
    body=payload();first=evaluate(client,body)
    assert evaluate(client,body)['run_id']==first['run_id']
    fresh=payload();fresh['simulation']['evaluation_time']=(datetime.now(timezone.utc)+timedelta(seconds=2)).isoformat()
    response=client.post(PREFIX+'/runs',json=fresh)
    assert response.status_code==503 and response.json()['detail']['code']=='SHADOW_CAPACITY_EXCEEDED'


def test_bounded_keyset_pagination_and_invalid_cursor(client):
    ingest(client);ingest(client,auth(BASE,offset=9000,ip='192.0.2.31'))
    value=evaluate(client)
    assert len(value['result']['finding_ids'])==2
    first=client.get(PREFIX+'/findings?limit=1').json()
    second=client.get(PREFIX+'/findings',params={'limit':1,'cursor':first['next_cursor']}).json()
    assert first['items'][0]['finding_id']!=second['items'][0]['finding_id'] and second['next_cursor'] is None
    assert client.get(PREFIX+'/findings?cursor=SQL-INJECTION').status_code==422


def test_new_rule_version_is_distinct_and_explicit_supersession_preserves_old(client):
    ingest(client);body=payload();old=evaluate(client,body)['result']['finding_ids'][0]
    old_version=client.get(PREFIX+'/findings/'+old).json()['rule_version']
    body['simulation']['rule']['title']='SYNTHETIC M31 reviewed version'
    new=evaluate(client,body)['result']['finding_ids'][0]
    assert old!=new
    change={'expected_revision':1,'expected_state':'SHADOW_CANDIDATE','target':'SUPERSEDED','reason':'RULE_SUPERSEDED','superseded_by':new}
    response=client.post(PREFIX+'/findings/'+old+'/transitions',json=change)
    assert response.status_code==200 and response.json()['rule_version']==old_version
    change['superseded_by']=old
    assert client.post(PREFIX+'/findings/'+new+'/transitions',json=change).status_code==422


def test_evidence_link_corruption_and_csrf(client,prepared):
    ingest(client);finding=evaluate(client)['result']['finding_ids'][0]
    assert client.post(PREFIX+'/runs',headers={'X-CSRF-Token':'invalid'},json=payload()).status_code==403
    with closing(sqlite3.connect(prepared[1].path)) as c:
        c.execute("UPDATE shadow_evidence SET envelope_sha=?",('0'*64,));c.commit()
    assert client.get(PREFIX+'/findings/'+finding).status_code==503


@pytest.mark.parametrize('different_agent',[False,True])
def test_synthetic_ssh_then_sudo_context_no_guessed_ip(client,different_agent):
    login_event=ssh(18001,BASE,True)
    sudo=copy.deepcopy(login_event);sudo['id']='SYNTHETIC-M31-SUDO';sudo['timestamp']=(BASE+timedelta(seconds=10)).isoformat()
    sudo['decoder']={'name':'sudo'};sudo['data']={'user':'analyst'}
    sudo['full_log']=f'<34>1 {(BASE+timedelta(seconds=10)).isoformat()} SYNTH-M30-LINUX sudo 18002 - - analyst : user=analyst ; COMMAND=/usr/bin/id'
    if different_agent:sudo['agent']['id']='SYNTHETIC-OTHER-AGENT'
    ingest(client,[login_event,sudo]);body=payload('SHADOW-SSH-AUTH')
    body['simulation']['rule'].update(rule_id='SHADOW-SSH-SUDO-M31',required_fields=['host.name','user.name'],group_by=['user.name'],
        steps=[{'query':'event.category = "linux_ssh" AND event.outcome = "success"'},
            {'query':'event.category = "linux_sudo" AND event.outcome = "success"'}])
    value=evaluate(client,body)
    assert len(value['result']['finding_ids'])==int(not different_agent)


def test_failure_context_exposes_run_id_and_recovery_checkpoint(client):
    ingest(client);service=client.app.state.shadow_history_service
    def fail(stage):
        if stage=='AFTER_SNAPSHOT_COMMIT':raise RuntimeError('SYNTHETIC-private')
    service._fault=fail;response=client.post(PREFIX+'/runs',json=payload())
    assert response.status_code==503
    run_id=response.json()['detail']['run_id']
    status=client.get(PREFIX+'/runs/'+run_id).json()
    assert status['recovery_state']=='EXPLICIT_RESUME_REQUIRED'
    assert client.get(PREFIX+'/history-status').json()['recovery_runs'][0]['run_id']==run_id


def test_real_viewer_can_read_but_cannot_mutate_history(client):
    ingest(client);value=evaluate(client);finding=value['result']['finding_ids'][0]
    response=client.post('/api/v1/auth/analysts',json={'username':'m31.viewer','display_name':'SYNTHETIC M31 viewer',
        'password':'SYNTHETIC-M31-Viewer-Only-77','role':'VIEWER'})
    assert response.status_code==201
    response=client.post('/api/v1/auth/login',json={'username':'m31.viewer','password':'SYNTHETIC-M31-Viewer-Only-77'})
    assert response.status_code==200;client.headers['X-CSRF-Token']=response.json()['csrf_token']
    assert client.get(PREFIX+'/findings/'+finding).status_code==200
    assert client.get(PREFIX+'/runs/'+value['run_id']).status_code==200
    assert client.post(PREFIX+'/runs',json=payload()).status_code==403
    assert client.post(PREFIX+'/runs/'+value['run_id']+'/resume').status_code==403
    assert client.post(PREFIX+'/findings/'+finding+'/transitions',json={}).status_code==403


def test_signed_verified_identity_survives_history_restart_with_attestation(prepared):
    settings,store=prepared
    with TestClient(create_app(settings,disposable_detection_simulation=True,shadow_history=store)) as first:
        bootstrap_and_login(first);sample=list(records(first))
    from app.schemas.shadow_history import AuthorityInventory
    scope=sample[0]['scope'];key=b'SYNTHETIC-EXTERNAL-ROOT-32-BYTE-KEY'
    inventory=AuthorityInventory.model_validate({'issuer':'SYNTHETIC-INDEPENDENT','key_id':'SYNTHETIC-EXTERNAL',
        'evidence_sha256':'c'*64,'issued_at':(BASE-timedelta(days=1)).isoformat(),
        'expires_at':(datetime.now(timezone.utc)+timedelta(days=1)).isoformat(),'entries':[
            {'kind':kind,'scope':scope,'native_key':native,'entity_id':entity,
                'evidence_fingerprints':[record['sha'] for record in sample]}
            for kind,native,entity in [('HOST',scope[2],'SYNTHETIC-HOST'),('ACCOUNT','NAME:'+sample[0]['values']['user.name'],'SYNTHETIC-ACCOUNT')]]})
    document=inventory.model_dump(mode='json');signature=hmac.new(key,canonical_json(document).encode(),hashlib.sha256).hexdigest()
    resolver=IdentityResolver.from_signed_inventory(document,signature,{'SYNTHETIC-EXTERNAL':key})
    with TestClient(create_app(settings,disposable_detection_simulation=True,shadow_history=ShadowHistoryRepository(store.path,store.source),identity_resolver=resolver)) as second:
        login(second);value=evaluate(second,payload(identity_policy={'minimum':'VERIFIED'}));finding=value['result']['finding_ids'][0]
        detail=second.get(PREFIX+'/findings/'+finding).json()
        assert detail['identity']['satisfied'] and len(detail['authority_documents'])==1
        assert all(entity['status']=='VERIFIED' for entity in detail['identity']['entities'] if entity['kind'] in ('HOST','ACCOUNT'))
    with TestClient(create_app(settings,disposable_detection_simulation=True,shadow_history=ShadowHistoryRepository(store.path,store.source))) as third:
        login(third);detail=third.get(PREFIX+'/findings/'+finding).json()
        assert detail['identity_context']=='AT_ORIGINAL_EVALUATION_NOT_CURRENT_SOURCE_ATTESTATION'
        assert detail['authority_documents'][0]['signature']==signature


def test_consistent_sidecar_backup_and_logical_restore(client,prepared,tmp_path):
    ingest(client);finding=evaluate(client)['result']['finding_ids'][0]
    original=prepared[1].detail(finding);backup=tmp_path/'verified-sidecar-backup.db'
    with closing(sqlite3.connect(prepared[1].path)) as source,closing(sqlite3.connect(backup)) as target:source.backup(target)
    checksum=hashlib.sha256(backup.read_bytes()).hexdigest()
    restored=ShadowHistoryRepository(backup,prepared[1].source)
    assert restored.detail(finding)==original
    assert checksum==hashlib.sha256(backup.read_bytes()).hexdigest()
    with closing(sqlite3.connect(backup)) as c:
        assert c.execute('PRAGMA quick_check').fetchone()[0]=='ok'
        assert not c.execute('PRAGMA foreign_key_check').fetchall()


def test_sidecar_cannot_be_bound_to_a_different_source_database(prepared,tmp_path):
    alternate=tmp_path/'different-source.db'
    AlertRepository(f'sqlite:///{alternate.as_posix()}',migration_target_version=17).initialize()
    with pytest.raises(ShadowStoreError,match='SOURCE_BINDING_MISMATCH'):
        ShadowHistoryRepository(prepared[1].path,alternate)
