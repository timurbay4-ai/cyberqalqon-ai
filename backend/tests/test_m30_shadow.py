from __future__ import annotations

import json
import copy
import sqlite3
import threading
import subprocess
import sys
import os
from pathlib import Path
from contextlib import closing
from datetime import datetime,timedelta,timezone

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from app.core.config import Settings
from app.main import create_app
from app.schemas.shadow_detection import ShadowRule,ShadowSimulationRequest
from app.services.shadow_rules import catalog
from app.services.shadow_detection import compare,_record,_graph,evaluate_records,ShadowResourceLimitError
from app.schemas.shadow_detection import ShadowFinding
from app.services.cqql import parse_cqql,compile_cqql
from app.db.cqql import CQQLQueryCancelledError,CQQLQueryBusyError,CQQLQueryTimeoutError
from tests.conftest import bootstrap_and_login
from scripts.m30_synthetic import scenarios,auth,win

BASE = datetime.now(timezone.utc).replace(microsecond=0)-timedelta(minutes=20)
RULES = {rule.rule_id:rule for rule in catalog()}
PREFIX = '/api/v1/detection-engineering/shadow-v2'


@pytest.fixture
def client(database_path):
    settings = Settings(database_url=f'sqlite:///{database_path.as_posix()}',wazuh_ingest_api_key='test-ingest-key',
        allow_m14_schema_migration=False,correlation_enabled=False)
    with TestClient(create_app(settings,disposable_detection_simulation=True)) as value:
        bootstrap_and_login(value)
        yield value


def request(rule_id='SHADOW-WINDOWS-AUTH',**updates):
    value = dict(rule=RULES[rule_id].model_dump(mode='json'),start_time=(BASE-timedelta(seconds=1)).isoformat(),
        end_time=(BASE+timedelta(minutes=15)).isoformat(),evaluation_time=(datetime.now(timezone.utc)+timedelta(minutes=1)).isoformat())
    value.update(updates)
    return value


def ingest(client,raw):
    response = client.post('/api/v1/events/ingest',headers={'X-API-Key':'test-ingest-key'},json=raw)
    assert response.status_code in (200,201),response.text
    return response.json()['event']['event_id']


@pytest.mark.parametrize('name,rule_id,raws,expected,label',scenarios(BASE),ids=lambda value:value if isinstance(value,str) else None)
def test_synthetic_end_to_end(client,database_path,name,rule_id,raws,expected,label):
    event_ids = {ingest(client,raw) for raw in raws}
    payload = request(rule_id)
    result = client.post(PREFIX+'/simulate',json=payload)
    assert result.status_code == 200,result.text
    body = result.json()
    assert len(body['findings']) == expected,(name,body)
    assert body['side_effects'] is False and body['historical_continuity'] == 'UNPROVEN'
    again = client.post(PREFIX+'/simulate',json=payload).json()
    assert [finding['finding_id'] for finding in again['findings']] == [finding['finding_id'] for finding in body['findings']]
    for finding in body['findings']:
        assert finding['status'] == 'SHADOW_ONLY' and finding['completeness'] == 'UNPROVEN'
        assert finding['confidence'] <= 40 and finding['rule_version'] == RULES[rule_id].rule_version
        assert {item['event_id'] for item in finding['evidence']} <= event_ids
        for item in finding['evidence']:
            detail = client.get('/api/v1/events/'+item['event_id'])
            assert detail.status_code == 200
            assert detail.json()['cuse']['content_fingerprint'] == item['stored_envelope_sha256']
        assert all(item['evidence_strength'] == 'RULE_TAGGED_TECHNIQUE' for item in finding['mitre'])
    with closing(sqlite3.connect(database_path)) as connection:
        assert connection.execute('PRAGMA user_version').fetchone()[0] == 17
        assert connection.execute('PRAGMA quick_check').fetchone()[0] == 'ok'
        assert not connection.execute('PRAGMA foreign_key_check').fetchall()
        assert connection.execute('SELECT COUNT(*) FROM incidents').fetchone()[0] == 0
        assert connection.execute('SELECT COUNT(*) FROM soc_cases').fetchone()[0] == 0


@pytest.mark.parametrize('field,value',[
    ('status','ACTIVE'),('required_fields',['process.pid']),('window_seconds',3601),
    ('window_seconds',True),('allowed_lateness',601),('references',['javascript:alert(1)']),
    ('mitre_ids',['T9999']),('python','__import__("os").system("whoami")'),
    ('steps',[{'query':'text CONTAINS "synthetic"'}]),('steps',[{'query':'SELECT * FROM security_events'}]),
])
def test_definition_rejection_sanitized(client,field,value):
    definition = RULES['SHADOW-WINDOWS-AUTH'].model_dump(mode='json')
    definition[field] = value
    result = client.post(PREFIX+'/validate',json=definition)
    assert result.status_code == 422,result.text
    assert result.json()['detail']['code'] == 'invalid_rule_definition'
    assert '__import__' not in result.text and 'SELECT *' not in result.text


@pytest.mark.parametrize('query',[
    'event.severity >= 3 AND NOT event.provider = "x"',
    'event.provider = "abc" OR event.severity < 3',
    'NOT (event.provider != "Straße")',
    'event.provider = "x\' OR 1=1 --"',
])
def test_cqql_interpreter_differential_sqlite(query):
    ast,compiled = parse_cqql(query).expression,compile_cqql(query)
    with closing(sqlite3.connect(':memory:')) as connection:
        connection.execute('CREATE TABLE security_events(event_provider TEXT,severity INTEGER)')
        for provider in (None,'ABC','Straße','STRASSE','x'):
            for severity in (None,0,3,7):
                connection.execute('DELETE FROM security_events')
                connection.execute('INSERT INTO security_events VALUES(?,?)',(provider,severity))
                expected = connection.execute('SELECT '+compiled.sql+' FROM security_events e',compiled.parameters).fetchone()[0]
                actual = compare(ast,{'event.provider':provider,'event.severity':severity})
                assert actual == (None if expected is None else bool(expected))


def test_default_gate_and_role_csrf_boundaries(client,database_path):
    with TestClient(create_app(Settings(database_url=f'sqlite:///{database_path.as_posix()}',allow_m14_schema_migration=False))) as normal:
        login = normal.post('/api/v1/auth/login',headers={'Origin':'http://localhost:5173'},
            json={'username':'admin','password':'Correct-Horse-Battery-77'})
        normal.headers.update({'Origin':'http://localhost:5173','X-CSRF-Token':login.json()['csrf_token']})
        assert normal.post(PREFIX+'/simulate',json=request()).status_code == 409
        assert normal.get(PREFIX+'/catalog').json()['simulation_enabled'] is False
    assert client.post(PREFIX+'/simulate',headers={'X-CSRF-Token':'wrong'},json=request()).status_code == 403
    created = client.post('/api/v1/auth/analysts',json={'username':'m30.viewer','display_name':'SYNTHETIC viewer',
        'password':'SYNTHETIC-Viewer-M30!','role':'VIEWER'})
    assert created.status_code == 201
    login = client.post('/api/v1/auth/login',json={'username':'m30.viewer','password':'SYNTHETIC-Viewer-M30!'})
    client.headers['X-CSRF-Token'] = login.json()['csrf_token']
    assert client.get(PREFIX+'/catalog').status_code == 200
    assert client.post(PREFIX+'/simulate',json=request()).status_code == 403
    assert client.post(PREFIX+'/validate',json=RULES['SHADOW-WINDOWS-AUTH'].model_dump(mode='json')).status_code == 403


def test_cancel_and_slots_recover(client):
    engine,repo = client.app.state.advanced_detection_engine,client.app.state.cqql_search_repository
    event = threading.Event(); event.set()
    with pytest.raises(CQQLQueryCancelledError): engine.simulate_contract(ShadowSimulationRequest.model_validate(request()),repo,cancel_event=event)
    assert engine._shadow_v2_slots.acquire(blocking=False)
    assert engine._shadow_v2_slots.acquire(blocking=False)
    try:
        with pytest.raises(CQQLQueryBusyError): engine.simulate_contract(ShadowSimulationRequest.model_validate(request()),repo)
    finally:
        engine._shadow_v2_slots.release(); engine._shadow_v2_slots.release()
    assert client.post(PREFIX+'/simulate',json=request()).status_code == 200


def test_content_addressed_versions_and_disabled_evaluation(client):
    original = RULES['SHADOW-WINDOWS-AUTH']
    changed = ShadowRule.model_validate({**original.model_dump(mode='json'),'title':'Changed meaning/version'})
    assert changed.rule_version != original.rule_version
    with pytest.raises(ValidationError): original.title = 'mutation'
    payload = request(); payload['rule']['status'] = 'DISABLED_BY_POLICY'
    result = client.post(PREFIX+'/simulate',json=payload).json()
    assert result['status'] == 'RULE_DISABLED' and result['findings'] == []


@pytest.mark.parametrize('lateness,expected',[(60,1),(5,0)])
def test_out_of_order_has_explicit_lateness_not_silent_loss(client,lateness,expected):
    raw = auth(BASE)
    for index in (3,0,2,1): ingest(client,raw[index])
    payload=request();payload['rule']['allowed_lateness']=lateness
    body=client.post(PREFIX+'/simulate',json=payload).json()
    assert len(body['findings'])==expected
    assert body['diagnostics'].get('LATE_WITHIN_WINDOW' if expected else 'LATE_OUTSIDE_WINDOW')==3
    if not expected: assert body['coverage']=='PARTIAL'


@pytest.mark.parametrize('success_at,expected',[(600,1),(601,0),(0,0)])
def test_window_and_equal_time_semantics(client,success_at,expected):
    raw=auth(BASE)
    raw[-1]['timestamp']=raw[-1]['data']['win']['system']['systemTime']=(BASE+timedelta(seconds=success_at)).isoformat()
    for event in raw: ingest(client,event)
    assert len(client.post(PREFIX+'/simulate',json=request()).json()['findings'])==expected


@pytest.mark.parametrize('sid_last',['S-1-5-21-2',None])
def test_sid_conflict_or_missing_sid_cannot_downgrade_to_name_join(client,sid_last):
    raw=auth(BASE)
    for event in raw[:3]: event['data']['win']['eventdata']['targetUserSid']='S-1-5-21-1'
    if sid_last: raw[-1]['data']['win']['eventdata']['targetUserSid']=sid_last
    for event in raw: ingest(client,event)
    assert client.post(PREFIX+'/simulate',json=request()).json()['findings']==[]


def test_alternate_delivery_dedup_keeps_legacy_ingest_identity_and_finding_id(client,database_path):
    raw=auth(BASE)
    original_ids=[ingest(client,event) for event in raw]
    first=client.post(PREFIX+'/simulate',json=request()).json()['findings'][0]
    alternate=copy.deepcopy(raw)
    for event in alternate: event['id']+='-alternate-delivery'
    alternate_ids=[ingest(client,event) for event in alternate]
    assert set(alternate_ids).isdisjoint(original_ids)
    body=client.post(PREFIX+'/simulate',json=request()).json()
    assert len(body['findings'])==1 and body['diagnostics']['DUPLICATE_SOURCE_RECORD']==4
    assert body['findings'][0]['finding_id']==first['finding_id']
    with closing(sqlite3.connect(database_path)) as connection:
        connection.row_factory=sqlite3.Row
        rows=[_record(dict(row)) for row in connection.execute('SELECT * FROM security_events WHERE event_id IN (?,?,?,?)',alternate_ids)]
    findings,_=evaluate_records(RULES['SHADOW-WINDOWS-AUTH'],rows)
    assert findings[0].finding_id==first['finding_id']
    assert findings[0].evidence_manifest_sha256!=first['evidence_manifest_sha256']


def test_conflicting_source_record_fails_closed(client):
    raw=auth(BASE)
    for event in raw: ingest(client,event)
    conflict=copy.deepcopy(raw[0]);conflict['id']='SYNTHETIC-M30-CONFLICT'
    conflict['data']['win']['eventdata']['targetUserName']='another-user'
    ingest(client,conflict)
    result=client.post(PREFIX+'/simulate',json=request())
    assert result.status_code==429 and result.json()['detail']['code']=='shadow_resource_limit'


def test_missing_process_guid_never_falls_back_to_reused_pid(client):
    raw=[win(1001,BASE,'1',sysmon=True),win(1002,BASE+timedelta(seconds=5),'3',sysmon=True)]
    for event in raw:
        event['data']['win']['eventdata'].pop('processGuid')
        ingest(client,event)
    body=client.post(PREFIX+'/simulate',json=request('SHADOW-PROCESS-NETWORK')).json()
    assert body['outcome']=='UNSUPPORTED_FIELDS' and body['diagnostics']['UNSUPPORTED_FIELDS']==2


def test_record_corruption_and_audit_failure_are_sanitized(client,database_path,monkeypatch):
    for event in auth(BASE): ingest(client,event)
    with closing(sqlite3.connect(database_path)) as connection:
        connection.execute("UPDATE security_events SET raw_event_json='{}'")
        connection.commit()
    body=client.post(PREFIX+'/simulate',json=request()).json()
    assert body['outcome']=='INVALID_EVENT' and body['diagnostics']['INVALID_EVENT_OR_PROVENANCE']==4
    def failed(**kwargs): raise sqlite3.OperationalError('SYNTHETIC-private-audit-error')
    monkeypatch.setattr(client.app.state.audit_repository,'append',failed)
    result=client.post(PREFIX+'/simulate',json=request())
    assert result.status_code==503 and 'private-audit' not in result.text


def test_query_error_releases_both_semaphores(client,monkeypatch):
    repo=client.app.state.cqql_search_repository
    original=repo._connect
    def busy(): raise sqlite3.OperationalError('database locked')
    monkeypatch.setattr(repo,'_connect',busy)
    assert client.post(PREFIX+'/simulate',json=request()).status_code==429
    monkeypatch.setattr(repo,'_connect',original)
    assert client.post(PREFIX+'/simulate',json=request()).status_code==200
    acquired=[repo._slots.acquire(blocking=False) for _ in range(4)]
    assert all(acquired)
    for _ in acquired: repo._slots.release()


def test_direct_resource_timeout_cancel_and_disabled_guards(client,database_path):
    for event in auth(BASE)[:1]: ingest(client,event)
    with closing(sqlite3.connect(database_path)) as connection:
        connection.row_factory=sqlite3.Row
        record=_record(dict(connection.execute('SELECT * FROM security_events').fetchone()))
    with pytest.raises(CQQLQueryTimeoutError): evaluate_records(RULES['SHADOW-WINDOWS-AUTH'],[record],deadline=0)
    cancel=threading.Event();cancel.set()
    with pytest.raises(CQQLQueryCancelledError): evaluate_records(RULES['SHADOW-WINDOWS-AUTH'],[record],cancel_event=cancel)
    for count,mode in ((257,'scopes'),(65,'group')):
        records=[]
        for index in range(count):
            value={**record,'id':f'SYNTHETIC-RESOURCE-{index}','sha':f'{index:064x}','source_key':None}
            if mode=='scopes': value['scope']=('SYNTHETIC-manager',str(index),'SYNTHETIC-host')
            records.append(value)
        with pytest.raises(ShadowResourceLimitError): evaluate_records(RULES['SHADOW-WINDOWS-AUTH'],records)


def test_retention_missing_first_failure_never_produces_false_complete_finding(client,database_path):
    client.app.state.event_repository.max_records=3
    for event in auth(BASE): ingest(client,event)
    body=client.post(PREFIX+'/simulate',json=request()).json()
    assert body['findings']==[] and body['window_completeness']=='UNPROVEN'
    with closing(sqlite3.connect(database_path)) as connection:
        assert connection.execute('SELECT retained_records FROM security_event_store_state').fetchone()[0]==3


def test_oversized_rule_rejected_before_compilation(client):
    result=client.post(PREFIX+'/validate',json={'SYNTHETIC-padding':'x'*28000})
    assert result.status_code==413


def test_restart_and_read_process_crash_do_not_change_events_or_finding_identity(client,database_path):
    for event in auth(BASE): ingest(client,event)
    before=client.post(PREFIX+'/simulate',json=request()).json()
    code='''import json,os,sys,threading
sys.path.insert(0,sys.argv[3])
from app.schemas.shadow_detection import ShadowSimulationRequest
from app.db.cqql import CQQLSearchRepository
from app.services.shadow_detection import simulate
from pathlib import Path
repo=CQQLSearchRepository(Path(sys.argv[1]))
original=repo._connect
def connect():
    connection=original()
    connection.set_trace_callback(lambda sql:os._exit(19) if sql.startswith('SELECT') else None)
    return connection
repo._connect=connect
simulate(ShadowSimulationRequest.model_validate(json.loads(sys.argv[2])),repo,threading.BoundedSemaphore(2))
'''
    crashed=subprocess.run([sys.executable,'-c',code,str(database_path),json.dumps(request()),str(Path(__file__).parents[1])],
        capture_output=True,timeout=15)
    assert crashed.returncode==19,crashed.stderr.decode(errors='replace')
    settings=Settings(database_url=f'sqlite:///{database_path.as_posix()}',allow_m14_schema_migration=False,correlation_enabled=False)
    with TestClient(create_app(settings,disposable_detection_simulation=True)) as restarted:
        login=restarted.post('/api/v1/auth/login',headers={'Origin':'http://localhost:5173'},
            json={'username':'admin','password':'Correct-Horse-Battery-77'})
        restarted.headers.update({'Origin':'http://localhost:5173','X-CSRF-Token':login.json()['csrf_token']})
        after=restarted.post(PREFIX+'/simulate',json=request()).json()
    assert [value['finding_id'] for value in after['findings']]==[value['finding_id'] for value in before['findings']]
    assert [value['evidence_manifest_sha256'] for value in after['findings']]==[value['evidence_manifest_sha256'] for value in before['findings']]
    with closing(sqlite3.connect(database_path)) as connection:
        assert connection.execute('PRAGMA quick_check').fetchone()[0]=='ok'
        assert connection.execute('SELECT COUNT(*) FROM security_events').fetchone()[0]==4


def test_bounded_audit_writer_busy_rolls_back_then_recovers(client,database_path):
    repository=client.app.state.audit_repository
    with closing(sqlite3.connect(database_path)) as lock:
        before=lock.execute('SELECT COUNT(*) FROM security_audit_events').fetchone()[0]
        lock.execute('BEGIN IMMEDIATE')
        with pytest.raises(sqlite3.OperationalError):
            repository.append(action='SYNTHETIC_M30_LOCK',actor_id=None,actor_display='SYNTHETIC',target_type='test',budget_ms=50)
        lock.rollback()
        assert lock.execute('SELECT COUNT(*) FROM security_audit_events').fetchone()[0]==before
    repository.append(action='SYNTHETIC_M30_RECOVERY',actor_id=None,actor_display='SYNTHETIC',target_type='test',budget_ms=100)


def test_cli_repeated_isolated_processes_cleanly_complete():
    root=Path(__file__).parents[2]
    environment={**os.environ,'PYTHONPATH':str(root/'backend')}
    for _ in range(3):
        result=subprocess.run([sys.executable,'-m','app.cli.shadow_scenario','--scenario','windows-positive'],
            cwd=root,env=environment,capture_output=True,timeout=30)
        assert result.returncode==0,result.stderr.decode(errors='replace')
        report=json.loads(result.stdout)
        assert report['integrity']=='PASS' and report['scenarios'][0]['finding_count']==1


def test_irrelevant_benign_records_do_not_fill_temporal_group(client,database_path):
    ingest(client,win(1200,BASE,'1',sysmon=True))
    with closing(sqlite3.connect(database_path)) as connection:
        connection.row_factory=sqlite3.Row
        record=_record(dict(connection.execute('SELECT * FROM security_events').fetchone()))
    irrelevant=[]
    for index in range(100):
        value={**record,'id':f'SYNTHETIC-IRRELEVANT-{index}','sha':f'{index:064x}','source_key':None,
               'values':{**record['values'],'process.name':'C:\\Windows\\notepad.exe'}}
        irrelevant.append(value)
    findings,counts=evaluate_records(RULES['SHADOW-OFFICE-SCRIPT'],irrelevant)
    assert findings==[] and counts['NO_MATCH']==100


def test_candidate_byte_limit_rejects_before_returning_partial_findings(client,monkeypatch):
    for event in auth(BASE): ingest(client,event)
    monkeypatch.setattr('app.services.shadow_detection.MAX_INPUT_BYTES',1)
    result=client.post(PREFIX+'/simulate',json=request())
    assert result.status_code==429 and result.json()['detail']['code']=='shadow_resource_limit'
    assert 'findings' not in result.json()


def test_graph_and_input_count_limits_are_fail_closed(client):
    for event in auth(BASE): ingest(client,event)
    original=client.post(PREFIX+'/simulate',json=request()).json()['findings'][0]
    values=[]
    for index in range(30):
        row=copy.deepcopy(original);row['finding_id']='SF-'+f'{index:064x}'
        for offset,item in enumerate(row['evidence']): item['event_id']='EVT-'+f'{index*4+offset:024X}'
        values.append(ShadowFinding.model_validate(row))
    with pytest.raises(ShadowResourceLimitError,match='MAX_GRAPH'): _graph(values)
    with pytest.raises(ShadowResourceLimitError,match='MAX_EVENTS'):
        evaluate_records(RULES['SHADOW-WINDOWS-AUTH'],[{}]*1001)


def test_minimum_confidence_rejects_even_matching_records(client,database_path):
    for event in auth(BASE): ingest(client,event)
    payload=request();payload['rule']['minimum_confidence']=41
    body=client.post(PREFIX+'/simulate',json=payload).json()
    assert body['findings']==[] and body['diagnostics']['BELOW_MINIMUM_CONFIDENCE']==1


def test_candidate_limit_reports_partial_not_false_complete_window(client,monkeypatch):
    for event in auth(BASE): ingest(client,event)
    monkeypatch.setattr('app.services.shadow_detection.MAX_EVENTS',3)
    result=client.post(PREFIX+'/simulate',json=request())
    assert result.status_code==200
    body=result.json()
    assert body['candidate_truncated'] is True and body['coverage']=='PARTIAL'
    assert body['findings']==[] and body['diagnostics']['CANDIDATE_ROWS']==3
    assert body['window_completeness']=='UNPROVEN'


def test_candidate_query_uses_existing_time_index_not_unbounded_outcome_or_scan(client,database_path,monkeypatch):
    for event in auth(BASE): ingest(client,event)
    statements=[]
    repository=client.app.state.cqql_search_repository
    original=repository._connect
    def traced():
        connection=original();connection.set_trace_callback(statements.append);return connection
    monkeypatch.setattr(repository,'_connect',traced)
    assert len(client.post(PREFIX+'/simulate',json=request()).json()['findings'])==1
    selection=next(sql for sql in statements if sql.startswith('SELECT'))
    with closing(sqlite3.connect(database_path)) as connection:
        plans=[row[-1] for row in connection.execute('EXPLAIN QUERY PLAN '+selection)]
    assert any('idx_security_events_occurred_id' in plan for plan in plans)
    assert not any('MULTI-INDEX OR' in plan for plan in plans)


def test_http_audit_writer_lock_returns_503_without_claiming_a_finding_then_recovers(client,database_path):
    for event in auth(BASE): ingest(client,event)
    before=client.post(PREFIX+'/simulate',json=request()).json()
    with closing(sqlite3.connect(database_path)) as connection:
        connection.execute('BEGIN IMMEDIATE')
        failed=client.post(PREFIX+'/simulate',json=request())
        connection.rollback()
        assert failed.status_code==503 and failed.json()['detail']['code']=='audit_unavailable'
        assert 'findings' not in failed.json()
    after=client.post(PREFIX+'/simulate',json=request()).json()
    assert [row['finding_id'] for row in after['findings']]==[row['finding_id'] for row in before['findings']]
