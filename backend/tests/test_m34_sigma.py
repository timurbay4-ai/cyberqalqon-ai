from contextlib import closing
from copy import deepcopy
from datetime import timedelta, datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3

import pytest
import yaml

from app.schemas.shadow_detection import ShadowRule
from app.services.sigma import convert_sigma, SigmaImportError
from app.services.shadow_rules import catalog
from app.services.cqql import compile_cqql, parse_cqql
from app.services.shadow_detection import compare
from scripts.m30_synthetic import win
from tests.test_m31_history import prepared, client, ingest, BASE, PREFIX

ROOT = Path(__file__).resolve().parents[2]
API = '/api/v1/detection-engineering/sigma/preview'


def base(index=1, *, selection=None, condition='selection', source=None):
    return {'title': 'SYNTHETIC Sigma fixture', 'id': f'00000000-0000-4000-8000-{index:012d}',
            'name': f'synthetic_{index}', 'date': '2026-10-27', 'status': 'test',
            'logsource': source or {'product':'windows','service':'security'},
            'detection': {'selection': selection or {'EventID':4625}, 'condition': condition},
            'author': 'SYNTHETIC test author', 'references':['https://example.invalid/synthetic']}


def encode(*documents):
    return yaml.safe_dump_all(documents, sort_keys=False)


def correlated(kind='temporal_ordered', *, reverse=False):
    first, second = base(), base(2, selection={'EventID':4624})
    root = {'title':'SYNTHETIC temporal', 'id':'00000000-0000-4000-8000-000000000003', 'date':'2026-10-27',
            'correlation':{'type':kind,'rules':['synthetic_1','synthetic_2'],'group-by':['Computer'],'timespan':'5m'}}
    return [first, second, root]


def evaluate(client, rule):
    response = client.post(PREFIX+'/runs', json={'simulation':{'rule':rule,
        'start_time':(BASE-timedelta(seconds=1)).isoformat(), 'end_time':(BASE+timedelta(minutes=5)).isoformat(),
        'evaluation_time':datetime.now(timezone.utc).isoformat()}})
    assert response.status_code == 200, response.text
    return response.json()


def test_legacy_cdrc_v2_definitions_and_hashes_are_unchanged():
    rows=json.loads((ROOT/'docs/siem/M34_CDRC_V2_BASELINE.json').read_text())
    assert {rule.rule_version for rule in catalog()} == {row['rule_version'] for row in rows}
    for row in rows:
        rule=ShadowRule.model_validate(row['definition'])
        assert rule.rule_version==row['rule_version']
        assert rule.model_dump(mode='json')==row['definition']
        assert 'predicate_semantics' not in rule.model_dump(mode='json')


def test_sigma_conversion_is_deterministic_preserves_metadata_and_never_activates():
    text=encode(base());first=convert_sigma(text);second=convert_sigma(text)
    assert first==second and first['production_active'] is False
    assert first['source_sha256']==hashlib.sha256(text.encode()).hexdigest()
    row=first['rules'][0];rule=ShadowRule.model_validate(row['definition'])
    assert rule.rule_version==row['rule_version'] and rule.status=='SHADOW_ONLY'
    assert rule.contract=='cdrc-v3' and rule.predicate_semantics=='SIGMA_2VL'
    metadata=json.loads(rule.external_metadata_json)
    assert metadata['author']=='SYNTHETIC test author' and metadata['id']==base()['id']


@pytest.mark.parametrize('modifier,value', [('contains','PowerShell'),('startswith',r'C:\Windows')])
def test_sigma_string_operators_match_real_normalized_events(client, modifier, value):
    raw=win(3401,BASE,'1',sysmon=True)
    raw['data']['win']['eventdata']['image']=r'C:\Windows\PowerShell.EXE'
    ingest(client,[raw])
    document=base(selection={'Image|'+modifier:value},source={'product':'windows','service':'sysmon'})
    rule=convert_sigma(encode(document))['rules'][0]['definition']
    result=evaluate(client,rule)
    assert len(result['result']['finding_ids'])==1
    detail=client.get(PREFIX+'/findings/'+result['result']['finding_ids'][0]).json()
    assert detail['matching_evidence']['evaluation_version']=='m34-shadow-v1'
    assert detail['matching_evidence']['rule_snapshot']['contract']=='cdrc-v3'


def test_sigma_boolean_not_on_missing_field_is_two_valued_without_unsafe_sql_prefilter(client):
    raw=win(3401,BASE,'4625');raw['data']['win']['eventdata'].pop('parentImage',None)
    ingest(client,[raw])
    document=base(condition='selection and not excluded')
    document['detection']['excluded']={'ParentImage|contains':'bad.exe'}
    rule=convert_sigma(encode(document))['rules'][0]['definition']
    assert len(evaluate(client,rule)['result']['finding_ids'])==1
    expression=parse_cqql('NOT process.parent.name = "bad.exe"').expression
    assert compare(expression,{'process.parent.name':None}) is None
    assert compare(expression,{'process.parent.name':None},two_valued=True) is True


@pytest.mark.parametrize('kind,reverse,same_time,expected', [
    ('temporal_ordered',False,False,1),('temporal_ordered',True,False,0),
    ('temporal',True,False,1),('temporal',False,True,1),('temporal_ordered',False,True,0),
])
def test_sigma_temporal_order_and_equal_timestamp_semantics(client,kind,reverse,same_time,expected):
    rows=[win(3401,BASE,'4625'),win(3402,BASE+timedelta(seconds=0 if same_time else 1),'4624')]
    if reverse:
        rows=[win(3401,BASE,'4624'),win(3402,BASE+timedelta(seconds=1),'4625')]
    ingest(client,rows)
    rule=convert_sigma(encode(*correlated(kind)))['rules'][0]['definition']
    assert len(evaluate(client,rule)['result']['finding_ids'])==expected


@pytest.mark.parametrize('operator,threshold', [('gte',3),('gt',2)])
def test_sigma_bounded_event_count_requires_real_distinct_records(client,operator,threshold):
    document=base();root={'title':'SYNTHETIC count','id':'00000000-0000-4000-8000-000000000002',
        'date':'2026-10-27','correlation':{'type':'event_count','rules':['synthetic_1'],
        'group-by':['Computer'],'timespan':'5m','condition':{operator:threshold}}}
    rule=convert_sigma(encode(document,root))['rules'][0]['definition']
    rows=[win(3401+i,BASE+timedelta(seconds=i),'4625') for i in range(3)]
    ingest(client,rows[:2]*2)
    assert evaluate(client,rule)['result']['finding_ids']==[]
    ingest(client,rows[2:])
    assert len(evaluate(client,rule)['result']['finding_ids'])==1


@pytest.mark.parametrize('mutation', ['regex','wildcard','unknown_field','null','empty_list','condition_pattern',
                                    'unicode','unscoped_group','account_group','count_eq','oversize_count',
                                    'oversize_window','overlap','missing_reference','category','unknown_status'])
def test_sigma_unsupported_features_are_rejected_explicitly(mutation):
    docs=correlated();document=docs[0]
    if mutation=='regex':document['detection']['selection']={'Image|re':'.*'}
    if mutation=='wildcard':document['detection']['selection']={'Image':'*powershell*'}
    if mutation=='unknown_field':document['detection']['selection']={'untrusted.sql.path':'x'}
    if mutation=='null':document['detection']['selection']={'Image':None}
    if mutation=='empty_list':document['detection']['selection']={'Image':[]}
    if mutation=='condition_pattern':document['detection']['condition']='1 of selection*'
    if mutation=='unicode':document['detection']['selection']={'Image':'\u0130mage'}
    if mutation=='unscoped_group':docs[-1]['correlation']['group-by']=['SourceIp']
    if mutation=='account_group':docs[-1]['correlation']['group-by']=['Computer','TargetUserName']
    if mutation in {'count_eq','oversize_count'}:
        docs[-1]['correlation'].update(type='event_count',rules=['synthetic_1'],condition={'eq':3} if mutation=='count_eq' else {'gte':11})
    if mutation=='oversize_window':docs[-1]['correlation']['timespan']='1h'
    if mutation=='overlap':docs[1]['detection']['selection']={'EventID':4625}
    if mutation=='missing_reference':docs[-1]['correlation']['rules']=['missing']
    if mutation=='category':document['logsource']['category']='process_creation'
    if mutation=='unknown_status':document['status']='PRODUCTION_ACTIVE'
    with pytest.raises(SigmaImportError):convert_sigma(encode(*docs))


@pytest.mark.parametrize('text', ['!!python/object:builtins.object {}','title: &anchor value\nother: *anchor',
                                'title: x\ntitle: duplicate','true: bad-key','[not,a,rule]',
                                'x'*32769,'\ud800', '['*600+']'*600],
                         ids=['unsafe-tag','alias','duplicate-key','non-text-key','root-shape','oversize','invalid-unicode','depth'])
def test_sigma_unsafe_yaml_bounds_and_encoding_fail_closed(text):
    with pytest.raises(SigmaImportError):convert_sigma(text)


def test_sigma_disconnected_cycle_cannot_hide_behind_a_valid_rule():
    docs=correlated();docs[1].pop('detection');docs[1].pop('logsource')
    docs[1]['correlation']={'type':'event_count','rules':[docs[2]['id']],'group-by':['Computer'],
                           'timespan':'5m','condition':{'gte':2}}
    docs[2]['correlation']['rules']=[docs[1]['id']]
    with pytest.raises(SigmaImportError,match='CYCLIC'):
        convert_sigma(encode(*docs))


def test_nested_count_marker_is_not_silently_flattened_into_parent_time_window():
    docs=correlated()
    count={'title':'SYNTHETIC count marker','id':'00000000-0000-4000-8000-000000000004',
           'name':'failure_marker','date':'2026-10-27','correlation':{'type':'event_count',
           'rules':['synthetic_1'],'group-by':['Computer'],'timespan':'5m','condition':{'gte':3}}}
    docs[-1]['correlation']['rules']=['failure_marker','synthetic_2']
    with pytest.raises(SigmaImportError,match='NESTED_CORRELATION_MARKER'):
        convert_sigma(encode(*docs,count))


def test_sigma_substring_values_are_bound_and_resource_cost_is_explicit():
    query='process.name CONTAINS "x%_\u0027 OR 1=1 --"'
    compiled=compile_cqql(query)
    assert compiled.parameters==("x%_' OR 1=1 --",)
    assert "OR 1=1" not in compiled.sql and not compiled.uses_fts
    assert 'BOUNDED_SUBSTRING_SCAN' in compiled.diagnostic_reasons
    assert compiled.cost_class=='HIGH'


def test_sigma_preview_requires_human_session_origin_csrf_and_does_not_persist(client,prepared):
    body={'yaml':encode(base()),'profile':'CQ_ENDPOINT_SHADOW_V1'}
    response=client.post(API,json=body)
    assert response.status_code==200,response.text
    assert response.json()['rules'][0]['definition']['status']=='SHADOW_ONLY'
    with closing(sqlite3.connect(prepared[1].path)) as connection:
        assert connection.execute('SELECT COUNT(*) FROM shadow_findings').fetchone()[0]==0
        assert connection.execute('SELECT COUNT(*) FROM shadow_rules').fetchone()[0]==0
    headers=dict(client.headers);client.headers.pop('X-CSRF-Token')
    assert client.post(API,json=body).status_code==403
    client.headers.update(headers)
    assert client.post(API,json=body,headers={'Origin':'https://untrusted.invalid'}).status_code==403
    rejected=client.post(API,json={'yaml':'!!python/object:builtins.object {}','profile':'CQ_ENDPOINT_SHADOW_V1'})
    assert rejected.status_code==422 and 'python/object' not in rejected.text
    client.cookies.clear()
    assert client.post(API,json=body,headers={'X-API-Key':'SYNTHETIC-m31-key'}).status_code==401


def test_sigma_preview_admission_is_bounded_and_recovers(client):
    from app.api.routes.sigma import _preview_slots
    body={'yaml':encode(base()),'profile':'CQ_ENDPOINT_SHADOW_V1'}
    _preview_slots.acquire();_preview_slots.acquire()
    try:
        response=client.post(API,json=body)
        assert response.status_code==503 and response.headers['Retry-After']=='1'
    finally:_preview_slots.release();_preview_slots.release()
    assert client.post(API,json=body).status_code==200
