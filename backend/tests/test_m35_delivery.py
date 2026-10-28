from contextlib import closing
from dataclasses import asdict
from copy import deepcopy
import json
from pathlib import Path
import sqlite3

import pytest
from jsonschema import Draft202012Validator

from app.schemas.collection import CollectionEnvelope
from app.services.collection_delivery import classify_response
from app.services.network_telemetry import digest
from tests.test_m34_network import network_client, HEADERS
from scripts.m34_synthetic import envelope, source_key


def ack(body,duplicate=False):
    return {'contract':'cq-collection-ack-v1','committed':True,'duplicate':duplicate,
            'event_id':'EVT-'+digest(['cq-source-record-v1',body['source_id'],body['collector_id'],body['source_generation'],body['source_event_id']])[:24].upper(),
            **{key:body[key] for key in ['source_event_id','delivery_identity','checkpoint_identity','integrity_fingerprint']}}


@pytest.mark.parametrize('source,stream',[('ZEEK_JSON','dns'),('SURICATA_EVE','alert')])
def test_m35_actual_ingestion_lost_ack_duplicate_and_schema_contract(network_client,source,stream):
    body=envelope(stream,source_type=source);model=CollectionEnvelope.model_validate(body)
    headers={**HEADERS,'X-Source-Key':source_key(source)}
    first=network_client.post('/api/v1/collection/events',headers=headers,json=body)
    assert first.status_code==201
    assert classify_response(model,201,first.json()).inserted is True
    # Deliberately discard the successful response. No verified ACK means no
    # permission to advance; resend exactly the stable source-record identity.
    lost=classify_response(model,None)
    assert lost.state=='UNKNOWN_ACK' and lost.retry and not lost.may_advance
    second=network_client.post('/api/v1/collection/events',headers=headers,json=body)
    verified=classify_response(model,second.status_code,second.json())
    assert second.status_code==200 and verified.may_advance and verified.inserted is False
    path=Path(__file__).resolve().parents[2]/'docs/contracts'
    Draft202012Validator(json.loads((path/'m34-collection-v1.schema.json').read_text())).validate(body)
    Draft202012Validator(json.loads((path/'m34-collection-ack-v1.schema.json').read_text())).validate(second.json())
    database=network_client.app.state.event_repository.path
    with closing(sqlite3.connect(database)) as c:
        assert c.execute('SELECT COUNT(*) FROM security_events').fetchone()[0]==1
        assert c.execute('PRAGMA quick_check').fetchone()[0]=='ok'
        assert not c.execute('PRAGMA foreign_key_check').fetchall()
    event=network_client.get('/api/v1/events/'+second.json()['event_id']).json()
    assert event['cuse']['source_generation']==body['source_generation']


@pytest.mark.parametrize('status,state',[(400,'PERMANENT_REJECTION'),(422,'PERMANENT_REJECTION'),
    (413,'PERMANENT_REJECTION'),(401,'BLOCKED'),(403,'BLOCKED'),(409,'BLOCKED'),
    (429,'RETRYABLE_FAILURE'),(503,'RETRYABLE_FAILURE'),(500,'RETRYABLE_FAILURE'),
    (307,'BLOCKED'),(302,'BLOCKED'),(204,'BLOCKED')])
def test_m35_non_ack_status_never_permits_checkpoint_advance(status,state):
    body=envelope();result=classify_response(CollectionEnvelope.model_validate(body),status,ack(body))
    assert result.state==state and not result.may_advance
    if state=='RETRYABLE_FAILURE':assert result.retry and 1<=result.retry_after_seconds<=60


@pytest.mark.parametrize('mutation',['wrong-event','source-id','delivery-id','checkpoint-id','fingerprint',
    'wrong-contract','false-commit','integer-commit','string-duplicate','status-disagrees','extra-field','oversized-id'])
def test_m35_untrusted_ack_must_match_all_immutable_bindings(mutation):
    body=envelope();value=ack(body)
    keys={'wrong-event':'event_id','source-id':'source_event_id','delivery-id':'delivery_identity',
          'checkpoint-id':'checkpoint_identity','fingerprint':'integrity_fingerprint','wrong-contract':'contract'}
    if mutation in keys:value[keys[mutation]]='SYNTHETIC-wrong-binding'
    if mutation=='false-commit':value['committed']=False
    if mutation=='integer-commit':value['committed']=1
    if mutation=='string-duplicate':value['duplicate']='false'
    if mutation=='status-disagrees':value['duplicate']=True
    if mutation=='extra-field':value['untrusted']='SYNTHETIC'
    if mutation=='oversized-id':value['event_id']='x'*129
    result=classify_response(CollectionEnvelope.model_validate(body),201,value)
    assert result.state=='BLOCKED' and not result.may_advance and result.reason=='INVALID_ACK_BINDING'


@pytest.mark.parametrize('header',['0','99','-1','NaN','SYNTHETIC-private-header','1\r\nInjected: x','9'*1000])
def test_m35_retry_after_is_bounded_and_diagnostics_do_not_echo_values(header):
    result=classify_response(CollectionEnvelope.model_validate(envelope()),503,retry_after=header)
    assert 1<=result.retry_after_seconds<=60
    assert 'private-header' not in json.dumps(asdict(result)) and 'Injected' not in json.dumps(asdict(result))


def test_m35_authentication_rejection_and_source_conflict_stay_distinct(network_client):
    body=envelope();model=CollectionEnvelope.model_validate(body)
    wrong=network_client.post('/api/v1/collection/events',headers={**HEADERS,'X-Source-Key':'SYNTHETIC-wrong-key'},json=body)
    assert classify_response(model,wrong.status_code,wrong.json()).reason=='AUTHENTICATION_REQUIRED'
    assert network_client.post('/api/v1/collection/events',headers=HEADERS,json=body).status_code==201
    changed=deepcopy(body);changed['payload']['uid']='SYNTHETIC-conflicting-record';changed['integrity_fingerprint']=digest(changed['payload'])
    conflict=network_client.post('/api/v1/collection/events',headers=HEADERS,json=changed)
    assert conflict.status_code==409
    assert classify_response(CollectionEnvelope.model_validate(changed),409,conflict.json()).reason=='SOURCE_RECORD_CONFLICT'
