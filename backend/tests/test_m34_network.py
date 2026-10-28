from contextlib import closing
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import sqlite3

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app
from app.schemas.collection import CollectionEnvelope
from app.services.event_normalizer import EventNormalizationError
from app.services.network_telemetry import digest, normalize_network
from tests.conftest import bootstrap_and_login
from scripts.m34_synthetic import MACHINE_KEY, SOURCE_KEY, binding, envelope, source_key

HEADERS = {'X-API-Key': MACHINE_KEY, 'X-Source-Key': SOURCE_KEY}


@pytest.fixture
def network_client(database_path):
    settings = Settings(database_url=f'sqlite:///{database_path.as_posix()}',
                        allow_m14_schema_migration=False, wazuh_ingest_api_key=MACHINE_KEY,
                        correlation_enabled=False, ai_enabled=False, max_event_ingest_bytes=4096)
    with TestClient(create_app(settings, disposable_detection_simulation=True,
                              disposable_collection_sources=(binding(), binding('SURICATA_EVE')))) as client:
        bootstrap_and_login(client)
        yield client


@pytest.mark.parametrize('source_type,stream,attribute', [
    ('ZEEK_JSON', 'conn', 'network_duration_ms'), ('ZEEK_JSON', 'dns', 'dns_question_name'),
    ('ZEEK_JSON', 'http', 'http_host'), ('ZEEK_JSON', 'ssl', 'tls_server_name'),
    ('SURICATA_EVE', 'alert', 'signature_signature'), ('SURICATA_EVE', 'dns', 'dns_question_name'),
    ('SURICATA_EVE', 'http', 'url_path'), ('SURICATA_EVE', 'tls', 'tls_server_name'),
    ('SURICATA_EVE', 'flow', 'network_duration_ms'),
])
def test_network_source_ingest_detail_and_provenance(network_client, source_type, stream, attribute):
    body = envelope(stream, source_type=source_type)
    response = network_client.post('/api/v1/collection/events', headers={**HEADERS,'X-Source-Key':source_key(source_type)}, json=body)
    assert response.status_code == 201, response.text
    value = response.json()
    event = network_client.get('/api/v1/events/' + value['event_id']).json()
    assert event['source_type'] == 'network' and event['normalization_schema'] == 'collection-event-v1'
    assert event['source_ip'] == '192.0.2.34' and event['destination_port']
    cuse = event['cuse']
    assert cuse['adapter_version'] == 'm34-network-v1' and attribute in cuse['attributes']
    assert cuse['source_generation'] == body['source_generation']
    assert cuse['original_event_identity'] == body['source_event_id']
    assert cuse['attributes']['collector_version'] == body['collector_version']
    assert cuse['attributes']['collector_checkpoint_identity'] == body['checkpoint_identity']
    assert event['source_event_id'].startswith('COLL-')
    assert cuse['endpoint_identity_verified'] is False and cuse['provenance_status'] == 'PARTIAL'
    assert event.get('related_alert_id') is None
    assert event['outcome'] == 'observed'
    if stream != 'alert':
        assert event.get('severity') is None and event.get('rule_id') is None
    coverage = network_client.get('/api/v1/collection/sources').json()
    registered = next(row for row in coverage['registered_sources'] if row['source_id'] == body['source_id'])
    assert registered['sample_event_count'] == 1
    assert registered['connected'] == 'UNKNOWN' and registered['last_acknowledged_delivery'] is None
    assert registered['queue_backlog'] is None and registered['last_committed_delivery_at']


def test_network_lost_ack_duplicate_and_conflicting_record_are_distinct(network_client, database_path):
    body = envelope()
    first = network_client.post('/api/v1/collection/events', headers=HEADERS, json=body)
    body['delivery_identity'] = 'different-transport-attempt'
    body['observed_timestamp'] = datetime.now(timezone.utc).isoformat()
    second = network_client.post('/api/v1/collection/events', headers=HEADERS, json=body)
    assert first.status_code == 201 and second.status_code == 200
    assert second.json()['duplicate'] and first.json()['event_id'] == second.json()['event_id']
    assert second.json()['delivery_identity'] == body['delivery_identity']
    body['payload']['query'] = 'conflicting.example.test'
    body['integrity_fingerprint'] = digest(body['payload'])
    conflict = network_client.post('/api/v1/collection/events', headers=HEADERS, json=body)
    assert conflict.status_code == 409
    with closing(sqlite3.connect(database_path)) as connection:
        assert connection.execute('SELECT COUNT(*) FROM security_events').fetchone()[0] == 1
        assert connection.execute('PRAGMA user_version').fetchone()[0] == 17
        assert connection.execute('PRAGMA quick_check').fetchone()[0] == 'ok'
        assert connection.execute('PRAGMA foreign_key_check').fetchall() == []


@pytest.mark.parametrize('change,expected', [
    ({'source_generation': 'unapproved-generation'}, 422),
    ({'collector_id': 'unregistered-collector'}, 422),
    ({'source_id': 'unregistered-source'}, 401),
    ({'integrity_fingerprint': '0' * 64}, 422),
    ({'contract': 'untrusted-v99'}, 422),
    ({'stream': 'flow'}, 422),
])
def test_network_identity_and_contract_rejections_do_not_write(network_client, database_path, change, expected):
    body = envelope();body.update(change)
    response = network_client.post('/api/v1/collection/events', headers=HEADERS, json=body)
    assert response.status_code == expected
    with closing(sqlite3.connect(database_path)) as connection:
        assert connection.execute('SELECT COUNT(*) FROM security_events').fetchone()[0] == 0


@pytest.mark.parametrize('field,value', [('id.orig_h', 'not-an-ip'), ('id.resp_p', True),
                                       ('id.orig_p', 65536), ('duration', -1), ('duration', float('nan'))])
def test_network_malformed_source_values_are_rejected(field, value):
    body = envelope('conn');body['payload'][field] = value
    if field != 'duration' or value == value:
        body['integrity_fingerprint'] = digest(body['payload'])
    with pytest.raises(EventNormalizationError):
        normalize_network(CollectionEnvelope.model_validate(body), binding())


def test_network_auth_gate_bounds_unknown_state_and_search_pivots(network_client):
    body = envelope()
    assert network_client.post('/api/v1/collection/events', json=body).status_code == 401
    assert network_client.post('/api/v1/collection/events', headers={'X-API-Key': MACHINE_KEY}, json=body).status_code == 401
    before = network_client.get('/api/v1/collection/sources').json()
    assert all(row['connected'] == 'UNKNOWN' and not row['observed'] for row in before['families'])
    oversized = deepcopy(body);oversized['payload']['padding'] = 'x' * 5000
    assert network_client.post('/api/v1/collection/events', headers=HEADERS, json=oversized).status_code == 413
    accepted = network_client.post('/api/v1/collection/events', headers=HEADERS, json=body)
    assert accepted.status_code == 201
    at = datetime.fromisoformat(body['event_timestamp'])
    response = network_client.post('/api/v1/siem/search', json={
        'query': 'dns.question.name = "synthetic.example.test" AND source.ip = "192.0.2.34"',
        'start_time': (at-timedelta(seconds=1)).isoformat(), 'end_time': (at+timedelta(seconds=1)).isoformat()})
    assert response.status_code == 200, response.text
    assert [row['event_id'] for row in response.json()['items']] == [accepted.json()['event_id']]
    workbench = network_client.post('/api/v1/investigations/workbench', json={
        'target_type': 'EVENT', 'target_id': accepted.json()['event_id'], 'relative_minutes': None,
        'start_time': (at-timedelta(seconds=1)).isoformat(), 'end_time': (at+timedelta(seconds=1)).isoformat()})
    assert workbench.status_code == 200, workbench.text
    assert workbench.json()['primary_event']['event_id'] == accepted.json()['event_id']
    assert 'payload' not in json.dumps(network_client.get('/api/v1/collection/sources').json())


def test_network_collection_is_closed_by_default_and_cannot_bypass_sandbox(database_path):
    settings = Settings(database_url=f'sqlite:///{database_path.as_posix()}',
                        allow_m14_schema_migration=False, wazuh_ingest_api_key=MACHINE_KEY, ai_enabled=False)
    with pytest.raises(ValueError, match='disposable'):
        create_app(settings, disposable_collection_sources=(binding(),))
    with TestClient(create_app(settings)) as client:
        assert client.post('/api/v1/collection/events', headers=HEADERS, json=envelope()).status_code == 503
        assert client.get('/api/v1/collection/sources').status_code == 401


def test_source_specific_key_cannot_impersonate_another_registered_sensor(network_client):
    body = envelope('alert', source_type='SURICATA_EVE')
    assert network_client.post('/api/v1/collection/events', headers=HEADERS, json=body).status_code == 401
    assert network_client.post('/api/v1/collection/events', headers={**HEADERS,'X-Source-Key':source_key('SURICATA_EVE')}, json=body).status_code == 201
    from dataclasses import replace
    from app.services.collection import CollectionRegistry
    with pytest.raises(ValueError, match='Distinct source key'):
        CollectionRegistry((binding(), replace(binding('SURICATA_EVE'), source_key_sha256=binding().source_key_sha256)))


def test_sensor_labels_in_payload_do_not_override_authenticated_context(network_client):
    body = envelope()
    body['payload'].update(sensor_id='untrusted-sensor', host='untrusted-host', agent={'id':'untrusted-agent'})
    body['integrity_fingerprint'] = digest(body['payload'])
    response = network_client.post('/api/v1/collection/events', headers=HEADERS, json=body)
    assert response.status_code == 201
    event = network_client.get('/api/v1/events/'+response.json()['event_id']).json()
    assert event['hostname'] == 'SYNTHETIC-M34-SENSOR' and event['agent_id'] == body['source_id']
    assert event['cuse']['endpoint_identity_verified'] is False


@pytest.mark.parametrize('stream', ['dns','http','ssl'])
def test_canonical_network_domains_reuse_existing_exact_ioc_workflow(network_client,stream):
    body=envelope(stream)
    response=network_client.post('/api/v1/collection/events',headers=HEADERS,json=body)
    assert response.status_code==201
    indicator=network_client.post('/api/v1/iocs',json={'indicator_type':'DOMAIN','value':'SYNTHETIC.EXAMPLE.TEST.',
        'source':'SYNTHETIC local fixture','confidence':25})
    assert indicator.status_code==201,indicator.text
    matches=network_client.get('/api/v1/iocs/matches').json()
    assert matches['total_matches']==1
    assert matches['matches'][0]['event_id']==response.json()['event_id']


@pytest.mark.parametrize('multiple', [False,True])
def test_suricata_dns_v3_questions_and_answers_preserve_available_evidence(network_client,multiple):
    body=envelope('dns',source_type='SURICATA_EVE')
    questions=[{'rrname':'synthetic.example.test','rrtype':'A'}]
    if multiple:questions.append({'rrname':'second.example.test','rrtype':'AAAA'})
    body['payload']['dns']={'version':3,'type':'answer','queries':questions,'rcode':'NOERROR',
        'answers':[{'rrname':'synthetic.example.test','rrtype':'A','rdata':'203.0.113.34','ttl':60}]}
    body['integrity_fingerprint']=digest(body['payload'])
    response=network_client.post('/api/v1/collection/events',headers={**HEADERS,'X-Source-Key':source_key('SURICATA_EVE')},json=body)
    assert response.status_code==201,response.text
    cuse=network_client.get('/api/v1/events/'+response.json()['event_id']).json()['cuse']
    assert cuse['attributes']['dns_question_name']=='synthetic.example.test'
    assert len(json.loads(cuse['attributes']['dns_questions_json']))==len(questions)
    assert json.loads(cuse['attributes']['dns_answers_json'])[0]['ttl']==60
    assert cuse['normalization_status']==('PARTIAL' if multiple else 'NORMALIZED')


def test_suricata_grouped_response_does_not_invent_missing_question(network_client):
    body=envelope('dns',source_type='SURICATA_EVE')
    body['payload']['dns']={'version':3,'type':'answer','rcode':'NOERROR','grouped':{'A':['203.0.113.34']}}
    body['integrity_fingerprint']=digest(body['payload'])
    response=network_client.post('/api/v1/collection/events',headers={**HEADERS,'X-Source-Key':source_key('SURICATA_EVE')},json=body)
    assert response.status_code==201
    cuse=network_client.get('/api/v1/events/'+response.json()['event_id']).json()['cuse']
    assert cuse['normalization_status']=='PARTIAL'
    assert 'dns_question_name' not in cuse['attributes'] and cuse['attributes']['dns_grouped_answers_json']


def test_source_coverage_admission_is_bounded_and_recovers(network_client):
    slot=network_client.app.state.collection_registry._read_slot
    slot.acquire()
    try:
        assert network_client.get('/api/v1/collection/sources').status_code==503
    finally:slot.release()
    assert network_client.get('/api/v1/collection/sources').status_code==200


@pytest.mark.parametrize('stream,query', [
    ('conn','network.protocol = "udp"'),('conn','network.duration_ms >= 1250'),
    ('conn','network.sensor.id = "synthetic-zeek"'),('conn','network.connection.uid = "SYNTHETIC-CONNECTION-1"'),
    ('dns','dns.question.name = "synthetic.example.test"'),('dns','dns.response.code = "NOERROR"'),
    ('http','http.host = "synthetic.example.test"'),('http','url.path = "/synthetic-path"'),
    ('ssl','tls.server.name = "synthetic.example.test"'),
])
def test_every_new_network_query_field_uses_existing_bounded_cqql(network_client,stream,query):
    body=envelope(stream)
    response=network_client.post('/api/v1/collection/events',headers=HEADERS,json=body)
    assert response.status_code==201
    at=datetime.fromisoformat(body['event_timestamp'])
    result=network_client.post('/api/v1/siem/search',json={'query':query,
        'start_time':(at-timedelta(seconds=1)).isoformat(),'end_time':(at+timedelta(seconds=1)).isoformat()})
    assert result.status_code==200,result.text
    assert [row['event_id'] for row in result.json()['items']]==[response.json()['event_id']]
