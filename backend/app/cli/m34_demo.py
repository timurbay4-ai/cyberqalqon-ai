"""Owned synthetic M34 acceptance. No live DB/URL/source/checkpoint arguments."""
from __future__ import annotations

import argparse
from contextlib import closing, ExitStack
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import secrets
import shutil
import sqlite3
import tempfile

from fastapi.testclient import TestClient

from app.core.config import Settings
from app.db.alerts import AlertRepository
from app.db.shadow_history import initialize, ShadowHistoryRepository
from app.main import create_app
from app.schemas.auth import AnalystCreate, AnalystRole
from app.services.continuous_shadow import prepare, ContinuousShadowWorker
from app.services.shadow_rules import catalog

PREFIX = '/api/v1/detection-engineering/shadow-v2'
ORIGIN = 'http://localhost:5173'


def _json(response, expected=200):
    if response.status_code != expected:
        raise RuntimeError(f'M34 synthetic HTTP contract: {response.status_code}, expected {expected}')
    return response.json()


def _integrity(path):
    with closing(sqlite3.connect(path.as_uri()+'?mode=ro', uri=True)) as connection:
        return {'schema': connection.execute('PRAGMA user_version').fetchone()[0],
                'quick_check': connection.execute('PRAGMA quick_check').fetchone()[0],
                'foreign_key_violations': len(connection.execute('PRAGMA foreign_key_check').fetchall())}


def run_demo():
    from scripts.m34_synthetic import MACHINE_KEY, binding, envelope, source_key
    from scripts.m30_synthetic import auth, ssh
    root = Path(__file__).resolve().parents[3]
    with tempfile.TemporaryDirectory(prefix='cyberqalqon-m34-SYNTHETIC-', ignore_cleanup_errors=True) as name:
        directory = Path(name)
        source, history = directory/'source.db', directory/'history.db'
        settings = Settings(database_url='sqlite:///'+source.as_posix(), allow_m14_schema_migration=False,
                            wazuh_ingest_api_key=MACHINE_KEY, ai_enabled=False, correlation_enabled=False,
                            event_batch_ingest_enabled=False)
        AlertRepository(settings.database_url, migration_target_version=17).initialize()
        initialize(history, source, disposable_only=True)
        store = ShadowHistoryRepository(history, source)
        app = create_app(settings, disposable_detection_simulation=True, shadow_history=store,
                         disposable_collection_sources=(binding(),binding('SURICATA_EVE')))
        at = datetime.now(timezone.utc).replace(microsecond=0)-timedelta(minutes=5)
        with TestClient(app) as client:
            password = secrets.token_urlsafe(32)
            app.state.auth_repository.bootstrap_first_admin(AnalystCreate(
                username='synthetic-m34-admin', display_name='SYNTHETIC M34 operator', password=password, role=AnalystRole.ADMIN))
            session = _json(client.post('/api/v1/auth/login', headers={'Origin':ORIGIN},
                                       json={'username':'synthetic-m34-admin','password':password}))
            client.headers.update({'Origin':ORIGIN,'X-CSRF-Token':session['csrf_token']})
            empty = _json(client.get('/api/v1/collection/sources'))
            accepted, duplicates, network = [], [], []
            for kind, streams in [('ZEEK_JSON',('conn','dns','http','ssl')),
                                  ('SURICATA_EVE',('alert','dns','http','tls','flow'))]:
                for stream in streams:
                    body = envelope(stream,source_type=kind,record=kind+'-'+stream,at=at)
                    headers = {'X-API-Key':MACHINE_KEY,'X-Source-Key':source_key(kind)}
                    ack = _json(client.post('/api/v1/collection/events',headers=headers,json=body),201)
                    accepted.append(ack['event_id'])
                    network.append(_json(client.get('/api/v1/events/'+ack['event_id'])))
                    body['delivery_identity'] = 'retry-'+body['source_event_id']
                    duplicate = _json(client.post('/api/v1/collection/events',headers=headers,json=body))
                    if not duplicate['duplicate'] or duplicate['event_id'] != ack['event_id']:
                        raise RuntimeError('M34 synthetic duplicate contract failed')
                    duplicates.append(duplicate['event_id'])
            for body in [*auth(at), *[ssh(34000+i,at+timedelta(seconds=i*10),i==3) for i in range(4)]]:
                accepted.append(_json(client.post('/api/v1/events/ingest',headers={'X-API-Key':MACHINE_KEY},json=body),201)['event']['event_id'])
            service = app.state.shadow_history_service
            with ExitStack() as stack:
                workers = []
                for name_, rule_id in [('windows','SHADOW-WINDOWS-AUTH'),('linux','SHADOW-SSH-AUTH')]:
                    rule = next(rule for rule in catalog() if rule.rule_id == rule_id)
                    path = directory/(name_+'-evaluation.db')
                    prepare(path,service,rule,first_end=at+timedelta(seconds=40),disposable_only=True)
                    worker = stack.enter_context(ContinuousShadowWorker(path,service,rule,disposable_only=True))
                    workers.append(worker)
                app.state.continuous_shadow_workers = workers
                results = [worker.tick() for worker in workers]
                if not all(len(value['last_finding_ids']) == 1 for value in results):
                    raise RuntimeError('M34 continuous authentication scenario failed')
                sigma_source = (root/'examples/sigma/network-dns-repeats.yml').read_text(encoding='utf-8')
                preview = _json(client.post('/api/v1/detection-engineering/sigma/preview',
                                           json={'yaml':sigma_source,'profile':'CQ_ENDPOINT_SHADOW_V1'}))
                request = {'simulation': {'rule':preview['rules'][0]['definition'],
                           'start_time':(at-timedelta(seconds=1)).isoformat(),
                           'end_time':(at+timedelta(seconds=40)).isoformat(),
                           'evaluation_time':datetime.now(timezone.utc).isoformat()}}
                benign = _json(client.post(PREFIX+'/runs',json=request))
                if benign['result']['finding_ids']:
                    raise RuntimeError('M34 DNS single observation incorrectly crossed count threshold')
                for index in (2,3):
                    body = envelope('dns',record='dns-repeat-'+str(index),at=at+timedelta(seconds=index))
                    ack = _json(client.post('/api/v1/collection/events',
                                headers={'X-API-Key':MACHINE_KEY,'X-Source-Key':source_key()},json=body),201)
                    accepted.append(ack['event_id'])
                request['simulation']['evaluation_time'] = datetime.now(timezone.utc).isoformat()
                evaluated = _json(client.post(PREFIX+'/runs',json=request))
                if len(evaluated['result']['finding_ids']) != 1:
                    raise RuntimeError('M34 DNS review candidate was not durably stored')
                finding_id = evaluated['result']['finding_ids'][0]
                detail = _json(client.get(PREFIX+'/findings/'+finding_id))
                target = {'target_type':'DURABLE_SHADOW_FINDING','target_id':finding_id,'shadow_revision':1,
                          'relative_minutes':None,'start_time':(at-timedelta(seconds=1)).isoformat(),
                          'end_time':(at+timedelta(seconds=40)).isoformat()}
                investigation = _json(client.post('/api/v1/investigations/workbench',json=target))
                if investigation['durable_shadow_context']['finding_id'] != finding_id:
                    raise RuntimeError('M34 durable investigation provenance failed')
                match_event = detail['matching_evidence']['evidence'][0]['event_id']
                search = _json(client.post('/api/v1/siem/search',json={'query':'dns.question.name = "synthetic.example.test"',
                               'start_time':(at-timedelta(seconds=1)).isoformat(),'end_time':(at+timedelta(seconds=40)).isoformat()}))
                indicator = _json(client.post('/api/v1/iocs',json={'indicator_type':'DOMAIN','value':'synthetic.example.test',
                                  'source':'SYNTHETIC local fixture','confidence':25}),201)
                matches = _json(client.get('/api/v1/iocs/matches'))
                case = _json(client.post('/api/v1/cases',json={'title':'SYNTHETIC M34 analyst review',
                             'description':'Pattern review only; historical continuity UNPROVEN.','severity':'MEDIUM','priority':'MEDIUM'}),201)
                case_id = case['case_id']
                for route, body in [('related/event',{'reference_id':match_event}),
                                    ('comments',{'body':'SYNTHETIC review; a local IOC/pattern match is not proof of compromise.'}),
                                    ('evidence',{'reference_type':'EVENT','reference_id':match_event,'annotation':finding_id})]:
                    case = _json(client.post(f'/api/v1/cases/{case_id}/{route}',json={**body,'expected_version':case['version']}),201)
                report_response = client.post(f'/api/v1/cases/{case_id}/reports/json')
                if report_response.status_code != 200:
                    raise RuntimeError('M34 bounded case export failed')
                observation = _json(client.get('/api/v1/collection/sources'))
                _json(client.get('/health'))
            app.state.continuous_shadow_workers = []
            with closing(sqlite3.connect(source)) as connection:
                count = connection.execute('SELECT COUNT(*) FROM security_events').fetchone()[0]
                incidents = connection.execute('SELECT COUNT(*) FROM incidents').fetchone()[0]
                cases = connection.execute('SELECT COUNT(*) FROM soc_cases').fetchone()[0]
            integrity = {'source':_integrity(source),'history':_integrity(history),
                         'checkpoints':[_integrity(worker.path) for worker in workers]}
            if count != len(accepted) or incidents != 0 or cases != 1 or any(
                    row['quick_check'] != 'ok' or row['foreign_key_violations'] for row in
                    [integrity['source'],integrity['history'],*integrity['checkpoints']]):
                raise RuntimeError('M34 synthetic integrity or record identity failed')
            return {'scope':'SYNTHETIC_DISPOSABLE_M34','production':'NOT_DEPLOYED','historical_continuity':'UNPROVEN',
                    'go_execution':'BLOCKED_TOOLCHAIN' if shutil.which('go') is None else 'NOT_RUN',
                    'new_201':len(accepted),'duplicate_200':len(duplicates),'event_count':count,
                    'auth_findings':sum(len(value['last_finding_ids']) for value in results),
                    'network_findings':1,'benign_dns_findings':0,'explicit_cases':cases,'automatic_incidents':incidents,
                    'dns_query_events':len(search['items']),'ioc_matches':matches['total_matches'],
                    'report_sha256':hashlib.sha256(report_response.content).hexdigest(),'integrity':integrity,
                    'AI_ENABLED':False,'batch_enabled':False,'detections':'SHADOW_ONLY','browser_uat':'DEFERRED_BY_USER',
                    'empty_source_coverage':empty,'source_coverage':observation,'network_events':network,
                    'sigma_source':sigma_source,'sigma_preview':preview,'network_evaluation':evaluated,'finding_detail':detail,
                    'investigation_finding_id':investigation['durable_shadow_context']['finding_id'],
                    'case_id':case_id,'ioc_id':indicator['indicator_id']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        parser.error('New evidence output required')
    report = run_demo()
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({key:report[key] for key in ('scope','new_201','duplicate_200','event_count','auth_findings','network_findings','go_execution')}))


if __name__ == '__main__':
    main()
