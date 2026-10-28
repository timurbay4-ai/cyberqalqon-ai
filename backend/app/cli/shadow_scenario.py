"""Run only self-created SYNTHETIC disposable CDRC scenarios. No live DB option."""
import argparse
import json
import hashlib
import gc
import secrets
import sqlite3
import tempfile
from contextlib import closing
from datetime import datetime,timedelta,timezone
from pathlib import Path

from fastapi.testclient import TestClient
from app.core.config import Settings
from app.main import create_app
from app.schemas.auth import AnalystCreate,AnalystRole
from app.services.shadow_rules import catalog
from app.db.alerts import AlertRepository
from app.db.shadow_history import initialize,ShadowHistoryRepository


def run_scenario(name,rule_id,raws,expected,label,base,root,*,durable=False):
    key,password = secrets.token_urlsafe(32),secrets.token_urlsafe(32)
    path=root/(name+'.db')
    settings=Settings(database_url=f'sqlite:///{path.as_posix()}',wazuh_ingest_api_key=key,
        allow_m14_schema_migration=False,correlation_enabled=False)
    history=None
    if durable:
        AlertRepository(settings.database_url,migration_target_version=17).initialize()
        target=root/(name+'-history.db');initialize(target,path,disposable_only=True)
        history=ShadowHistoryRepository(target,path)
    with TestClient(create_app(settings,disposable_detection_simulation=True,shadow_history=history)) as client:
        client.app.state.auth_repository.bootstrap_first_admin(AnalystCreate(username='m30-synthetic',display_name='SYNTHETIC M30',
            password=password,role=AnalystRole.ADMIN))
        origin='http://localhost:5173'
        login=client.post('/api/v1/auth/login',headers={'Origin':origin},json={'username':'m30-synthetic','password':password})
        if login.status_code!=200: raise RuntimeError('synthetic authentication failed')
        client.headers.update({'Origin':origin,'X-CSRF-Token':login.json()['csrf_token']})
        accepted=set()
        for raw in raws:
            response=client.post('/api/v1/events/ingest',headers={'X-API-Key':key},json=raw)
            if response.status_code not in (200,201): raise RuntimeError('synthetic ingest failed')
            accepted.add(response.json()['event']['event_id'])
        selected=next(rule for rule in catalog() if rule.rule_id==rule_id)
        search=client.post('/api/v1/siem/search',json={'query':selected.steps[0].query,
            'start_time':(base-timedelta(seconds=1)).isoformat(),'end_time':(base+timedelta(minutes=15)).isoformat(),
            'limit':100,'sort':'oldest'})
        if search.status_code!=200 or not {value['event_id'] for value in search.json()['items']} <= accepted:
            raise RuntimeError('synthetic CQQL integration failed')
        validation=client.post('/api/v1/detection-engineering/shadow-v2/validate',json=selected.model_dump(mode='json'))
        if validation.status_code!=200: raise RuntimeError('synthetic rule validation failed')
        payload={'rule':selected.model_dump(mode='json'),'start_time':(base-timedelta(seconds=1)).isoformat(),
            'end_time':(base+timedelta(minutes=15)).isoformat(),'evaluation_time':datetime.now(timezone.utc).isoformat()}
        first=client.post('/api/v1/detection-engineering/shadow-v2/simulate',json=payload)
        second=client.post('/api/v1/detection-engineering/shadow-v2/simulate',json=payload)
        if first.status_code!=200 or second.status_code!=200: raise RuntimeError('synthetic simulation failed')
        result=first.json()
        assert len(result['findings'])==expected
        assert [value['finding_id'] for value in result['findings']]==[value['finding_id'] for value in second.json()['findings']]
        for finding in result['findings']:
            assert {value['event_id'] for value in finding['evidence']} <= accepted
            for value in finding['evidence']:
                detail=client.get('/api/v1/events/'+value['event_id'])
                assert detail.status_code==200 and detail.json()['cuse']['content_fingerprint']==value['stored_envelope_sha256']
        with closing(sqlite3.connect(path)) as connection:
            assert connection.execute('PRAGMA quick_check').fetchone()[0]=='ok'
            assert not connection.execute('PRAGMA foreign_key_check').fetchall()
            assert connection.execute('PRAGMA user_version').fetchone()[0]==17
            assert connection.execute('SELECT COUNT(*) FROM incidents').fetchone()[0]==0
            assert connection.execute('SELECT COUNT(*) FROM soc_cases').fetchone()[0]==0
        extra={}
        if durable:
            run=client.post('/api/v1/detection-engineering/shadow-v2/runs',json={'simulation':payload})
            assert run.status_code==200
            again=client.post('/api/v1/detection-engineering/shadow-v2/runs',json={'simulation':payload})
            assert again.json()['run_id']==run.json()['run_id']
            assert len(run.json()['result']['finding_ids'])==expected
            page=client.get('/api/v1/detection-engineering/shadow-v2/findings').json()
            detail=client.get('/api/v1/detection-engineering/shadow-v2/findings/'+run.json()['result']['finding_ids'][0]).json() if expected else None
            extra={'history_status':client.get('/api/v1/detection-engineering/shadow-v2/history-status').json(),
                'durable_run':run.json(),'history_page':page,'history_detail':detail,
                'reconciliation':client.get('/api/v1/detection-engineering/shadow-v2/reconciliation').json()}
            with closing(sqlite3.connect(history.path)) as connection:
                assert connection.execute('PRAGMA quick_check').fetchone()[0]=='ok'
                assert not connection.execute('PRAGMA foreign_key_check').fetchall()
                assert connection.execute('SELECT COUNT(*) FROM shadow_findings').fetchone()[0]==expected
        return {'scenario':name,'label':label,'semantic_expected':expected,'finding_count':len(result['findings']),
            'finding_ids':[value['finding_id'] for value in result['findings']], 'execution_ms':result['execution_ms'],
            'coverage':result['coverage'],'diagnostics':result['diagnostics'],'integrity':'PASS'}, {
                'catalog':client.get('/api/v1/detection-engineering/shadow-v2/catalog').json(),
                'validation':validation.json(),'result':result,**extra}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--scenario',default='all')
    parser.add_argument('--output',type=Path)
    parser.add_argument('--emit-contract',action='store_true')
    parser.add_argument('--durable',action='store_true',help='Explicit isolated M31 sidecar, never an arbitrary database path')
    args=parser.parse_args()
    root=Path(__file__).resolve().parents[3]
    import sys
    sys.path.insert(0,str(root/'scripts'))
    from m30_synthetic import scenarios
    base=datetime.now(timezone.utc).replace(microsecond=0)-timedelta(minutes=20)
    selected=[row for row in scenarios(base) if args.scenario in ('all',row[0])]
    if not selected: parser.error('unknown synthetic scenario')
    results=[]; contract=None
    with tempfile.TemporaryDirectory(prefix='cyberqalqon-m30-scenarios-') as temporary:
        for row in selected:
            result,contract=run_scenario(*row,base,Path(temporary),durable=args.durable)
            results.append(result)
            # Some unchanged legacy repositories rely on GC to close SQLite.
            # Release their cycles before Windows removes our disposable files.
            gc.collect()
    tp=sum(row['label']=='POSITIVE' and row['finding_count']>0 for row in results)
    fp=sum(row['label']=='NEGATIVE' and row['finding_count']>0 for row in results)
    fn=sum(row['label']=='POSITIVE' and row['finding_count']==0 for row in results)
    tn=sum(row['label']=='NEGATIVE' and row['finding_count']==0 for row in results)
    report={'scope':'LABELED_SYNTHETIC_FIXTURES_ONLY','dataset_version':'m30-synthetic-v1','scenarios':results,
        'durable_mode':args.durable,
        'source_sha256':{name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in (
            'backend/app/cli/shadow_scenario.py','scripts/m30_synthetic.py','backend/app/services/shadow_detection.py',
            'backend/app/schemas/shadow_detection.py','backend/app/services/shadow_rules.py')},
        'metrics':{'true_positives':tp,'false_positives':fp,'false_negatives':fn,'true_negatives':tn,
            'precision':tp/(tp+fp) if tp+fp else None,'recall':tp/(tp+fn) if tp+fn else None},
        'note':'Candidate-pattern labels, not production efficacy; benign threshold retries deliberately produce an FP.',
        'integrity':'PASS','production':'NOT_DEPLOYED'}
    if args.durable:report['m31_source_sha256']={name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in (
        'backend/app/db/shadow_history.py','backend/app/services/shadow_history.py','backend/app/services/identity_resolution.py','backend/app/schemas/shadow_history.py')}
    if args.output: args.output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(contract if args.emit_contract else report))


if __name__=='__main__': main()
