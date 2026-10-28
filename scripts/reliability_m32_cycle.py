"""Bounded SYNTHETIC restarts/ingest/dedup/reconciliation/backup cycles, no live path."""
from __future__ import annotations
import argparse
import gc
from contextlib import closing
from datetime import datetime,timedelta,timezone
import json
from pathlib import Path
import secrets
import sqlite3
import sys
import tempfile
import time
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'backend'),str(ROOT/'scripts')]
from fastapi.testclient import TestClient
from app.core.config import Settings
from app.main import create_app
import app.main as application
from app.db.alerts import AlertRepository
from app.db.shadow_history import initialize,ShadowHistoryRepository
from app.db.fts_rowid import install,verify
from app.db.cqql import CQQLQueryCancelledError
from app.db.cqql import CQQLSearchRepository
from unittest.mock import patch
from app.schemas.auth import AnalystCreate,AnalystRole
from app.schemas.shadow_history import DurableEvaluationRequest
from app.services.shadow_backup import capture_pair,restore_offline
from app.services.shadow_rules import catalog
from m30_synthetic import auth,ssh
from benchmark_m29_performance import process_memory


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--cycles',type=int,default=16);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    if not 1<=args.cycles<=32 or args.output.exists():raise ValueError('NEW_OUTPUT_AND_BOUNDED_CYCLES_REQUIRED')
    began=time.perf_counter();cpu=time.process_time();observations=[];accepted=duplicates=backups=restores=cancellations=0
    key,password=secrets.token_urlsafe(32),secrets.token_urlsafe(32);base=datetime.now(timezone.utc)-timedelta(minutes=args.cycles+2)
    with tempfile.TemporaryDirectory(prefix='cq-m32-cycle-') as raw:
        root=Path(raw);source=root/'source.db';sidecar=root/'history.db'
        settings=Settings(database_url=f'sqlite:///{source.as_posix()}',allow_m14_schema_migration=False,wazuh_ingest_api_key=key,correlation_enabled=False,ai_enabled=False)
        AlertRepository(settings.database_url,migration_target_version=17).initialize();initialize(sidecar,source,disposable_only=True)
        install(source,root/'before-index.db',disposable_only=True)
        for cycle in range(args.cycles):
            store=ShadowHistoryRepository(sidecar,source)
            with patch.object(application,'CQQLSearchRepository',lambda path:CQQLSearchRepository(path,fts_strategy='m32_rowid')):
                app=create_app(settings,disposable_detection_simulation=True,shadow_history=store)
            with TestClient(app) as client:
                if cycle==0:client.app.state.auth_repository.bootstrap_first_admin(AnalystCreate(username='m32-cycle',display_name='SYNTHETIC',password=password,role=AnalystRole.ADMIN))
                login=client.post('/api/v1/auth/login',headers={'Origin':'http://localhost:5173'},json={'username':'m32-cycle','password':password});assert login.status_code==200
                client.headers.update({'Origin':'http://localhost:5173','X-CSRF-Token':login.json()['csrf_token']})
                stamp=base+timedelta(seconds=cycle*60);ip='192.0.2.'+str(50+cycle)
                events=auth(stamp,offset=340000+cycle*10,ip=ip)
                for index in range(4):
                    event=ssh(350000+cycle*10+index,stamp+timedelta(seconds=index*10),index==3)
                    event['full_log']=event['full_log'].replace('192.0.2.30',ip);events.append(event)
                for event in events:
                    first=client.post('/api/v1/events/ingest',headers={'X-API-Key':key},json=event);again=client.post('/api/v1/events/ingest',headers={'X-API-Key':key},json=event)
                    assert first.status_code==201 and again.status_code==200 and first.json()['event']['event_id']==again.json()['event']['event_id'];accepted+=1;duplicates+=1
                # Evaluation request bounds stay the same for this cycle's evidence.
                for rule_id in ('SHADOW-WINDOWS-AUTH','SHADOW-SSH-AUTH'):
                    rule=next(v for v in catalog() if v.rule_id==rule_id)
                    body={'simulation':{'rule':rule.model_dump(mode='json'),'start_time':(stamp-timedelta(seconds=1)).isoformat(),
                        'end_time':(stamp+timedelta(seconds=40)).isoformat(),'evaluation_time':datetime.now(timezone.utc).isoformat()},'identity_policy':{'minimum':'PARTIAL'}}
                    first=client.post('/api/v1/detection-engineering/shadow-v2/runs',json=body);again=client.post('/api/v1/detection-engineering/shadow-v2/runs',json=body)
                    assert first.status_code==again.status_code==200 and first.json()['run_id']==again.json()['run_id'] and first.json()['result']['finding_ids']
                report=client.get('/api/v1/detection-engineering/shadow-v2/reconciliation').json()
                assert not any(report['counts'].get(key,0) for key in ('MISSING','CHANGED','UNKNOWN'))
                for term in ('SYNTHETIC','m32_never_present'):
                    search=client.post('/api/v1/siem/search',json={'query':'text CONTAINS "'+term+'"','start_time':(base-timedelta(seconds=1)).isoformat(),
                        'end_time':(stamp+timedelta(seconds=40)).isoformat(),'limit':10,'sort':'newest'})
                    assert search.status_code==200
                cancel=__import__('threading').Event();cancel.set()
                try:client.app.state.shadow_history_service.evaluate(DurableEvaluationRequest.model_validate(body),'SYNTHETIC-cancel',cancel_event=cancel)
                except CQQLQueryCancelledError:cancellations+=1
                else:raise AssertionError('cancel ignored')
                if cycle%4==0:
                    captured=capture_pair(client.app.state.shadow_history_service,root/f'backup-{cycle}',disposable_only=True);backups+=1
                    restored=restore_offline(root/f'backup-{cycle}',root/f'restore-{cycle}',captured['manifest_sha256'],disposable_only=True)
                    assert restored['runtime_activation']=='BLOCKED_BINDING_APPROVAL_REQUIRED';restores+=1
                with closing(sqlite3.connect(source)) as c:
                    verify(c,integrity=True);assert c.execute('PRAGMA quick_check').fetchone()[0]=='ok' and not c.execute('PRAGMA foreign_key_check').fetchall()
                    count=c.execute('SELECT COUNT(*) FROM security_events').fetchone()[0]
                assert count==accepted
                state=client.app.state.shadow_history_service.scheduler.snapshot();assert state['inflight']==state['queue_depth']==0
                wal=source.with_name(source.name+'-wal')
                observations.append({'cycle':cycle,'events':count,'source_bytes':source.stat().st_size,'wal_observed_bytes':wal.stat().st_size if wal.exists() else 0,
                    'scheduler':state,**process_memory()})
            gc.collect()
    result={'scope':'BOUNDED_DISPOSABLE_CYCLES_NOT_MULTI_HOUR_SOAK','runtime':sqlite3.sqlite_version,'cycles':args.cycles,
        'single_event_201':accepted,'duplicate_200':duplicates,'service_lifespan_restarts':args.cycles,'backup_restore_pairs':restores,'fts_http_200':args.cycles*2,
        'cancelled_before_execution':cancellations,'failures':0,'wall_seconds':round(time.perf_counter()-began,3),'cpu_seconds':round(time.process_time()-cpu,3),
        'observations':observations,'production':'NOT_DEPLOYED','historical_continuity':'UNPROVEN'}
    args.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({key:result[key] for key in ('cycles','single_event_201','duplicate_200','backup_restore_pairs','wall_seconds')}))


if __name__=='__main__':main()
