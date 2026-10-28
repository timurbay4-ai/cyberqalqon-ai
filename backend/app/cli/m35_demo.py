"""Owned M35 recovery demonstration; accepts no live DB, URL or source paths."""
from __future__ import annotations

import argparse
from contextlib import closing
from dataclasses import asdict
from datetime import datetime,timedelta,timezone
import json
from pathlib import Path
import secrets
import sqlite3
import tempfile

from fastapi.testclient import TestClient

from app.core.config import Settings
from app.db.alerts import AlertRepository
from app.db.shadow_history import initialize,ShadowHistoryRepository,ShadowStoreError
from app.main import create_app
from app.schemas.auth import AnalystCreate,AnalystRole
from app.schemas.collection import CollectionEnvelope
from app.services.collection_delivery import classify_response
from app.services.continuous_shadow import prepare,ContinuousShadowWorker,ContinuousShadowError
from app.services.shadow_rules import catalog
from app.cli.m34_demo import _json,_integrity,ORIGIN,PREFIX


def run_demo():
    from scripts.m34_synthetic import MACHINE_KEY,binding,envelope,source_key
    from scripts.m30_synthetic import auth,win
    with tempfile.TemporaryDirectory(prefix='cyberqalqon-m35-SYNTHETIC-',ignore_cleanup_errors=True) as name:
        directory=Path(name);source=directory/'source.db';history=directory/'history.db';checkpoint=directory/'evaluation.db'
        settings=Settings(database_url='sqlite:///'+source.as_posix(),allow_m14_schema_migration=False,
                          wazuh_ingest_api_key=MACHINE_KEY,correlation_enabled=False,ai_enabled=False,event_batch_ingest_enabled=False)
        AlertRepository(settings.database_url,migration_target_version=17).initialize()
        initialize(history,source,disposable_only=True);store=ShadowHistoryRepository(history,source)
        app=create_app(settings,disposable_detection_simulation=True,shadow_history=store,
                       disposable_collection_sources=(binding(),binding('SURICATA_EVE')))
        at=datetime.now(timezone.utc).replace(microsecond=0)-timedelta(minutes=5)
        with TestClient(app) as client:
            password=secrets.token_urlsafe(32)
            app.state.auth_repository.bootstrap_first_admin(AnalystCreate(username='synthetic-m35-admin',
                display_name='SYNTHETIC M35 operator',password=password,role=AnalystRole.ADMIN))
            session=_json(client.post('/api/v1/auth/login',headers={'Origin':ORIGIN},json={'username':'synthetic-m35-admin','password':password}))
            client.headers.update({'Origin':ORIGIN,'X-CSRF-Token':session['csrf_token']})
            decisions=[];network=[]
            for source_type,stream in [('ZEEK_JSON','dns'),('SURICATA_EVE','alert')]:
                body=envelope(stream,source_type=source_type,record='m35-'+stream,at=at)
                headers={'X-API-Key':MACHINE_KEY,'X-Source-Key':source_key(source_type)}
                ack=_json(client.post('/api/v1/collection/events',headers=headers,json=body),201)
                model=CollectionEnvelope.model_validate(body)
                decisions.append(asdict(classify_response(model,201,ack)))
                network.append(_json(client.get('/api/v1/events/'+ack['event_id'])))
                if source_type=='ZEEK_JSON':
                    decisions.append(asdict(classify_response(model,None)))
                    duplicate=_json(client.post('/api/v1/collection/events',headers=headers,json=body))
                    decisions.append(asdict(classify_response(model,200,duplicate)))
            for body in auth(at):
                _json(client.post('/api/v1/events/ingest',headers={'X-API-Key':MACHINE_KEY},json=body),201)
            service=app.state.shadow_history_service
            rule=next(row for row in catalog() if row.rule_id=='SHADOW-WINDOWS-AUTH')
            prepare(checkpoint,service,rule,first_end=at+timedelta(seconds=60),disposable_only=True)
            worker=ContinuousShadowWorker(checkpoint,service,rule,disposable_only=True)
            with worker:
                app.state.continuous_shadow_workers=[worker]
                def stop_unsealed(stage):
                    if stage=='AFTER_RUN_BEGIN':raise RuntimeError('SYNTHETIC pre-seal interruption')
                service._fault=stop_unsealed
                try:worker.tick()
                except ShadowStoreError:pass
                else:raise RuntimeError('Expected owned unsealed failure not observed')
                finally:service._fault=lambda stage:None
                unsealed_coverage=_json(client.get('/api/v1/collection/sources'))
                run_id=unsealed_coverage['detection_workers'][0]['progress']['pending_run_id']
                unsealed_run=_json(client.get(PREFIX+'/runs/'+run_id))
                unsealed_history_status=_json(client.get(PREFIX+'/history-status'))
            restarted=ContinuousShadowWorker(checkpoint,service,rule,disposable_only=True)
            with restarted:
                app.state.continuous_shadow_workers=[restarted]
                def stop_after_history(stage):
                    if stage=='AFTER_HISTORY_COMMIT':raise RuntimeError('SYNTHETIC history/checkpoint interruption')
                restarted._fault=stop_after_history
                try:restarted.tick()
                except RuntimeError:pass
                else:raise RuntimeError('Expected owned post-history failure not observed')
                history_coverage=_json(client.get('/api/v1/collection/sources'))
                restarted._fault=lambda stage:None
                committed=restarted.tick()
                checkpoint_coverage=_json(client.get('/api/v1/collection/sources'))
                completed=_json(client.get(PREFIX+'/runs/'+run_id))
                if committed['ticks_committed']!=1 or completed['status']!='COMPLETED':raise RuntimeError('Recovery did not commit')
                finding=completed['result']['finding_ids'][0]
                detail=_json(client.get(PREFIX+'/findings/'+finding))
                investigation=_json(client.post('/api/v1/investigations/workbench',json={
                    'target_type':'DURABLE_SHADOW_FINDING','target_id':finding,'shadow_revision':1,
                    'relative_minutes':None,'start_time':(at-timedelta(seconds=1)).isoformat(),'end_time':(at+timedelta(minutes=2)).isoformat()}))
                _json(client.post('/api/v1/events/ingest',headers={'X-API-Key':MACHINE_KEY},
                                  json=win(35099,at-timedelta(seconds=1000),'4624')),201)
                late=restarted.tick()
                if late['late_outside_overlap']!=1:raise RuntimeError('Late observation not accounted')
                # Owned synthetic, unpinned event only: prove unavailable evidence
                # is reported without changing immutable finding metadata.
                expired=detail['matching_evidence']['evidence'][0]['event_id']
                with closing(sqlite3.connect(source)) as c:c.execute('DELETE FROM security_events WHERE event_id=?',(expired,));c.commit()
                try:restarted.tick()
                except ContinuousShadowError as exc:
                    if str(exc)!='SOURCE_RETENTION_GAP':raise
                else:raise RuntimeError('Synthetic retention gap was hidden')
                missing=_json(client.get(PREFIX+'/findings/'+finding))
                retention=_json(client.get('/api/v1/collection/sources'))
                integrity={label:_integrity(path) for label,path in [('source',source),('history',history),('checkpoint',checkpoint)]}
                with closing(sqlite3.connect(history)) as c:
                    counts={'findings':c.execute('SELECT COUNT(*) FROM shadow_findings').fetchone()[0],
                            'revisions':c.execute('SELECT COUNT(*) FROM shadow_revisions').fetchone()[0]}
                return {'scope':'SYNTHETIC_DISPOSABLE_M35','production':'NOT_DEPLOYED','go':'NOT_EVALUATED_BY_THIS_PYTHON_DEMO',
                    'collector_binary_and_spool':'NOT_EVALUATED_BY_THIS_PYTHON_DEMO','file_rotation_acceptance':'NOT_EVALUATED_BY_THIS_PYTHON_DEMO',
                    'delivery_reference_decisions':decisions,'network_events':network,
                    'unsealed_run':unsealed_run,'completed_run':completed,'unsealed_coverage':unsealed_coverage,
                    'unsealed_history_status':unsealed_history_status,
                    'history_committed_coverage':history_coverage,'checkpoint_committed_coverage':checkpoint_coverage,
                    'late_progress':late,'retention_gap_coverage':retention,'finding_detail':detail,'missing_evidence_detail':missing,
                    'investigation_finding_id':investigation['durable_shadow_context']['finding_id'],
                    'counts':counts,'integrity':integrity,'historical_continuity':'UNPROVEN','AI_ENABLED':False,'batch_enabled':False,
                    'detections':'SHADOW_ONLY','browser_uat':'DEFERRED_BY_USER'}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    if args.output.exists() or args.output.is_symlink():parser.error('New output path required')
    result=run_demo();args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open('x',encoding='utf-8') as stream:json.dump(result,stream,indent=2)
    print(json.dumps({'scope':result['scope'],'counts':result['counts'],'go':result['go']}))


if __name__=='__main__':main()
