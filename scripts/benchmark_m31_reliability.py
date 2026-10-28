"""Like-for-like controlled M30-mode/M31-mode disposable HTTP workloads only."""
import json
import sqlite3
import sys
import threading
import time
from collections import Counter,defaultdict
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
from datetime import datetime,timedelta,timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'backend'),str(ROOT/'scripts')]
import benchmark_m30_detection as harness
import profile_m31_baseline as profile
from app.db.shadow_history import initialize,ShadowHistoryRepository
from app.services.shadow_history import ShadowHistoryService
from app.services.identity_resolution import IdentityResolver
from app.schemas.shadow_detection import ShadowSimulationRequest
from app.services.shadow_rules import catalog
import m30_synthetic

SOURCE_FILES=('backend/app/db/shadow_history.py','backend/app/services/shadow_history.py',
    'backend/app/services/identity_resolution.py','backend/app/services/shadow_scheduling.py',
    'backend/app/services/shadow_detection.py','scripts/benchmark_m31_reliability.py')
PREFIX='/api/v1/detection-engineering/shadow-v2'
COUNTS={10000:31,50000:41,100000:89}


def measure(path,base,enabled,repository,pinned_before,client):
    population=100000 if '100000-' in path.name else 50000 if '50000-' in path.name else 10000
    count=COUNTS[population];rule=catalog()[0]
    start=(base-timedelta(days=3)).isoformat();end=(base+timedelta(hours=1)).isoformat()
    simulation={'rule':rule.model_dump(mode='json'),'start_time':(base-timedelta(seconds=1)).isoformat(),
        'end_time':(base+timedelta(seconds=31)).isoformat(),'evaluation_time':datetime.now(timezone.utc).isoformat()}
    endpoint=PREFIX+('/runs' if enabled else '/simulate')
    warm=client.post(endpoint,json={'simulation':simulation} if enabled else simulation)
    assert warm.status_code==200,warm.text
    profile.STAGES.clear();profile.ERRORS.clear()
    outcomes=[];lock=threading.Lock();wal_peak=0;write_times=[];duplicate_times=[];search=defaultdict(list);search_codes=Counter();ids=set()
    barrier=threading.Barrier(3);cpu_started=time.process_time();wall_started=time.perf_counter()
    def observed(response,kind,index,began):
        detail=response.json().get('detail',{}) if response.status_code!=200 else {}
        row={'request_id':response.headers.get('X-Correlation-ID',f'SYNTHETIC-{kind}-{index}'),
            'logical_id':f'{kind}-{index:03d}','request_class':kind,'status':response.status_code,
            'code':detail.get('code','OK'),'reason':detail.get('reason_code',detail.get('code','OK')),
            'start_ms':round((began-wall_started)*1000,3),'wall_ms':round((time.perf_counter()-began)*1000,4)}
        with lock:outcomes.append(row)
        return row
    def shadow():
        barrier.wait()
        for index in range(count):
            body={**simulation,'evaluation_time':(datetime.now(timezone.utc)+timedelta(seconds=1,microseconds=index)).isoformat()}
            began=time.perf_counter();response=client.post(endpoint,json={'simulation':body} if enabled else body)
            observed(response,'DURABLE' if enabled else 'LEGACY_SHADOW',index,began)
            if response.status_code==200:
                found=response.json()['result']['finding_ids'] if enabled else [item['finding_id'] for item in response.json()['findings']]
                assert len(found)==1
                with lock:ids.update(found)
            elif response.status_code not in (408,429,503):raise RuntimeError('unexpected detection status')
            time.sleep(.002)  # Identical bounded offered-load pacing in both variants.
    def queries():
        barrier.wait()
        # FTS begins immediately, overlapping ingestion instead of being hidden after it.
        specs=[('FTS','text CONTAINS "SYNTHETIC"'),('PROVIDER','event.provider = "Microsoft-Windows-Sysmon"'),
            ('BOOLEAN','event.severity >= 3 AND NOT event.provider = "absent-SYNTHETIC"'),('ANALYTICS','event.severity >= 0')]*3
        for index,(kind,query) in enumerate(specs):
            body={'query':query,'start_time':start,'end_time':end}
            if kind=='ANALYTICS':body.update(group_by=['event.provider','event.severity','event.source_type'],top_n=10,interval='day')
            else:body.update(limit=100,sort='newest')
            began=time.perf_counter();response=client.post('/api/v1/siem/search'+('/analytics' if kind=='ANALYTICS' else ''),json=body)
            row=observed(response,kind,index,began)
            with lock:search[kind].append(row['wall_ms']);search_codes[kind+':'+str(response.status_code)+':'+row['code']]+=1
            if response.status_code==200 and kind=='ANALYTICS':assert response.json()['matching_events']==sum(item['count'] for item in response.json()['time_series'])
            elif response.status_code not in (200,408,429,503):raise RuntimeError('unexpected query status')
    with ThreadPoolExecutor(max_workers=2) as executor:
        worker=executor.submit(shadow);reader=executor.submit(queries);barrier.wait()
        for index in range(20):
            raw=m30_synthetic.win(81_000_000+index,base+timedelta(seconds=40+index),'4688')
            began=time.perf_counter();response=client.post('/api/v1/events/ingest',headers={'X-API-Key':'SYNTHETIC-M31-BENCH'},json=raw)
            assert response.status_code==201,response.text
            write_times.append((time.perf_counter()-began)*1000)
            began=time.perf_counter();duplicate=client.post('/api/v1/events/ingest',headers={'X-API-Key':'SYNTHETIC-M31-BENCH'},json=raw)
            assert duplicate.status_code==200 and duplicate.json()['event']['event_id']==response.json()['event']['event_id']
            duplicate_times.append((time.perf_counter()-began)*1000)
            wal=path.with_name(path.name+'-wal');wal_peak=max(wal_peak,wal.stat().st_size if wal.exists() else 0)
        worker.result(timeout=30);reader.result(timeout=30)
    mixed_wall=time.perf_counter()-wall_started;mixed_cpu=time.process_time()-cpu_started
    stage_metrics={name:harness.stats(values) for name,values in profile.STAGES.items()};internal=dict(profile.ERRORS)
    detection=[row for row in outcomes if row['request_class'] in {'DURABLE','LEGACY_SHADOW'}]
    assert len(detection)==count and len(ids)==1
    recovery=client.post(endpoint,json={'simulation':simulation} if enabled else simulation)
    assert recovery.status_code==200
    slots=client.app.state.cqql_search_repository._slots
    acquired=[slots.acquire(blocking=False) for _ in range(4)];assert all(acquired)
    for _ in acquired:slots.release()
    sidecar=None
    if enabled:
        service=client.app.state.shadow_history_service
        finding=next(iter(ids));began=time.perf_counter();detail=client.get(PREFIX+'/findings/'+finding)
        lookup_ms=(time.perf_counter()-began)*1000
        assert detail.status_code==200 and all(value=='AVAILABLE' for value in detail.json()['current_evidence_availability'].values())
        assert len(detail.json()['history'])==1
        with closing(sqlite3.connect(service.store.path)) as c:
            sidecar={'quick_check':c.execute('PRAGMA quick_check').fetchone()[0],
                'foreign_keys':len(c.execute('PRAGMA foreign_key_check').fetchall()),'schema':c.execute('PRAGMA user_version').fetchone()[0],
                'findings':c.execute('SELECT COUNT(*) FROM shadow_findings').fetchone()[0],
                'revisions':c.execute('SELECT COUNT(*) FROM shadow_revisions').fetchone()[0],
                'runs':c.execute('SELECT COUNT(*) FROM shadow_runs').fetchone()[0],
                'db_bytes':service.store.path.stat().st_size,'detail_lookup_ms':lookup_ms,'resources':service.scheduler.snapshot()}
        assert sidecar['quick_check']=='ok' and sidecar['foreign_keys']==0 and sidecar['findings']==sidecar['revisions']==1
        assert sidecar['resources']['inflight']==sidecar['resources']['queue_depth']==0
    state=harness.integrity(path)
    assert state['schema']==17 and state['quick_check']=='ok' and state['foreign_keys']==state['identity_mismatches']==0
    assert state['count']==state['counter']==state['fts_count']<=100000
    assert state['protected_records']==8 and pinned_before==harness.protected_hash(path)
    return {'scope':'CONTROLLED_REAL_HTTP_MIXED_LOAD','writer':harness.stats(write_times),'duplicate_http':harness.stats(duplicate_times),
        'new_201':20,'duplicate_200':20,'search':{kind:harness.stats(values) for kind,values in search.items()},
        'query_statuses':dict(search_codes),'shadow':harness.stats([row['wall_ms'] for row in detection]),
        'shadow_statuses':dict(Counter(str(row['status']) for row in detection)),
        'shadow_reasons':dict(Counter(row['reason'] for row in detection)),'logical_outcomes':sorted(outcomes,key=lambda row:row['start_ms']),
        'stage_metrics':stage_metrics,'internal_errors':internal,'mixed_wall_seconds':mixed_wall,'mixed_cpu_seconds':mixed_cpu,
        'source_wal_observed_max_bytes':wal_peak,'recovery_http':recovery.status_code,'query_slots_recovered':True,
        'sidecar':sidecar,'integrity':state,'protected_bytes_preserved':True,'db_bytes':path.stat().st_size,**harness.process_memory()}


def main():
    original_create=harness.create_app
    def create(settings,**kwargs):
        settings=replace(settings,wazuh_ingest_api_key='SYNTHETIC-M31-BENCH')
        path=Path(settings.database_url.removeprefix('sqlite:///'))
        if 'with_shadow' in path.name:
            target=path.with_name(path.stem+'-history.db');initialize(target,path,disposable_only=True)
            kwargs['shadow_history']=ShadowHistoryRepository(target,path)
        return original_create(settings,**kwargs)
    harness.create_app=create;harness.measure_database=measure
    original_connect=sqlite3.connect
    def connect(*args,**kwargs):kwargs.setdefault('factory',profile.ProfileConnection);return original_connect(*args,**kwargs)
    sqlite3.connect=connect
    for owner,name,label in ((harness.EventRepository,'ingest','INGEST_REPOSITORY'),(ShadowHistoryRepository,'complete','FINDING_TRANSACTION'),
        (ShadowHistoryRepository,'seal','SNAPSHOT_TRANSACTION'),(IdentityResolver,'assess','IDENTITY_RESOLUTION')):profile.timed(owner,name,label)
    original_cpu=harness.cpu_probe;original_evaluate=harness.evaluate_records;original_record=harness._record
    resolver=IdentityResolver()
    def evaluated(rule,records):
        findings,diagnostics=original_evaluate(rule,records);by_id={row['id']:row for row in records}
        from app.schemas.shadow_history import IdentityPolicy
        for finding in findings:resolver.assess([by_id[item.event_id] for item in finding.evidence],rule,IdentityPolicy())
        return findings,diagnostics
    harness.evaluate_records=evaluated;harness._record=lambda row:original_record(row,include_raw=True)
    def cpu(count,base):
        profile.STAGES.clear();result=original_cpu(count,base)
        result['identity_resolution']=harness.stats(profile.STAGES.get('IDENTITY_RESOLUTION',[]));return result
    harness.cpu_probe=cpu
    output=Path(sys.argv[sys.argv.index('--output')+1])
    harness.main()
    report=json.loads(output.read_text());report['scope']='M31_PAIRED_LEGACY_VS_DURABLE_DISPOSABLE_HTTP'
    report['m31_source_sha256']={name:harness.file_sha(ROOT/name) for name in SOURCE_FILES}
    report['acceptance_predeclared']={'unexpected_503':0,'integrity_failures':0,'duplicate_findings':0,
        'writer_p95_ratio_max':1.25,'query_deadline_ms':1500,'schema_source':17,'live_authority':'NONE'}
    for row in report['populations']:
        row['variants']={'legacy_m30_mode':row['variants']['no_shadow'],'m31_durable':row['variants']['with_shadow']}
        before,after=row['variants']['legacy_m30_mode'],row['variants']['m31_durable']
        row['writer_p95_ratio']=after['writer']['p95_ms']/before['writer']['p95_ms']
        row['performance_gate']='PASS' if row['writer_p95_ratio']<=1.25 else 'PERFORMANCE_BLOCKED'
    output.write_text(json.dumps(report,indent=2)+'\n')


if __name__=='__main__':main()
