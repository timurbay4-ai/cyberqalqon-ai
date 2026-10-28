"""Bounded M30 CPU and SQLite experiments; ONLY synthetic fixed-path seeds/temp DBs."""
import argparse
import copy
import gc
import json
import secrets
import sqlite3
import sys
import tempfile
import threading
import time
import uuid
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import datetime,timedelta,timezone
from pathlib import Path
from fastapi.testclient import TestClient

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'backend'),str(ROOT/'scripts')]
from benchmark_m29_performance import file_sha,stats,integrity,protected_hash
from benchmark_cqql import process_memory
import m28_synthetic,m29_synthetic,m30_synthetic
from app.db.events import EventRepository
from app.services.event_normalizer import normalize_wazuh_event
from app.services.source_adapters import SourceContext
from app.services.shadow_detection import _record,evaluate_records,_graph,ShadowResourceLimitError,ShadowEventError
from app.services.shadow_rules import catalog
from app.schemas.shadow_detection import ShadowSimulationRequest,ShadowSimulationResult
from app.schemas.auth import AnalystCreate,AnalystRole
from app.core.config import Settings
from app.main import create_app
from app.services.cqql import compile_cqql
from app.services.wazuh_normalizer import canonical_json
from app.db.fts_locator_proposal import install
from app.db.analytics_index_proposal import install as install_cover


def row_for(event,index,base):
    row=event.model_dump(mode='json')
    row.update(occurred_at=event.timestamp.isoformat(),ingested_at=(base+timedelta(hours=3,microseconds=index)).isoformat(),
        raw_event_json=canonical_json(event.raw_payload),structured_json=canonical_json(event.structured_payload),
        mitre_ids_json=canonical_json(event.mitre.ids))
    return row


def cpu_probe(count,base):
    templates=[raw for _,raw,_ in m28_synthetic.cases(base)]
    rules=catalog(); batches=[]; generation=[]; evaluation=[]; graph=[]; diagnostics=Counter(); findings=0; valid=0; limits=0
    per_rule={rule.rule_id:{'evaluation':[],'graph':[],'findings':0,'rejections':0} for rule in rules}
    cpu_start,wall_start=time.process_time(),time.perf_counter()
    batch=[]
    for index in range(count):
        began=time.perf_counter()
        raw=copy.deepcopy(templates[index%len(templates)])
        stamp=base+timedelta(seconds=(index//len(templates))*2,microseconds=(index%len(templates))*10000)
        raw['id']=f'SYNTHETIC-M30-CAPACITY-{index}'
        raw['timestamp']=stamp.isoformat()
        win=raw.get('data',{}).get('win')
        journal=raw.get('data',{}).get('journald')
        if win:
            win['system']['systemTime']=stamp.isoformat();win['system']['eventRecordID']=str(index)
            win['eventdata']['processGuid']=str(uuid.uuid5(uuid.NAMESPACE_URL,'SYNTHETIC-M30-PROCESS-'+str(index//len(templates))))
        elif journal:
            journal['__REALTIME_TIMESTAMP']=str(int(stamp.timestamp()*1_000_000))
            journal['__CURSOR']=f'SYNTHETIC-CURSOR-{index}'
        else:
            program=raw.get('predecoder',{}).get('program_name',raw.get('decoder',{}).get('name','synthetic'))
            raw['full_log']=f'<34>1 {stamp.isoformat()} SYNTHETIC-M30-LINUX {program} {index} - - '+str(raw.get('full_log',''))
        event=normalize_wazuh_event(raw,context=SourceContext(transport_authenticated=True))
        try: batch.append(_record(row_for(event,index,base)));valid+=1
        except ShadowEventError as exc: diagnostics[str(exc)]+=1
        except (ValueError,TypeError,KeyError): diagnostics['INVALID_EVENT']+=1
        generation.append((time.perf_counter()-began)*1000)
        if len(batch)>=1000 or index==count-1:
            batches.append(len(batch))
            for rule in rules:
                began=time.perf_counter()
                try:
                    candidates,counts=evaluate_records(rule,batch)
                    evaluation.append((time.perf_counter()-began)*1000)
                    per_rule[rule.rule_id]['evaluation'].append(evaluation[-1])
                    diagnostics.update(counts);findings+=len(candidates)
                    began=time.perf_counter();_graph(candidates);graph.append((time.perf_counter()-began)*1000)
                    per_rule[rule.rule_id]['graph'].append(graph[-1]);per_rule[rule.rule_id]['findings']+=len(candidates)
                except ShadowResourceLimitError:
                    limits+=1;evaluation.append((time.perf_counter()-began)*1000)
                    per_rule[rule.rule_id]['rejections']+=1
            batch=[]
    elapsed=time.perf_counter()-wall_start
    return {'generated_events':count,'validated_records':valid,'independent_chunk_sizes':batches,
        'normalization_and_record_validation':stats(generation),'rule_per_chunk':stats(evaluation),'graph':stats(graph),
        'candidate_findings':findings,'candidate_findings_per_evaluation_second':findings/(sum(evaluation)/1000) if sum(evaluation) else 0,
        'per_rule':{name:{'evaluation':stats(row['evaluation']),'graph':stats(row['graph']),
                    'findings':row['findings'],'rejections':row['rejections']} for name,row in per_rule.items()},
        'diagnostics_per_rule_attempt':dict(diagnostics),'resource_limits':limits,'wall_seconds':round(elapsed,3),
        'cpu_seconds':round(time.process_time()-cpu_start,3),**process_memory(),
        'scope':'INDEPENDENT_MAX_1000_RECORD_CHUNKS; NO_CROSS_CHUNK_CONTINUITY_OR_DURABLE_STREAM_CLAIM'}


def database_probe(seed,path,base,with_shadow):
    with closing(sqlite3.connect(seed)) as source,closing(sqlite3.connect(path)) as destination:source.backup(destination)
    with closing(sqlite3.connect(path)) as connection:
        install(connection,disposable_only=True);install_cover(connection,disposable_only=True)
    repository=EventRepository(path,retention_days=30,max_records=100000)
    for raw in m30_synthetic.auth(base,offset=80_000_000):
        event=normalize_wazuh_event(raw,context=SourceContext(transport_authenticated=True))
        stored=repository.ingest(event)
        with closing(sqlite3.connect(path)) as connection:
            connection.execute('PRAGMA foreign_keys=ON')
            connection.execute('INSERT INTO case_events(case_id,event_id,linked_at,linked_by_display) VALUES(?,?,?,?)',
                ('SYNTHETIC-M29-PROTECTED-CASE',stored.event.event_id,datetime.now(timezone.utc).isoformat(),'SYNTHETIC M30 fixture'))
            connection.commit()
    pinned_before=protected_hash(path)
    settings=Settings(database_url=f'sqlite:///{path.as_posix()}',allow_m14_schema_migration=False,
        correlation_enabled=False,ai_enabled=False,event_batch_ingest_enabled=False)
    with TestClient(create_app(settings,disposable_detection_simulation=True)) as client:
        password=secrets.token_urlsafe(32)
        client.app.state.auth_repository.bootstrap_first_admin(AnalystCreate(username='m30-capacity',
            display_name='SYNTHETIC capacity',password=password,role=AnalystRole.ADMIN))
        login=client.post('/api/v1/auth/login',headers={'Origin':'http://localhost:5173'},
            json={'username':'m30-capacity','password':password})
        assert login.status_code==200
        client.headers.update({'Origin':'http://localhost:5173','X-CSRF-Token':login.json()['csrf_token']})
        return measure_database(path,base,with_shadow,repository,pinned_before,client)


def measure_database(path,base,with_shadow,repository,pinned_before,client):
    query=compile_cqql('event.provider = "Microsoft-Windows-Sysmon"')
    repo=client.app.state.cqql_search_repository;engine=client.app.state.advanced_detection_engine
    rule=catalog()[0]
    payload=ShadowSimulationRequest(rule=rule,start_time=base-timedelta(seconds=1),end_time=base+timedelta(seconds=31),
        evaluation_time=datetime.now(timezone.utc)+timedelta(minutes=1))
    # Equal bounded warmup for both variants; no warmup write/ACK counted as measured.
    warmup={}
    for name,operation in (
        ('shadow',lambda:engine.simulate_contract(payload,repo)),
        ('provider',lambda:repo.search(query,start_time=base-timedelta(days=3),end_time=base+timedelta(hours=1),sort='newest',limit=100,cursor=None))):
        try:
            result=operation()
            if name=='shadow': assert len(result.findings)==1
            warmup[name]='COMPLETE'
        except Exception as exc:
            if type(exc).__name__ not in {'CQQLQueryTimeoutError','CQQLQueryBusyError'}:raise
            warmup[name]=type(exc).__name__
    stop=threading.Event();barrier=threading.Barrier(2) if with_shadow else None
    simulation_times=[];simulation_errors=Counter();http_statuses=Counter();finding_ids=set()
    def shadow():
        barrier.wait()
        end=time.perf_counter()+20
        for _ in range(512):
            if stop.is_set() or time.perf_counter()>=end:break
            began=time.perf_counter()
            try:
                response=client.post('/api/v1/detection-engineering/shadow-v2/simulate',json=payload.model_dump(mode='json'))
                http_statuses[str(response.status_code)]+=1
                if response.status_code==200:
                    result=ShadowSimulationResult.model_validate(response.json())
                    assert len(result.findings)==1
                    finding_ids.add(result.findings[0].finding_id)
                elif response.status_code in {408,429,503}:
                    simulation_errors['HTTP_'+str(response.status_code)]+=1
                else: raise RuntimeError('unexpected shadow HTTP status')
            except Exception as exc:
                if type(exc).__name__ not in {'CQQLQueryTimeoutError','CQQLQueryBusyError','ShadowResourceLimitError'}:raise
                simulation_errors[type(exc).__name__]+=1
            simulation_times.append((time.perf_counter()-began)*1000)
            stop.wait(.002)
    writer_times=[];search_times=[];search_errors=Counter();wal_peak=0
    cpu_start=time.process_time()
    with ThreadPoolExecutor(max_workers=1) as executor:
        worker=executor.submit(shadow) if with_shadow else None
        if barrier:barrier.wait()
        try:
            for index in range(20):
                event=normalize_wazuh_event(m30_synthetic.win(81_000_000+index,base+timedelta(seconds=40+index),'4688'),
                    context=SourceContext(transport_authenticated=True))
                began=time.perf_counter();assert not repository.ingest(event).duplicate
                writer_times.append((time.perf_counter()-began)*1000)
                assert repository.ingest(event).duplicate
                began=time.perf_counter()
                try:repo.search(query,start_time=base-timedelta(days=3),end_time=base+timedelta(hours=1),sort='newest',limit=100,cursor=None)
                except Exception as exc:
                    if type(exc).__name__ not in {'CQQLQueryTimeoutError','CQQLQueryBusyError'}:raise
                    search_errors[type(exc).__name__]+=1
                search_times.append((time.perf_counter()-began)*1000)
                wal=path.with_name(path.name+'-wal');wal_peak=max(wal_peak,wal.stat().st_size if wal.exists() else 0)
            began=time.perf_counter()
            try:
                result=repo.analytics(compile_cqql('event.severity >= 0'),start_time=base-timedelta(days=3),
                    end_time=base+timedelta(hours=1),group_by=['event.provider','event.severity','event.source_type'],top_n=10,interval='day')
                analytics={'status':'COMPLETE','matching_events':result.matching_events,'bucket_sum':sum(row.count for row in result.time_series)}
                assert analytics['matching_events']==analytics['bucket_sum']
            except Exception as exc:
                if type(exc).__name__ not in {'CQQLQueryTimeoutError','CQQLQueryBusyError'}:raise
                analytics={'status':type(exc).__name__}
            analytics['wall_ms']=round((time.perf_counter()-began)*1000,3)
        finally:
            stop.set()
            if worker:worker.result(timeout=5)
    acquired=[repo._slots.acquire(blocking=False) for _ in range(4)]
    assert all(acquired)
    for _ in acquired:repo._slots.release()
    state=integrity(path)
    assert state['quick_check']=='ok' and state['foreign_keys']==state['identity_mismatches']==0
    assert state['count']==state['counter']==state['fts_count']<=100000
    assert state['protected_records']==8 and pinned_before==protected_hash(path)
    assert len(finding_ids)<=1
    return {'writer':stats(writer_times),'provider':stats(search_times),'provider_errors':dict(search_errors),'analytics':analytics,
        'shadow':stats(simulation_times),'shadow_errors':dict(simulation_errors),'shadow_http_statuses':dict(http_statuses),
        'unique_finding_ids':len(finding_ids),'warmup':warmup,
        'new_repository_inserts':20,'repository_duplicate_acknowledgements':20,
        'measurement_scope':'REAL_AUTHENTICATED_SHADOW_HTTP_WITH_AUDIT; WRITER_AND_SEARCH_REPOSITORY_LATENCY',
        'query_slots_recovered':True,'wal_observed_max_bytes':wal_peak,'cpu_seconds':round(time.process_time()-cpu_start,3),
        'integrity':state,'protected_bytes_preserved':True,'db_bytes':path.stat().st_size,**process_memory()}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--sizes',nargs='+',type=int,default=[10000,50000,100000])
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if any(size not in {10000,50000,100000} for size in args.sizes):parser.error('only bounded synthetic sizes supported')
    report={'scope':'SYNTHETIC_DISPOSABLE_ONLY','production':'NOT_DEPLOYED','populations':[],
        'storage':'M29_PROPOSALS_EXPLICITLY_INSTALLED_ONLY_IN_TEMP_COPIES',
        'source_sha256':{name:file_sha(ROOT/name) for name in ('backend/app/services/shadow_detection.py',
            'backend/app/services/shadow_rules.py','backend/app/schemas/shadow_detection.py','scripts/benchmark_m30_detection.py')}}
    # Preserve the PRIMARY failure rather than masking it with Windows cleanup
    # errors from an unchanged legacy repository's GC-held SQLite connection.
    with tempfile.TemporaryDirectory(prefix='cyberqalqon-m30-bench-',ignore_cleanup_errors=True) as temporary:
        for size in args.sizes:
            source=ROOT/('artifacts/runtime/m29-seed.db' if size==100000 else f'artifacts/runtime/m29-seed-{size}.db')
            manifest=json.loads(source.with_name(source.stem+'-manifest.json').read_text())
            if manifest['scope']!='SYNTHETIC_DISPOSABLE_ONLY' or file_sha(source)!=manifest['sha256']:raise RuntimeError('synthetic seed mismatch')
            seed=Path(temporary)/f'seed-{size}.db'
            with closing(sqlite3.connect(source.as_uri()+'?mode=ro',uri=True)) as original,closing(sqlite3.connect(seed)) as target:
                original.backup(target)
                base=datetime.fromisoformat(target.execute('SELECT MAX(occurred_at) FROM security_events').fetchone()[0])
                m29_synthetic.decorate(target,EventRepository(seed,retention_days=30,max_records=100000),base)
            row={'size':size,'variants':{}};report['populations'].append(row)
            for enabled in (False,True):
                name='with_shadow' if enabled else 'no_shadow'
                row['variants'][name]=database_probe(seed,Path(temporary)/f'{size}-{name}.db',base-timedelta(minutes=1),enabled)
                print(f'M30 database size={size} variant={name}',flush=True)
                args.output.write_text(json.dumps(report,indent=2)+'\n')
                gc.collect()
            assert len({value['integrity']['evidence_sha256'] for value in row['variants'].values()})==1
            row['cpu']=cpu_probe(size,datetime.now(timezone.utc)-timedelta(hours=3))
            args.output.write_text(json.dumps(report,indent=2)+'\n')
            print(f'M30 CPU size={size}',flush=True)
    report['integrity']='PASS'
    args.output.write_text(json.dumps(report,indent=2)+'\n')


if __name__=='__main__':main()
