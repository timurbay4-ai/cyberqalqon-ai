"""Independent balanced M33 experiments. Only checksum-verified synthetic seeds.

E7 delegates to the unchanged M31 measure(), including barriers, pacing and counts.
Other E cells are explicitly diagnostics, never substitutes for E7 acceptance.
"""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, nullcontext
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import gc
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import sqlite3
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'backend'), str(ROOT/'scripts')]
import benchmark_m31_reliability as original
import m30_synthetic
import m29_synthetic
import m33_request_trace
from app.db.fts_rowid import install as install_rowid
from app.db.fts_rowid import verify as verify_rowid
from app.db.shadow_history import initialize, ShadowHistoryRepository
from app.services.request_tracing import TraceCollector, accounting

H = original.harness


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2)+'\n', encoding='utf-8')


class ObservedClient:
    def __init__(self, client):
        self.client, self.app = client, client.app
        self.rows, self.lock = [], threading.Lock()
        self._pending = []

    def post(self, url, **kwargs):
        body = kwargs.get('json', {})
        if url.endswith('/events/ingest'):
            kind = 'INGEST'
        elif 'shadow-v2' in url:
            kind = 'SHADOW'
        elif url.endswith('/analytics'):
            kind = 'ANALYTICS'
        elif url.endswith('/siem/search'):
            query = body.get('query', '')
            kind = 'FTS' if 'CONTAINS' in query else 'BOOLEAN' if 'NOT' in query else 'PROVIDER'
        else:
            kind = 'OTHER'
        start = time.perf_counter_ns()
        try:
            response = self.client.post(url, **kwargs)
        except Exception as exc:
            with self.lock:
                self.rows.append({'request_id':None,'kind':kind,'client_start_ns':start,
                                  'client_end_ns':time.perf_counter_ns(),'status':None,
                                  'code':'CLIENT_EXCEPTION','error_type':type(exc).__name__})
            raise
        end = time.perf_counter_ns()
        row = {'request_id': response.headers.get('x-perf-trace-id'), 'kind': kind,
               'client_start_ns': start, 'client_end_ns': end,
               'wall_ms': (end-start)/1e6, 'status': response.status_code,
               'acknowledgement':'NEW' if kind=='INGEST' and response.status_code==201 else 'DUPLICATE' if kind=='INGEST' and response.status_code==200 else None}
        correlation=response.headers.get('x-correlation-id','')
        if len(correlation)==32 and all(ch in '0123456789abcdef' for ch in correlation):
            row['shadow_correlation_id']=correlation
        with self.lock:
            self.rows.append(row)
            self._pending.append((row,body,response))
        return response

    def finalize(self):
        # Outside the measured workload: hashing/JSON parsing must not become
        # an artificial component of the original writer's client timer.
        for row,body,response in self._pending:
            try:detail=response.json().get('detail',{}) if response.status_code>=400 else {}
            except ValueError:detail={'code':'NON_JSON_RESPONSE'}
            if not isinstance(detail,dict):detail={'code':'UNSTRUCTURED_ERROR'}
            row.update(code=detail.get('code','OK'),reason=detail.get('reason_code',detail.get('code','OK')))
            if row['kind']=='INGEST':
                wire=json.dumps(body,separators=(',',':'),ensure_ascii=False).encode('utf-8')
                row.update(payload_bytes=len(wire),payload_sha256=hashlib.sha256(wire).hexdigest())
                normalized=H.normalize_wazuh_event(body,context=H.SourceContext(transport_authenticated=True))
                document=H.canonical_json(normalized.model_dump(mode='json')).encode('utf-8')
                row.update(normalized_bytes=len(document),normalized_sha256=hashlib.sha256(document).hexdigest())
        self._pending.clear()

    def get(self, *args, **kwargs):
        start=time.perf_counter_ns()
        response=self.client.get(*args,**kwargs)
        end=time.perf_counter_ns()
        row={'request_id':response.headers.get('x-perf-trace-id'),'kind':'DETAIL',
             'client_start_ns':start,'client_end_ns':end,'wall_ms':(end-start)/1e6,
             'status':response.status_code,'acknowledgement':None}
        with self.lock:
            self.rows.append(row);self._pending.append((row,{},response))
        return response


def diagnostic(experiment, path, base, enabled, repository, pinned, client):
    population = int(path.name.split('-')[0])
    shadow_on, read_kind = experiment == 'E5', {'E2': 'PROVIDER', 'E3': 'FTS', 'E4': 'ANALYTICS'}.get(experiment)
    rule = original.catalog()[0]
    simulation = {'rule': rule.model_dump(mode='json'), 'start_time': (base-timedelta(seconds=1)).isoformat(),
                  'end_time': (base+timedelta(seconds=31)).isoformat(), 'evaluation_time': datetime.now(timezone.utc).isoformat()}
    endpoint = original.PREFIX+('/runs' if enabled else '/simulate')
    if shadow_on:
        assert client.post(endpoint, json={'simulation': simulation} if enabled else simulation).status_code == 200
    writer, duplicate, codes, failures = [], [], Counter(), []
    tasks = int(shadow_on) + int(read_kind is not None)
    barrier = threading.Barrier(tasks+1)
    def shadow():
        barrier.wait()
        for i in range(original.COUNTS[population]):
            body = {**simulation, 'evaluation_time': (datetime.now(timezone.utc)+timedelta(seconds=1,microseconds=i)).isoformat()}
            r = client.post(endpoint, json={'simulation': body} if enabled else body)
            codes['SHADOW:'+str(r.status_code)] += 1
            assert r.status_code in (200,408,429,503)
            time.sleep(.002)
    def reader():
        barrier.wait()
        query = {'PROVIDER':'event.provider = "Microsoft-Windows-Sysmon"',
                 'FTS':'text CONTAINS "SYNTHETIC"', 'ANALYTICS':'event.severity >= 0'}[read_kind]
        for _ in range(12):
            body = {'query':query, 'start_time':(base-timedelta(days=3)).isoformat(), 'end_time':(base+timedelta(hours=1)).isoformat()}
            if read_kind == 'ANALYTICS': body.update(group_by=['event.provider','event.severity','event.source_type'],top_n=10,interval='day')
            else: body.update(limit=100,sort='newest')
            r=client.post('/api/v1/siem/search'+('/analytics' if read_kind=='ANALYTICS' else ''),json=body)
            codes[read_kind+':'+str(r.status_code)] += 1
            assert r.status_code in (200,408,429,503)
    # E8 preloads its complete duplicate set. At cap the original E7 timestamps
    # (seed MAX minus 20s) are legitimately evicted by subsequent inserts. Use
    # a newer diagnostic-only set so all 20 remain eligible for duplication.
    offset=120 if experiment=='E8' else 40
    samples=[m30_synthetic.win(81_000_000+i,base+timedelta(seconds=offset+i),'4688') for i in range(20)]
    if experiment=='E8':
        for raw in samples: assert client.post('/api/v1/events/ingest',headers={'X-API-Key':'SYNTHETIC-M31-BENCH'},json=raw).status_code==201
    begin, cpu, wal_peak = time.perf_counter(), time.process_time(), 0
    with ThreadPoolExecutor(max_workers=max(1,tasks)) as pool:
        futures=[]
        if shadow_on: futures.append(pool.submit(shadow))
        if read_kind: futures.append(pool.submit(reader))
        barrier.wait()
        for raw in samples:
            if experiment!='E8':
                start=time.perf_counter();r=client.post('/api/v1/events/ingest',headers={'X-API-Key':'SYNTHETIC-M31-BENCH'},json=raw)
                writer.append((time.perf_counter()-start)*1000);assert r.status_code==201
            start=time.perf_counter();r=client.post('/api/v1/events/ingest',headers={'X-API-Key':'SYNTHETIC-M31-BENCH'},json=raw)
            duplicate.append((time.perf_counter()-start)*1000);assert r.status_code==200
            wal=path.with_name(path.name+'-wal');wal_peak=max(wal_peak,wal.stat().st_size if wal.exists() else 0)
        for future in futures: future.result(timeout=30)
    state=H.integrity(path)
    assert state['schema']==17 and state['quick_check']=='ok' and state['foreign_keys']==state['identity_mismatches']==0
    assert state['count']==state['counter']==state['fts_count']<=100000
    assert state['protected_records']==8 and pinned==H.protected_hash(path)
    sidecar=None
    if enabled:
        service=client.app.state.shadow_history_service
        with closing(sqlite3.connect(service.store.path)) as c:
            sidecar={'quick_check':c.execute('PRAGMA quick_check').fetchone()[0],
                     'foreign_keys':len(c.execute('PRAGMA foreign_key_check').fetchall()),
                     'findings':c.execute('SELECT COUNT(*) FROM shadow_findings').fetchone()[0],
                     'revisions':c.execute('SELECT COUNT(*) FROM shadow_revisions').fetchone()[0]}
        assert sidecar['quick_check']=='ok' and sidecar['foreign_keys']==0
        if shadow_on: assert sidecar['findings']==sidecar['revisions']==1
        assert service.scheduler.snapshot()['inflight']==service.scheduler.snapshot()['queue_depth']==0
    slots=client.app.state.cqql_search_repository._slots
    acquired=[slots.acquire(blocking=False) for _ in range(4)];assert all(acquired)
    for _ in acquired:slots.release()
    return {'writer':H.stats(writer),'duplicate_http':H.stats(duplicate), 'integrity':state,'sidecar':sidecar,
            'query_slots_recovered':True,'statuses':dict(codes),'mixed_wall_seconds':time.perf_counter()-begin,
            'mixed_cpu_seconds':time.process_time()-cpu,'source_wal_observed_max_bytes':wal_peak,**H.process_memory()}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--sizes',nargs='+',type=int,choices=[10000,50000,100000],default=[10000,50000,100000])
    parser.add_argument('--experiments',nargs='+',choices=[f'E{i}' for i in range(1,9)],default=['E7'])
    parser.add_argument('--modes',nargs='+',choices=['legacy','durable'],default=['legacy','durable'])
    parser.add_argument('--order',choices=['A','B','AB','BA','ABBA','BAAB'],default='ABBA')
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--trace-off',action='store_true')
    parser.add_argument('--legacy-profiler',action='store_true')
    parser.add_argument('--connection-control',choices=['normal','held'],default='normal',
                        help='held is a diagnostic WAL-lifecycle intervention, never original acceptance')
    args=parser.parse_args()
    if args.legacy_profiler and not args.trace_off:parser.error('Legacy profiler control requires --trace-off')
    if args.output.exists():parser.error('New evidence path required')
    report={'scope':'SYNTHETIC_DISPOSABLE_ONLY','transport':'FASTAPI_TESTCLIENT_IN_PROCESS_ASGI_HTTPX_NO_SOCKET',
            'started_at':datetime.now(timezone.utc).isoformat(),'order':args.order,'runs':[],
            'python':sys.version,'sqlite':sqlite3.sqlite_version,'platform':platform.platform(),'owned_process_id':os.getpid(),
            'cpu_count':os.cpu_count(),'free_bytes':shutil.disk_usage(ROOT).free,
            'flags':{'AI_ENABLED':False,'batch':False,'single_event_writers':1,'retention_records':100000,'retention_days':30,'CQQL_ms':1500,'CQQL_slots':4,
                     'source_schema':17,'sidecar_schema':1,'detections':'SHADOW_ONLY',
                     'auth':'NORMAL_COOKIE_ORIGIN_CSRF_ANALYST_AND_MACHINE_KEY_INGEST'},
            'tracing':not args.trace_off, 'source_hashes':{}, 'seeds':{}, 'production':'NOT_DEPLOYED'}
    report['connection_control']=args.connection_control
    report['legacy_profiler']=args.legacy_profiler
    for folder in ('backend/app','scripts'):
        for p in sorted((ROOT/folder).rglob('*.py')):
            report['source_hashes'][p.relative_to(ROOT).as_posix()]=H.file_sha(p)
    with closing(sqlite3.connect(':memory:')) as c:
        report['sqlite_source_id']=c.execute('SELECT sqlite_source_id()').fetchone()[0]
        report['sqlite_compile_options']=[r[0] for r in c.execute('PRAGMA compile_options')]
    original_create, original_measure = H.create_app, H.measure_database
    context={}
    def create(settings,**kwargs):
        settings=replace(settings,wazuh_ingest_api_key='SYNTHETIC-M31-BENCH')
        path=Path(settings.database_url.removeprefix('sqlite:///'))
        if context['candidate']:
            install_rowid(path,path.with_name(path.stem+'-rowid-backup.db'),disposable_only=True)
            kwargs['disposable_fts_rowid']=True
        if 'with_shadow' in path.name:
            target=path.with_name(path.stem+'-history.db');initialize(target,path,disposable_only=True)
            kwargs['shadow_history']=ShadowHistoryRepository(target,path)
        if not args.trace_off:kwargs['disposable_request_traces']=context['collector']
        return original_create(settings,**kwargs)
    def measure(path,base,enabled,repository,pinned,client):
        # Login is an unmeasured precondition, not an unpaired benchmark request.
        context['collector'].clear_completed()
        with closing(sqlite3.connect(path)) as c:
            context['prestate']={key:c.execute('PRAGMA '+key).fetchone()[0] for key in ('journal_mode','synchronous','busy_timeout','wal_autocheckpoint','user_version','cache_size','page_size','locking_mode','mmap_size','schema_version')}
            context['prestate']['actual_fts_strategy']=client.app.state.cqql_search_repository.fts_strategy
            context['prestate']['events']=c.execute('SELECT COUNT(*) FROM security_events').fetchone()[0]
            context['prestate']['last_retention_at']=c.execute('SELECT last_retention_at FROM security_event_store_state').fetchone()[0]
            context['prestate']['fts_triggers']=[r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='trigger' AND name LIKE '%fts%' ORDER BY name")]
        observed=ObservedClient(client)
        with closing(sqlite3.connect(path)) if args.connection_control=='held' else nullcontext() as keeper:
            if keeper is not None:
                keeper.execute('SELECT event_id FROM security_events LIMIT 1').fetchall()
            try:
                result=original.measure(path,base,enabled,repository,pinned,observed) if context['experiment']=='E7' else diagnostic(context['experiment'],path,base,enabled,repository,pinned,observed)
            finally:
                context['samples']=observed.rows
                observed.finalize()
        context['samples']=observed.rows
        for sample in observed.rows: sample['phase']='MEASURED'
        for sample in observed.rows:
            if sample['kind']=='DETAIL':sample['phase']='VALIDATION'
        shadows=[s for s in observed.rows if s['kind']=='SHADOW']
        if shadows:
            shadows[0]['phase']='WARMUP'
            if context['experiment']=='E7':shadows[-1]['phase']='RECOVERY'
        if context['experiment']=='E8':
            for sample in observed.rows:
                if sample['kind']=='INGEST' and sample['status']==201:sample['phase']='SETUP'
        return result
    H.create_app,H.measure_database=create,measure
    try:
        with tempfile.TemporaryDirectory(prefix='cyberqalqon-m33p0-',ignore_cleanup_errors=True) as temporary:
            tmp=Path(temporary)
            for size in args.sizes:
                source=ROOT/('artifacts/runtime/m29-seed.db' if size==100000 else f'artifacts/runtime/m29-seed-{size}.db')
                manifest=json.loads(source.with_name(source.stem+'-manifest.json').read_text(encoding='utf-8'))
                assert manifest['scope']=='SYNTHETIC_DISPOSABLE_ONLY' and H.file_sha(source)==manifest['sha256']
                report['seeds'][str(size)]={'sha256':manifest['sha256'],'bytes':source.stat().st_size}
                seed=tmp/f'seed-{size}.db'
                with closing(sqlite3.connect(source.as_uri()+'?mode=ro',uri=True)) as src,closing(sqlite3.connect(seed)) as target:
                    src.backup(target)
                    base=datetime.fromisoformat(target.execute('SELECT MAX(occurred_at) FROM security_events').fetchone()[0])
                    m29_synthetic.decorate(target,H.EventRepository(seed,retention_days=30,max_records=100000),base)
                for experiment in args.experiments:
                    if experiment=='E6' and size!=100000:continue
                    for mode in args.modes:
                        for sequence,variant in enumerate(args.order):
                            run_id=f'{args.output.stem}-{size}-{experiment}-{mode}-{sequence}-{variant}'
                            context.update(candidate=variant=='B',collector=TraceCollector(),experiment=experiment)
                            suffix='with_shadow' if mode=='durable' else 'no_shadow'
                            path=tmp/f'{size}-{run_id}-{suffix}.db'
                            started=time.perf_counter()
                            context['samples']=[]
                            process_diagnostic=None
                            try:
                                instrumentation=(m33_request_trace.installed() if not args.trace_off else
                                                 m33_request_trace.legacy_profile_installed() if args.legacy_profiler else nullcontext())
                                with instrumentation as process_diagnostic:
                                    result=H.database_probe(seed,path,base-timedelta(minutes=1),mode=='durable')
                            except BaseException as exc:
                                failure=args.output.with_name(run_id+'-FAILED.json')
                                write(failure,{'run_id':run_id,'error_type':type(exc).__name__,
                                               'status':'FAILED','samples':context['samples'],
                                               'traces':context['collector'].export(),'process_diagnostic':process_diagnostic,
                                               'prestate':context.get('prestate')})
                                report['failed_run']={'run_id':run_id,'failure_path':failure.name,'error_type':type(exc).__name__}
                                write(args.output,report)
                                raise
                            if context['candidate']:
                                with closing(sqlite3.connect(path)) as c:
                                    verify_rowid(c,integrity=True)
                                result['candidate_fts_integrity']='PASS_EXTERNAL_CONTENT_RANK1'
                            traces=context['collector'].export()
                            if traces['dropped'] or any(r['incomplete'] for r in traces['requests']):
                                write(args.output.with_name(run_id+'-TRACE_INCOMPLETE.json'),traces)
                                raise RuntimeError('TRACE_BUDGET_EXHAUSTED')
                            index={row['request_id']:row for row in traces['requests']}
                            if not args.trace_off and set(index)!={s['request_id'] for s in context['samples']}:
                                raise RuntimeError('UNPAIRED_REQUEST_TRACE')
                            for sample in context['samples']:
                                if sample['request_id'] in index:
                                    sample['accounting']=accounting(index[sample['request_id']],sample['client_start_ns'],sample['client_end_ns'])
                            tracefile=args.output.with_name(run_id+'-requests.json')
                            write(tracefile,{'run_id':run_id,'samples':context['samples'],'traces':traces,
                                             'process_diagnostic':process_diagnostic})
                            row={'run_id':run_id,'size':size,'experiment':experiment,'mode':mode,'variant':variant,'sequence':sequence,
                                 'wall_seconds':time.perf_counter()-started,'prestate':context['prestate'],'result':result,
                                 'requests_path':tracefile.name,'requests_sha256':H.file_sha(tracefile),
                                 'requests_bytes':tracefile.stat().st_size,'post_trace_export_memory':H.process_memory()}
                            report['runs'].append(row);write(args.output,report)
                            print(json.dumps({'run':run_id,'p95':result['writer'].get('p95_ms'),'duplicate_p95':result['duplicate_http'].get('p95_ms'),'seconds':row['wall_seconds']}),flush=True)
                            gc.collect()
                            # Only this invocation's self-created run files. Preserve
                            # raw JSON, immutable seeds and all unrelated artifacts.
                            cleanup=[]
                            for owned in tmp.iterdir():
                                if owned.name.startswith(path.stem) and owned.is_file():
                                    try: owned.unlink()
                                    except PermissionError: cleanup.append(owned.name)
                            row['temporary_files_locked_until_process_exit']=cleanup
                            write(args.output,report)
    finally:
        H.create_app,H.measure_database=original_create,original_measure
    report['ended_at']=datetime.now(timezone.utc).isoformat();write(args.output,report)


if __name__=='__main__':
    try:main()
    except Exception as exc:
        # Do not leak exception text (which may contain SQL/response envelopes).
        print(json.dumps({'status':'FAILED','error_type':type(exc).__name__}),flush=True)
        raise SystemExit(1) from None
