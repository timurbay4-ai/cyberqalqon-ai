"""Overlap-aware per-request waterfalls; no global maxima used as attribution."""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import statistics
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'backend'),str(ROOT/'scripts')]
from app.services.request_tracing import union_ns


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def describe(run,path):
    data=json.loads(path.read_text(encoding='utf-8'))
    traces={r['request_id']:r for r in data['traces']['requests']}
    gc_observable='gc_events' in (data.get('process_diagnostic') or {})
    gc_events=(data.get('process_diagnostic') or {}).get('gc_events',[])
    samples=data['samples'];writer=[];retained=run['prestate']['events']
    for sample in sorted(samples,key=lambda s:s['client_start_ns']):
        if sample['kind']!='INGEST':continue
        trace=traces.get(sample['request_id'])
        if trace is None:continue
        stages=defaultdict(float);exclusive=defaultdict(float)
        spans=trace['spans']
        for s in spans:
            if s['end_ns'] is None:continue
            elapsed=s['end_ns']-s['start_ns'];stages[s['stage']]+=elapsed/1e6
            children=[(max(s['start_ns'],c['start_ns']),min(s['end_ns'],c['end_ns'])) for c in spans
                      if c['parent']==s['id'] and c['end_ns'] is not None
                      and c['start_ns']<=s['end_ns'] and c['end_ns']>=s['start_ns']]
            exclusive[s['stage']]+=(elapsed-union_ns(children))/1e6
        account=sample['accounting']
        assert sum(account[k] for k in ('measured_union_ns','server_unattributed_ns','transport_or_client_ns'))==account['http_total_ns']
        result={'request_id':sample['request_id'],'status':sample['status'],'http_ms':sample['wall_ms'],
                'database_rows_before_derived_single_writer':retained,'incomplete':trace['incomplete'],
                'phase':sample.get('phase','SETUP' if run['experiment']=='E8' and sample['status']==201 else 'MEASURED'),
                'stage_inclusive_ms':dict(stages),'stage_exclusive_ms':dict(exclusive),'accounting_ns':account,
                'commit_observed':any(s['stage']=='SQLITE_EXPLICIT_COMMIT' and not s['failed'] for s in spans),
                'retention_evaluated':'RETENTION' in stages,'retention_delete_observed':'RETENTION_DELETE_INCLUDING_FTS' in stages,
                'sqlite_begin_ms_is_lock_wait_upper_bound':True,'fts_native_component_ms':None,
                'fts_note':'INSERT_INCLUDING_FTS includes all row/index/trigger work; native FTS alone is unobservable',
                'gc_invoked_by_request_ms':sum((g['end_ns']-g['start_ns'])/1e6 for g in gc_events if g['invoking_request_id']==sample['request_id']),
                'gc_overlap_upper_bound_ms':union_ns([(max(sample['client_start_ns'],g['start_ns']),min(sample['client_end_ns'],g['end_ns']))
                    for g in gc_events if g['start_ns']<=sample['client_end_ns'] and g['end_ns']>=sample['client_start_ns']])/1e6,
                'waterfall':[{'stage':s['stage'],'parent':s['parent'],'offset_ms':(s['start_ns']-trace['start_ns'])/1e6,
                              'duration_ms':(s['end_ns']-s['start_ns'])/1e6,'failed':s['failed'],
                              'thread_cpu_ms':s.get('thread_cpu_ns',0)/1e6 if 'thread_cpu_ns' in s else None,
                              'resource':s.get('resource'),'connection_id':s.get('connection_id')}
                             for s in spans if s['end_ns'] is not None]}
        writer.append(result)
        if sample['status']==201:retained=min(100000,retained+1)
    measured=[s for s in writer if s['phase']=='MEASURED']
    new=[s for s in measured if s['status']==201];dup=[s for s in measured if s['status']==200]
    slow=sorted(new,key=lambda s:s['http_ms'],reverse=True)[:max(1,len(new)//5)]
    fast=sorted(new,key=lambda s:s['http_ms'])[:max(1,len(new)//5)]
    def med(rows,key):return statistics.median([r['stage_inclusive_ms'].get(key,0) for r in rows]) if rows else None
    seen={s['connection_id'] for t in traces.values() for s in t['spans'] if s.get('resource')=='SOURCE'}
    closed={s['connection_id'] for t in traces.values() for s in t['spans'] if s.get('resource')=='SOURCE' and s['stage']=='SQLITE_CLOSE_CHECKPOINT_INCLUSIVE' and not s['failed']}
    return {'run_id':run['run_id'],'size':run['size'],'mode':run['mode'],'variant':run['variant'],
            'experiment':run['experiment'],'new':len(new),'duplicate':len(dup),
            'trace_requests':len(traces),'trace_dropped':data['traces']['dropped'],
            'incomplete_requests':sum(r['incomplete'] for r in traces.values()),
            'source_connections_seen':len(seen) if seen else None,'source_connections_explicitly_closed':len(closed) if seen else None,
            'source_connections_without_explicit_close_observed':len(seen-closed) if seen else None,
            'gc_events':len(gc_events) if gc_observable else None,'gc_max_ms':max(((g['end_ns']-g['start_ns'])/1e6 for g in gc_events),default=None),
            'statuses_all_samples':dict(Counter(str(s['status']) for s in samples)),
            'http_errors':[{'kind':s['kind'],'status':s['status'],'code':s['code'],'reason':s['reason'],'wall_ms':s['wall_ms']} for s in samples if s['status']>=400],
            'slowest_20_percent_new':slow,'fastest_20_percent_new':fast,
            'slowest_20_percent_duplicate':sorted(dup,key=lambda s:s['http_ms'],reverse=True)[:max(1,len(dup)//5)],
            'same_run_medians':{key:{'slow_ms':med(slow,key),'fast_ms':med(fast,key)} for key in
                               ('DEPENDENCY_WORKER_QUEUE','INGEST_WORKER_QUEUE','INGEST_REPOSITORY',
                                'SQLITE_BEGIN_LOCK_INCLUSIVE','IDEMPOTENCY_LOOKUP','INSERT_INCLUDING_FTS',
                                'SQLITE_EXPLICIT_COMMIT','SQLITE_CLOSE_CHECKPOINT_INCLUSIVE','RETENTION')},
            'requests_sha256':sha(path)}


def main():
    parser=argparse.ArgumentParser();parser.add_argument('inputs',nargs='+',type=Path);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    report={'scope':'DISPOSABLE_REQUEST_ATTRIBUTION','threshold':1.25,'runs':[],'pairs':[],
            'uncertainty':'Only 2 runs/variant in ABBA cells; no environment-level confidence interval claimed',
            'causal_warning':'BEGIN includes schema/cache/scheduling as well as potential lock wait; COMMIT is not an fsync syscall measurement.'}
    for path in args.inputs:
        data=json.loads(path.read_text(encoding='utf-8'));groups=defaultdict(list)
        for run in data['runs']:
            report['runs'].append(describe(run,path.with_name(run['requests_path'])))
            groups[(run['size'],run['experiment'],run['mode'],run['sequence']//2)].append(run)
        for (size,experiment,mode,pair),runs in groups.items():
            before=next((r for r in runs if r['variant']=='A'),None);after=next((r for r in runs if r['variant']=='B'),None)
            if before is None or after is None:continue
            metric='duplicate_http' if experiment=='E8' else 'writer'
            a,b=before['result'][metric]['p95_ms'],after['result'][metric]['p95_ms']
            report['pairs'].append({'input':path.name,'size':size,'experiment':experiment,'mode':mode,'pair':pair,
                                    'a_p95_ms':a,'b_p95_ms':b,'ratio':b/a,
                                    'scope':'ORIGINAL_E7_ACCEPTANCE' if experiment=='E7' and data.get('connection_control','normal')=='normal' else 'DIAGNOSTIC_ONLY',
                                    'gate':'PASS' if b/a<=1.25 else 'PERFORMANCE_BLOCKED'})
    report['gate']='PERFORMANCE_BLOCKED' if any(p['gate']!='PASS' for p in report['pairs'] if p['scope']=='ORIGINAL_E7_ACCEPTANCE') else 'PARTIAL'
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    md=['# M33 P0 request-correlated waterfalls','',
        'Raw JSON retains every individual client sample and full monotonic spans. Tables show the slowest 20% of new writes, plus same-run fast controls in JSON. Inclusive columns overlap; never sum them. BEGIN is a lock-wait upper bound; FTS is included in INSERT, not separately measured.','',
        '| Run | Request | HTTP ms | Dependency queue | Ingest queue | BEGIN inclusive | Insert+FTS | Commit | Close inclusive | Server unattributed | Client/transport |',
        '|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|']
    for run in report['runs']:
        for r in run['slowest_20_percent_new']:
            s=r['stage_inclusive_ms'];a=r['accounting_ns']
            numbers=[r['http_ms'],s.get('DEPENDENCY_WORKER_QUEUE',0),s.get('INGEST_WORKER_QUEUE',0),s.get('SQLITE_BEGIN_LOCK_INCLUSIVE',0),s.get('INSERT_INCLUDING_FTS',0),s.get('SQLITE_EXPLICIT_COMMIT',0),s.get('SQLITE_CLOSE_CHECKPOINT_INCLUSIVE',0),a['server_unattributed_ns']/1e6,a['transport_or_client_ns']/1e6]
            md.append('| '+run['run_id']+' | '+r['request_id']+' | '+' | '.join(f'{n:.3f}' for n in numbers)+' |')
    args.output.with_suffix('.md').write_text('\n'.join(md)+'\n',encoding='utf-8')
    print(json.dumps({'runs':len(report['runs']),'pairs':len(report['pairs']),'gate':report['gate'],'errors':sum(len(r['http_errors']) for r in report['runs'])}))


if __name__=='__main__':main()
